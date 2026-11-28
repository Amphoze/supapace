#!/bin/sh
# Installs a supapace node on a systemd host with Docker (a CI VM or a real
# server), as root:
#
#   scripts/install-node.sh --domain D (--dev | --tls-cert F --tls-key F) [--ack-escrow]
#       [--studio-domain S [--studio-tls-cert F --studio-tls-key F]]
#       [--pooler-label L [--pooler-tls-cert F --pooler-tls-key F]] [--public-addr A]...
#
# The studio pair is required with --studio-domain, and the pooler pair (naming
# *.<L>.<D> alone) with --pooler-label, unless --dev is given or a pair is
# already stored. --public-addr, once for each, names every address under
# which the outside sees the node: what its names resolve to, and every source
# address the provider gives its outbound traffic.
#
# The arguments are passed to `supapaced init` (--no-systemd is refused: this
# script exists to wire systemd). Binaries come from BIN_DIR (default bin/, as
# built by `make build`). Before running it, mount the projects filesystem:
# XFS at /var/lib/supapace/projects with usrquota,prjquota; and the repository
# filesystem: XFS at /var/lib/supapace/repo with usrquota,nosuid,nodev,noexec
# (a file system of its own, so a full repository never fills the projects').
# Do not run it on a
# host before the daemon binary provides `serve`: Docker's drop-in pulls in
# the daemon unit, which would otherwise restart every second.
#
# Steps: check the tools and the two filesystems; block br_netfilter, list the
# kernel modules a node needs for the host's boot (loaded by nothing here: the
# command is printed for a host that is not rebooted), set
# kernel.core_pattern and fs.protected_hardlinks; install the binaries
# (supapaced, supapace-arch, supapace when built); supapaced init; enable the
# units; restart Docker (so its drop-in and daemon.json apply before the first
# network exists, with our tables loaded before it); verify the tables. Safe
# to rerun: every step leaves an installed node as it is.
#
# ROOT (default empty) prefixes the paths this script itself reads and writes;
# it exists for the script's tests. It does not redirect `supapaced init`,
# which always writes the real /etc: the tests use a stand-in supapaced, and
# stand-ins for systemctl, sysctl, dockerd and nft on PATH.
set -eu
umask 022

ROOT=${ROOT:-}
BIN_DIR=${BIN_DIR:-bin}
PROJECTS=/var/lib/supapace/projects
REPO=/var/lib/supapace/repo

log() { echo "install-node: $*" >&2; }
die() {
	log "$*"
	exit 1
}

# write DEST MODE TEXT: replace DEST with one line of TEXT unless it is a
# regular file (not a link) holding exactly that. The new file is written,
# synced and renamed into place in DEST's directory, so an existing link at
# DEST is replaced, never written through.
write() {
	if [ -f "$1" ] && [ ! -L "$1" ] && [ "$(cat "$1")" = "$3" ]; then
		chmod "$2" "$1"
		return 0
	fi
	mkdir -p "${1%/*}"
	printf '%s\n' "$3" >"$1.tmp.$$"
	chmod "$2" "$1.tmp.$$"
	sync "$1.tmp.$$" 2>/dev/null || sync
	mv -f "$1.tmp.$$" "$1"
	log "wrote $1"
}

# install_bin NAME: copy BIN_DIR/NAME to /usr/local/bin atomically (a running
# process keeps its old file).
install_bin() {
	dest=$ROOT/usr/local/bin/$1
	mkdir -p "${dest%/*}"
	cp "$BIN_DIR/$1" "$dest.tmp.$$"
	chmod 0755 "$dest.tmp.$$"
	mv -f "$dest.tmp.$$" "$dest"
	log "installed $dest"
}

for a in "$@"; do
	case $a in
	-no-systemd | --no-systemd | -no-systemd=* | --no-systemd=*)
		die "$a is refused: this script installs and enables the systemd units"
		;;
	esac
done
[ -n "$ROOT" ] || [ "$(id -u)" = 0 ] || die "must run as root"
[ -x "$BIN_DIR/supapaced" ] || die "$BIN_DIR/supapaced not found; run make build"
[ -x "$BIN_DIR/supapace-arch" ] || die "$BIN_DIR/supapace-arch not found; run make build"
command -v systemctl >/dev/null || die "systemd is required"
command -v dockerd >/dev/null || die "Docker is not installed"
# Docker's drop-in requires the tables unit, which runs nft: without it Docker
# would not start again.
command -v nft >/dev/null || die "nftables (nft) is required"

# xfs_opts PATH: the mount options of PATH when the mount on top (the last
# entry for the path, the one that is used) is XFS; empty otherwise.
xfs_opts() {
	awk -v m="$1" '$2 == m { t = $3; o = $4 } END { if (t == "xfs") print o }' "$ROOT/proc/mounts"
}

# The disk limit of a project is its XFS user quota, so enforcement must be on;
# project quota is used for accounting.
opts=$(xfs_opts "$PROJECTS")
[ -n "$opts" ] || die "$PROJECTS is not an XFS mount (or another mount covers it); mount it with usrquota,prjquota first"
case ",$opts," in
*,usrquota,* | *,uquota,*) ;;
*) die "user quota enforcement is off on $PROJECTS (mount options: $opts)" ;;
esac
case ",$opts," in
*,prjquota,* | *,pquota,* | *,pqnoenforce,*) ;;
*) die "project quota accounting is off on $PROJECTS (mount options: $opts)" ;;
esac
# The repositories: each project's limit is its user quota there too; nothing
# on it is ever run, set-uid or a device.
opts=$(xfs_opts "$REPO")
[ -n "$opts" ] || die "$REPO is not an XFS mount (or another mount covers it); mount it with usrquota,nosuid,nodev,noexec first"
case ",$opts," in
*,usrquota,* | *,uquota,*) ;;
*) die "user quota enforcement is off on $REPO (mount options: $opts)" ;;
esac
for o in nosuid nodev noexec; do
	case ",$opts," in
	*,$o,*) ;;
	*) die "$REPO is not mounted $o (mount options: $opts)" ;;
	esac
done
# A file system of its own: on the projects filesystem (a bind mount) one user
# quota per uid would be both limits.
mount_src() { awk -v m="$1" '$2 == m { s = $1 } END { print s }' "$ROOT/proc/mounts"; }
[ "$(mount_src "$REPO")" != "$(mount_src "$PROJECTS")" ] ||
	die "$REPO is on the projects filesystem; give the repositories a file system of their own"
# root:root 0700: the script runs as root (only the tests' ROOT runs it as
# another user, which then owns the scratch tree).
chown "$(id -u):$(id -g)" "$ROOT/var/lib/supapace"
chmod 0700 "$ROOT/var/lib/supapace"

# br_netfilter would divert bridged frames into the routed chains; nothing on
# a node may load it. Core files stay inside the crashing container. Protected
# hard links: a process links only files it owns or can read and write.
write "$ROOT/etc/modprobe.d/supapace.conf" 0644 "install br_netfilter /bin/false"
# The modules the containment tables need, loaded by the host's own boot before
# the tables' unit; this script loads none.
write "$ROOT/etc/modules-load.d/supapace.conf" 0644 "nf_conntrack_bridge
nft_connlimit"
for m in nf_conntrack_bridge nft_connlimit; do
	if [ ! -e "$ROOT/sys/module/$m" ]; then
		log "the kernel modules of /etc/modules-load.d/supapace.conf load at the next boot; to load them now, run: modprobe -a nf_conntrack_bridge nft_connlimit"
		break
	fi
done
write "$ROOT/etc/sysctl.d/90-supapace.conf" 0644 "kernel.core_pattern = core
fs.protected_hardlinks = 1"
sysctl -q -p "$ROOT/etc/sysctl.d/90-supapace.conf"
if [ -e "$ROOT/sys/module/br_netfilter" ]; then
	log "warning: br_netfilter is loaded; it is blocked from now on, reboot to unload it"
fi

install_bin supapaced
install_bin supapace-arch
if [ -x "$BIN_DIR/supapace" ]; then
	install_bin supapace
fi

"$ROOT/usr/local/bin/supapaced" init "$@"

systemctl daemon-reload
systemctl enable supapace-nft.service supapaced.service
systemctl restart docker.service
"$ROOT/usr/local/bin/supapaced" nft check
log "node installed"
