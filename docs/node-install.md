# Installing a node

A node is one Linux host that runs `supapaced`, the shared platform containers and the
projects. This page covers a real host. For a disposable node in a container, see the quick
start in the [README](../README.md); everything there runs the same daemon in development
mode.

> Do not host real data yet: this release has **no backups**.

## A node is dedicated

The node's firewall tables and checks assume nothing else runs on the host:

- **The uplink is not a bridge.** Every interface recorded in `node.json` (`uplinks`, taken at
  init from the interfaces that carry a default route) and every interface that carries a
  default route now must exist and must not be of kind `bridge` (node-check row `uplinks`).
  No macvlan or ipvlan interface may exist besides the uplinks.
- **No other Docker networks.** Only the platform's networks (`platform`, `ingress`,
  `proj-<ref>`) and Docker's defaults (`bridge`, `host`, `none`) may exist, with the drivers
  `bridge`, `host` or `null` (row `docker-networks`); no network may turn inter-container
  traffic off.
- **No other containers that run in the host's network namespace or share the network
  namespace of a platform or project container** unless they drop every capability and add
  none; otherwise every tenant start is refused.
- **Other bridges stop working.** The bridge table drops frames on every bridge it does not
  name, so virtual machines, other container runtimes or anything else that uses a Linux
  bridge cannot talk across it while the tables are loaded.
- **`br_netfilter` must never be loaded.** The install blocks it from loading; if it is
  already loaded, reboot after the install.

## Prerequisites

- Linux on amd64 or arm64, with systemd. Developed and tested with cgroup v2 only.
- nftables (`nft`) with kernel support for the `inet` and `bridge` families and bridge
  connection tracking. The facts the ruleset rests on were established with nftables 1.1 and
  Docker 29 in the test node; re-run the network experiments (`test/harness/experiments`,
  see `AGENTS.md`) after a kernel, nftables or Docker change.
- Docker Engine 26.1.3 or later, with seccomp (`docker info` lists `name=seccomp` with a
  profile other than `unconfined`) and `live-restore` off. Docker's own
  `/etc/docker/daemon.json` must be empty or absent: init writes it (see below) and refuses
  one that holds any other key.
- Host settings checked by `node check`:
  - `kernel.yama.ptrace_scope` at least 1 (row `ptrace_scope`);
  - `fs.file-max` at least 1073741824 (row `file-max`); set it in `/etc/sysctl.d/` if your
    kernel's default is lower;
  - `kernel.core_pattern` not a pipe to a helper (row `core_pattern`; the install sets
    `core`);
  - `br_netfilter` not loaded and a modprobe line `install br_netfilter /bin/false` present
    (row `br_netfilter`; the install writes it).
- **The projects filesystem:** XFS mounted at `/var/lib/supapace/projects` with user-quota
  enforcement and project-quota accounting, and nothing mounted over it. For example:

  ```sh
  mkfs.xfs /dev/DEVICE
  mkdir -p /var/lib/supapace/projects
  echo '/dev/DEVICE /var/lib/supapace/projects xfs defaults,usrquota,prjquota 0 0' >>/etc/fstab
  mount /var/lib/supapace/projects
  grep ' /var/lib/supapace/projects ' /proc/mounts   # must show xfs and usrquota,prjquota
  ```

  A project's disk limit is the XFS user quota of its uid: blocks and an inode limit of
  `max(65536, 256 × MiB)`.
- **Address space.** These ranges are fixed in this release and must not be used or routed by
  anything else on the host:
  - `10.212.0.0/21` the platform network (gateway `10.212.0.2`, PostgREST containers from
    `10.212.0.16`, Docker's dynamic range `10.212.6.0/23`);
  - `10.212.8.0/24` the ingress network (gateway `10.212.8.2`);
  - `10.213.0.0/16` the project networks, one `/26` per project;
  - `10.214.0.0/16` Docker's default address pool (`/26` networks), written to
    `daemon.json`.
- **Ids.** Project uids and gids are taken from `700000` to `765535`; none of them may appear
  in `/etc/passwd`, `/etc/group`, `/etc/subuid` or `/etc/subgid`.
- **Memory.** Each project reserves 768 MiB (512 MiB cluster, 256 MiB PostgREST) against an
  admission ceiling of 75 % of the host's memory (or of the daemon's cgroup limit, if lower);
  the platform containers come on top (gateway limit 768 MiB, control-plane database
  256 MiB). A 4 GiB host admits 4 projects.
- Go 1.25 and make to build the binaries (`make build`), or the binaries from a release.

## Install

As root, from a checkout with `bin/` built (`make build`):

```sh
scripts/install-node.sh --domain example.test --tls-cert /path/cert.pem --tls-key /path/key.pem
# or, for a development node with its own CA:
scripts/install-node.sh --domain example.test --dev
```

The script, which is safe to rerun:

1. checks for root, `bin/supapaced`, `systemctl`, `dockerd` and `nft`, and that
   `/var/lib/supapace/projects` is the topmost mount, XFS with `usrquota` and `prjquota`
   (or `pqnoenforce`);
2. makes `/var/lib/supapace` root 0700;
3. writes `/etc/modprobe.d/supapace.conf` (`install br_netfilter /bin/false`) and
   `/etc/sysctl.d/90-supapace.conf` (`kernel.core_pattern = core`) and applies the latter;
   it warns when `br_netfilter` is already loaded (reboot to unload it);
4. installs `supapaced` and `supapace` to `/usr/local/bin`;
5. runs `supapaced init` with your arguments (below);
6. reloads systemd, enables `supapace-nft.service` and `supapaced.service`, restarts Docker;
7. runs `supapaced nft check`.

`--no-systemd` is refused by the script. Then wait until the daemon serves and check the node:

```sh
until test -S /run/supapace/admin.sock; do sleep 1; done
supapace node check          # exit 0, every row "ok": true
```

### The units

- `supapace-nft.service` (oneshot) runs `supapaced nft load` before Docker starts and again
  whenever the distribution's `nftables.service` is restarted or reloaded (that service
  replaces the whole ruleset); after a stop and start of that service the daemon's drift check
  reloads the tables within 10 s. It has no stop action: stopping it leaves the tables in place.
- `/etc/systemd/system/docker.service.d/10-supapace.conf` makes Docker require the tables
  unit and pull in the daemon.
- `supapaced.service` runs `supapaced serve` as root with `UMask=0077`, restarts it one
  second after any exit, is part of Docker's lifecycle and keeps `/run/supapace` (0700)
  across daemon restarts. Its binary path `/usr/local/bin/supapaced` is fixed. The daemon
  logs to the journal: `journalctl -u supapaced`.

### `supapaced init`

```
supapaced init --domain D [--dev] [--no-systemd] [--ack-escrow] [--tls-cert F --tls-key F]
```

Runs as root without Docker or a database, checks every input before writing, and changes
nothing on a second run with the same inputs. It writes:

- `/etc/supapace/` (0700): `node.json`, `nftables.nft`, `kek` (0400), `kek.escrowed`, and
  with `--dev` the marker `dev-mode`; `tls/cert.pem` and `tls/key.pem`; with `--dev`
  `ca/ca.key` (0400) and `ca/ca.pem` (0644, in the 0700 directory);
- `/etc/docker/daemon.json`: the address pool, `"ipv6": false` and the `local` log driver
  (`max-size` 10m, `max-file` 3). It refuses a file holding any other key and prints the
  merged document to apply by hand; an empty file or a subset is rewritten;
- the three unit files, unless `--no-systemd`.

The domain and development mode are fixed at the first init: a later run with another domain,
or with `--dev` added or dropped, is refused before anything is written.

**The key-encryption key.** The first init generates the node's key-encryption key, which
protects every project's secrets, and prints it as hex:

```
Key-encryption key of this node. Store it offline now; it is shown until acknowledged, then never again:

<64 hex digits>

Type "escrowed" once it is stored:
```

Store it offline, then type `escrowed`. Until you do (or pass `--ack-escrow`, which is
refused when standard output is the null device), every init run shows the same key again
and writes no `kek.escrowed` marker. The key is never replaced: if the key file is damaged
after the acknowledgement, init refuses and asks for the escrowed key. To put it back, write
the 32 bytes as a root-owned regular file of mode 0400 (in bash; `xxd` is in the vim package
on some distributions):

```sh
read -rs HEX            # paste the 64 hex digits; not echoed, not in history
(umask 077; printf '%s' "$HEX" | xxd -r -p >/etc/supapace/kek); chmod 0400 /etc/supapace/kek
unset HEX
```

Without the key, no project secret on the node can be read.

### TLS and DNS

- **DNS:** a wildcard record `*.<domain>` pointing at the node's public IPv4 address. Project
  hosts are `<ref>.<domain>`; the gateway answers IPv4 only (its ports are published on
  `0.0.0.0`) and refuses a request whose TLS server name is not its `Host`.
- **The base domain is dedicated to project hosts.** Put no operator interface and no other
  site under it, and register it as a public suffix before you serve cookie-based surfaces or
  real users from it: projects are sibling hosts, and the gateway's response filter
  (no domain cookies, `Content-Security-Policy: sandbox` on every response) is what keeps one
  project's answers from acting on another's host in a browser. Active content belongs on
  other hosts.
- **Operator certificate:** `--tls-cert`/`--tls-key` (PEM) must match, cover a project host
  of the domain (a `*.<domain>` name), be valid now, and, if it lists extended key usages,
  include serverAuth. To renew, run init again with the new pair; the gateway is re-created
  with the new certificate at the daemon's next repair round (within 60 s; in-flight requests
  are cut).
- **Development CA (`--dev`):** init issues a CA name-constrained to the domain and the
  gateway's ingress address, and a server certificate for `*.<domain>` valid 825 days,
  re-issued from the same CA when it cannot be loaded or expires within 30 days. Clients trust
  `/etc/supapace/ca/ca.pem` (`project keys` prints its path as `ca_cert`). The `dev-mode`
  marker makes the host-global rows `core_pattern`, `br_netfilter` and `file-max`
  informational; every other row stays blocking.

## The reboot check

After the install, and after any kernel, Docker or nftables change, reboot once and check:

```sh
systemctl is-active supapace-nft supapaced docker   # active, three times
supapaced nft check                                   # "nft: tables verified", exit 0
supapace node check                                   # exit 0
cat /run/supapace/boot.json
# {"started_at":"…","nft_ok":true,"tenants_running_at_start":[]}
supapace project list --state active                  # then a request to each project
```

`nft_ok` true means the tables were in place when the daemon first started in this boot;
`tenants_running_at_start` lists tenant containers that were already running at that moment
and must be empty after a reboot (tenant containers have no restart policy: only the daemon
starts them, behind the start gate). Every active project is served again within seconds of
the daemon's start.

## Drift after an nftables upgrade

`supapaced nft check` compares the installed tables with what the last `nft load` recorded:
a hash of the ruleset file and of `nft -s list table` of both tables. A new `nft` that lists
the same rules differently therefore reads as drift (exit 4). If nothing else touched the
tables:

```sh
supapaced nft load      # loads the file again and records the new listing
supapaced nft check     # exit 0
```

The running daemon does the same on its own: its drift check reloads once and checks again
every 10 s, and logs `drift: tables restored by the reload`. If the check still fails after a
load, something else is changing the tables: find it before going on; meanwhile the node is
`containment_failed` (see [operations](operations.md#containment_failed)). Exit codes of
`nft load` and `nft check`: 0 verified, 1 failure, 2 usage, 3 a table is absent, 4 drift,
5 a bridge-netfilter switch is on, 6 not verified (`nft` could not run, failed or timed out).

## Upgrading

Build the new binaries, put them in place and restart the daemon:

```sh
install -m 0755 bin/supapaced bin/supapace /usr/local/bin/
systemctl restart supapaced
```

Do not rerun `scripts/install-node.sh` for an upgrade: it restarts Docker, which stops every
container on the node (the daemon then starts the projects again). A daemon restart does not restart
projects: running tenant containers are adopted. The daemon re-renders the ruleset at start
and loads it when the installed file differs. An upgrade that changes a container's
arguments, rendered files or seccomp profile restarts that container once, cleanly.
