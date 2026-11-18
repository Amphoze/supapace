package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nft"
)

// Every error class of the nft package has its own exit status, wrapped or
// not; anything else is 1.
func TestNftFail_ExitPerClass(t *testing.T) {
	newNode(t)
	for _, c := range []struct {
		err  error
		code int
	}{
		{nft.ErrAbsent, exitAbsent},
		{nft.ErrDrift, exitDrift},
		{nft.ErrBridgeNF, exitBridgeNF},
		{fmt.Errorf("load: %w", nft.ErrBridgeNF), exitBridgeNF},
		{nft.ErrUnverified, exitUnverified},
		{errors.New("other"), 1},
	} {
		var errb strings.Builder
		old := stderr
		stderr = &errb
		code := nftFail("check", c.err)
		stderr = old
		if code != c.code || !oneLine(errb.String()) {
			t.Errorf("nftFail(%v) = %d, stderr %q; want %d and one line", c.err, code, errb.String(), c.code)
		}
	}
}

// A link or a non-directory where init expects one of its directories is
// refused, and nothing is written through it.
func TestInit_RefusesLinkedDirectories(t *testing.T) {
	for _, rel := range []string{"etc/supapace", "etc/supapace/tls"} {
		t.Run(rel, func(t *testing.T) {
			n := newNode(t)
			if rel != "etc/supapace" {
				if err := os.Mkdir(n.path("etc/supapace"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			target := n.path("elsewhere")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, n.path(rel)); err != nil {
				t.Fatal(err)
			}
			if code, _, _ := n.run("", append([]string{"init"}, devArgs...)...); code != 1 {
				t.Fatalf("init with %s a link: exit %d, want 1", rel, code)
			}
			if ents, _ := os.ReadDir(target); len(ents) != 0 {
				t.Errorf("init wrote %d entries through the link", len(ents))
			}
			absent(t, n.p.KEK())
		})
	}
}

// Root-only: a configuration directory owned by another user is refused, and
// a file of init's that another user owns is taken back.
func TestInit_OwnershipAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create files owned by another user")
	}
	t.Run("directory of another user", func(t *testing.T) {
		n := newNode(t)
		if err := os.Mkdir(n.path("etc/supapace"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(n.path("etc/supapace"), 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := n.run("", append([]string{"init"}, devArgs...)...); code != 1 {
			t.Fatalf("exit %d, want 1", code)
		}
		absent(t, n.p.NodeJSON())
	})
	t.Run("file of another user", func(t *testing.T) {
		n := newNode(t)
		n.mustInit(devArgs...)
		if err := os.Chown(n.p.NodeJSON(), 65534, 65534); err != nil {
			t.Fatal(err)
		}
		n.mustInit(devArgs...)
		n.wantMode("etc/supapace/node.json", 0o600)
	})
	// A daemon.json that another user can write is taken back to root 0644,
	// even when its content matches.
	t.Run("daemon.json of another user", func(t *testing.T) {
		n := newNode(t)
		n.mustInit(devArgs...)
		p := n.path("etc/docker/daemon.json")
		if err := os.Chown(p, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
		code, _, errs := n.run("", append([]string{"init"}, devArgs...)...)
		if fi, _ := os.Lstat(p); code != 0 || owner(fi) != 0 || fi.Mode().Perm() != 0o644 {
			t.Errorf("exit %d (stderr %q), daemon.json owner %d mode %v; want 0 and root 0644", code, errs, owner(fi), fi.Mode().Perm())
		}
	})
}

// The projects mount check reads the mount that is on top at the path, and
// only an XFS one counts.
func TestInstallNode_MountChecks(t *testing.T) {
	script := installScript(t)
	for name, mounts := range map[string]string{
		"ext4 with quota options": "/dev/loop0 /var/lib/supapace/projects ext4 rw,usrquota,prjquota 0 0\n",
		"tmpfs over the xfs mount": "/dev/loop0 /var/lib/supapace/projects xfs rw,usrquota,prjquota 0 0\n" +
			"tmpfs /var/lib/supapace/projects tmpfs rw 0 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			// Every other precondition holds, so only the mount check can refuse.
			root, _, env := installEnv(t, mounts)
			if code, out := runInstall(t, script, env); code != 1 || !strings.Contains(out, "/var/lib/supapace/projects") {
				t.Errorf("install of %s: exit %d, want a refusal naming the projects mount\n%s", name, code, out)
			}
			absent(t, filepath.Join(root, "usr/local/bin/supapaced"))
		})
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// The escrow is never marked acknowledged unless its text was shown: a write
// that fails, or --ack-escrow with standard output on the null device (also
// what a closed standard output becomes: the Go runtime opens the null device
// on a closed standard descriptor), ends init with exit 1 and no marker. As
// root, the next run shows the same key.
func TestInit_EscrowNotMarkedWhenNotShown(t *testing.T) {
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skip(err)
	}
	defer null.Close()
	for name, sink := range map[string]io.Writer{"write fails": failWriter{}, "null device": null} {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			var errb strings.Builder
			oldOut, oldErr := stdout, stderr
			stdout, stderr = sink, &errb
			code := run(append([]string{"init"}, devArgs...))
			stdout, stderr = oldOut, oldErr
			if code != 1 || !strings.Contains(errb.String(), "escrow") {
				t.Fatalf("exit %d, stderr %q; want 1 and a message about the escrow", code, errb.String())
			}
			absent(t, filepath.Join(filepath.Dir(n.p.NodeJSON()), "kek.escrowed"))
			if os.Geteuid() != 0 {
				t.Skip("the rerun loads the existing key, which requires a root-owned key file")
			}
			out := n.mustInit(devArgs...)
			if key := escrowLine(t, out); key != fmt.Sprintf("%x", n.read("etc/supapace/kek")) {
				t.Error("the rerun shows another key")
			}
		})
	}
}
