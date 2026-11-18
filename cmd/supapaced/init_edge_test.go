package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A linked tls/ directory is refused, and the cleanup does not reach into the
// directory it names.
func TestInit_LeftoversNotFollowedThroughLink(t *testing.T) {
	n := newNode(t)
	n.mustInit(devArgs...)
	outside := n.path("outside")
	n.write("outside/.key.pem.tmp-0011223344556677", "not init's", 0o600)
	if err := os.Rename(n.path("etc/supapace/tls"), n.path("tls.real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, n.path("etc/supapace/tls")); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := n.run("", append([]string{"init"}, devArgs...)...); code != 1 {
		t.Errorf("init with a linked tls/: exit %d, want 1", code)
	}
	if _, err := os.Lstat(filepath.Join(outside, ".key.pem.tmp-0011223344556677")); err != nil {
		t.Errorf("a file behind the link was removed: %v", err)
	}
}

// On a development node the server pair is issued again from the same CA
// whenever it cannot be loaded.
func TestInit_DevPairReissued(t *testing.T) {
	other := newNode(t)
	other.mustInit(devArgs...)
	otherKey := other.read("etc/supapace/tls/key.pem")
	for name, spoil := range map[string]func(n *node) error{
		"certificate garbage": func(n *node) error {
			return os.WriteFile(n.path("etc/supapace/tls/cert.pem"), []byte("garbage\n"), 0o600)
		},
		"key missing": func(n *node) error { return os.Remove(n.path("etc/supapace/tls/key.pem")) },
		"key of another pair": func(n *node) error {
			return os.WriteFile(n.path("etc/supapace/tls/key.pem"), otherKey, 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			n.mustInit(devArgs...)
			ca := n.read("etc/supapace/ca/ca.pem")
			if err := spoil(n); err != nil {
				t.Fatal(err)
			}
			n.mustInit(devArgs...)
			if _, err := tls.LoadX509KeyPair(n.path("etc/supapace/tls/cert.pem"), n.path("etc/supapace/tls/key.pem")); err != nil {
				t.Fatalf("the development pair does not load after init: %v", err)
			}
			if string(ca) != string(n.read("etc/supapace/ca/ca.pem")) {
				t.Error("the CA was replaced")
			}
			n.wantMode("etc/supapace/tls/key.pem", 0o600)
			n.wantMode("etc/supapace/tls/cert.pem", 0o600)
		})
	}
}

// The install script refuses every spelling the Go flag syntax accepts for
// --no-systemd, before anything is written.
func TestInstallNode_RefusesEveryNoSystemdSpelling(t *testing.T) {
	script := installScript(t)
	for _, a := range []string{"--no-systemd", "-no-systemd", "--no-systemd=true", "-no-systemd=1"} {
		root, calls, env := installEnv(t, goodMount)
		code, out := runInstall(t, script, env, "--domain", "sp.test", "--dev", a)
		if code != 1 || !strings.Contains(out, a+" is refused") {
			t.Errorf("%s: exit %d, want a refusal naming it\n%s", a, code, out)
		}
		absent(t, calls)
		absent(t, filepath.Join(root, "etc/modprobe.d"))
		absent(t, filepath.Join(root, "usr/local/bin/supapaced"))
	}
}
