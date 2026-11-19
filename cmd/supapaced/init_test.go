package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/secrets"
)

// node is a fake node root for one test: init writes below it.
type node struct {
	t    *testing.T
	root string
	p    nodecfg.Paths
}

// newNode prepares a root holding /etc with passwd and group files that keep
// clear of the reserved id range, and points the command at it.
func newNode(t *testing.T) *node {
	t.Helper()
	root := t.TempDir()
	n := &node{t: t, root: root, p: nodecfg.Paths{Root: root}}
	n.write("etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n", 0o644)
	n.write("etc/group", "root:x:0:\nnogroup:x:65534:\n", 0o644)
	oldPaths, oldRoot := paths, rootOnly
	paths, rootOnly = n.p, false
	t.Cleanup(func() { paths, rootOnly = oldPaths, oldRoot })
	return n
}

func (n *node) path(rel string) string { return filepath.Join(n.root, rel) }

func (n *node) write(rel, s string, mode os.FileMode) {
	n.t.Helper()
	p := n.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		n.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), mode); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) read(rel string) []byte {
	n.t.Helper()
	b, err := os.ReadFile(n.path(rel))
	if err != nil {
		n.t.Fatal(err)
	}
	return b
}

// run runs supapaced with args and input on stdin; it returns the exit status
// and what went to stdout and stderr.
func (n *node) run(input string, args ...string) (int, string, string) {
	n.t.Helper()
	var out, errb bytes.Buffer
	oldIn, oldOut, oldErr := stdin, stdout, stderr
	stdin, stdout, stderr = strings.NewReader(input), &out, &errb
	defer func() { stdin, stdout, stderr = oldIn, oldOut, oldErr }()
	code := run(args)
	return code, out.String(), errb.String()
}

// mustInit runs init and fails the test unless it exits 0.
func (n *node) mustInit(args ...string) string {
	n.t.Helper()
	code, out, errs := n.run("", append([]string{"init"}, args...)...)
	if code != 0 {
		n.t.Fatalf("init %v: exit %d\nstdout: %s\nstderr: %s", args, code, out, errs)
	}
	return out
}

var devArgs = []string{"--domain", "sp.test", "--dev", "--no-systemd", "--ack-escrow"}

// mode returns the permission bits and owner of rel.
func (n *node) mode(rel string) (os.FileMode, int) {
	n.t.Helper()
	fi, err := os.Lstat(n.path(rel))
	if err != nil {
		n.t.Fatal(err)
	}
	return fi.Mode(), int(fi.Sys().(*syscall.Stat_t).Uid)
}

func (n *node) wantMode(rel string, want os.FileMode) {
	n.t.Helper()
	m, uid := n.mode(rel)
	if m != want || uid != os.Geteuid() {
		n.t.Errorf("%s: mode %v owner %d, want %v owner %d", rel, m, uid, want, os.Geteuid())
	}
}

func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("%s exists (%v), want absent", path, err)
	}
}

// snapshot records every file and directory below root with its mode, owner,
// inode, modification time and content: equal snapshots mean nothing changed.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		v := fmt.Sprintf("%v %d %d %d", fi.Mode(), st.Uid, st.Ino, fi.ModTime().UnixNano())
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		m[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInit_WritesNodeJSONDefaults(t *testing.T) {
	n := newNode(t)
	n.mustInit(devArgs...)
	n.wantMode("etc/supapace", fs.ModeDir|0o700)
	n.wantMode("etc/supapace/node.json", 0o600)
	got, err := nodecfg.Load(n.p.NodeJSON())
	if err != nil {
		t.Fatalf("node.json does not load: %v", err)
	}
	want := nodecfg.Default("sp.test")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("node.json = %+v\nwant nodecfg.Default = %+v", got, want)
	}
	locked, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	if got.Images != locked {
		t.Errorf("images = %+v, want the embedded lock %+v", got.Images, locked)
	}
	if got.NodeID != "local" || got.GatewayIP != "10.212.0.2" || got.UIDBase != 700000 || got.UIDCount != 65536 || got.Retention != "168h" {
		t.Errorf("fixed defaults not written: %+v", got)
	}
}

// The admission ceiling recorded at init is 75 % of the smallest of MemTotal
// and every numeric memory.max from this process's cgroup up to the namespace
// root. The oracle below walks the real tree independently; on the test node
// (a 4 GiB container whose daemon sits in a child cgroup with no limit) it is
// 3072. The fixture-root variant of the same walk is nodecfg's
// TestDefault_ComputedFromRoot.
func TestInit_MemAllocWalksCgroupAncestors(t *testing.T) {
	limit := int64(-1)
	mi, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Skipf("no /proc/meminfo: %v", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(mi))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			limit = kb * 1024
		}
	}
	cg, _ := os.ReadFile("/proc/self/cgroup")
	for _, line := range strings.Split(string(cg), "\n") {
		rel, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		for dir := filepath.Join("/sys/fs/cgroup", rel); strings.HasPrefix(dir, "/sys/fs/cgroup"); dir = filepath.Dir(dir) {
			b, err := os.ReadFile(filepath.Join(dir, "memory.max"))
			if v, perr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && perr == nil && v < limit {
				limit = v
			}
		}
	}
	want := int(limit / (1 << 20) * 3 / 4)

	n := newNode(t)
	n.mustInit(devArgs...)
	c, err := nodecfg.Load(n.p.NodeJSON())
	if err != nil {
		t.Fatal(err)
	}
	if c.MemAllocMB != want {
		t.Errorf("mem_alloc_mb = %d, want %d", c.MemAllocMB, want)
	}
	t.Logf("mem_alloc_mb = %d", c.MemAllocMB)
}

func TestInit_RefusesOverlapUIDRange(t *testing.T) {
	cases := map[string][2]string{
		"passwd uid": {"etc/passwd", "root:x:0:0:root:/root:/bin/sh\nsvc:x:700100:100:svc:/srv:/bin/false\n"},
		"passwd gid": {"etc/passwd", "root:x:0:0:root:/root:/bin/sh\nsvc:x:1000:765535:svc:/srv:/bin/false\n"},
		"group gid":  {"etc/group", "root:x:0:\nsvc:x:700000:\n"},
		"subuid":     {"etc/subuid", "user:600000:200000\n"},
		"subgid":     {"etc/subgid", "user:765535:10\n"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			n.write(c[0], c[1], 0o644)
			code, _, errs := n.run("", append([]string{"init"}, devArgs...)...)
			if code != 1 || !strings.Contains(errs, "reserved range") {
				t.Fatalf("init with %s in the range: exit %d, stderr %q; want 1 and the range refusal", name, code, errs)
			}
			absent(t, n.p.NodeJSON())
			absent(t, n.p.KEK())
			absent(t, n.path("etc/docker/daemon.json"))
		})
	}
	t.Run("ids just outside", func(t *testing.T) {
		n := newNode(t)
		n.write("etc/passwd", "a:x:699999:699999:svc:/srv:/bin/false\nb:x:765536:765536:svc:/srv:/bin/false\n", 0o644)
		n.write("etc/subuid", "user:100000:600000\n", 0o644)
		n.mustInit(devArgs...)
	})
	t.Run("passwd missing", func(t *testing.T) {
		n := newNode(t)
		if err := os.Remove(n.path("etc/passwd")); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := n.run("", append([]string{"init"}, devArgs...)...); code != 1 {
			t.Fatalf("init without passwd: exit %d, want 1", code)
		}
		absent(t, n.p.NodeJSON())
	})
}

// Without --ack-escrow the key is shown and init waits for the typed word; a
// run that is not acknowledged leaves no marker. Whether to show is decided by
// the marker, never by the key file: a key that was written but never
// acknowledged is shown again (the same key).
func TestInit_ShowsEscrowOnceAndNeedsAck(t *testing.T) {
	args := []string{"init", "--domain", "sp.test", "--dev", "--no-systemd"}
	t.Run("no ack, then ack", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("re-showing an existing key loads it, which requires a root-owned key file: runs as root on the node")
		}
		n := newNode(t)
		marker := filepath.Join(filepath.Dir(n.p.NodeJSON()), "kek.escrowed")
		code, out1, errs := n.run("", args...)
		if code != 1 || !strings.Contains(errs, "not acknowledged") {
			t.Fatalf("init without acknowledgement: exit %d, stderr %q", code, errs)
		}
		key1 := escrowLine(t, out1)
		absent(t, marker)
		n.wantMode("etc/supapace/kek", 0o400)

		code, out2, errs := n.run("no\n", args...)
		if code != 1 || escrowLine(t, out2) != key1 {
			t.Fatalf("wrong word: exit %d (stderr %q); want 1 and the same key shown again", code, errs)
		}
		absent(t, marker)

		code, out3, errs := n.run("escrowed\n", args...)
		if code != 0 {
			t.Fatalf("acknowledged: exit %d, stderr %q", code, errs)
		}
		if escrowLine(t, out3) != key1 {
			t.Error("the acknowledged key is not the key shown first")
		}
		n.wantMode("etc/supapace/kek.escrowed", 0o600)

		before := snapshot(t, n.root)
		code, out4, _ := n.run("", args...)
		if code != 0 || strings.Contains(out4, key1) {
			t.Fatalf("after acknowledgement: exit %d, output shows the key: %q", code, out4)
		}
		if after := snapshot(t, n.root); !reflect.DeepEqual(before, after) {
			t.Error("a run after acknowledgement changed files")
		}
	})

	t.Run("no ack leaves no marker", func(t *testing.T) {
		n := newNode(t)
		code, out, errs := n.run("", args...)
		if code != 1 || !strings.Contains(errs, "not acknowledged") || !strings.Contains(out, `"escrowed"`) {
			t.Fatalf("init without acknowledgement: exit %d, stdout %q, stderr %q", code, out, errs)
		}
		escrowLine(t, out)
		absent(t, filepath.Join(filepath.Dir(n.p.NodeJSON()), "kek.escrowed"))
		n.wantMode("etc/supapace/kek", 0o400)
	})

	t.Run("typed ack on a fresh key", func(t *testing.T) {
		n := newNode(t)
		code, out, errs := n.run("escrowed\n", args...)
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
		key := escrowLine(t, out)
		raw := n.read("etc/supapace/kek")
		if key != fmt.Sprintf("%x", raw) {
			t.Error("the escrow text is not the key written")
		}
		code, out, _ = n.run("", args...)
		if code != 0 || strings.Contains(out, key) {
			t.Fatalf("second run: exit %d, shows the key: %q", code, out)
		}
	})

	t.Run("flag ack shows once", func(t *testing.T) {
		n := newNode(t)
		out := n.mustInit(devArgs...)
		key := escrowLine(t, out)
		if out = n.mustInit(devArgs...); strings.Contains(out, key) {
			t.Fatalf("second run shows the key: %q", out)
		}
	})

	t.Run("marker without key refused", func(t *testing.T) {
		n := newNode(t)
		n.mustInit(devArgs...)
		if err := os.Remove(n.p.KEK()); err != nil {
			t.Fatal(err)
		}
		code, out, errs := n.run("", append([]string{"init"}, devArgs...)...)
		if code != 1 || !strings.Contains(errs, "key") {
			t.Fatalf("marker without key: exit %d, stderr %q", code, errs)
		}
		absent(t, n.p.KEK())
		if strings.Contains(out, "escrow") {
			t.Errorf("a new key was offered: %q", out)
		}
	})
}

// escrowLine returns the 64-hex-digit key line of init's output.
func escrowLine(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if len(l) == 64 && strings.Trim(l, "0123456789abcdef") == "" {
			return l
		}
	}
	t.Fatalf("no escrow line in %q", out)
	return ""
}

func TestInit_Idempotent(t *testing.T) {
	n := newNode(t)
	first := n.mustInit("--domain", "sp.test", "--dev", "--ack-escrow")
	key := escrowLine(t, first)
	before := snapshot(t, n.root)
	second := n.mustInit("--domain", "sp.test", "--dev", "--ack-escrow")
	if strings.Contains(second, key) {
		t.Errorf("second run shows key material: %q", second)
	}
	if !strings.Contains(second, "nothing to change") {
		t.Errorf("second run output %q, want it to say nothing changed", second)
	}
	if after := snapshot(t, n.root); !reflect.DeepEqual(before, after) {
		for k, v := range after {
			if before[k] != v {
				t.Errorf("changed: %s", k)
			}
		}
		t.Fatal("second run changed files")
	}

	t.Run("other domain refused", func(t *testing.T) {
		code, _, errs := n.run("", "init", "--domain", "other.test", "--dev", "--ack-escrow")
		if code != 1 || !strings.Contains(errs, "domain") {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
		if after := snapshot(t, n.root); !reflect.DeepEqual(before, after) {
			t.Error("a refused run changed files")
		}
	})
	t.Run("invalid node.json kept", func(t *testing.T) {
		m := newNode(t)
		m.write("etc/supapace/node.json", `{"node_id":"local"}`, 0o600)
		if err := os.Chmod(m.path("etc/supapace"), 0o700); err != nil {
			t.Fatal(err)
		}
		code, _, _ := m.run("", append([]string{"init"}, devArgs...)...)
		if code != 1 || string(m.read("etc/supapace/node.json")) != `{"node_id":"local"}` {
			t.Fatalf("exit %d; an invalid node.json must be refused and kept", code)
		}
	})
	t.Run("mode of node.json repaired", func(t *testing.T) {
		if err := os.Chmod(n.p.NodeJSON(), 0o644); err != nil {
			t.Fatal(err)
		}
		n.mustInit("--domain", "sp.test", "--dev", "--ack-escrow")
		n.wantMode("etc/supapace/node.json", 0o600)
	})
	t.Run("loose directory refused", func(t *testing.T) {
		m := newNode(t)
		if err := os.MkdirAll(m.path("etc/supapace"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(m.path("etc/supapace"), 0o755); err != nil {
			t.Fatal(err)
		}
		code, _, errs := m.run("", append([]string{"init"}, devArgs...)...)
		if code != 1 || !strings.Contains(errs, "0700") {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
		absent(t, m.p.KEK())
	})
}

func TestInit_WritesDaemonJSON(t *testing.T) {
	n := newNode(t)
	n.mustInit(devArgs...)
	n.wantMode("etc/docker/daemon.json", 0o644)
	var got map[string]any
	if err := json.Unmarshal(n.read("etc/docker/daemon.json"), &got); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(`{
		"default-address-pools": [{"base": "10.214.0.0/16", "size": 26}],
		"ipv6": false,
		"log-driver": "local",
		"log-opts": {"max-size": "10m", "max-file": "3"}
	}`), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("daemon.json = %v, want %v", got, want)
	}
	for _, k := range []string{"userland-proxy", "icc", "live-restore"} {
		if _, ok := got[k]; ok {
			t.Errorf("daemon.json carries %q; the userland proxy stays on, icc and live-restore are left alone", k)
		}
	}

	t.Run("same keys in another layout accepted", func(t *testing.T) {
		m := newNode(t)
		m.write("etc/docker/daemon.json", `{"ipv6":false,"log-driver":"local","log-opts":{"max-file":"3","max-size":"10m"},"default-address-pools":[{"size":26,"base":"10.214.0.0/16"}]}`, 0o644)
		before := m.read("etc/docker/daemon.json")
		m.mustInit(devArgs...)
		if !bytes.Equal(before, m.read("etc/docker/daemon.json")) {
			t.Error("an equivalent daemon.json was rewritten")
		}
	})
	t.Run("empty object completed", func(t *testing.T) {
		m := newNode(t)
		m.write("etc/docker/daemon.json", "{}\n", 0o644)
		m.mustInit(devArgs...)
		var got map[string]any
		if err := json.Unmarshal(m.read("etc/docker/daemon.json"), &got); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("daemon.json after {} = %v (%v)", got, err)
		}
	})

	foreign := map[string]string{
		"other key":         `{"data-root":"/srv/docker"}`,
		"userland-proxy":    `{"userland-proxy":false}`,
		"different value":   `{"ipv6":true}`,
		"not an object":     `[1]`,
		"not json":          `{"ipv6":`,
		"other pool":        `{"default-address-pools":[{"base":"10.214.0.0/16","size":24}]}`,
		"icc and live-rest": `{"icc":false,"live-restore":true}`,
	}
	for name, body := range foreign {
		t.Run("refuses "+name, func(t *testing.T) {
			m := newNode(t)
			m.write("etc/docker/daemon.json", body, 0o644)
			code, _, errs := m.run("", append([]string{"init"}, devArgs...)...)
			if code != 1 || !strings.Contains(errs, "daemon.json") {
				t.Fatalf("exit %d, stderr %q; want a refusal naming daemon.json", code, errs)
			}
			if got := string(m.read("etc/docker/daemon.json")); got != body {
				t.Errorf("daemon.json changed to %q", got)
			}
			absent(t, m.p.NodeJSON())
			absent(t, m.p.KEK())
			if strings.HasPrefix(body, "{") && json.Valid([]byte(body)) {
				// The merge it needs is printed as one JSON document.
				i := strings.Index(errs, "{")
				var merged map[string]any
				if i < 0 || json.NewDecoder(strings.NewReader(errs[i:])).Decode(&merged) != nil {
					t.Fatalf("no merged document in %q", errs)
				}
				for k, v := range want {
					if !reflect.DeepEqual(merged[k], v) {
						t.Errorf("merge: %s = %v, want %v", k, merged[k], v)
					}
				}
				for _, k := range []string{"userland-proxy", "icc", "live-restore"} {
					if _, ok := merged[k]; ok {
						t.Errorf("merge keeps %q", k)
					}
				}
				if name == "other key" && merged["data-root"] != "/srv/docker" {
					t.Error("merge drops the operator's own key")
				}
			}
		})
	}
}

func TestInit_DevCA(t *testing.T) {
	n := newNode(t)
	n.mustInit(devArgs...)
	n.wantMode("etc/supapace/ca", fs.ModeDir|0o700)
	n.wantMode("etc/supapace/tls", fs.ModeDir|0o700)
	n.wantMode("etc/supapace/ca/ca.key", 0o400)
	n.wantMode("etc/supapace/ca/ca.pem", 0o644)
	n.wantMode("etc/supapace/tls/key.pem", 0o600)
	n.wantMode("etc/supapace/tls/cert.pem", 0o600)
	n.wantMode("etc/supapace/dev-mode", 0o600)
	if len(n.read("etc/supapace/dev-mode")) != 0 {
		t.Error("dev-mode marker is not empty")
	}
	ents, err := os.ReadDir(n.path("etc/supapace/tls"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Errorf("tls/ holds %d entries, want cert.pem and key.pem only", len(ents))
	}
	caKey := n.read("etc/supapace/ca/ca.key")
	for _, e := range ents {
		if bytes.Equal(n.read("etc/supapace/tls/"+e.Name()), caKey) {
			t.Errorf("tls/%s is the CA key", e.Name())
		}
	}

	pair, err := tls.X509KeyPair(n.read("etc/supapace/tls/cert.pem"), n.read("etc/supapace/tls/key.pem"))
	if err != nil {
		t.Fatalf("server pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leaf.DNSNames, []string{"*.sp.test"}) {
		t.Errorf("server certificate names %v, want [*.sp.test]", leaf.DNSNames)
	}
	if leaf.IsCA {
		t.Error("server certificate is a CA")
	}
	block, _ := pem.Decode(n.read("etc/supapace/ca/ca.pem"))
	if block == nil {
		t.Fatal("ca.pem holds no PEM block")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA {
		t.Fatalf("ca.pem: %v, IsCA %v", err, ca != nil && ca.IsCA)
	}
	if _, err := tls.X509KeyPair(n.read("etc/supapace/ca/ca.pem"), caKey); err != nil {
		t.Errorf("ca.key does not match ca.pem: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, host := range []string{"abcdefghij0123456789.sp.test", "10.212.8.2"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("server certificate for %s does not verify against the dev CA: %v", host, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "a.b.sp.test"}); err == nil {
		t.Error("server certificate verifies for a host two labels below the domain")
	}

	t.Run("no CA without dev", func(t *testing.T) {
		m := newNode(t)
		certPEM, keyPEM := n.read("etc/supapace/tls/cert.pem"), n.read("etc/supapace/tls/key.pem")
		m.write("in/cert.pem", string(certPEM), 0o644)
		m.write("in/key.pem", string(keyPEM), 0o600)
		m.mustInit("--domain", "sp.test", "--no-systemd", "--ack-escrow", "--tls-cert", m.path("in/cert.pem"), "--tls-key", m.path("in/key.pem"))
		absent(t, m.path("etc/supapace/ca"))
		absent(t, m.path("etc/supapace/dev-mode"))
		m.wantMode("etc/supapace/tls/key.pem", 0o600)
		m.wantMode("etc/supapace/tls/cert.pem", 0o600)
		if !bytes.Equal(m.read("etc/supapace/tls/key.pem"), keyPEM) {
			t.Error("operator key not installed")
		}
	})
}

// Operator TLS input is checked before anything is written.
func TestInit_TLSFlags(t *testing.T) {
	src := newNode(t)
	src.mustInit(devArgs...)
	cert, key := string(src.read("etc/supapace/tls/cert.pem")), string(src.read("etc/supapace/tls/key.pem"))
	caKey := string(src.read("etc/supapace/ca/ca.key"))

	cases := []struct {
		name string
		args []string
		code int
	}{
		{"no domain", []string{"--dev", "--ack-escrow"}, 2},
		{"bad domain", []string{"--domain", "SP.test", "--dev", "--ack-escrow"}, 1},
		{"no tls without dev", []string{"--domain", "sp.test", "--ack-escrow"}, 2},
		{"cert without key", []string{"--domain", "sp.test", "--ack-escrow", "--tls-cert", "C"}, 2},
		{"dev with tls", []string{"--domain", "sp.test", "--dev", "--ack-escrow", "--tls-cert", "C", "--tls-key", "K"}, 2},
		{"extra argument", []string{"--domain", "sp.test", "--dev", "--ack-escrow", "extra"}, 2},
		{"key does not match", []string{"--domain", "sp.test", "--ack-escrow", "--tls-cert", "C", "--tls-key", "W"}, 1},
		{"other domain", []string{"--domain", "other.test", "--ack-escrow", "--tls-cert", "C", "--tls-key", "K"}, 1},
		{"missing file", []string{"--domain", "sp.test", "--ack-escrow", "--tls-cert", "C", "--tls-key", "missing"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := newNode(t)
			n.write("in/C", cert, 0o644)
			n.write("in/K", key, 0o600)
			n.write("in/W", caKey, 0o600)
			args := []string{"init", "--no-systemd"}
			for _, a := range c.args {
				if a == "C" || a == "K" || a == "W" || a == "missing" {
					a = n.path("in/" + a)
				}
				args = append(args, a)
			}
			code, _, errs := n.run("", args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d; stderr %q", code, c.code, errs)
			}
			absent(t, n.p.NodeJSON())
			absent(t, n.p.KEK())
			absent(t, n.path("etc/supapace/tls"))
		})
	}
}

func TestInit_RefusesWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	n := newNode(t)
	rootOnly = true
	code, _, errs := n.run("", append([]string{"init"}, devArgs...)...)
	if code != 1 || !strings.Contains(errs, "root") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	absent(t, n.path("etc/supapace"))
}

func TestInit_InstallsUnitsUnlessNoSystemd(t *testing.T) {
	n := newNode(t)
	n.mustInit("--domain", "sp.test", "--dev", "--ack-escrow")
	units := nft.Units()
	if len(units) != 3 {
		t.Fatalf("nft.Units() has %d files, want 3", len(units))
	}
	want := map[string]string{
		"supapace-nft.service":    "etc/systemd/system/supapace-nft.service",
		"supapaced.service":       "etc/systemd/system/supapaced.service",
		"docker-10-supapace.conf": "etc/systemd/system/docker.service.d/10-supapace.conf",
	}
	for name, text := range units {
		rel, ok := want[name]
		if !ok {
			t.Errorf("unit %s has no expected path", name)
			continue
		}
		if !bytes.Equal(n.read(rel), text) {
			t.Errorf("%s differs from nft.Units()[%q]", rel, name)
		}
		n.wantMode(rel, 0o644)
	}

	m := newNode(t)
	m.mustInit(devArgs...)
	absent(t, m.path("etc/systemd"))
}

func TestInit_RendersRuleset(t *testing.T) {
	n := newNode(t)
	n.mustInit(devArgs...)
	n.wantMode("etc/supapace/nftables.nft", 0o600)
	c, err := nodecfg.Load(n.p.NodeJSON())
	if err != nil {
		t.Fatal(err)
	}
	want, err := nft.Render(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(n.read("etc/supapace/nftables.nft"), want) {
		t.Error("nftables.nft is not nft.Render(node.json)")
	}
	// A file from an older binary is rendered again.
	if err := os.WriteFile(n.p.NftFile(), []byte("table inet supapace {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.mustInit(devArgs...)
	if !bytes.Equal(n.read("etc/supapace/nftables.nft"), want) {
		t.Error("a stale ruleset file was not rendered again")
	}
}

func TestMain_Usage(t *testing.T) {
	n := newNode(t)
	for _, args := range [][]string{nil, {"bogus"}, {"nft"}, {"nft", "flush"}, {"nft", "load", "extra"}} {
		if code, _, errs := n.run("", args...); code != 2 || errs == "" {
			t.Errorf("supapaced %v: exit %d, stderr %q; want 2 and a usage line", args, code, errs)
		}
	}
}

// installScript returns the install script's path, relative to this package
// in the repository; a test binary run elsewhere skips.
func installScript(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	script, err := filepath.Abs("../../scripts/install-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Skipf("install script not found relative to the test (%v): run the test from cmd/supapaced in the repository", err)
	}
	return script
}

// installEnv prepares a scratch root whose /proc/mounts holds mounts, a
// BIN_DIR with a supapaced stand-in, and stand-ins for every host tool the
// script needs except those in missing. Every stand-in records its call.
func installEnv(t *testing.T, mounts string, missing ...string) (root, calls string, env []string) {
	t.Helper()
	root, bin, fake := t.TempDir(), t.TempDir(), t.TempDir()
	calls = filepath.Join(t.TempDir(), "calls")
	rec := "#!/bin/sh\necho \"${0##*/} $*\" >>" + calls + "\n"
	for dir, names := range map[string][]string{bin: {"supapaced"}, fake: {"systemctl", "sysctl", "dockerd", "nft"}} {
		for _, name := range names {
			if slices.Contains(missing, name) {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(rec), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, d := range []string{"proc", "var/lib/supapace/projects"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "proc/mounts"), []byte("proc /proc proc rw 0 0\n"+mounts), 0o644); err != nil {
		t.Fatal(err)
	}
	// PATH holds only the stand-ins and links to the utilities the script
	// itself runs, so no real systemctl, dockerd or nft on this machine can
	// satisfy a "missing" case.
	tools := t.TempDir()
	for _, name := range []string{"awk", "cat", "chmod", "chown", "cp", "id", "mkdir", "mv", "sync"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("the install script needs %s: %v", name, err)
		}
		if p, err = filepath.Abs(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(tools, name)); err != nil {
			t.Fatal(err)
		}
	}
	env = append(os.Environ(), "ROOT="+root, "BIN_DIR="+bin, "PATH="+fake+":"+tools)
	return root, calls, env
}

func runInstall(t *testing.T, script string, env []string, args ...string) (int, string) {
	t.Helper()
	if len(args) == 0 {
		args = []string{"--domain", "sp.test", "--dev"}
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

const goodMount = "/dev/loop0 /var/lib/supapace/projects xfs rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,usrquota,prjquota 0 0\n"

// The install script against a scratch root, with stand-ins for supapaced
// (ROOT does not redirect init's own writes) and the host tools.
func TestInstallNode_ScratchRoot(t *testing.T) {
	script := installScript(t)
	if b, _ := os.ReadFile(script); bytes.Contains(b, []byte("DOCKER_IGNORE_BR_NETFILTER_ERROR")) {
		t.Error("the install script sets Docker's br_netfilter override")
	}
	root, calls, env := installEnv(t, goodMount)
	code, out := runInstall(t, script, env)
	if code != 0 {
		t.Fatalf("install: exit %d\n%s", code, out)
	}
	files := map[string]string{
		"etc/modprobe.d/supapace.conf":  "install br_netfilter /bin/false\n",
		"etc/sysctl.d/90-supapace.conf": "kernel.core_pattern = core\n",
		"usr/local/bin/supapaced":       "",
	}
	for rel, want := range files {
		p := filepath.Join(root, rel)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		fi, _ := os.Lstat(p)
		if want != "" && (string(b) != want || fi.Mode() != 0o644) {
			t.Errorf("%s = %q mode %v, want %q 0644", rel, b, fi.Mode(), want)
		}
		if want == "" && fi.Mode() != 0o755 {
			t.Errorf("%s mode %v, want 0755", rel, fi.Mode())
		}
	}
	if fi, _ := os.Lstat(filepath.Join(root, "var/lib/supapace")); fi.Mode() != fs.ModeDir|0o700 || owner(fi) != os.Geteuid() {
		t.Errorf("/var/lib/supapace mode %v owner %d, want 0700 owned by the installing (root) user", fi.Mode(), owner(fi))
	}
	wantCalls := "sysctl -q -p " + root + "/etc/sysctl.d/90-supapace.conf\n" +
		"supapaced init --domain sp.test --dev\n" +
		"systemctl daemon-reload\n" +
		"systemctl enable supapace-nft.service supapaced.service\n" +
		"systemctl restart docker.service\n" +
		"supapaced nft check\n"
	if got, _ := os.ReadFile(calls); string(got) != wantCalls {
		t.Errorf("calls:\n%s\nwant:\n%s", got, wantCalls)
	}
	if left, _ := filepath.Glob(filepath.Join(root, "etc/*/*.tmp*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}

	// A second run rewrites no configuration file and runs the same steps.
	code, out = runInstall(t, script, env)
	if code != 0 || strings.Contains(out, "wrote") {
		t.Errorf("rerun: exit %d, output %q; want 0 and no configuration file written", code, out)
	}
	if got, _ := os.ReadFile(calls); string(got) != wantCalls+wantCalls {
		t.Errorf("rerun calls:\n%s", got)
	}

	for name, mounts := range map[string]string{
		"no xfs mount":      "",
		"user quota off":    "/dev/loop0 /var/lib/supapace/projects xfs rw,uqnoenforce,prjquota 0 0\n",
		"project quota off": "/dev/loop0 /var/lib/supapace/projects xfs rw,usrquota 0 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			root, calls, env := installEnv(t, mounts)
			code, out := runInstall(t, script, env)
			if code != 1 || !strings.Contains(out, "/var/lib/supapace/projects") {
				t.Fatalf("exit %d, output %q; want a refusal naming the projects mount", code, out)
			}
			absent(t, filepath.Join(root, "usr/local/bin/supapaced"))
			absent(t, filepath.Join(root, "etc/modprobe.d"))
			absent(t, calls)
		})
	}

	// Without nft the Docker drop-in's required unit cannot start, so Docker
	// would not come back after the restart.
	t.Run("nft missing", func(t *testing.T) {
		root, calls, env := installEnv(t, goodMount, "nft")
		code, out := runInstall(t, script, env)
		if code != 1 || !strings.Contains(out, "nft") {
			t.Fatalf("exit %d, output %q; want a refusal naming nft", code, out)
		}
		absent(t, filepath.Join(root, "usr/local/bin/supapaced"))
		absent(t, filepath.Join(root, "etc/modprobe.d"))
		absent(t, calls)
	})

	// A link at a file the script writes is replaced by a regular file; its
	// target is neither written nor chmodded.
	t.Run("linked configuration file", func(t *testing.T) {
		root, _, env := installEnv(t, goodMount)
		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, []byte("install br_netfilter /bin/false\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		conf := filepath.Join(root, "etc/modprobe.d/supapace.conf")
		if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, conf); err != nil {
			t.Fatal(err)
		}
		if code, out := runInstall(t, script, env); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		fi, err := os.Lstat(conf)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s: %v %v, want a regular 0644 file", conf, fi.Mode(), err)
		}
		if tf, _ := os.Lstat(target); tf.Mode().Perm() != 0o600 {
			t.Errorf("link target chmodded to %v", tf.Mode().Perm())
		}
	})
}

// With the marker present the key file must still be usable; each defect is
// named.
func TestInit_MarkerKeyChecks(t *testing.T) {
	cases := map[string]struct {
		spoil func(p string) error
		word  string
	}{
		"mode 0600":     {func(p string) error { return os.Chmod(p, 0o600) }, "mode"},
		"33 bytes":      {func(p string) error { return rewrite(p, make([]byte, 33), 0o400) }, "size"},
		"empty":         {func(p string) error { return rewrite(p, nil, 0o400) }, "size"},
		"directory":     {func(p string) error { os.Remove(p); return os.Mkdir(p, 0o700) }, "regular"},
		"link to key":   {func(p string) error { os.Rename(p, p+".real"); return os.Symlink(p+".real", p) }, "regular"},
		"missing":       {func(p string) error { return os.Remove(p) }, "missing"},
		"dangling link": {func(p string) error { os.Remove(p); return os.Symlink(p+".none", p) }, "regular"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			n.mustInit(devArgs...)
			if err := c.spoil(n.p.KEK()); err != nil {
				t.Fatal(err)
			}
			code, out, errs := n.run("", append([]string{"init"}, devArgs...)...)
			if code != 1 || !strings.Contains(errs, c.word) || strings.Contains(out, "nothing to change") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want 1 and a message naming %q", code, out, errs, c.word)
			}
		})
	}
	t.Run("another owner", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root to give the key file another owner")
		}
		n := newNode(t)
		n.mustInit(devArgs...)
		if err := os.Chown(n.p.KEK(), 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if code, _, errs := n.run("", append([]string{"init"}, devArgs...)...); code != 1 || !strings.Contains(errs, "owned") {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
	})
}

// rewrite replaces p with a new file of data and mode.
func rewrite(p string, data []byte, mode os.FileMode) error {
	if err := os.Remove(p); err != nil {
		return err
	}
	return os.WriteFile(p, data, mode)
}

// Development mode is fixed at the first init, like the domain; both refusals
// come before any write.
func TestInit_DevModeFixedAtFirstInit(t *testing.T) {
	t.Run("dev node without --dev", func(t *testing.T) {
		n := newNode(t)
		n.mustInit(devArgs...)
		before := snapshot(t, n.root)
		code, _, errs := n.run("", "init", "--domain", "sp.test", "--no-systemd", "--ack-escrow")
		if code != 1 || !strings.Contains(errs, "--dev") {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
		if !reflect.DeepEqual(before, snapshot(t, n.root)) {
			t.Error("the refused run changed files")
		}
	})
	t.Run("operator node with --dev", func(t *testing.T) {
		src := newNode(t)
		src.mustInit(devArgs...)
		cert, key := src.read("etc/supapace/tls/cert.pem"), src.read("etc/supapace/tls/key.pem")
		n := newNode(t)
		n.write("in/cert.pem", string(cert), 0o644)
		n.write("in/key.pem", string(key), 0o600)
		n.mustInit("--domain", "sp.test", "--no-systemd", "--ack-escrow", "--tls-cert", n.path("in/cert.pem"), "--tls-key", n.path("in/key.pem"))
		before := snapshot(t, n.root)
		code, _, errs := n.run("", append([]string{"init"}, devArgs...)...)
		if code != 1 || !strings.Contains(errs, "--dev") {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
		if !reflect.DeepEqual(before, snapshot(t, n.root)) {
			t.Error("the refused run changed files")
		}
		absent(t, n.path("etc/supapace/dev-mode"))
	})
	// The marker is written before node.json, so a first run that stops after
	// node.json can be completed with --dev.
	t.Run("marker before node.json", func(t *testing.T) {
		n := newNode(t)
		out := n.mustInit(devArgs...)
		i, j := strings.Index(out, "/dev-mode\n"), strings.Index(out, "/node.json\n")
		if i < 0 || j < 0 || i > j {
			t.Errorf("dev-mode written at %d, node.json at %d; want the marker first\n%s", i, j, out)
		}
	})
}

// The development CA is bounded: path length 0, certificate and CRL signing
// only, at most ten years, and a critical name constraint to the node's
// domain and the gateway's ingress address. Certificates it signs verify only
// for those names, never for look-alikes, other addresses, or below an
// intermediate.
func TestInit_DevCABounds(t *testing.T) {
	n := newNode(t)
	n.mustInit(devArgs...)
	block, _ := pem.Decode(n.read("etc/supapace/ca/ca.pem"))
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.MaxPathLenZero || ca.MaxPathLen != 0 {
		t.Errorf("CA path length %d (zero %v), want 0", ca.MaxPathLen, ca.MaxPathLenZero)
	}
	if ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("CA key usage %v", ca.KeyUsage)
	}
	if max := time.Now().AddDate(10, 0, 1); ca.NotAfter.After(max) {
		t.Errorf("CA valid until %v, beyond ten years", ca.NotAfter)
	}
	if !ca.PermittedDNSDomainsCritical || !reflect.DeepEqual(ca.PermittedDNSDomains, []string{"sp.test"}) {
		t.Errorf("permitted DNS domains %v (critical %v), want [sp.test] critical", ca.PermittedDNSDomains, ca.PermittedDNSDomainsCritical)
	}
	if len(ca.PermittedIPRanges) != 1 || ca.PermittedIPRanges[0].String() != "10.212.8.2/32" {
		t.Errorf("permitted IP ranges %v, want [10.212.8.2/32]", ca.PermittedIPRanges)
	}
	kb, _ := pem.Decode(n.read("etc/supapace/ca/ca.key"))
	caKey, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sign := func(tmpl, parent *x509.Certificate, key any) (*x509.Certificate, *ecdsa.PrivateKey) {
		t.Helper()
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl.SerialNumber = big.NewInt(3)
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, k.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	server := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	ip := func(s string) []net.IP { return []net.IP{net.ParseIP(s)} }
	for _, c := range []struct {
		name string
		dns  []string
		ips  []net.IP
		host string
		ok   bool
	}{
		{"project host", []string{"abcdefghij0123456789.sp.test"}, nil, "abcdefghij0123456789.sp.test", true},
		{"wildcard of the domain", []string{"*.sp.test"}, nil, "abcdefghij0123456789.sp.test", true},
		{"ingress address", nil, ip("10.212.8.2"), "10.212.8.2", true},
		{"another domain", []string{"x.other.test"}, nil, "x.other.test", false},
		{"prefix trick", []string{"evil-sp.test"}, nil, "evil-sp.test", false},
		{"suffix trick", []string{"x.sp.test.other"}, nil, "x.sp.test.other", false},
		{"wildcard above the domain", []string{"*.test"}, nil, "sp.test", false},
		{"one good, one foreign name", []string{"x.sp.test", "x.other.test"}, nil, "x.sp.test", false},
		{"another address", nil, ip("10.212.8.3"), "10.212.8.3", false},
		{"IPv6 address", nil, ip("::1"), "::1", false},
	} {
		leaf, _ := sign(&x509.Certificate{DNSNames: c.dns, IPAddresses: c.ips, ExtKeyUsage: server}, ca, caKey)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: c.host}); (err == nil) != c.ok {
			t.Errorf("%s (%s) signed by the dev CA: verify error %v, want ok=%v", c.name, c.host, err, c.ok)
		}
	}
	inter, interKey := sign(&x509.Certificate{Subject: pkix.Name{CommonName: "intermediate"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, ca, caKey)
	leaf, _ := sign(&x509.Certificate{DNSNames: []string{"x.sp.test"}, ExtKeyUsage: server}, inter, interKey)
	mid := x509.NewCertPool()
	mid.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: mid, DNSName: "x.sp.test"}); err == nil {
		t.Error("a certificate below an intermediate of the development CA verifies")
	}
}

// selfSigned writes an operator certificate for *.sp.test with the given
// validity and extended key usage to in/cert.pem and in/key.pem.
func selfSigned(t *testing.T, n *node, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"*.sp.test"}, NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: eku}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(k)
	n.write("in/cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
	n.write("in/key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})), 0o600)
}

func TestInit_OperatorCertificateChecks(t *testing.T) {
	day := 24 * time.Hour
	nowT := time.Now()
	cases := []struct {
		name     string
		from, to time.Time
		eku      []x509.ExtKeyUsage
		ok       bool
		word     string
	}{
		{"valid, server auth", nowT.Add(-day), nowT.Add(90 * day), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true, ""},
		{"valid, no extended key usage", nowT.Add(-day), nowT.Add(90 * day), nil, true, ""},
		{"expired", nowT.Add(-90 * day), nowT.Add(-day), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false, "expired"},
		{"not yet valid", nowT.Add(day), nowT.Add(90 * day), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false, "not valid before"},
		{"client auth only", nowT.Add(-day), nowT.Add(90 * day), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, "serverAuth"},
		{"any purpose", nowT.Add(-day), nowT.Add(90 * day), []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := newNode(t)
			selfSigned(t, n, c.from, c.to, c.eku)
			code, _, errs := n.run("", "init", "--domain", "sp.test", "--no-systemd", "--ack-escrow",
				"--tls-cert", n.path("in/cert.pem"), "--tls-key", n.path("in/key.pem"))
			if c.ok {
				if code != 0 {
					t.Fatalf("exit %d, stderr %q", code, errs)
				}
				return
			}
			if code != 1 || !strings.Contains(errs, c.word) {
				t.Fatalf("exit %d, stderr %q; want 1 naming %q", code, errs, c.word)
			}
			absent(t, n.p.NodeJSON())
			absent(t, n.path("etc/supapace/tls"))
		})
	}
}

// daemon.json in place with the right content is taken back to 0644 when its
// mode is wrong; a number spelled differently is a foreign value.
func TestInit_DaemonJSONModeAndNumbers(t *testing.T) {
	n := newNode(t)
	n.mustInit(devArgs...)
	p := n.path("etc/docker/daemon.json")
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	n.mustInit(devArgs...)
	n.wantMode("etc/docker/daemon.json", 0o644)

	for _, size := range []string{"26.0", "2.6e1", "26.5"} {
		t.Run("size "+size, func(t *testing.T) {
			m := newNode(t)
			body := `{"default-address-pools":[{"base":"10.214.0.0/16","size":` + size + `}],"ipv6":false,"log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}`
			m.write("etc/docker/daemon.json", body, 0o644)
			if code, _, errs := m.run("", append([]string{"init"}, devArgs...)...); code != 1 || !strings.Contains(errs, "daemon.json") {
				t.Fatalf("exit %d, stderr %q", code, errs)
			}
			if string(m.read("etc/docker/daemon.json")) != body {
				t.Error("daemon.json changed")
			}
		})
	}
}

// A masked unit (a link, usually to /dev/null) is refused before any write,
// never replaced.
func TestInit_RefusesMaskedUnit(t *testing.T) {
	for _, rel := range []string{"etc/systemd/system/supapaced.service", "etc/systemd/system/docker.service.d/10-supapace.conf"} {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			n := newNode(t)
			if err := os.MkdirAll(filepath.Dir(n.path(rel)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/null", n.path(rel)); err != nil {
				t.Fatal(err)
			}
			code, _, errs := n.run("", "init", "--domain", "sp.test", "--dev", "--ack-escrow")
			if code != 1 || !strings.Contains(errs, "unmask") {
				t.Fatalf("exit %d, stderr %q; want 1 and a message to unmask", code, errs)
			}
			if fi, err := os.Lstat(n.path(rel)); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
				t.Error("the masked unit was replaced")
			}
			absent(t, n.p.NodeJSON())
		})
	}
}

// Leftovers of interrupted writes are removed at the start of a run: every
// ".<name>.tmp-*" in init's own directories, and in the system directories
// only the exact temporary names of daemon.json and the unit files. A leftover
// that is a link is unlinked, its target kept; every other name stays.
func TestInit_RemovesLeftoverTempFiles(t *testing.T) {
	args := []string{"--domain", "sp.test", "--dev", "--ack-escrow"}
	t.Run("before the first run", func(t *testing.T) {
		n := newNode(t)
		n.write("etc/supapace/.kek.tmp-0011223344556677", "stale", 0o400)
		if err := os.Chmod(n.path("etc/supapace"), 0o700); err != nil {
			t.Fatal(err)
		}
		n.mustInit(args...)
		absent(t, n.path("etc/supapace/.kek.tmp-0011223344556677"))
	})

	n := newNode(t)
	n.mustInit(args...)
	left := []string{
		"etc/supapace/.node.json.tmp-0011223344556677",
		"etc/supapace/.kek.tmp-0011223344556677",
		"etc/supapace/.kek.escrowed.tmp-0011223344556677",
		"etc/supapace/.dev-mode.tmp-0011223344556677",
		"etc/supapace/ca/.ca.key.tmp-0011223344556677",
		"etc/supapace/tls/.key.pem.tmp-0011223344556677",
		"etc/docker/.daemon.json.tmp-123456",
		"etc/systemd/system/.supapaced.service.tmp-123456",
		"etc/systemd/system/.supapace-nft.service.tmp-123456",
		"etc/systemd/system/docker.service.d/.10-supapace.conf.tmp-123456",
	}
	keep := []string{
		"etc/supapace/notes",
		"etc/supapace/notes.tmp-1",
		"etc/supapace/.kek.tmpX",
		"etc/supapace/tls/cert.tmp-1",
		"etc/docker/.other.json.tmp-1",
		"etc/docker/daemon.json.tmp-1",
		"etc/systemd/system/.other.service.tmp-1",
		"etc/systemd/system/docker.service.d/.20-other.conf.tmp-1",
		"target",
	}
	for _, rel := range append(left, keep...) {
		n.write(rel, "x", 0o600)
	}
	// A leftover name that is a link to a file outside: unlinked, never followed.
	link := "etc/docker/.daemon.json.tmp-linked"
	if err := os.Symlink(n.path("target"), n.path(link)); err != nil {
		t.Fatal(err)
	}
	left = append(left, link)
	for _, d := range []string{"etc/supapace", "etc/supapace/ca", "etc/supapace/tls"} {
		if err := os.Chmod(n.path(d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	n.mustInit(args...)
	for _, rel := range left {
		absent(t, n.path(rel))
	}
	for _, rel := range keep {
		if b, err := os.ReadFile(n.path(rel)); err != nil || string(b) != "x" {
			t.Errorf("%s removed or changed: %v", rel, err)
		}
	}
}

// The development server certificate is valid 825 days and is issued again
// from the same CA when it expires within 30 days.
func TestInit_DevCertRenewal(t *testing.T) {
	n := newNode(t)
	real := time.Now()
	n.mustInit(devArgs...)
	leaf := func() *x509.Certificate {
		b, _ := pem.Decode(n.read("etc/supapace/tls/cert.pem"))
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if d := leaf().NotAfter.Sub(real) - 825*24*time.Hour; d < -time.Minute || d > time.Minute {
		t.Errorf("server certificate valid until %v, want 825 days", leaf().NotAfter)
	}
	ca, first := n.read("etc/supapace/ca/ca.pem"), n.read("etc/supapace/tls/cert.pem")
	old := now
	t.Cleanup(func() { now = old })

	now = func() time.Time { return real.AddDate(0, 0, 700) }
	if out := n.mustInit(devArgs...); !strings.Contains(out, "nothing to change") {
		t.Errorf("at 125 days before expiry: %q, want nothing changed", out)
	}
	at := real.AddDate(0, 0, 796) // 29 days left
	now = func() time.Time { return at }
	n.mustInit(devArgs...)
	if bytes.Equal(first, n.read("etc/supapace/tls/cert.pem")) {
		t.Fatal("server certificate not issued again 29 days before expiry")
	}
	if !bytes.Equal(ca, n.read("etc/supapace/ca/ca.pem")) {
		t.Error("the CA was replaced")
	}
	if d := leaf().NotAfter.Sub(at) - 825*24*time.Hour; d < -time.Minute || d > time.Minute {
		t.Errorf("renewed certificate valid until %v, want 825 days from %v", leaf().NotAfter, at)
	}
	if _, err := tls.X509KeyPair(n.read("etc/supapace/tls/cert.pem"), n.read("etc/supapace/tls/key.pem")); err != nil {
		t.Errorf("renewed pair: %v", err)
	}
	if out := n.mustInit(devArgs...); !strings.Contains(out, "nothing to change") {
		t.Errorf("rerun after renewal: %q", out)
	}
}

// Root-only: the script takes /var/lib/supapace back to root:root.
func TestInstallNode_StateDirOwner(t *testing.T) {
	script := installScript(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand the directory to another user first")
	}
	root, _, env := installEnv(t, goodMount)
	dir := filepath.Join(root, "var/lib/supapace")
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if code, out := runInstall(t, script, env); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if fi, _ := os.Lstat(dir); owner(fi) != 0 || fi.Sys().(*syscall.Stat_t).Gid != 0 || fi.Mode().Perm() != 0o700 {
		t.Errorf("/var/lib/supapace owner %d mode %v, want root:root 0700", owner(fi), fi.Mode().Perm())
	}
}

// init writes the control plane's cipher passphrase, sealed under the key,
// once: a later run leaves it as it is.
func TestInit_WritesControlPlanePassphraseOnce(t *testing.T) {
	n := newNode(t)
	out := n.mustInit(devArgs...)
	if !strings.Contains(out, "wrote "+n.p.CPStanzaSealed()) {
		t.Errorf("init did not report the passphrase file: %q", out)
	}
	n.wantMode("etc/supapace/cp-stanza.sealed", 0o600)
	var k secrets.KEK
	copy(k[:], n.read("etc/supapace/kek"))
	sealed := n.read("etc/supapace/cp-stanza.sealed")
	pass, err := offsite.EnsureControlPlanePass(n.p, k)
	if err != nil || len(pass) != 43 {
		t.Fatalf("the file does not open under the node's key: %v", err)
	}
	if bytes.Contains(sealed, []byte(pass)) || strings.Contains(out, pass) {
		t.Fatal("the passphrase is stored or shown in plain text")
	}
	if !bytes.Equal(n.read("etc/supapace/cp-stanza.sealed"), sealed) {
		t.Fatal("opening the file changed it")
	}
	before := snapshot(t, n.root)
	if out := n.mustInit(devArgs...); !strings.Contains(out, "nothing to change") {
		t.Errorf("second run: %q", out)
	}
	if !reflect.DeepEqual(before, snapshot(t, n.root)) {
		t.Fatal("a second run changed files")
	}

	// A file in place is never replaced, whatever it holds.
	if err := os.WriteFile(n.p.CPStanzaSealed(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.mustInit(devArgs...)
	if string(n.read("etc/supapace/cp-stanza.sealed")) != "x" {
		t.Fatal("init replaced the passphrase file")
	}
}

// Without the escrow acknowledged nothing is sealed under the key.
func TestInit_NoPassphraseBeforeTheKeyIsAcknowledged(t *testing.T) {
	n := newNode(t)
	if code, _, _ := n.run("", "init", "--domain", "sp.test", "--dev", "--no-systemd"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	absent(t, n.p.CPStanzaSealed())
}

// A node initialised before the passphrase existed gains it on the next run;
// that run loads the key file, which must be root's.
func TestInit_AddsThePassphraseToAnInitialisedNode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading an existing key requires a root-owned key file: runs as root on the node")
	}
	n := newNode(t)
	n.mustInit(devArgs...)
	if err := os.Remove(n.p.CPStanzaSealed()); err != nil {
		t.Fatal(err)
	}
	out := n.mustInit(devArgs...)
	if !strings.Contains(out, "wrote "+n.p.CPStanzaSealed()) || strings.Contains(out, "nothing to change") {
		t.Fatalf("output %q", out)
	}
	n.wantMode("etc/supapace/cp-stanza.sealed", 0o600)
}
