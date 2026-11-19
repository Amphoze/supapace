package offsite

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/secrets"
)

// testKEK is a fresh random key; no key is ever written into a test file.
func testKEK(t *testing.T) secrets.KEK {
	t.Helper()
	var k secrets.KEK
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

// secret is a fresh random value standing for an access or secret key.
func secret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func cred(t *testing.T) Credential { return Credential{AccessKey: secret(t), SecretKey: secret(t)} }

// fullDecl is a declaration with both buckets and all four credentials.
func fullDecl(t *testing.T) Declaration {
	return Declaration{
		Endpoint: "https://s3.example.test:9443", Region: "test-1", PathStyle: true,
		Projects:     Bucket{Name: "sp-projects", Prefix: "node-a", Write: cred(t), Read: cred(t)},
		ControlPlane: Bucket{Name: "sp-cp", Prefix: "node-a/cp", Write: cred(t), Read: cred(t)},
	}
}

// etcRoot is a node root whose /etc/supapace is a 0700 directory of the caller.
func etcRoot(t *testing.T) nodecfg.Paths {
	t.Helper()
	p := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(filepath.Dir(p.OffsiteSealed()), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSealNode_RoundTrip_WrongNameFails_TamperFails(t *testing.T) {
	k := testKEK(t)
	plain := []byte(secret(t))
	sealed, err := secrets.SealNode(k, "offsite", plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("the sealed bytes hold the plaintext")
	}
	got, err := secrets.OpenNode(k, "offsite", sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	if len(sealed) != 12+len(plain)+16 {
		t.Errorf("sealed length %d, want nonce + plaintext + tag = %d", len(sealed), 12+len(plain)+16)
	}
	again, _ := secrets.SealNode(k, "offsite", plain)
	if bytes.Equal(again[:12], sealed[:12]) {
		t.Error("two seals share a nonce")
	}
	if _, err := secrets.OpenNode(k, "cp-stanza", sealed); err == nil {
		t.Error("opened under another name")
	}
	if _, err := secrets.OpenNode(testKEK(t), "offsite", sealed); err == nil {
		t.Error("opened under another key")
	}
	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 1
		if _, err := secrets.OpenNode(k, "offsite", bad); err == nil {
			t.Fatalf("opened with byte %d flipped", i)
		}
	}
	for _, short := range [][]byte{nil, sealed[:12], sealed[:27]} {
		if _, err := secrets.OpenNode(k, "offsite", short); err == nil {
			t.Errorf("opened %d bytes", len(short))
		}
	}
	if _, err := secrets.SealNode(k, "", plain); err == nil {
		t.Error("sealed under an empty name")
	}
	_, err = secrets.OpenNode(k, "offsite", sealed[:len(sealed)-1])
	if err == nil || strings.Contains(err.Error(), string(plain)) {
		t.Errorf("truncated: %v", err)
	}
}

func TestSave_Mode0600_Atomic(t *testing.T) {
	p, k := etcRoot(t), testKEK(t)
	d := fullDecl(t)
	if err := Save(p, k, d); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p.OffsiteSealed())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != 0o600 || int(fi.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		t.Fatalf("mode %v owner %d, want 0600 owned by %d", fi.Mode(), fi.Sys().(*syscall.Stat_t).Uid, os.Geteuid())
	}
	raw, _ := os.ReadFile(p.OffsiteSealed())
	for _, s := range []string{d.Projects.Write.SecretKey, d.ControlPlane.Read.AccessKey, d.Endpoint} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatal("the saved file holds a declaration value in plain text")
		}
	}

	// A second save replaces the file by rename: a new inode, never an
	// in-place rewrite.
	d2 := d
	d2.Region = "test-2"
	if err := Save(p, k, d2); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Lstat(p.OffsiteSealed())
	if os.SameFile(fi, fi2) {
		t.Error("the second save rewrote the file in place")
	}
	if got, st, err := Load(p, k); err != nil || st != StateDeclared || got.Region != "test-2" {
		t.Fatalf("after replace: %v %v %q", err, st, got.Region)
	}

	// A save that cannot write leaves the previous file whole and no
	// temporary file behind.
	dir := filepath.Dir(p.OffsiteSealed())
	before, _ := os.ReadFile(p.OffsiteSealed())
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if os.Geteuid() != 0 {
		if err := Save(p, k, d); err == nil {
			t.Fatal("save into a read-only directory succeeded")
		}
		if after, _ := os.ReadFile(p.OffsiteSealed()); !bytes.Equal(before, after) {
			t.Error("a failed save changed the file")
		}
	}
	os.Chmod(dir, 0o700)
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "offsite.sealed" {
			t.Errorf("left behind: %s", e.Name())
		}
	}

	// A link in place of the file is refused, never followed.
	q, _ := os.MkdirTemp(t.TempDir(), "x")
	os.Remove(p.OffsiteSealed())
	os.Symlink(filepath.Join(q, "target"), p.OffsiteSealed())
	if _, _, err := Load(p, k); err == nil {
		t.Error("Load followed a link")
	}
}

func TestLoad_StateUndeclaredPartialDeclared(t *testing.T) {
	p, k := etcRoot(t), testKEK(t)
	d, st, err := Load(p, k)
	if err != nil || st != StateUndeclared || d.Endpoint != "" {
		t.Fatalf("no file: %v %q %+v", err, st, d)
	}

	// What recover writes: the endpoint and the control-plane bucket with its
	// read-only credential.
	part := Declaration{Endpoint: "https://s3.example.test", Region: "test-1", PathStyle: true,
		ControlPlane: Bucket{Name: "sp-cp", Prefix: "node-a/cp", Read: cred(t)}}
	if err := Save(p, k, part); err != nil {
		t.Fatal(err)
	}
	got, st, err := Load(p, k)
	if err != nil || st != StatePartial || got.ControlPlane.Read != part.ControlPlane.Read || got.ControlPlane.Name != "sp-cp" {
		t.Fatalf("recover's file: %v %q", err, st)
	}

	full := fullDecl(t)
	if err := Save(p, k, full); err != nil {
		t.Fatal(err)
	}
	got, st, err = Load(p, k)
	if err != nil || st != StateDeclared || got != full {
		t.Fatalf("full: %v %q", err, st)
	}

	// One credential short of full is partial.
	for name, spoil := range map[string]func(*Declaration){
		"no projects bucket":  func(d *Declaration) { d.Projects.Name = "" },
		"no cp write secret":  func(d *Declaration) { d.ControlPlane.Write.SecretKey = "" },
		"no projects read id": func(d *Declaration) { d.Projects.Read.AccessKey = "" },
	} {
		d := fullDecl(t)
		spoil(&d)
		if err := Save(p, k, d); err != nil {
			t.Fatal(err)
		}
		if _, st, err := Load(p, k); err != nil || st != StatePartial {
			t.Errorf("%s: %v %q, want partial", name, err, st)
		}
	}

	// Another key, or the file sealed under another name, does not load.
	if _, _, err := Load(p, testKEK(t)); err == nil {
		t.Error("loaded under another key")
	}
	pass, err := EnsureControlPlanePass(p, k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p.CPStanzaSealed())
	os.WriteFile(p.OffsiteSealed(), b, 0o600)
	if _, _, err := Load(p, k); err == nil || strings.Contains(err.Error(), pass) {
		t.Errorf("the passphrase file loaded as a declaration: %v", err)
	}
}

func TestSave_RefusesWhatTheDeclarationRules(t *testing.T) {
	p, k := etcRoot(t), testKEK(t)
	for name, spoil := range map[string]func(*Declaration){
		"http endpoint":       func(d *Declaration) { d.Endpoint = "http://s3.example.test" },
		"endpoint with path":  func(d *Declaration) { d.Endpoint = "https://s3.example.test/x" },
		"endpoint with user":  func(d *Declaration) { d.Endpoint = "https://:@s3.example.test" },
		"endpoint bad port":   func(d *Declaration) { d.Endpoint = "https://s3.example.test:0" },
		"endpoint no host":    func(d *Declaration) { d.Endpoint = "https://:9443" },
		"same bucket, nested": func(d *Declaration) { d.ControlPlane.Name = d.Projects.Name },
		"prefix slash":        func(d *Declaration) { d.Projects.Prefix = "a/" },
	} {
		d := fullDecl(t)
		spoil(&d)
		if err := Save(p, k, d); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
	absentFile(t, p.OffsiteSealed())
	if err := Save(p, k, fullDecl(t)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func absentFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s exists (%v)", path, err)
	}
}

func TestOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"", "x", true}, {"x", "x", true}, {"a/b", "a", true}, {"a", "a/b/c", true},
		{"a", "ab", false}, {"a/b", "a/c", false}, {"ab/c", "a", false},
	} {
		if got := overlap(c.a, c.b); got != c.want {
			t.Errorf("overlap(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestCheckPrefix_TheKeyRuleAndItsBounds(t *testing.T) {
	for _, bad := range []string{"/a", "a/", "a//b", "a/./b", "a/../b", ".", "..", "/", strings.Repeat("a", 257), strings.Repeat("ab/", 85) + "ab", "a\x00b", strings.Repeat("a", 256), "b/" + strings.Repeat("a", 256)} {
		if checkPrefix(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, ok := range []string{"", "a", "a/b.c/d", "..a/b..", "b/" + strings.Repeat("a", 254), strings.Repeat("a", 255), "b/" + strings.Repeat("a", 253)} {
		if err := checkPrefix(ok); err != nil {
			t.Errorf("refused %q: %v", ok, err)
		}
	}
}

func TestEnsureControlPlanePass_NeverReplaced(t *testing.T) {
	p, k := etcRoot(t), testKEK(t)
	pass, err := EnsureControlPlanePass(p, k)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(pass)
	if err != nil || len(raw) != 32 {
		t.Fatalf("passphrase is not 32 bytes in base64url: %d bytes, %v", len(raw), err)
	}
	fi, _ := os.Lstat(p.CPStanzaSealed())
	if fi.Mode() != 0o600 || int(fi.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		t.Fatalf("mode %v", fi.Mode())
	}
	sealed, _ := os.ReadFile(p.CPStanzaSealed())
	if bytes.Contains(sealed, []byte(pass)) {
		t.Fatal("the passphrase is stored in plain text")
	}
	again, err := EnsureControlPlanePass(p, k)
	if err != nil || again != pass {
		t.Fatalf("second call: %v, same %v", err, again == pass)
	}
	fi2, _ := os.Lstat(p.CPStanzaSealed())
	if !os.SameFile(fi, fi2) || !fi.ModTime().Equal(fi2.ModTime()) {
		t.Error("the file was rewritten")
	}
	// A file that does not open is refused and kept, never replaced.
	os.Chmod(p.CPStanzaSealed(), 0o600)
	if _, err := EnsureControlPlanePass(p, testKEK(t)); err == nil {
		t.Fatal("opened under another key")
	}
	if b, _ := os.ReadFile(p.CPStanzaSealed()); !bytes.Equal(b, sealed) {
		t.Fatal("a file under another key was replaced")
	}
	// A file sealed under the right name that holds no 32-byte passphrase.
	for _, short := range []string{"", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		odd, _ := secrets.SealNode(k, "cp-stanza", []byte(short))
		os.WriteFile(p.CPStanzaSealed(), odd, 0o600)
		if got, err := EnsureControlPlanePass(p, k); err == nil {
			t.Fatalf("a passphrase of %d characters was taken", len(got))
		}
	}
	os.WriteFile(p.CPStanzaSealed(), nil, 0o600)
	if _, err := EnsureControlPlanePass(p, k); err == nil {
		t.Fatal("an empty file was taken")
	}
	if b, _ := os.ReadFile(p.CPStanzaSealed()); len(b) != 0 {
		t.Fatal("an empty file was replaced")
	}
	// A link is refused, never followed or replaced.
	os.Remove(p.CPStanzaSealed())
	target := filepath.Join(t.TempDir(), "t")
	os.Symlink(target, p.CPStanzaSealed())
	if _, err := EnsureControlPlanePass(p, k); err == nil {
		t.Fatal("a link was taken")
	}
	absentFile(t, target)
	// No temporary file is left by any of these.
	ents, _ := os.ReadDir(filepath.Dir(p.CPStanzaSealed()))
	for _, e := range ents {
		if e.Name() != "cp-stanza.sealed" {
			t.Errorf("left behind: %s", e.Name())
		}
	}
	// Two concurrent first calls agree on one passphrase.
	q := etcRoot(t)
	res := make(chan string, 8)
	for range 8 {
		go func() {
			s, err := EnsureControlPlanePass(q, k)
			if err != nil {
				s = "error: " + err.Error()
			}
			res <- s
		}()
	}
	first := <-res
	for range 7 {
		if s := <-res; s != first {
			t.Fatalf("concurrent calls disagree (%d vs %d bytes)", len(s), len(first))
		}
	}
}

// The passphrase is created only in a directory of the caller's that no one
// else can write, as Save requires of its directory.
func TestEnsureControlPlanePass_RefusesALooseDirectory(t *testing.T) {
	p, k := etcRoot(t), testKEK(t)
	dir := filepath.Dir(p.CPStanzaSealed())
	for _, mode := range []os.FileMode{0o770, 0o702, 0o777} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := EnsureControlPlanePass(p, k); err == nil {
			t.Errorf("created in a directory of mode %v", mode)
		}
		absentFile(t, p.CPStanzaSealed())
	}
	os.Chmod(dir, 0o700)
	if _, err := EnsureControlPlanePass(p, k); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// The directory must also be the caller's own: as root, a directory owned by
// another uid is refused although root could write it.
func TestEnsureControlPlanePass_RefusesADirectoryOfAnotherOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing a directory's owner needs root")
	}
	p, k := etcRoot(t), testKEK(t)
	dir := filepath.Dir(p.CPStanzaSealed())
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureControlPlanePass(p, k); err == nil {
		t.Error("created in a directory of another owner")
	}
	absentFile(t, p.CPStanzaSealed())
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureControlPlanePass(p, k); err != nil {
		t.Fatalf("control: %v", err)
	}
}
