package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/secrets"
)

// osNode is a fake node with its configuration directory and a key the
// command reads through loadKEK; every credential is made at run time.
type osNode struct {
	*node
	k       secrets.KEK
	secrets []string          // every access and secret key written to a keys file
	keys    map[string]string // keys-file flag → path
}

func newOffsiteNode(t *testing.T) *osNode {
	t.Helper()
	n := &osNode{node: newNode(t), keys: map[string]string{}}
	if err := os.MkdirAll(filepath.Dir(n.p.OffsiteSealed()), 0o700); err != nil {
		t.Fatal(err)
	}
	rand.Read(n.k[:])
	old := loadKEK
	loadKEK = func(string) (secrets.KEK, error) { return n.k, nil }
	t.Cleanup(func() { loadKEK = old })
	dir := t.TempDir()
	for _, f := range []string{"projects-write-keys", "projects-read-keys", "cp-write-keys", "cp-read-keys"} {
		a, s := randText(), randText()
		n.secrets = append(n.secrets, a, s)
		n.keys[f] = filepath.Join(dir, f)
		if err := os.WriteFile(n.keys[f], []byte(a+"\n"+s+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return n
}

func randText() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// setArgs is a complete `offsite set` command line, with overrides.
func (n *osNode) setArgs(over ...string) []string {
	m := map[string]string{
		"--endpoint": "https://s3.example.test:9443", "--region": "test-1",
		"--projects-bucket": "sp-projects", "--projects-prefix": "node-a",
		"--cp-bucket": "sp-cp", "--cp-prefix": "node-a",
	}
	for f, p := range n.keys {
		m["--"+f] = p
	}
	for i := 0; i+1 < len(over); i += 2 {
		m[over[i]] = over[i+1]
	}
	args := []string{"offsite", "set"}
	for f, v := range m {
		args = append(args, f+"="+v)
	}
	return args
}

func (n *osNode) declared() (offsite.Declaration, offsite.State) {
	n.t.Helper()
	d, st, err := offsite.Load(n.p, n.k)
	if err != nil {
		n.t.Fatal(err)
	}
	return d, st
}

func TestSet_RefusesHTTP(t *testing.T) {
	n := newOffsiteNode(t)
	for _, ep := range []string{"http://s3.example.test", "s3.example.test", "https://s3.example.test/path", "ftp://s3.example.test"} {
		if code, _, errs := n.run("", n.setArgs("--endpoint", ep)...); code != 1 || errs == "" {
			t.Errorf("%s: exit %d, stderr %q", ep, code, errs)
		}
	}
	absent(t, n.p.OffsiteSealed())
	if code, out, errs := n.run("", n.setArgs()...); code != 0 || !strings.Contains(out, "wrote") {
		t.Fatalf("control: exit %d, %q %q", code, out, errs)
	}
	if d, st := n.declared(); st != offsite.StateDeclared || d.Endpoint != "https://s3.example.test:9443" || !d.PathStyle {
		t.Fatalf("saved %q %q", st, d.Endpoint)
	}
}

func TestSet_RefusesSameBucketOverlappingPrefix(t *testing.T) {
	n := newOffsiteNode(t)
	for _, c := range [][2]string{{"a", "a"}, {"a", "a/b"}, {"a/b/c", "a/b"}, {"", "x"}, {"x", ""}} {
		if code, _, errs := n.run("", n.setArgs("--cp-bucket", "sp-projects", "--projects-prefix", c[0], "--cp-prefix", c[1])...); code != 1 || !strings.Contains(errs, "overlap") {
			t.Errorf("prefixes %q and %q: exit %d, stderr %q", c[0], c[1], code, errs)
		}
	}
	absent(t, n.p.OffsiteSealed())
	// Controls: one bucket, disjoint prefixes; two buckets, one prefix.
	for _, args := range [][]string{
		n.setArgs("--cp-bucket", "sp-projects", "--projects-prefix", "a", "--cp-prefix", "ab"),
		n.setArgs("--projects-prefix", "", "--cp-prefix", ""),
	} {
		if code, _, errs := n.run("", args...); code != 0 {
			t.Errorf("control: exit %d, stderr %q", code, errs)
		}
	}
}

func TestOffsiteSet_RefusesAPrefixThatBreaksTheKeyRule(t *testing.T) {
	n := newOffsiteNode(t)
	for _, p := range []string{"/a", "a/", "a//b", "a/./b", "./a", "a/..", "..", strings.Repeat("p", 257), strings.Repeat("ab/", 85) + "ab", strings.Repeat("p", 256)} {
		for _, flag := range []string{"--projects-prefix", "--cp-prefix"} {
			if code, _, errs := n.run("", n.setArgs(flag, p)...); code != 1 || !strings.Contains(errs, "prefix") {
				t.Errorf("%s %.20q: exit %d, stderr %q", flag, p, code, errs)
			}
		}
	}
	absent(t, n.p.OffsiteSealed())
	for _, p := range []string{"", "a/" + strings.Repeat("p", 254), strings.Repeat("p", 255), "x/" + strings.Repeat("p", 252) + "/y"} {
		if code, _, errs := n.run("", n.setArgs("--projects-prefix", p, "--cp-prefix", "cp")...); code != 0 {
			t.Errorf("prefix of %d bytes: exit %d, stderr %q", len(p), code, errs)
		}
		if d, _ := n.declared(); d.Projects.Prefix != p {
			t.Errorf("saved prefix %q", d.Projects.Prefix)
		}
	}
}

func TestSet_KeysFileForm(t *testing.T) {
	n := newOffsiteNode(t)
	a, s := randText(), randText()
	file := filepath.Join(t.TempDir(), "keys")
	for name, content := range map[string]string{
		"one line":         a + "\n",
		"three lines":      a + "\n" + s + "\nx\n",
		"empty secret":     a + "\n\n",
		"empty access":     "\n" + s + "\n",
		"blank line first": "\n" + a + "\n" + s + "\n",
		"crlf":             a + "\r\n" + s + "\r\n",
		"space inside":     a + "\n" + s[:4] + " " + s[4:] + "\n",
		"two final lines":  a + "\n" + s + "\n\n",
		"empty":            "",
		"over 4 KiB":       a + "\n" + strings.Repeat("s", 4100) + "\n",
	} {
		os.WriteFile(file, []byte(content), 0o600)
		code, out, errs := n.run("", n.setArgs("--cp-read-keys", file)...)
		if code != 1 || !strings.Contains(errs, "cp-read-keys") {
			t.Errorf("%s: exit %d, stderr %q", name, code, errs)
		}
		if strings.Contains(out+errs, a) || strings.Contains(out+errs, s[:8]) {
			t.Errorf("%s: the output quotes the keys file", name)
		}
	}
	absent(t, n.p.OffsiteSealed())
	if code, _, _ := n.run("", n.setArgs("--cp-read-keys", "/nonexistent/keys")...); code != 1 {
		t.Error("a missing keys file was accepted")
	}
	// Accepted: with and without the final newline.
	for _, content := range []string{a + "\n" + s + "\n", a + "\n" + s} {
		os.WriteFile(file, []byte(content), 0o600)
		if code, _, errs := n.run("", n.setArgs("--cp-read-keys", file)...); code != 0 {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
		if d, _ := n.declared(); d.ControlPlane.Read != (offsite.Credential{AccessKey: a, SecretKey: s}) {
			t.Fatal("the credential saved is not the file's")
		}
	}
	// Each flag fills its own credential.
	d, _ := n.declared()
	if d.Projects.Write.AccessKey != n.secrets[0] || d.Projects.Read.SecretKey != n.secrets[3] || d.ControlPlane.Write.AccessKey != n.secrets[4] {
		t.Fatal("a keys file landed in another credential")
	}
}

func TestSet_NoSecretInArgvOrOutput(t *testing.T) {
	n := newOffsiteNode(t)
	// No flag takes a credential itself: every flag naming keys takes a file.
	code, _, usage := n.run("", "offsite", "set", "--help")
	if code != 2 {
		t.Fatalf("--help: exit %d", code)
	}
	for _, l := range strings.Split(usage, "\n") {
		if f := strings.Fields(l); len(f) > 0 && strings.HasPrefix(f[0], "-") &&
			(strings.Contains(f[0], "key") || strings.Contains(f[0], "secret") || strings.Contains(f[0], "cred")) &&
			!strings.HasSuffix(f[0], "-keys") {
			t.Errorf("flag %s takes a credential on the command line", f[0])
		}
	}
	file := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(file, []byte(n.secrets[0]+"\n"+n.secrets[1]+"\n"+n.secrets[2]+"\n"), 0o600)
	runs := [][]string{
		n.setArgs(),
		n.setArgs("--projects-write-keys", file),          // malformed keys file
		n.setArgs("--projects-bucket", "Bad_Bucket"),      // refused by the client's checks
		n.setArgs("--endpoint", "http://s3.example.test"), // refused by the declaration's
		n.setArgs("--region", ""),                         // usage
		{"offsite", "show"},
	}
	var all strings.Builder
	for _, args := range runs {
		_, out, errs := n.run("", args...)
		all.WriteString(strings.Join(args, " ") + out + errs)
	}
	old := loadKEK
	loadKEK = func(string) (secrets.KEK, error) {
		return secrets.KEK{}, errors.New("secrets: KEK file is not owned by uid 0")
	}
	_, out, errs := n.run("", n.setArgs()...)
	loadKEK = old
	all.WriteString(out + errs)
	raw, _ := os.ReadFile(n.p.OffsiteSealed())
	for _, s := range n.secrets {
		if strings.Contains(all.String(), s) {
			t.Fatal("a credential appears in an argument or in the output")
		}
		if bytes.Contains(raw, []byte(s)) {
			t.Fatal("a credential is stored in plain text")
		}
	}
	if !strings.Contains(all.String(), `"state": "declared"`) {
		t.Fatalf("control: show did not run on the declared node: %s", all.String())
	}
}

func TestOffsiteShow_ExitsZeroWhenUndeclared(t *testing.T) {
	n := newOffsiteNode(t)
	// Undeclared needs no key.
	old := loadKEK
	loadKEK = func(string) (secrets.KEK, error) { return secrets.KEK{}, errors.New("no key") }
	code, out, errs := n.run("", "offsite", "show")
	loadKEK = old
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc["state"] != "undeclared" || len(doc) != 1 {
		t.Fatalf("output %q (%v)", out, err)
	}

	if code, _, errs := n.run("", n.setArgs("--virtual-host", "true")...); code != 0 {
		t.Fatalf("set: %d %q", code, errs)
	}
	code, out, errs = n.run("", "offsite", "show")
	if code != 0 {
		t.Fatalf("declared: exit %d, %q", code, errs)
	}
	var shown struct {
		State        string `json:"state"`
		Endpoint     string `json:"endpoint"`
		PathStyle    bool   `json:"path_style"`
		Projects     map[string]any
		ControlPlane map[string]any `json:"control_plane"`
	}
	if err := json.Unmarshal([]byte(out), &shown); err != nil || shown.State != "declared" || shown.Endpoint != "https://s3.example.test:9443" ||
		shown.PathStyle || shown.Projects["name"] != "sp-projects" || shown.ControlPlane["write_credential"] != true {
		t.Fatalf("declared: %q (%v)", out, err)
	}
	// A partial declaration (what recover writes) shows as partial.
	d, _ := n.declared()
	d.Projects = offsite.Bucket{}
	d.ControlPlane.Write = offsite.Credential{}
	if err := offsite.Save(n.p, n.k, d); err != nil {
		t.Fatal(err)
	}
	if _, out, _ = n.run("", "offsite", "show"); !strings.Contains(out, `"state": "partial"`) || !strings.Contains(out, `"write_credential": false`) {
		t.Fatalf("partial: %q", out)
	}
	// A declaration that does not open is an error, not undeclared.
	rand.Read(n.k[:])
	if code, _, errs := n.run("", "offsite", "show"); code != 1 || errs == "" {
		t.Fatalf("another key: exit %d", code)
	}
	if code, _, _ := n.run("", "offsite", "show", "extra"); code != 2 {
		t.Errorf("an argument: exit %d, want 2", code)
	}
}

func TestOffsiteCmd_SubcommandsRegisterThemselves(t *testing.T) {
	n := newNode(t)
	var got []string
	offsiteCommands["zz-test"] = func(args []string) int { got = args; return 7 }
	t.Cleanup(func() { delete(offsiteCommands, "zz-test") })
	if code, _, _ := n.run("", "offsite", "zz-test", "a", "b"); code != 7 || strings.Join(got, " ") != "a b" {
		t.Fatalf("exit %d, args %q", code, got)
	}
	code, _, errs := n.run("", "offsite", "nope")
	if code != 2 || !strings.Contains(errs, "set|show|zz-test") {
		t.Fatalf("unknown: exit %d, stderr %q", code, errs)
	}
	if code, _, errs := n.run("", "offsite"); code != 2 || !strings.Contains(errs, "usage") {
		t.Fatalf("none: exit %d, stderr %q", code, errs)
	}
	if _, ok := commands["offsite"]; !ok {
		t.Fatal("offsite is not a command")
	}
}

func TestCredential_Redacted(t *testing.T) {
	n := newOffsiteNode(t)
	if code, _, errs := n.run("", n.setArgs()...); code != 0 {
		t.Fatalf("set: %q", errs)
	}
	d, st := n.declared()
	c := d.Projects.Write
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "cred", c, "decl", d, "ptr", &c, "bucket", d.ControlPlane)
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("x", "cred", c, "decl", d, "ptr", &c, "bucket", d.ControlPlane)
	js, _ := json.Marshal(d)
	show, err := json.Marshal(showDocument(d, st))
	if err != nil {
		t.Fatal(err)
	}
	_, shown, _ := n.run("", "offsite", "show")
	renders := []string{
		fmt.Sprintf("%v %+v %#v %s %q %x %X %d %10.3v", c, c, c, c, c, c, c, c, c),
		fmt.Sprintf("%v %+v %#v", d, d, d), fmt.Sprintf("%v %+v %#v", &d, &d, &c),
		fmt.Sprint(c, d.ControlPlane), fmt.Sprintln(d), c.String(), c.GoString(),
		logs.String(), string(js), string(show), shown,
	}
	for i, r := range renders {
		for _, s := range n.secrets {
			if strings.Contains(r, s) || strings.Contains(r, hex.EncodeToString([]byte(s))) {
				t.Errorf("render %d holds a credential", i)
			}
		}
	}
	// Control: the renders keep what is not secret.
	if !strings.Contains(string(show), "sp-projects") || !strings.Contains(shown, "https://s3.example.test:9443") ||
		!strings.Contains(logs.String(), "redacted") || !strings.Contains(fmt.Sprint(d), "sp-cp") {
		t.Errorf("a render lost what is not secret")
	}
}

// The object-store client's own checks run before anything is saved.
func TestSet_RefusesWhatTheClientRefuses(t *testing.T) {
	n := newOffsiteNode(t)
	noCert := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(noCert, []byte("not a certificate\n"), 0o600)
	for name, args := range map[string][]string{
		"bucket name":      n.setArgs("--projects-bucket", "Bad_Bucket"),
		"cp bucket name":   n.setArgs("--cp-bucket", "x"),
		"CA without cert":  n.setArgs("--ca-file", noCert),
		"missing CA file":  n.setArgs("--ca-file", noCert+".none"),
		"empty region arg": n.setArgs("--region", ""),
	} {
		if code, _, errs := n.run("", args...); code == 0 || errs == "" {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	absent(t, n.p.OffsiteSealed())
	if code, _, errs := n.run("", n.setArgs()...); code != 0 {
		t.Fatalf("control: %q", errs)
	}
}

func TestOffsite_RefusesWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as an unprivileged user")
	}
	n := newOffsiteNode(t)
	rootOnly = true
	for _, args := range [][]string{n.setArgs(), {"offsite", "show"}} {
		if code, _, errs := n.run("", args...); code != 1 || !strings.Contains(errs, "root") {
			t.Errorf("%s: exit %d, stderr %q", args[1], code, errs)
		}
	}
	absent(t, n.p.OffsiteSealed())
}
