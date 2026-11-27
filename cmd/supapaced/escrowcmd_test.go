package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

// escrowNode is a node as `escrow show` needs it: the test database as its
// control plane, a key, a node.json, the control plane's passphrase and a
// declared store. Every secret is made at run time.
type escrowNode struct {
	*node
	st      *store.Store
	k       secrets.KEK
	d       offsite.Declaration
	pass    string
	imageID string
}

func newEscrowNode(t *testing.T) *escrowNode {
	t.Helper()
	cleanPGEnv(t)
	p, cfg, st := realStore(t, false)
	e := &escrowNode{node: &node{t: t, root: p.Root, p: p}, st: st, imageID: "sha256:" + strings.Repeat("ab", 32)}
	etc := filepath.Dir(p.NodeJSON())
	// The database's root is shared by the package's tests: start from no node files.
	if err := os.RemoveAll(etc); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(p.NodeJSON(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	rand.Read(e.k[:])
	oldPaths, oldRoot, oldKEK, oldID, oldNow := paths, rootOnly, loadKEK, imageID, now
	paths, rootOnly = p, false
	loadKEK = func(string) (secrets.KEK, error) { return e.k, nil }
	imageID = func(context.Context, string) (string, error) { return e.imageID, nil }
	t.Cleanup(func() { paths, rootOnly, loadKEK, imageID, now = oldPaths, oldRoot, oldKEK, oldID, oldNow })
	var err error
	if e.pass, err = offsite.EnsureControlPlanePass(p, e.k); err != nil {
		t.Fatal(err)
	}
	cred := func() offsite.Credential { return offsite.Credential{AccessKey: randText(), SecretKey: randText()} }
	e.d = offsite.Declaration{Endpoint: "https://s3.example.test:9443", Region: "test-1", PathStyle: true,
		Projects:     offsite.Bucket{Name: "sp-projects", Prefix: "node-a", Write: cred(), Read: cred()},
		ControlPlane: offsite.Bucket{Name: "sp-cp", Prefix: "node-a", Write: cred(), Read: cred()}}
	e.declare()
	return e
}

func (e *escrowNode) declare() {
	e.t.Helper()
	if err := offsite.Save(e.p, e.k, e.d); err != nil {
		e.t.Fatal(err)
	}
}

// stanza records the control plane's stanza as created.
func (e *escrowNode) stanza() {
	e.t.Helper()
	ctx := context.Background()
	if err := e.st.EnsureBackupState(ctx, "cp"); err != nil {
		e.t.Fatal(err)
	}
	if err := e.st.MarkStanza(ctx, "cp"); err != nil {
		e.t.Fatal(err)
	}
}

// secretTexts are the texts only the escrow document may show.
func (e *escrowNode) secretTexts() map[string]string {
	return map[string]string{"the key": base64.StdEncoding.EncodeToString(e.k[:]), "the key in hex": hex.EncodeToString(e.k[:]),
		"the passphrase": e.pass, "the read access key": e.d.ControlPlane.Read.AccessKey, "the read secret key": e.d.ControlPlane.Read.SecretKey}
}

func (e *escrowNode) acked() string {
	b, err := os.ReadFile(e.p.EscrowAcked())
	if err != nil {
		return ""
	}
	return string(b)
}

func TestEscrowShow_RefusedUntilDeclaredAndStanza(t *testing.T) {
	e := newEscrowNode(t)
	refused := func(what, want string, args ...string) {
		t.Helper()
		code, out, errs := e.run("", append([]string{"escrow"}, args...)...)
		if code != 1 || out != "" || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, want) {
			t.Fatalf("%s: exit %d, stdout %d bytes, stderr %q", what, code, len(out), errs)
		}
		for name, s := range e.secretTexts() {
			if strings.Contains(errs, s) {
				t.Fatalf("%s: the refusal shows %s", what, name)
			}
		}
		if e.acked() != "" {
			t.Fatalf("%s: an acknowledgement was written", what)
		}
	}
	for _, args := range [][]string{{"show"}, {"show", "--part", "kek"}, {"show", "--part", "rest"}, {"ack"}} {
		// Declared, but the control plane has no state row, then no stanza.
		refused("no state row", "has no backup stanza yet", args...)
		if err := e.st.EnsureBackupState(context.Background(), "cp"); err != nil {
			t.Fatal(err)
		}
		refused("stanza not created", "has no backup stanza yet", args...)
		dbExec(t, e.p, "delete from backup_state")
	}
	e.stanza()
	// The stanza exists, but the store is only partly declared, then not at all.
	full := e.d
	e.d.Projects = offsite.Bucket{}
	e.d.ControlPlane.Write = offsite.Credential{}
	e.declare()
	refused("partly declared", "is not declared (it is partial)", "show")
	refused("partly declared", "is not declared (it is partial)", "ack")
	if err := os.Remove(e.p.OffsiteSealed()); err != nil {
		t.Fatal(err)
	}
	refused("undeclared", "is not declared (it is undeclared)", "show")
	// Control: declared and with its stanza, the set is shown.
	e.d = full
	e.declare()
	if code, out, errs := e.run("", "escrow", "show"); code != 0 || !strings.Contains(out, `"part": "all"`) {
		t.Fatalf("control: exit %d, %q", code, errs)
	}
}

func TestEscrowShow_Parts_RestCarriesKEKID(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	bs, err := e.st.GetBackupState(context.Background(), "cp")
	if err != nil {
		t.Fatal(err)
	}
	show := func(args ...string) string {
		t.Helper()
		code, out, errs := e.run("", append([]string{"escrow", "show"}, args...)...)
		if code != 0 || errs != "" {
			t.Fatalf("show %v: exit %d, %q", args, code, errs)
		}
		return out
	}
	all, kek, rest := show(), show("--part", "kek"), show("--part=rest")
	sec := e.secretTexts()
	// The kek part: the key and nothing else of the set.
	var k map[string]any
	if err := json.Unmarshal([]byte(kek), &k); err != nil || len(k) != 3 || k["part"] != "kek" || k["kek"] != sec["the key"] {
		t.Fatalf("kek part %v, %v", k, err)
	}
	for _, name := range []string{"the passphrase", "the read access key", "the read secret key"} {
		if strings.Contains(kek, sec[name]) {
			t.Errorf("the kek part holds %s", name)
		}
	}
	// The rest part: everything else, bound to the key by its id, without the key.
	if strings.Contains(rest, sec["the key"]) || strings.Contains(rest, `"kek":`) {
		t.Error("the rest part holds the key")
	}
	if !strings.Contains(rest, `"kek_id": "`+offsite.KEKID(e.k)+`"`) {
		t.Errorf("the rest part lacks the key's id: %s", rest)
	}
	// The parts join to the document the whole print parses to.
	for what, parts := range map[string][][]byte{"all": {[]byte(all)}, "kek+rest": {[]byte(kek), []byte(rest)}, "rest+kek": {[]byte(rest), []byte(kek)}} {
		doc, err := offsite.ParseEscrow(parts...)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		cp, off, w := doc.ControlPlane, doc.Offsite, doc.WorkerImage
		if doc.KEK != e.k || cp.Stanza != "cp-"+bs.Incarnation || cp.Incarnation != bs.Incarnation || cp.CipherPass != e.pass ||
			cp.SchemaVersion != store.SchemaVersion() || !strings.Contains(cp.Image, "@sha256:") ||
			off.Endpoint != e.d.Endpoint || off.Region != e.d.Region || !off.PathStyle || off.Bucket != "sp-cp" || off.Prefix != "node-a" ||
			off.Read != e.d.ControlPlane.Read || !off.ReadOnly ||
			w.Reference != "supapace-worker:local" || w.ID != e.imageID || w.Archive != "supapace-worker.tar" || doc.SupapacedVersion != supapacedVersion {
			t.Fatalf("%s: the document does not hold the node's state (stanza %s, bucket %s, worker %+v)", what, cp.Stanza, off.Bucket, w)
		}
	}
	// Never a write credential, never the projects bucket's.
	for _, c := range []offsite.Credential{e.d.ControlPlane.Write, e.d.Projects.Write, e.d.Projects.Read} {
		if strings.Contains(all, c.AccessKey) || strings.Contains(all, c.SecretKey) {
			t.Fatal("the document holds a credential other than the control plane's read-only one")
		}
	}
	for _, args := range [][]string{{"--part", "all"}, {"--part", "KEK"}, {"extra"}, {"--part"}} {
		if code, out, _ := e.run("", append([]string{"escrow", "show"}, args...)...); code != 2 || out != "" {
			t.Errorf("show %v: exit %d, stdout %d bytes", args, code, len(out))
		}
	}
	for _, args := range [][]string{{}, {"print"}, {"ack", "--part", "rest"}, {"ack", "now"}} {
		if code, out, _ := e.run("", append([]string{"escrow"}, args...)...); code != 2 || out != "" {
			t.Errorf("escrow %v: exit %d, stdout %d bytes", args, code, len(out))
		}
	}
}

func TestEscrowShow_ReadOnlyIsFalseWhenTheReadCredentialIsTheWriteCredential(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	if _, out, _ := e.run("", "escrow", "show", "--part", "rest"); !strings.Contains(out, `"read_only": true`) {
		t.Fatalf("control: a separate read credential is not shown as read-only: %s", out)
	}
	e.d.ControlPlane.Read = e.d.ControlPlane.Write
	e.declare()
	code, out, errs := e.run("", "escrow", "show", "--part", "rest")
	if code != 0 || !strings.Contains(out, `"read_only": false`) || !strings.Contains(out, e.d.ControlPlane.Write.SecretKey) {
		t.Fatalf("exit %d, %q: %s", code, errs, out)
	}
}

func TestEscrowShow_RootOnly(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	rootOnly = true
	for _, sub := range []string{"show", "ack"} {
		if code, out, errs := e.run("", "escrow", sub); code != 1 || out != "" || !strings.Contains(errs, "must run as root") {
			t.Fatalf("%s: exit %d, stdout %d bytes, %q", sub, code, len(out), errs)
		}
	}
}

func TestEscrowAck_WritesEscrowRestHash_StableAcrossPrints(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	now = func() time.Time { return at }
	_, rest1, _ := e.run("", "escrow", "show", "--part", "rest")
	at = at.Add(26 * time.Hour)
	_, rest2, _ := e.run("", "escrow", "show", "--part", "rest")
	if rest1 == rest2 || !strings.Contains(rest1, "2026-11-20T10:00:00Z") || !strings.Contains(rest2, "2026-11-21T12:00:00Z") {
		t.Fatal("control: two prints at different times carry the same created_at")
	}
	want, err := offsite.EscrowRestHash([]byte(rest1))
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := offsite.EscrowRestHash([]byte(rest2)); again != want {
		t.Fatal("two prints of one state hash differently")
	}
	at = at.Add(time.Hour)
	code, out, errs := e.run("", "escrow", "ack")
	if code != 0 || errs != "" || !strings.Contains(out, e.p.EscrowAcked()) {
		t.Fatalf("exit %d, %q, %q", code, errs, out)
	}
	// What is acknowledged was shown: the rest part, never the key.
	if !strings.Contains(out, `"part": "rest"`) || !strings.Contains(out, e.pass) || strings.Contains(out, e.secretTexts()["the key"]) {
		t.Fatal("ack did not show the rest part, or showed the key")
	}
	if got := e.acked(); got != want {
		t.Fatalf("escrow.acked holds %q, want the hash of the rest part %q", got, want)
	}
	fi, err := os.Lstat(e.p.EscrowAcked())
	if err != nil || fi.Mode() != 0o600 {
		t.Fatalf("escrow.acked: %v, %v", fi.Mode(), err)
	}
	// Acknowledged as it stands: a later ack shows nothing and writes nothing.
	at = at.Add(time.Hour)
	code, out, _ = e.run("", "escrow", "ack")
	fi2, _ := os.Lstat(e.p.EscrowAcked())
	if code != 0 || strings.Contains(out, e.pass) || !strings.Contains(out, "already acknowledged") || !os.SameFile(fi, fi2) {
		t.Fatalf("a second ack: exit %d, %q", code, out)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(e.p.EscrowAcked()), ".*.tmp-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestEscrowAck_RefusedOnNullOutput(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	var errb bytes.Buffer
	oldOut, oldErr := stdout, stderr
	stdout, stderr = null, &errb
	code := run([]string{"escrow", "ack"})
	stdout, stderr = oldOut, oldErr
	if code != 1 || !strings.Contains(errb.String(), "must be shown somewhere") || e.acked() != "" {
		t.Fatalf("exit %d, %q, acknowledged %q", code, errb.String(), e.acked())
	}
	// Control: the same node, its output shown, is acknowledged.
	if code, _, errs := e.run("", "escrow", "ack"); code != 0 || e.acked() == "" {
		t.Fatalf("control: exit %d, %q", code, errs)
	}
}

// shownAgain acknowledges, applies change, and requires the next ack to show
// the changed part again and to replace the hash.
func shownAgain(t *testing.T, e *escrowNode, change func(), shows string) {
	t.Helper()
	if code, _, errs := e.run("", "escrow", "ack"); code != 0 {
		t.Fatalf("first ack: exit %d, %q", code, errs)
	}
	first := e.acked()
	// Control: nothing changed, nothing shown.
	if _, out, _ := e.run("", "escrow", "ack"); strings.Contains(out, `"part"`) || e.acked() != first {
		t.Fatal("control: an unchanged set was shown again")
	}
	change()
	_, rest, _ := e.run("", "escrow", "show", "--part", "rest")
	want, err := offsite.EscrowRestHash([]byte(rest))
	if err != nil || want == first {
		t.Fatalf("the change did not change the hash: %v", err)
	}
	if e.acked() != first {
		t.Fatal("a print changed the acknowledgement")
	}
	code, out, errs := e.run("", "escrow", "ack")
	if code != 0 || !strings.Contains(out, `"part": "rest"`) || !strings.Contains(out, shows) {
		t.Fatalf("ack after the change: exit %d, %q, shown %t", code, errs, strings.Contains(out, shows))
	}
	if e.acked() != want {
		t.Fatalf("escrow.acked %q, want %q", e.acked(), want)
	}
}

func TestEscrowAck_ChangedLocationShowsAgain(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	shownAgain(t, e, func() { e.d.ControlPlane.Prefix = "node-b"; e.declare() }, `"prefix": "node-b"`)
	shownAgain(t, e, func() { e.imageID = "sha256:" + strings.Repeat("cd", 32) }, "sha256:"+strings.Repeat("cd", 32))
}

func TestEscrowAck_RotatedReadCredentialShowsAgain(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	next := offsite.Credential{AccessKey: randText(), SecretKey: randText()}
	shownAgain(t, e, func() { e.d.ControlPlane.Read = next; e.declare() }, next.SecretKey)
	// A rotated write credential is not in the set: nothing to show again.
	before := e.acked()
	e.d.ControlPlane.Write = offsite.Credential{AccessKey: randText(), SecretKey: randText()}
	e.declare()
	if _, out, _ := e.run("", "escrow", "ack"); strings.Contains(out, `"part"`) || e.acked() != before {
		t.Fatal("a rotated write credential showed the set again")
	}
}

// The passphrase is made once, by init. A node that lost the file has backups
// no new passphrase opens: the commands refuse and make none.
func TestEscrow_NeverMakesAPassphrase(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	if err := os.Remove(e.p.CPStanzaSealed()); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"show", "ack"} {
		code, out, errs := e.run("", "escrow", sub)
		if code != 1 || out != "" || !strings.Contains(errs, "the control plane's passphrase") {
			t.Fatalf("%s: exit %d, stdout %d bytes, %q", sub, code, len(out), errs)
		}
		if exists(e.p.CPStanzaSealed()) || e.acked() != "" {
			t.Fatalf("%s made a passphrase file or an acknowledgement", sub)
		}
	}
}

// While a restore of the control plane is marked, the database that answers
// is a recovery start nothing has checked: no escrow set is built from it.
func TestEscrow_RefusedWhileARestoreIsMarked(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	if err := os.WriteFile(e.p.CPRestoring(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(e.p.CPRestoring()) }) // the database's root is shared
	for _, sub := range []string{"show", "ack"} {
		code, out, errs := e.run("", "escrow", sub)
		if code != 1 || out != "" || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "a control-plane restore is marked") || e.acked() != "" {
			t.Fatalf("%s: exit %d, stdout %d bytes, stderr %q", sub, code, len(out), errs)
		}
	}
	os.Remove(e.p.CPRestoring())
	if code, _, errs := e.run("", "escrow", "show"); code != 0 {
		t.Fatalf("control: exit %d, %q", code, errs)
	}
}
