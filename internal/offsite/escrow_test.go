package offsite

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func testCP(t *testing.T) EscrowControlPlane {
	return EscrowControlPlane{Stanza: "cp-7437201938442670123", Incarnation: "7437201938442670123",
		CipherPass: secret(t), Image: "example/cp@sha256:" + strings.Repeat("ab", 32), SchemaVersion: 2}
}

var testWorker = EscrowWorkerImage{Reference: "supapace-worker:local", ID: "sha256:" + strings.Repeat("cd", 32), Archive: "supapace-worker.tar"}

// built is one escrow document of a fresh key and declaration.
type built struct {
	d              Declaration
	cp             EscrowControlPlane
	all, kek, rest []byte
}

func build(t *testing.T) built {
	t.Helper()
	b := built{d: fullDecl(t), cp: testCP(t)}
	var err error
	b.all, b.kek, b.rest, err = BuildEscrow(testKEK(t), b.d, b.cp, testWorker, "v0.2.0", t0)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// members returns the top-level member names of a document, in order.
func members(t *testing.T, doc []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(doc))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %v", err)
	}
	var names []string
	for dec.More() {
		tok, _ := dec.Token()
		names = append(names, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return names
}

// edit decodes doc, applies f to its top-level map and encodes it again.
func edit(t *testing.T, doc []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEscrow_PartsSplitAndJoin(t *testing.T) {
	b := build(t)
	if got, want := strings.Join(members(t, b.all), " "), "version part created_at kek kek_id control_plane offsite worker_image supapaced_version"; got != want {
		t.Errorf("all: members %q, want %q", got, want)
	}
	if got := strings.Join(members(t, b.kek), " "); got != "version part kek" {
		t.Errorf("kek part: members %q", got)
	}
	if got, want := strings.Join(members(t, b.rest), " "), "version part created_at kek_id control_plane offsite worker_image supapaced_version"; got != want {
		t.Errorf("rest part: members %q, want %q", got, want)
	}
	whole, err := ParseEscrow(b.all)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := ParseEscrow(b.kek, b.rest)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := ParseEscrow(b.rest, b.kek)
	if err != nil {
		t.Fatal(err)
	}
	if whole != joined || whole != reversed {
		t.Fatal("the joined parts differ from the whole document")
	}
	if whole.Version != 1 || !whole.CreatedAt.Equal(t0) || whole.KEKID != KEKID(whole.KEK) ||
		whole.ControlPlane != b.cp || whole.WorkerImage != testWorker || whole.SupapacedVersion != "v0.2.0" {
		t.Fatalf("parsed document differs from its inputs")
	}
	o := whole.Offsite
	if o.Endpoint != b.d.Endpoint || o.Region != b.d.Region || !o.PathStyle || o.CAPEM != "" || o.Bucket != "sp-cp" ||
		o.Prefix != b.d.ControlPlane.Prefix || !o.ReadOnly || o.Read != b.d.ControlPlane.Read {
		t.Fatal("offsite member differs from the declaration's control-plane bucket")
	}
	// The kek part holds the key and nothing else; the rest holds no key.
	kekB64 := base64.StdEncoding.EncodeToString(whole.KEK[:])
	if !bytes.Contains(b.kek, []byte(kekB64)) || bytes.Contains(b.rest, []byte(kekB64)) {
		t.Error("the key is not in the kek part alone")
	}
	if !bytes.Contains(b.all, []byte(`"ca_pem": null`)) {
		t.Errorf("an empty CA is not null: %s", b.all)
	}
	// A part alone is not a document.
	for name, parts := range map[string][][]byte{"kek alone": {b.kek}, "rest alone": {b.rest}, "all and kek": {b.all, b.kek},
		"two rests": {b.rest, b.rest}, "none": nil, "three": {b.kek, b.rest, b.kek}} {
		_, err := ParseEscrow(parts...)
		if err == nil {
			t.Errorf("%s accepted", name)
		} else if (name == "kek alone" || name == "rest alone") && !strings.Contains(err.Error(), "alone") {
			t.Errorf("%s: %v, want it refused as a part alone", name, err)
		}
	}
	// Parts of two documents do not join.
	other := build(t)
	if _, err := ParseEscrow(other.kek, b.rest); err == nil {
		t.Error("a key joined the rest of another document")
	}
	// A CA travels with the document.
	d := b.d
	d.CAPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	all, _, _, err := BuildEscrow(testKEK(t), d, b.cp, testWorker, "v0.2.0", t0)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := ParseEscrow(all); err != nil || e.Offsite.CAPEM != d.CAPEM {
		t.Fatalf("CA: %v", err)
	}
}

func TestParseEscrow_RefusesUnknownMember(t *testing.T) {
	b := build(t)
	for name, doc := range map[string][]byte{
		"top level":         edit(t, b.all, func(m map[string]any) { m["note"] = "x" }),
		"nested":            edit(t, b.all, func(m map[string]any) { m["offsite"].(map[string]any)["write_secret_key"] = "x" }),
		"case-folded":       edit(t, b.all, func(m map[string]any) { m["KEK_ID"] = m["kek_id"]; delete(m, "kek_id") }),
		"kek in rest":       edit(t, b.rest, func(m map[string]any) { m["kek"] = base64.StdEncoding.EncodeToString(make([]byte, 32)) }),
		"kek_id in kek":     edit(t, b.kek, func(m map[string]any) { m["kek_id"] = "0000000000000000" }),
		"missing member":    edit(t, b.all, func(m map[string]any) { delete(m, "worker_image") }),
		"missing nested":    edit(t, b.all, func(m map[string]any) { delete(m["control_plane"].(map[string]any), "image") }),
		"duplicate":         bytes.Replace(b.all, []byte(`"version": 1,`), []byte(`"version": 1, "version": 1,`), 1),
		"trailing":          append(bytes.Clone(b.all), []byte("{}")...),
		"not an object":     []byte(`[1]`),
		"part as number":    edit(t, b.all, func(m map[string]any) { m["part"] = 1 }),
		"unknown part name": edit(t, b.all, func(m map[string]any) { m["part"] = "both" }),
		"null member":       edit(t, b.all, func(m map[string]any) { m["control_plane"] = nil }),
		"empty cipher pass": edit(t, b.all, func(m map[string]any) { m["control_plane"].(map[string]any)["cipher_pass"] = "" }),
	} {
		if _, err := ParseEscrow(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, parts := range map[string][2][]byte{
		"unknown in kek part":  {edit(t, b.kek, func(m map[string]any) { m["x"] = 1 }), b.rest},
		"unknown in rest part": {b.kek, edit(t, b.rest, func(m map[string]any) { m["x"] = 1 })},
	} {
		if _, err := ParseEscrow(parts[0], parts[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Control: the same edit path without a change parses.
	if _, err := ParseEscrow(edit(t, b.all, func(map[string]any) {})); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestParseEscrow_TwoKEKParts(t *testing.T) {
	b := build(t)
	if _, err := ParseEscrow(b.kek, b.kek); err == nil || !strings.Contains(err.Error(), `one "kek" and one "rest"`) {
		t.Fatalf("two kek parts: %v", err)
	}
	if _, err := ParseEscrow(b.kek, b.rest); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestParseEscrow_NewerVersion(t *testing.T) {
	b := build(t)
	for _, v := range []any{2, 0, "1", 1.5} {
		if _, err := ParseEscrow(edit(t, b.all, func(m map[string]any) { m["version"] = v })); err == nil {
			t.Errorf("version %v accepted", v)
		}
	}
	_, err := ParseEscrow(edit(t, b.all, func(m map[string]any) { m["version"] = 2 }))
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("version 2: %v, want an error saying the document is newer", err)
	}
	if _, err := ParseEscrow(b.kek, edit(t, b.rest, func(m map[string]any) { m["version"] = 2 })); err == nil {
		t.Error("a newer rest part accepted")
	}
	if _, err := ParseEscrow(edit(t, b.all, func(m map[string]any) { m["version"] = 1 })); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestParseEscrow_KeyNotMatchingKEKIDRefused(t *testing.T) {
	b := build(t)
	other := testKEK(t)
	for name, doc := range map[string][]byte{
		"other key":             edit(t, b.all, func(m map[string]any) { m["kek"] = base64.StdEncoding.EncodeToString(other[:]) }),
		"other id":              edit(t, b.all, func(m map[string]any) { m["kek_id"] = KEKID(other) }),
		"short key":             edit(t, b.all, func(m map[string]any) { m["kek"] = base64.StdEncoding.EncodeToString(other[:31]) }),
		"upper-case id":         edit(t, b.all, func(m map[string]any) { m["kek_id"] = strings.ToUpper(m["kek_id"].(string)) }),
		"key not base64":        edit(t, b.all, func(m map[string]any) { m["kek"] = "!" + m["kek"].(string)[1:] }),
		"key in hex":            edit(t, b.all, func(m map[string]any) { m["kek"] = hex.EncodeToString(other[:]) }),
		"id of the key raw":     edit(t, b.all, func(m map[string]any) { m["kek_id"] = hex.EncodeToString(other[:8]) }),
		"key with padding bits": edit(t, b.all, func(m map[string]any) { m["kek"] = paddingBitsSet(m["kek"].(string)) }),
	} {
		if _, err := ParseEscrow(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	otherKEK := edit(t, b.kek, func(m map[string]any) { m["kek"] = base64.StdEncoding.EncodeToString(other[:]) })
	if _, err := ParseEscrow(otherKEK, b.rest); err == nil {
		t.Error("split: a key not matching the rest's kek_id was accepted")
	}
}

func TestBuildEscrow_NoWriteCredential(t *testing.T) {
	b := build(t)
	for _, doc := range [][]byte{b.all, b.kek, b.rest} {
		for _, s := range []string{b.d.ControlPlane.Write.AccessKey, b.d.ControlPlane.Write.SecretKey,
			b.d.Projects.Write.AccessKey, b.d.Projects.Write.SecretKey, b.d.Projects.Read.AccessKey, b.d.Projects.Read.SecretKey,
			b.d.Projects.Name} {
			if bytes.Contains(doc, []byte(s)) {
				t.Fatalf("a document holds a credential or name of another bucket, or a write credential")
			}
		}
	}
	// Control: the control-plane bucket's read-only credential is there.
	if !bytes.Contains(b.all, []byte(b.d.ControlPlane.Read.SecretKey)) || !bytes.Contains(b.rest, []byte(b.d.ControlPlane.Read.AccessKey)) {
		t.Fatal("the read-only credential is missing")
	}
	// Without a read-only credential or a control-plane bucket nothing is built.
	for name, spoil := range map[string]func(*Declaration){
		"no read secret": func(d *Declaration) { d.ControlPlane.Read.SecretKey = "" },
		"no read id":     func(d *Declaration) { d.ControlPlane.Read.AccessKey = "" },
		"no bucket":      func(d *Declaration) { d.ControlPlane.Name = "" },
		"http endpoint":  func(d *Declaration) { d.Endpoint = "http://s3.example.test" },
	} {
		d := fullDecl(t)
		spoil(&d)
		if all, kek, rest, err := BuildEscrow(testKEK(t), d, testCP(t), testWorker, "v0.2.0", t0); err == nil || all != nil || kek != nil || rest != nil {
			t.Errorf("%s: built", name)
		}
	}
	// A partial declaration (recover's) is enough: only the cp bucket's read credential is used.
	part := Declaration{Endpoint: b.d.Endpoint, Region: "r", ControlPlane: Bucket{Name: "sp-cp", Read: cred(t)}}
	if _, _, _, err := BuildEscrow(testKEK(t), part, testCP(t), testWorker, "v0.2.0", t0); err != nil {
		t.Fatalf("partial: %v", err)
	}
	// Errors carry no secret.
	cp := testCP(t)
	cp.Stanza = "cp-1"
	_, _, _, err := BuildEscrow(testKEK(t), b.d, cp, testWorker, "v0.2.0", t0)
	if err == nil || strings.Contains(err.Error(), cp.CipherPass) || strings.Contains(err.Error(), b.d.ControlPlane.Read.SecretKey) {
		t.Errorf("error %v", err)
	}
}

func TestParseEscrow_StanzaMustBeNamedAfterItsIncarnation(t *testing.T) {
	b := build(t)
	cpEdit := func(f func(cp map[string]any)) []byte {
		return edit(t, b.all, func(m map[string]any) { f(m["control_plane"].(map[string]any)) })
	}
	for name, doc := range map[string][]byte{
		"other stanza":       cpEdit(func(cp map[string]any) { cp["stanza"] = "cp-1" }),
		"no cp- prefix":      cpEdit(func(cp map[string]any) { cp["stanza"] = cp["incarnation"] }),
		"incarnation number": cpEdit(func(cp map[string]any) { cp["incarnation"] = json.Number("7437201938442670123") }),
		"incarnation hex":    cpEdit(func(cp map[string]any) { cp["incarnation"] = "abc"; cp["stanza"] = "cp-abc" }),
		"incarnation empty":  cpEdit(func(cp map[string]any) { cp["incarnation"] = ""; cp["stanza"] = "cp-" }),
		"leading zero":       cpEdit(func(cp map[string]any) { cp["incarnation"] = "0123"; cp["stanza"] = "cp-0123" }),
		"signed":             cpEdit(func(cp map[string]any) { cp["incarnation"] = "+123"; cp["stanza"] = "cp-+123" }),
		"over 64 bits": cpEdit(func(cp map[string]any) {
			cp["incarnation"] = "18446744073709551616"
			cp["stanza"] = "cp-18446744073709551616"
		}),
	} {
		if _, err := ParseEscrow(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Control: a consistent other incarnation parses.
	if _, err := ParseEscrow(cpEdit(func(cp map[string]any) {
		cp["incarnation"] = "18446744073709551615"
		cp["stanza"] = "cp-18446744073709551615"
	})); err != nil {
		t.Fatalf("control: %v", err)
	}
	cp := testCP(t)
	cp.Stanza = "cp-1"
	if _, _, _, err := BuildEscrow(testKEK(t), b.d, cp, testWorker, "v0.2.0", t0); err == nil {
		t.Error("built with a stanza not named after its incarnation")
	}
}

func TestKEKID_StableAndNotTheKey(t *testing.T) {
	k := testKEK(t)
	id := KEKID(k)
	if id != KEKID(k) || len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("id %q", id)
	}
	sum := sha256.Sum256(append([]byte("supapace-kek-id\x00"), k[:]...))
	if id != hex.EncodeToString(sum[:8]) {
		t.Fatal("id is not the first 16 hex digits of SHA-256 over the label and the key")
	}
	if strings.Contains(hex.EncodeToString(k[:]), id) {
		t.Fatal("id is part of the key")
	}
	k2 := k
	k2[31] ^= 1
	if KEKID(k2) == id {
		t.Fatal("two keys share an id")
	}
	// The label matters: the bare hash of the key is not the id.
	bare := sha256.Sum256(k[:])
	if hex.EncodeToString(bare[:8]) == id {
		t.Fatal("id is the unlabelled hash")
	}
}

func TestEscrowRestHash_IgnoresCreatedAt_ChangesWithEveryOtherMember(t *testing.T) {
	k := testKEK(t)
	d, cp := fullDecl(t), testCP(t)
	rest := func(k [32]byte, d Declaration, cp EscrowControlPlane, w EscrowWorkerImage, v string, at time.Time) string {
		t.Helper()
		_, _, r, err := BuildEscrow(k, d, cp, w, v, at)
		if err != nil {
			t.Fatal(err)
		}
		h, err := EscrowRestHash(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
			t.Fatalf("hash %q", h)
		}
		return h
	}
	base := rest(k, d, cp, testWorker, "v0.2.0", t0)
	if later := rest(k, d, cp, testWorker, "v0.2.0", t0.Add(time.Second)); later != base {
		t.Fatal("two prints a second apart hash differently")
	}
	if later := rest(k, d, cp, testWorker, "v0.2.0", t0.Add(400*24*time.Hour)); later != base {
		t.Fatal("prints a year apart hash differently")
	}
	// A different text of the same document (indentation, member order) hashes alike.
	_, _, r, _ := BuildEscrow(k, d, cp, testWorker, "v0.2.0", t0)
	compact := edit(t, r, func(map[string]any) {})
	if h, err := EscrowRestHash(compact); err != nil || h != base {
		t.Fatalf("the same document in another layout: %v", err)
	}

	changes := map[string]func() string{}
	other := testKEK(t)
	changes["key"] = func() string { return rest(other, d, cp, testWorker, "v0.2.0", t0) }
	for name, f := range map[string]func(*Declaration){
		"read access key": func(d *Declaration) { d.ControlPlane.Read.AccessKey = secret(t) },
		"read secret key": func(d *Declaration) { d.ControlPlane.Read.SecretKey = secret(t) },
		"endpoint":        func(d *Declaration) { d.Endpoint = "https://s3.other.test" },
		"region":          func(d *Declaration) { d.Region = "test-9" },
		"path style":      func(d *Declaration) { d.PathStyle = false },
		"ca":              func(d *Declaration) { d.CAPEM = "x" },
		"bucket":          func(d *Declaration) { d.ControlPlane.Name = "sp-cp2" },
		"prefix":          func(d *Declaration) { d.ControlPlane.Prefix = "node-b/cp" },
	} {
		changes[name] = func() string { d2 := d; f(&d2); return rest(k, d2, cp, testWorker, "v0.2.0", t0) }
	}
	for name, f := range map[string]func(*EscrowControlPlane){
		"incarnation": func(c *EscrowControlPlane) { c.Incarnation = "42"; c.Stanza = "cp-42" },
		"cipher pass": func(c *EscrowControlPlane) { c.CipherPass = secret(t) },
		"cp image":    func(c *EscrowControlPlane) { c.Image = "example/cp@sha256:" + strings.Repeat("ef", 32) },
		"schema":      func(c *EscrowControlPlane) { c.SchemaVersion = 3 },
	} {
		changes[name] = func() string { c2 := cp; f(&c2); return rest(k, d, c2, testWorker, "v0.2.0", t0) }
	}
	for name, f := range map[string]func(*EscrowWorkerImage){
		"worker reference": func(w *EscrowWorkerImage) { w.Reference = "supapace-worker:other" },
		"worker id":        func(w *EscrowWorkerImage) { w.ID = "sha256:" + strings.Repeat("01", 32) },
		"worker archive":   func(w *EscrowWorkerImage) { w.Archive = "other.tar" },
	} {
		changes[name] = func() string { w := testWorker; f(&w); return rest(k, d, cp, w, "v0.2.0", t0) }
	}
	changes["daemon version"] = func() string { return rest(k, d, cp, testWorker, "v0.2.1", t0) }
	for name, f := range changes {
		if f() == base {
			t.Errorf("%s changed and the hash did not", name)
		}
	}
	// What the escrow does not carry does not move the hash.
	d2 := d
	d2.Projects.Write = cred(t)
	d2.ControlPlane.Write = cred(t)
	if rest(k, d2, cp, testWorker, "v0.2.0", t0) != base {
		t.Error("a write credential or the projects bucket moved the hash")
	}
	// Only a rest part is hashed.
	all, kekPart, _, _ := BuildEscrow(k, d, cp, testWorker, "v0.2.0", t0)
	for _, p := range [][]byte{all, kekPart, []byte(`{}`), edit(t, r, func(m map[string]any) { m["x"] = 1 }),
		edit(t, r, func(m map[string]any) { m["kek_id"] = strings.ToUpper(m["kek_id"].(string)) })} {
		if _, err := EscrowRestHash(p); err == nil {
			t.Errorf("hashed %.40s", p)
		}
	}
}

func TestEscrow_NoSecretInRenders(t *testing.T) {
	b := build(t)
	e, err := ParseEscrow(b.all)
	if err != nil {
		t.Fatal(err)
	}
	kekB64 := base64.StdEncoding.EncodeToString(e.KEK[:])
	js, _ := json.Marshal(e)
	cpjs, _ := json.Marshal(b.cp)
	for _, r := range []string{fmt.Sprintf("%v %+v %#v %s %x %d", e, e, e, e, e, e), fmt.Sprintf("%v %+v %#v %x %d", &e, b.cp, b.cp, b.cp, b.cp), string(js), string(cpjs)} {
		for _, s := range []string{kekB64, hex.EncodeToString(e.KEK[:]), b.cp.CipherPass, e.Offsite.Read.SecretKey, e.Offsite.Read.AccessKey} {
			if strings.Contains(r, s) {
				t.Fatalf("a render holds a secret: %.60s", r)
			}
		}
		if strings.Contains(r, fmt.Sprint(e.KEK[0], ",", e.KEK[1], ",", e.KEK[2], ",")) {
			t.Fatal("a render holds the key's bytes as a JSON array")
		}
		if strings.Contains(r, fmt.Sprint(e.KEK[0], " ", e.KEK[1], " ", e.KEK[2])) {
			t.Fatal("a render holds the key's bytes")
		}
	}
}

// paddingBitsSet returns the base64 text of 32 bytes with a non-zero padding
// bit in its last character: it decodes to the same bytes unless decoding is
// strict.
func paddingBitsSet(s string) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alpha, s[42])
	return s[:42] + string(alpha[i|1]) + s[43:]
}

// read_only states what the credential is: false when the control-plane
// bucket's read credential is its write credential.
func TestBuildEscrow_ReadOnlyFalseWhenTheReadCredentialIsTheWriteCredential(t *testing.T) {
	d := fullDecl(t)
	d.ControlPlane.Read = d.ControlPlane.Write
	all, _, _, err := BuildEscrow(testKEK(t), d, testCP(t), testWorker, "v0.2.0", t0)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := ParseEscrow(all); err != nil || e.Offsite.ReadOnly {
		t.Fatalf("read credential = write credential: read_only %v (%v)", e.Offsite.ReadOnly, err)
	}
	// Control: a credential of its own is read-only.
	all, _, _, _ = BuildEscrow(testKEK(t), fullDecl(t), testCP(t), testWorker, "v0.2.0", t0)
	if e, err := ParseEscrow(all); err != nil || !e.Offsite.ReadOnly {
		t.Fatalf("own read credential: read_only %v (%v)", e.Offsite.ReadOnly, err)
	}
}
