package offsite

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// Declared needs the control-plane read-only credential too.
func TestLoad_DeclaredNeedsTheControlPlaneReadCredential(t *testing.T) {
	p, k := etcRoot(t), testKEK(t)
	d := fullDecl(t)
	d.ControlPlane.Read = Credential{}
	if err := Save(p, k, d); err != nil {
		t.Fatal(err)
	}
	if _, st, err := Load(p, k); err != nil || st != StatePartial {
		t.Fatalf("%v %q, want partial", err, st)
	}
}

// The whole answer is checked before the 16 lowest are kept: a refused
// address above the 16th still refuses the answer.
func TestResolve_RefusedAddressBeyondTheSixteenthRefusesTheAnswer(t *testing.T) {
	var answer []string
	for i := 1; i <= 16; i++ {
		answer = append(answer, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String())
	}
	answer = append(answer, "203.0.113.200") // inside the bridge virbr0 of testIfs
	fakeNet(t, answer, testIfs)
	if got, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err == nil {
		t.Fatalf("the refused address was dropped, not the answer refused: %v", got)
	}
}

func TestParseEscrow_RefusesWhatTheOffsiteMemberRules(t *testing.T) {
	b := build(t)
	for name, f := range map[string]func(o map[string]any){
		"prefix with a trailing slash": func(o map[string]any) { o["prefix"] = "node-a/" },
		"prefix with a dot segment":    func(o map[string]any) { o["prefix"] = "a/./b" },
		"http endpoint":                func(o map[string]any) { o["endpoint"] = "http://s3.example.test" },
	} {
		doc := edit(t, b.all, func(m map[string]any) { f(m["offsite"].(map[string]any)) })
		if _, err := ParseEscrow(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseEscrow_RefusesAnAllPartWithARestPart(t *testing.T) {
	b := build(t)
	if _, err := ParseEscrow(b.all, b.rest); err == nil {
		t.Error("an all part and a rest part were joined")
	}
	if _, err := ParseEscrow(b.all, b.all); err == nil {
		t.Error("two all parts were joined")
	}
}

// A key member longer than 32 bytes is refused even when its first 32 bytes
// are the key.
func TestParseEscrow_RefusesAKeyOfAnotherLength(t *testing.T) {
	b := build(t)
	var m map[string]any
	json.Unmarshal(b.all, &m)
	raw, _ := base64.StdEncoding.DecodeString(m["kek"].(string))
	long := base64.StdEncoding.EncodeToString(append(raw, 0))
	doc := edit(t, b.all, func(m map[string]any) { m["kek"] = long })
	if _, err := ParseEscrow(doc); err == nil {
		t.Error("a 33-byte key was accepted")
	}
}

// Only ca_pem may be null; any other member given as null is refused, not
// read as its zero value (a null prefix is not the empty prefix).
func TestParseEscrow_RefusesNullMembers(t *testing.T) {
	b := build(t)
	for _, member := range []string{"prefix", "read_only", "path_style", "region", "read_secret_key"} {
		doc := edit(t, b.all, func(m map[string]any) { m["offsite"].(map[string]any)[member] = nil })
		if _, err := ParseEscrow(doc); err == nil {
			t.Errorf("offsite.%s null accepted", member)
		}
	}
	doc := edit(t, b.all, func(m map[string]any) { m["created_at"] = nil })
	if _, err := ParseEscrow(doc); err == nil {
		t.Error("created_at null accepted")
	}
}

// A JSON error beside a secret names a position, never the text around it.
func TestParseEscrow_SyntaxErrorBesideASecret(t *testing.T) {
	b := build(t)
	pass := b.cp.CipherPass
	quoted := []byte(`"` + pass + `"`)
	for i, broken := range [][]byte{
		bytes.Replace(b.all, quoted, []byte(`"`+pass+`"x`), 1),
		bytes.Replace(b.all, quoted, []byte(pass), 1),
		bytes.Replace(b.all, quoted, []byte(`[`+pass+`]`), 1),
		bytes.Replace(b.all, quoted, []byte(`{"`+pass+`":1}`), 1),
		bytes.Replace(b.all, []byte(`"cipher_pass"`), quoted, 1),
	} {
		_, err := ParseEscrow(broken)
		if err == nil || strings.Contains(err.Error(), pass[:8]) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

// An endpoint refused for carrying user information is not echoed with it.
func TestEndpointError_DoesNotEchoUserInformation(t *testing.T) {
	user, pass := secret(t), secret(t)
	_, _, err := hostPort("https://" + user + ":" + pass + "@s3.example.test")
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), pass) || strings.Contains(err.Error(), user) {
		t.Errorf("the error quotes the user information: %v", err)
	}
}

// The escrow types redact in every render the platform uses.
func TestEscrow_RedactedInLogsAndWrappedErrors(t *testing.T) {
	b := build(t)
	e, err := ParseEscrow(b.all)
	if err != nil {
		t.Fatal(err)
	}
	d := b.d
	var logs bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&logs, nil), slog.NewJSONHandler(&logs, nil)} {
		slog.New(h).Info("x", "d", d, "pd", &d, "e", e, "o", e.Offsite, "cp", e.ControlPlane)
	}
	js, _ := json.Marshal(map[string]any{"o": e.Offsite, "b": []Bucket{d.Projects}, "m": map[string]Credential{"k": d.Projects.Write}})
	renders := []string{
		logs.String(), string(js),
		errors.Join(fmt.Errorf("w: %v", d), fmt.Errorf("w: %+v", e), fmt.Errorf("w: %#v", e.Offsite)).Error(),
		fmt.Sprintf("%v %+v %#v %v", []*Bucket{&d.Projects}, map[string]Bucket{"a": d.Projects}, e.Offsite, []EscrowControlPlane{e.ControlPlane}),
	}
	for i, r := range renders {
		for _, s := range []string{d.Projects.Write.SecretKey, d.ControlPlane.Read.SecretKey, d.ControlPlane.Read.AccessKey, b.cp.CipherPass} {
			if strings.Contains(r, s) {
				t.Errorf("render %d holds a secret", i)
			}
		}
	}
}

// Processes that create the passphrase at the same moment all get one
// passphrase, and one file is left.
func TestEnsureControlPlanePass_ConcurrentProcesses(t *testing.T) {
	if root := os.Getenv("SUPAPACE_TEST_PASS_ROOT"); root != "" {
		var k [32]byte
		copy(k[:], os.Getenv("SUPAPACE_TEST_PASS_KEY"))
		at, _ := strconv.ParseInt(os.Getenv("SUPAPACE_TEST_PASS_AT"), 10, 64)
		time.Sleep(time.Until(time.Unix(0, at)))
		s, err := EnsureControlPlanePass(nodecfg.Paths{Root: root}, k)
		if err != nil {
			s = "error"
		}
		fmt.Println("result:" + s)
		return
	}
	for round := range 10 {
		p := etcRoot(t)
		at := strconv.FormatInt(time.Now().Add(300*time.Millisecond).UnixNano(), 10)
		var cmds []*exec.Cmd
		var outs []*bytes.Buffer
		for range 6 {
			c := exec.Command(os.Args[0], "-test.run=^TestEnsureControlPlanePass_ConcurrentProcesses$")
			c.Env = append(os.Environ(), "SUPAPACE_TEST_PASS_ROOT="+p.Root, "SUPAPACE_TEST_PASS_KEY="+strings.Repeat("k", 32), "SUPAPACE_TEST_PASS_AT="+at)
			var o bytes.Buffer
			c.Stdout = &o
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			cmds, outs = append(cmds, c), append(outs, &o)
		}
		seen := map[string]bool{}
		for i, c := range cmds {
			c.Wait()
			for _, l := range strings.Split(outs[i].String(), "\n") {
				if strings.HasPrefix(l, "result:") {
					seen[l] = true
				}
			}
		}
		if len(seen) != 1 || seen["result:error"] {
			t.Fatalf("round %d: %d distinct results (error among them: %v)", round, len(seen), seen["result:error"])
		}
		if ents, _ := os.ReadDir(p.Root + "/etc/supapace"); len(ents) != 1 {
			t.Fatalf("round %d: %d entries left", round, len(ents))
		}
	}
}

func FuzzParseEscrow(f *testing.F) {
	var k [32]byte
	d := Declaration{Endpoint: "https://s3.example.test", Region: "r",
		ControlPlane: Bucket{Name: "sp-cp", Prefix: "a/b", Read: Credential{"ak", "sk"}}}
	cp := EscrowControlPlane{Stanza: "cp-12", Incarnation: "12", CipherPass: "pw", Image: "img", SchemaVersion: 2}
	all, kek, rest, err := BuildEscrow(k, d, cp, EscrowWorkerImage{"r", "i", "a"}, "v", t0)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(all, []byte{})
	f.Add(kek, rest)
	f.Add(rest, kek)
	f.Fuzz(func(t *testing.T, a, b []byte) {
		ParseEscrow(a)
		ParseEscrow(a, b)
		EscrowRestHash(a)
	})
}
