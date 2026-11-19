package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

func nodecfgPaths(t *testing.T) nodecfg.Paths { return nodecfg.Paths{Root: t.TempDir()} }

// spec builds the container of a job of kind for subj.
func (e *env) spec(subj, kind string) agent.JobSpec {
	e.t.Helper()
	ctx := context.Background()
	s, err := e.r.subjectOf(ctx, subj)
	must(e.t, err)
	j := store.Job{ID: 77, Subject: subj, Kind: kind, DeadlineS: 600}
	if kind == "restore" {
		j.Params = []byte(`{"set":"20261118-104332F","mode":"standby","target_timeline":2}`)
	}
	spec, err := e.r.jobSpec(ctx, j, s)
	must(e.t, err)
	return spec
}

var everyKind = []string{"push", "stanza-create", "backup", "check", "restore", "serve", "seed", "replicate", "fetch"}

// dump is everything of a spec a job can see but its credential file.
func dump(s agent.JobSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%v %v %s %q", s.Env, s.SecretEnv, s.Input, s.Files)
	return b.String()
}

func TestJobSpec_SecretsPerKind(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	e.declare()
	ref := e.project("active")
	pass := "pass-" + ref
	for _, kind := range everyKind {
		s := e.spec(ref, kind)
		switch kind {
		case "push", "stanza-create", "backup", "check", "restore", "serve":
			if len(s.SecretEnv) != 1 || s.SecretEnv["PGBACKREST_REPO1_CIPHER_PASS"] != pass || s.Cred != nil {
				t.Fatalf("%s: secret env %d entries, cred %v", kind, len(s.SecretEnv), s.Cred != nil)
			}
		case "seed":
			if len(s.SecretEnv) != 0 || s.Cred != nil {
				t.Fatalf("seed holds a secret")
			}
		case "replicate":
			if len(s.SecretEnv) != 0 || string(s.Cred) != "PW\npw-secret" {
				t.Fatalf("replicate: secret env %d entries, cred %q", len(s.SecretEnv), s.Cred)
			}
		case "fetch":
			if len(s.SecretEnv) != 0 || string(s.Cred) != "PR\npr-secret" {
				t.Fatalf("fetch: secret env %d entries, cred %q", len(s.SecretEnv), s.Cred)
			}
		}
		if strings.Contains(fmt.Sprint(s.Env)+string(s.Input), "secret") || strings.Contains(fmt.Sprint(s.Env)+string(s.Input), pass) {
			t.Fatalf("%s: a secret in the environment or the input", kind)
		}
		if s.UID != e.pr.specs[ref].UID || s.GID != e.pr.specs[ref].GID || s.Deadline.Seconds() != 600 {
			t.Fatalf("%s: ids %d:%d deadline %v", kind, s.UID, s.GID, s.Deadline)
		}
		in, err := jobio.ParseInput(s.Input)
		must(t, err)
		if in.Kind != kind || in.Stanza != ref+"-1" || len(in.Timelines) != 1 || in.Timelines[0] != 1 {
			t.Fatalf("%s: input %+v", kind, in)
		}
	}
	in, _ := jobio.ParseInput(e.spec(ref, "restore").Input)
	if in.Set != "20261118-104332F" || in.Mode != "standby" || in.TargetTimeline != 2 {
		t.Fatalf("restore input %+v", in)
	}
	if in, _ := jobio.ParseInput(e.spec(ref, "push").Input); in.MaxEntries != 56 {
		t.Fatalf("push input %+v", in)
	}
}

func TestJobSpec_ReplicatorNeverGetsPassphrase(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	e.declare()
	cpPass := e.controlPlane()
	ref := e.project("active")
	for _, subj := range []string{ref, "cp"} {
		for _, kind := range []string{"replicate", "fetch"} {
			s := e.spec(subj, kind)
			d := dump(s)
			if len(s.SecretEnv) != 0 || strings.Contains(d, "pass-"+ref) || strings.Contains(d, cpPass) || strings.Contains(string(s.Cred), cpPass) {
				t.Fatalf("%s %s holds a passphrase", subj, kind)
			}
			if s.Cred == nil {
				t.Fatalf("%s %s: no credential (control)", subj, kind)
			}
		}
	}
}

func TestJobSpec_WorkerNeverGetsObjectStoreCredential(t *testing.T) {
	e := newEnv(t)
	e.declare()
	e.controlPlane()
	ref := e.project("active")
	for _, subj := range []string{ref, "cp"} {
		for _, kind := range everyKind[:7] {
			s := e.spec(subj, kind)
			if s.Cred != nil || strings.Contains(dump(s), "-secret") || len(s.Addrs) != 0 || s.Env["SUPAPACE_S3_BUCKET"] != "" {
				t.Fatalf("%s %s holds an object-store credential or address", subj, kind)
			}
		}
	}
}

func TestJobSpec_ControlPlaneIdsAndPassphrase(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	e.declare()
	pass := e.controlPlane()
	bs, err := e.st.GetBackupState(context.Background(), "cp")
	must(t, err)
	s := e.spec("cp", "push")
	if s.UID != 70 || s.GID != 70 || s.SecretEnv["PGBACKREST_REPO1_CIPHER_PASS"] != pass || pass == "" {
		t.Fatalf("cp push: ids %d:%d, passphrase given %v", s.UID, s.GID, s.SecretEnv["PGBACKREST_REPO1_CIPHER_PASS"] == pass)
	}
	in, err := jobio.ParseInput(s.Input)
	must(t, err)
	if in.Stanza != "cp-"+bs.Incarnation || in.Timelines != nil || in.UID != 70 {
		t.Fatalf("cp input %+v", in)
	}
	if r := e.spec("cp", "replicate"); string(r.Cred) != "CW\ncw-secret" || r.Env["SUPAPACE_S3_BUCKET"] != "cp" {
		t.Fatalf("cp replicate: cred %q bucket %q", r.Cred, r.Env["SUPAPACE_S3_BUCKET"])
	}
}

// Without its sealed file the control plane's passphrase is refused, never made.
func TestJobSpec_ControlPlanePassphraseIsNeverMadeHere(t *testing.T) {
	e := newEnv(t)
	must(t, e.st.EnsureBackupState(context.Background(), "cp"))
	// The directory exists, so a passphrase could be made there.
	must(t, os.MkdirAll(filepath.Dir(e.p.CPStanzaSealed()), 0o700))
	if _, err := e.r.subjectOf(context.Background(), "cp"); err == nil {
		t.Fatal("a missing passphrase file was accepted")
	}
	if _, err := os.Lstat(e.p.CPStanzaSealed()); err == nil {
		t.Fatal("the runner made a passphrase")
	}
}

func TestJobSpec_ProjectNeverGetsControlPlaneCredential(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	e.declare()
	ref := e.project("active")
	for _, kind := range []string{"replicate", "fetch"} {
		s := e.spec(ref, kind)
		if strings.Contains(string(s.Cred), "C") || strings.Contains(dump(s), "cw-") || s.Env["SUPAPACE_S3_BUCKET"] != "projects" || s.Env["SUPAPACE_S3_PREFIX"] != "p" {
			t.Fatalf("%s: cred %q env %v", kind, s.Cred, s.Env)
		}
	}
}

// A networked job is refused while the store is not declared.
func TestJobSpec_NetworkedNeedsADeclaredStore(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	ref := e.project("active")
	s, err := e.r.subjectOf(context.Background(), ref)
	must(t, err)
	if _, err := e.r.jobSpec(context.Background(), store.Job{ID: 1, Subject: ref, Kind: "fetch", DeadlineS: 1}, s); err == nil {
		t.Fatal("a fetch was built without a declared store")
	}
}

// A project whose spec has no stanza or passphrase is never launched.
func TestJobSpec_ProjectWithoutPassphraseNotLaunched(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	sp := e.pr.specs[ref]
	sp.StanzaPass = ""
	e.pr.specs[ref] = sp
	id := e.submit(ref, "push")
	e.turn("push")
	if got := e.job(id); got.Code != "internal" || len(e.ag.specs) != 0 {
		t.Fatalf("job = %+v, launches %d", got, len(e.ag.specs))
	}
}
