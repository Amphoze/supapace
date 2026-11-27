package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/secrets"
)

// jobAgent is a fake of the agent's job side: it records every call in
// order and answers each job from a script keyed "<kind>/<subject>".
type jobAgent struct {
	mu     sync.Mutex
	calls  []string
	specs  []agent.JobSpec
	script map[string]func(context.Context, agent.JobSpec) (agent.JobResult, error)
	netErr error
}

func (a *jobAgent) log(s string) {
	a.mu.Lock()
	a.calls = append(a.calls, s)
	a.mu.Unlock()
}

func (a *jobAgent) EnsureBackupNetwork(context.Context) error {
	a.log("backup-network")
	return a.netErr
}

func (a *jobAgent) RunJob(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
	a.mu.Lock()
	a.calls = append(a.calls, "job "+j.Kind+"/"+j.Subject)
	a.specs = append(a.specs, j)
	f := a.script[j.Kind+"/"+j.Subject]
	a.mu.Unlock()
	if f == nil {
		return agent.JobResult{}, fmt.Errorf("no script for a %s job of %s", j.Kind, j.Subject)
	}
	return f(ctx, j)
}

func (a *jobAgent) spec(kind, subject string) agent.JobSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.specs) - 1; i >= 0; i-- {
		if a.specs[i].Kind == kind && a.specs[i].Subject == subject {
			return a.specs[i]
		}
	}
	return agent.JobSpec{}
}

func resultLine(t *testing.T, v any) []byte {
	t.Helper()
	b, err := jobio.MarshalResult(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jobDone(t *testing.T, v any) func(context.Context, agent.JobSpec) (agent.JobResult, error) {
	line := resultLine(t, v)
	return func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{Result: line}, nil
	}
}

var probeAddrs = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:9443"), netip.MustParseAddrPort("192.0.2.11:9443")}

// checkNode is a declared node whose agent, resolver and ruleset are fakes.
type checkNode struct {
	*node
	ag        *jobAgent
	k         secrets.KEK
	d         offsite.Declaration
	installed [][]netip.AddrPort
	resolved  []nodecfg.Config
	instErr   error
}

func probeRows(rows ...jobio.ProbeRow) jobio.ReplResult {
	return jobio.ReplResult{OK: true, Mode: "probe", ProbeRows: rows}
}

func newCheckNode(t *testing.T) *checkNode {
	t.Helper()
	c := &checkNode{node: newNode(t), ag: &jobAgent{script: map[string]func(context.Context, agent.JobSpec) (agent.JobResult, error){}}}
	etc := filepath.Dir(c.p.NodeJSON())
	if err := os.MkdirAll(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := nodecfg.Default("sp.test")
	cfg.MemAllocMB, cfg.PidsAlloc, cfg.Uplinks = 1<<20, 1<<20, nil
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(c.p.NodeJSON(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	rand.Read(c.k[:])
	cred := func() offsite.Credential { return offsite.Credential{AccessKey: randText(), SecretKey: randText()} }
	c.d = offsite.Declaration{Endpoint: "https://s3.example.test:9443", Region: "test-1", PathStyle: true, CAPEM: "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",
		Projects:     offsite.Bucket{Name: "sp-projects", Prefix: "node-a", Write: cred(), Read: cred()},
		ControlPlane: offsite.Bucket{Name: "sp-cp", Prefix: "node-c", Write: cred(), Read: cred()}}
	if err := offsite.Save(c.p, c.k, c.d); err != nil {
		t.Fatal(err)
	}
	oldKEK, oldResolve, oldInstall, oldAgent, oldNow := loadKEK, resolveEndpoint, installSet, newCheckAgent, now
	loadKEK = func(string) (secrets.KEK, error) { return c.k, nil }
	resolveEndpoint = func(_ context.Context, d offsite.Declaration, cfg nodecfg.Config) ([]netip.AddrPort, error) {
		c.ag.log("resolve " + d.Endpoint)
		c.resolved = append(c.resolved, cfg)
		return probeAddrs, nil
	}
	installSet = func(_ context.Context, p nodecfg.Paths, _ nodecfg.Config, set []netip.AddrPort) error {
		c.ag.log("install-set")
		if p != c.p {
			t.Errorf("the set is installed for other paths: %+v", p)
		}
		c.installed = append(c.installed, set)
		return c.instErr
	}
	newCheckAgent = func(nodecfg.Config) checkAgent { return c.ag }
	now = func() time.Time { return time.Date(2026, 11, 21, 9, 30, 0, 0, time.UTC) }
	t.Cleanup(func() {
		loadKEK, resolveEndpoint, installSet, newCheckAgent, now = oldKEK, oldResolve, oldInstall, oldAgent, oldNow
	})
	ok := probeRows(jobio.ProbeRow{Name: "versioning", OK: true, Detail: "enabled"})
	c.ag.script["probe/projects"], c.ag.script["probe/cp"] = jobDone(t, ok), jobDone(t, ok)
	return c
}

// checkRecord is the stored record, as its readers decode it.
type checkRecord struct {
	At       time.Time `json:"at"`
	Endpoint string    `json:"endpoint"`
	Rows     []struct {
		Bucket string `json:"bucket"`
		Name   string `json:"name"`
		OK     *bool  `json:"ok"`
		Detail string `json:"detail"`
	} `json:"rows"`
}

func (c *checkNode) record() (checkRecord, string) {
	c.t.Helper()
	b, err := os.ReadFile(c.p.OffsiteCheck())
	if err != nil {
		c.t.Fatal(err)
	}
	var r checkRecord
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		c.t.Fatalf("the record does not decode: %v: %s", err, b)
	}
	return r, string(b)
}

func (c *checkNode) row(r checkRecord, bucket, name string) (ok *bool, detail string, found bool) {
	for _, x := range r.Rows {
		if x.Bucket == bucket && x.Name == name {
			return x.OK, x.Detail, true
		}
	}
	return nil, "", false
}

func TestOffsiteCheck_RegistersItselfInOffsiteCommands(t *testing.T) {
	n := newNode(t)
	if offsiteCommands["check"] == nil {
		t.Fatal("offsite check is not registered")
	}
	if code, _, errs := n.run("", "offsite"); code != 2 || !strings.Contains(errs, "check|rebuild-continue|set|show") {
		t.Fatalf("exit %d, usage %q", code, errs)
	}
	if code, _, errs := n.run("", "offsite", "check", "extra"); code != 2 || !strings.Contains(errs, "usage: supapaced offsite check") {
		t.Fatalf("an argument: exit %d, %q", code, errs)
	}
	rootOnly = true
	if code, _, errs := n.run("", "offsite", "check"); code != 1 || !strings.Contains(errs, "must run as root") {
		t.Fatalf("not root: exit %d, %q", code, errs)
	}
}

func TestOffsiteCheck_Rows_StoredAndPrinted(t *testing.T) {
	c := newCheckNode(t)
	c.ag.script["probe/projects"] = jobDone(t, probeRows(
		jobio.ProbeRow{Name: "versioning", OK: true, Detail: "read back: Enabled"},
		jobio.ProbeRow{Name: "write-can-abort-multipart", OK: true, Detail: "an upload the probe opened was aborted"},
		jobio.ProbeRow{Name: "checksum-enforced", OK: true, Detail: "a wrong Content-MD5 and a wrong payload digest were refused"}))
	c.ag.script["probe/cp"] = jobDone(t, probeRows(
		jobio.ProbeRow{Name: "versioning", OK: true, Detail: "read back: Enabled"},
		jobio.ProbeRow{Name: "lifecycle-noncurrent-rule-present", OK: true, Detail: "rule \x1b[31mr1\n30 days " + strings.Repeat("x", 400)}))
	// A record of an earlier check is replaced by rename, never written in place.
	if err := os.WriteFile(c.p.OffsiteCheck(), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Lstat(c.p.OffsiteCheck())

	code, out, errs := c.run("", "offsite", "check")
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	r, raw := c.record()
	if out != raw {
		t.Fatalf("what was printed is not what was stored:\n%s\n%s", out, raw)
	}
	if !r.At.Equal(now()) || r.Endpoint != c.d.Endpoint || len(r.Rows) != 5 {
		t.Fatalf("record %+v", r)
	}
	if !strings.Contains(raw, `"at": "2026-11-21T09:30:00Z"`) {
		t.Fatalf("the time is not RFC 3339: %s", raw)
	}
	for _, want := range [][2]string{{"projects", "versioning"}, {"projects", "write-can-abort-multipart"}, {"projects", "checksum-enforced"}, {"cp", "versioning"}} {
		if ok, _, found := c.row(r, want[0], want[1]); !found || ok == nil || !*ok {
			t.Errorf("row %v: found %t, ok %v", want, found, ok)
		}
	}
	// A detail is the probe's words about a store's answer: cleaned and cut.
	_, detail, _ := c.row(r, "cp", "lifecycle-noncurrent-rule-present")
	if len(detail) > 256 || strings.ContainsAny(detail, "\x1b\n") || !strings.HasPrefix(detail, "rule ") {
		t.Fatalf("detail not cleaned or not cut: %q", detail)
	}
	fi, err := os.Lstat(c.p.OffsiteCheck())
	if err != nil || fi.Mode() != 0o600 || os.SameFile(old, fi) {
		t.Fatalf("the record: mode %v, replaced by rename %t, %v", fi.Mode(), !os.SameFile(old, fi), err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(c.p.OffsiteCheck()), ".*.tmp-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
	// No credential in what is stored or printed.
	for _, b := range []offsite.Bucket{c.d.Projects, c.d.ControlPlane} {
		for _, k := range []string{b.Write.AccessKey, b.Write.SecretKey, b.Read.AccessKey, b.Read.SecretKey} {
			if strings.Contains(raw+errs, k) {
				t.Fatal("the record holds a credential")
			}
		}
	}
}

func TestOffsiteCheck_StandinDeleteIsNotOK(t *testing.T) {
	c := newCheckNode(t)
	// What the probe reports of a store whose write right includes delete.
	c.ag.script["probe/projects"] = jobDone(t, probeRows(
		jobio.ProbeRow{Name: "versioning", OK: true, Detail: "read back: Enabled"},
		jobio.ProbeRow{Name: "write-cannot-delete", OK: false, Detail: "the delete of a version was not refused"},
		jobio.ProbeRow{Name: "region-checked", OK: false, Detail: "unknown: the store answered 503"}))
	code, out, errs := c.run("", "offsite", "check")
	if code != 1 || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "not passed: 2 of 4 rows are not ok") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	r, raw := c.record()
	if out != raw {
		t.Fatal("a check that did not pass was not printed as stored")
	}
	ok, detail, found := c.row(r, "projects", "write-cannot-delete")
	if !found || ok == nil || *ok || detail != "the delete of a version was not refused" {
		t.Fatalf("the delete row: found %t, ok %v, detail %q", found, ok, detail)
	}
	// A row the probe could not decide is false with its detail, never null.
	if ok, detail, _ := c.row(r, "projects", "region-checked"); ok == nil || *ok || !strings.HasPrefix(detail, "unknown:") {
		t.Fatalf("the undecided row: ok %v, detail %q", ok, detail)
	}
	if strings.Contains(raw, "null") {
		t.Fatalf("a null row although both probes left a result: %s", raw)
	}
}

func TestOffsiteCheck_AProbeWithoutAResultIsANullRowAndDoesNotPass(t *testing.T) {
	c := newCheckNode(t)
	cases := map[string]func(context.Context, agent.JobSpec) (agent.JobResult, error){
		"no result line": func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 137, TimedOut: true}, nil
		},
		"a launch error": func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{}, errors.New("docker: no such image")
		},
	}
	for what, f := range cases {
		c.ag.script["probe/cp"] = f
		code, _, errs := c.run("", "offsite", "check")
		r, _ := c.record()
		ok, detail, found := c.row(r, "cp", "probe")
		if code != 1 || !found || ok != nil || detail == "" || !strings.Contains(errs, "not passed") {
			t.Errorf("%s: exit %d, row found %t ok %v detail %q, stderr %q", what, code, found, ok, detail, errs)
		}
		// The other bucket's rows are kept.
		if ok, _, found := c.row(r, "projects", "versioning"); !found || ok == nil || !*ok {
			t.Errorf("%s: the other bucket's row was lost", what)
		}
	}
	// A failure the probe itself reported is a result: false, with its code.
	c.ag.script["probe/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{ExitCode: 1, Result: resultLine(t, jobio.Failure{Code: "credential", Message: "the credential file\x07 is not four lines"})}, nil
	}
	code, _, _ := c.run("", "offsite", "check")
	r, _ := c.record()
	if ok, detail, _ := c.row(r, "cp", "probe"); code != 1 || ok == nil || *ok || !strings.HasPrefix(detail, "credential: ") || strings.Contains(detail, "\x07") {
		t.Fatalf("a failed probe: exit %d, ok %v, detail %q", code, ok, detail)
	}
	// So is a line that does not parse: refused, and false.
	c.ag.script["probe/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{Result: []byte(`{"ok":true,"mode":"probe","rows":[{"name":"versioning","ok":"yes"}]}` + "\n")}, nil
	}
	code, _, _ = c.run("", "offsite", "check")
	r, _ = c.record()
	if ok, detail, _ := c.row(r, "cp", "probe"); code != 1 || ok == nil || *ok || detail == "" {
		t.Fatalf("an unreadable result: exit %d, ok %v, detail %q", code, ok, detail)
	}
}

func TestOffsiteCheck_RefusesMoreThan32ProbeRows(t *testing.T) {
	c := newCheckNode(t)
	rows := func(n int) jobio.ReplResult {
		var r []jobio.ProbeRow
		for i := 0; i < n; i++ {
			r = append(r, jobio.ProbeRow{Name: fmt.Sprintf("row-%d", i), OK: true})
		}
		return probeRows(r...)
	}
	c.ag.script["probe/projects"] = jobDone(t, rows(33))
	code, _, errs := c.run("", "offsite", "check")
	r, _ := c.record()
	if code != 1 || len(r.Rows) != 2 || !strings.Contains(errs, "not passed") {
		t.Fatalf("33 rows: exit %d, %d rows stored, %q", code, len(r.Rows), errs)
	}
	if ok, detail, found := c.row(r, "projects", "probe"); !found || ok == nil || *ok || !strings.Contains(detail, "more than 32 rows") {
		t.Fatalf("the refused result's row: found %t, ok %v, %q", found, ok, detail)
	}
	// Control: 32 rows are stored, each one.
	c.ag.script["probe/projects"] = jobDone(t, rows(32))
	if code, _, errs := c.run("", "offsite", "check"); code != 0 {
		t.Fatalf("32 rows: exit %d, %q", code, errs)
	}
	if r, _ := c.record(); len(r.Rows) != 33 {
		t.Fatalf("32 rows: %d stored", len(r.Rows))
	}
	// A row the record cannot carry refuses its probe's result as well.
	for what, bad := range map[string]jobio.ProbeRow{"a name with a control byte": {Name: "versio\nning", OK: true},
		"an empty name": {OK: true}, "a name of 65 bytes": {Name: strings.Repeat("a", 65), OK: true}, "the reserved name": {Name: "probe", OK: true}} {
		c.ag.script["probe/projects"] = jobDone(t, probeRows(jobio.ProbeRow{Name: "versioning", OK: true}, bad))
		code, _, _ := c.run("", "offsite", "check")
		r, _ := c.record()
		if ok, _, found := c.row(r, "projects", "probe"); code != 1 || len(r.Rows) != 2 || !found || ok == nil || *ok {
			t.Errorf("%s: exit %d, %d rows", what, code, len(r.Rows))
		}
	}
	// Twice the same name: one of them would hide the other.
	c.ag.script["probe/projects"] = jobDone(t, probeRows(jobio.ProbeRow{Name: "versioning", OK: true}, jobio.ProbeRow{Name: "versioning", OK: true}))
	if code, _, _ := c.run("", "offsite", "check"); code != 1 {
		t.Fatal("a repeated row name passed")
	}
}

func TestOffsiteCheck_ProbeGetsBothCredentialsOfOneBucketOnly(t *testing.T) {
	c := newCheckNode(t)
	if code, _, errs := c.run("", "offsite", "check"); code != 0 {
		t.Fatalf("exit %d, %q", code, errs)
	}
	for role, b := range map[string]offsite.Bucket{"projects": c.d.Projects, "cp": c.d.ControlPlane} {
		other := c.d.ControlPlane
		if role == "cp" {
			other = c.d.Projects
		}
		j := c.ag.spec("probe", role)
		// Four lines: the write pair, then the read-only pair, no final newline.
		if want := b.Write.AccessKey + "\n" + b.Write.SecretKey + "\n" + b.Read.AccessKey + "\n" + b.Read.SecretKey; string(j.Cred) != want {
			t.Errorf("%s: the credential file is not the bucket's write pair then its read-only pair", role)
		}
		everything := fmt.Sprintf("%s|%v|%v|%s", j.Input, j.Env, j.SecretEnv, j.Files)
		for _, k := range []string{other.Write.AccessKey, other.Write.SecretKey, other.Read.AccessKey, other.Read.SecretKey} {
			if strings.Contains(string(j.Cred)+everything, k) {
				t.Errorf("%s: the probe holds a credential of the other bucket", role)
			}
		}
		for _, k := range []string{b.Write.AccessKey, b.Write.SecretKey, b.Read.AccessKey, b.Read.SecretKey} {
			if strings.Contains(everything, k) {
				t.Errorf("%s: a credential outside the credential file", role)
			}
		}
		if len(j.SecretEnv) != 0 {
			t.Errorf("%s: a probe is given a secret environment", role)
		}
		want := map[string]string{"SUPAPACE_S3_ENDPOINT": c.d.Endpoint, "SUPAPACE_S3_REGION": "test-1", "SUPAPACE_S3_BUCKET": b.Name,
			"SUPAPACE_S3_PREFIX": b.Prefix, "SUPAPACE_S3_PATH_STYLE": "1", "SUPAPACE_S3_OTHER_BUCKET": other.Name,
			"SUPAPACE_S3_ADDRS": "192.0.2.10:9443,192.0.2.11:9443"}
		if fmt.Sprint(j.Env) != fmt.Sprint(want) {
			t.Errorf("%s: environment %v, want %v", role, j.Env, want)
		}
		if string(j.Files["ca.pem"]) != c.d.CAPEM || len(j.Files) != 1 {
			t.Errorf("%s: files %v", role, j.Files)
		}
	}
	// One bucket for both uses: no other bucket to try the credential on.
	c.d.ControlPlane.Name, c.d.CAPEM = c.d.Projects.Name, ""
	if err := offsite.Save(c.p, c.k, c.d); err != nil {
		t.Fatal(err)
	}
	c.run("", "offsite", "check")
	for _, role := range []string{"projects", "cp"} {
		j := c.ag.spec("probe", role)
		if _, has := j.Env["SUPAPACE_S3_OTHER_BUCKET"]; has || j.Files != nil {
			t.Errorf("%s with one bucket: environment %v, files %v", role, j.Env, j.Files)
		}
	}
}

func TestOffsiteCheck_ProbeNamedLabelledAndFiledApart_ARunningReplicationIsUntouched(t *testing.T) {
	c := newCheckNode(t)
	if code, _, errs := c.run("", "offsite", "check"); code != 0 {
		t.Fatalf("exit %d, %q", code, errs)
	}
	// The launcher names, labels and files a probe after its bucket's role —
	// job-probe-<role>, never job-<subject>-<kind> — when the spec is of kind
	// probe with the role as its subject and no job id: a subject's own
	// replication job, removed before each job of that subject, is not a
	// probe's to remove. Nothing else of the agent is called: no job is
	// killed, no quota set.
	want := []string{"resolve " + c.d.Endpoint, "install-set", "backup-network", "job probe/projects", "job probe/cp"}
	if fmt.Sprint(c.ag.calls) != fmt.Sprint(want) {
		t.Fatalf("calls %v, want %v", c.ag.calls, want)
	}
	for _, role := range []string{"projects", "cp"} {
		j := c.ag.spec("probe", role)
		in, err := jobio.ParseInput(j.Input)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := bklimit.Deadline("probe", 0, 0)
		if j.ID != 0 || j.UID != 0 || j.GID != 0 || j.MemMB != 0 || j.Deadline != d ||
			in.Kind != "probe" || in.Subject != role || in.Job != 0 || in.Repl == nil || in.Repl.Mode != "probe" || in.Stanza != "" {
			t.Errorf("%s: spec %v, deadline %v, input %s", role, j, j.Deadline, j.Input)
		}
		if fmt.Sprint(j.Addrs) != fmt.Sprint(probeAddrs) {
			t.Errorf("%s: addresses %v", role, j.Addrs)
		}
	}
}

func TestOffsiteCheck_InstallsTheSetThroughInstallSet(t *testing.T) {
	c := newCheckNode(t)
	if code, _, errs := c.run("", "offsite", "check"); code != 0 {
		t.Fatalf("exit %d, %q", code, errs)
	}
	if len(c.installed) != 1 || fmt.Sprint(c.installed[0]) != fmt.Sprint(probeAddrs) {
		t.Fatalf("installed %v", c.installed)
	}
	// The node's own configuration decides which addresses are refused.
	if len(c.resolved) != 1 || c.resolved[0].Domain != "sp.test" {
		t.Fatalf("resolved with %+v", c.resolved)
	}
	// A set that cannot be resolved or installed: no probe, no record.
	os.Remove(c.p.OffsiteCheck())
	c.ag.calls, c.ag.specs = nil, nil
	resolveEndpoint = func(context.Context, offsite.Declaration, nodecfg.Config) ([]netip.AddrPort, error) {
		return nil, errors.New("offsite: an address of the answer is the node's own")
	}
	code, out, errs := c.run("", "offsite", "check")
	if code != 1 || out != "" || len(c.installed) != 1 || len(c.ag.specs) != 0 || exists(c.p.OffsiteCheck()) || strings.Count(errs, "\n") != 1 {
		t.Fatalf("a refused answer: exit %d, %q, installs %d, jobs %d", code, errs, len(c.installed), len(c.ag.specs))
	}
}

func TestOffsiteCheck_AFailedLoadIsNotReportedAsABusyLock(t *testing.T) {
	c := newCheckNode(t)
	for what, tc := range map[string]struct {
		err       error
		want, not string
	}{
		"a failed load": {fmt.Errorf("nft: %w: syntax error", nft.ErrUnverified), "the ruleset could not be loaded", "busy"},
		"a busy lock":   {fmt.Errorf("nft: lock: %w", context.DeadlineExceeded), "the ruleset lock is busy", "could not be loaded"},
	} {
		c.instErr = tc.err
		code, out, errs := c.run("", "offsite", "check")
		if code != 1 || out != "" || !strings.Contains(errs, tc.want) || strings.Contains(errs, tc.not) || strings.Count(errs, "\n") != 1 {
			t.Errorf("%s: exit %d, %q", what, code, errs)
		}
		if len(c.ag.specs) != 0 || exists(c.p.OffsiteCheck()) {
			t.Errorf("%s: a probe ran or a record was written", what)
		}
	}
}

func TestOffsiteCheck_RefusedUntilDeclared(t *testing.T) {
	c := newCheckNode(t)
	c.d.Projects.Read = offsite.Credential{}
	if err := offsite.Save(c.p, c.k, c.d); err != nil {
		t.Fatal(err)
	}
	code, out, errs := c.run("", "offsite", "check")
	if code != 1 || out != "" || !strings.Contains(errs, "is not declared (it is partial)") || len(c.ag.calls) != 0 {
		t.Fatalf("exit %d, %q, calls %v", code, errs, c.ag.calls)
	}
	// The backup network is ensured before the first probe; without it none runs.
	c = newCheckNode(t)
	c.ag.netErr = errors.New("agent: the network backup is not the platform's")
	if code, _, errs := c.run("", "offsite", "check"); code != 1 || len(c.ag.specs) != 0 || !strings.Contains(errs, "not the platform's") {
		t.Fatalf("no backup network: exit %d, %q, jobs %d", code, errs, len(c.ag.specs))
	}
}

// A signal stops the check: the running probe is stopped through its
// context (the launcher then removes its container and credential file), no
// further probe starts, and no record is written.
func TestOffsiteCheck_ASignalStopsTheProbeAndWritesNoRecord(t *testing.T) {
	c := newCheckNode(t)
	os.Remove(c.p.OffsiteCheck())
	stopped := false
	c.ag.script["probe/projects"] = func(ctx context.Context, _ agent.JobSpec) (agent.JobResult, error) {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Error(err)
		}
		select {
		case <-ctx.Done():
			stopped = true
		case <-time.After(30 * time.Second):
		}
		return agent.JobResult{}, ctx.Err()
	}
	code, out, errs := c.run("", "offsite", "check")
	if code != 1 || out != "" || !stopped || !strings.Contains(errs, "interrupted") || strings.Count(errs, "\n") != 1 {
		t.Fatalf("exit %d, stdout %q, the probe stopped %t, stderr %q", code, out, stopped, errs)
	}
	if exists(c.p.OffsiteCheck()) || c.ag.spec("probe", "cp").Kind != "" {
		t.Fatal("a record was written, or the second probe ran")
	}
}
