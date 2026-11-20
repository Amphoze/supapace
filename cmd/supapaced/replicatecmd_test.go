package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/repl"
	"github.com/Amphoze/supapace/internal/s3x"
)

const (
	replRef    = "abcdefghij0123456789"
	replAccess = "testaccesskeyforthejob1"
	replSecret = "test-secret-key-for-the-job-0123"
)

// replJob lays out a job's files — input, credential, repository, index —
// and points the command's seams at them.
type replJob struct {
	dir       string
	env       []string
	out, errb bytes.Buffer
}

func newReplJob(t *testing.T, mode string, addrs string) *replJob {
	t.Helper()
	j := &replJob{dir: t.TempDir()}
	kind, r := "replicate", &jobio.ReplInput{Mode: mode, MaxFiles: 10, MaxEntries: 100, MaxBytes: 1 << 20, BudgetBytes: -1, BudgetObjects: -1, PageRows: 10}
	in := jobio.Input{Job: 1, Kind: kind, Subject: replRef, Stanza: replRef + "-1", UID: os.Getuid(), Timelines: []uint32{1}, Repl: r}
	cred := replAccess + "\n" + replSecret
	if mode == "probe" {
		in.Kind, in.Timelines = "probe", nil
		cred += "\n" + replAccess + "R\n" + replSecret + "R"
	}
	b, err := jobio.MarshalInput(in)
	if err != nil {
		t.Fatal(err)
	}
	for p, body := range map[string]string{"job/input.json": string(b), "cred": cred, "index": "",
		"repo/archive/" + replRef + "-1/archive.info": "info"} {
		os.MkdirAll(filepath.Dir(filepath.Join(j.dir, p)), 0o755)
		if err := os.WriteFile(filepath.Join(j.dir, p), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	j.env = []string{"PATH=/usr/bin", "SUPAPACE_S3_ENDPOINT=https://s3.example.test:9443", "SUPAPACE_S3_REGION=test-1",
		"SUPAPACE_S3_BUCKET=sp-projects", "SUPAPACE_S3_PREFIX=pre", "SUPAPACE_S3_PATH_STYLE=1", "SUPAPACE_S3_OTHER_BUCKET=sp-cp"}
	if addrs != "" {
		j.env = append(j.env, "SUPAPACE_S3_ADDRS="+addrs)
	}
	oJob, oCred, oRepo, oIndex, oEnv, oS3, oOut, oErr := replJobDir, replCred, replRepo, replIndex, replEnv, newS3, stdout, stderr
	replJobDir, replCred, replRepo, replIndex = filepath.Join(j.dir, "job"), filepath.Join(j.dir, "cred"), filepath.Join(j.dir, "repo"), filepath.Join(j.dir, "index")
	replEnv = func() []string { return j.env }
	stdout, stderr = &j.out, &j.errb
	t.Cleanup(func() {
		replJobDir, replCred, replRepo, replIndex, replEnv, newS3, stdout, stderr = oJob, oCred, oRepo, oIndex, oEnv, oS3, oOut, oErr
	})
	return j
}

// noKeys fails when a key of the job reached its output.
func (j *replJob) noKeys(t *testing.T) {
	t.Helper()
	for _, s := range []string{j.out.String(), j.errb.String()} {
		if strings.Contains(s, replSecret) || strings.Contains(s, replAccess) {
			t.Errorf("a key reached the output: %s", s)
		}
	}
}

func TestReplicateCmd_AddrsAllHandedToTheClient(t *testing.T) {
	for _, mode := range []string{"copy", "rebuild", "probe"} {
		j := newReplJob(t, mode, "192.0.2.10:9443,192.0.2.11:9443,198.51.100.7:443")
		var cfgs []s3x.Config
		newS3 = func(c s3x.Config) (*s3x.Client, error) {
			cfgs = append(cfgs, c)
			c.Addrs = []netip.AddrPort{closedPort(t)} // every call then fails at once
			return s3x.New(c)
		}
		code := run([]string{"replicate", mode})
		want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:9443"), netip.MustParseAddrPort("192.0.2.11:9443"),
			netip.MustParseAddrPort("198.51.100.7:443")}
		if len(cfgs) == 0 {
			t.Fatalf("%s: no client made (exit %d: %s %s)", mode, code, j.out.String(), j.errb.String())
		}
		for _, c := range cfgs {
			if fmt.Sprint(c.Addrs) != fmt.Sprint(want) || c.Endpoint != "https://s3.example.test:9443" || c.Timeout <= 0 {
				t.Errorf("%s: client %v %s %v", mode, c.Addrs, c.Endpoint, c.Timeout)
			}
		}
		if mode == "probe" && (len(cfgs) != 3 || cfgs[1].AccessKey != replAccess+"R" || cfgs[2].Bucket != "sp-cp" || cfgs[2].AccessKey != replAccess) {
			t.Errorf("probe clients: %d", len(cfgs))
		}
		j.noKeys(t)
	}
}

func TestReplicateCmd_RefusesAnEmptyAddressSet(t *testing.T) {
	for _, addrs := range []string{"", ","} {
		j := newReplJob(t, "copy", addrs)
		if addrs == "," {
			j.env = append(j.env, "SUPAPACE_S3_ADDRS=")
		}
		made := false
		newS3 = func(c s3x.Config) (*s3x.Client, error) { made = true; return nil, errors.New("not here") }
		if code := run([]string{"replicate", "copy"}); code != 2 || made || j.out.Len() != 0 {
			t.Errorf("addresses %q: exit %d, client made %v, output %q", addrs, code, made, j.out.String())
		}
	}
	// Control: with one address the client is made.
	newReplJob(t, "copy", "192.0.2.10:9443")
	made := false
	newS3 = func(c s3x.Config) (*s3x.Client, error) { made = true; return nil, errors.New("stop here") }
	if run([]string{"replicate", "copy"}); !made {
		t.Error("control: no client made")
	}
}

// The job refuses the credential of another role's shape, or none, and the
// input of another kind or mode, with a failure document; nothing of a key
// is in it.
func TestReplicateCmd_RefusesAnotherRolesKeysOrInput(t *testing.T) {
	for _, c := range []struct {
		mode, cred, code string
	}{
		{"copy", replAccess + "\n" + replSecret + "\n" + replAccess + "\n" + replSecret, "credential"},
		{"probe", replAccess + "\n" + replSecret, "credential"},
		{"copy", "", "credential"},
		{"copy", "-", "credential"}, // the file absent
	} {
		j := newReplJob(t, c.mode, "192.0.2.10:9443")
		if c.cred == "-" {
			os.Remove(replCred)
		} else {
			os.WriteFile(replCred, []byte(c.cred), 0o600)
		}
		newS3 = func(s3x.Config) (*s3x.Client, error) { t.Fatal("a client was made"); return nil, nil }
		if code := run([]string{"replicate", c.mode}); code != 1 || !strings.Contains(j.out.String(), `"code":"`+c.code+`"`) {
			t.Errorf("%s with %d bytes of keys: exit %d, %s", c.mode, len(c.cred), code, j.out.String())
		}
		j.noKeys(t)
	}
	// A passphrase in the environment is another role's environment.
	j := newReplJob(t, "copy", "192.0.2.10:9443")
	j.env = append(j.env, "PGBACKREST_REPO1_CIPHER_PASS="+replSecret)
	if code := run([]string{"replicate", "copy"}); code != 1 || !strings.Contains(j.out.String(), `"code":"input"`) {
		t.Errorf("exit %d %s", code, j.out.String())
	}
	j.noKeys(t)
	// An input of another mode.
	j = newReplJob(t, "copy", "192.0.2.10:9443")
	if code := run([]string{"replicate", "rebuild"}); code != 1 || !strings.Contains(j.out.String(), `"code":"input"`) {
		t.Errorf("exit %d %s", code, j.out.String())
	}
	for _, args := range [][]string{{"replicate"}, {"replicate", "seed"}, {"replicate", "copy", "x"}, {"replicate", "fetch", "x"}} {
		if code := run(args); code != 2 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

// Against a store that refuses everything and echoes the access key it was
// sent, the copy ends with a result line and the rebuild with a failure
// document: neither, nor the standard error, holds a key.
func TestReplicateCmd_NoKeyInTheResultOrAnError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("X-Echo", auth)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", replAccess, auth)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	for _, mode := range []string{"copy", "rebuild"} {
		j := newReplJob(t, mode, u.Host)
		os.WriteFile(filepath.Join(replJobDir, "ca.pem"), ca, 0o644)
		for i, kv := range j.env {
			if strings.HasPrefix(kv, "SUPAPACE_S3_ENDPOINT=") {
				j.env[i] = "SUPAPACE_S3_ENDPOINT=https://example.com:" + u.Port()
			}
		}
		newS3 = s3x.New
		code := run([]string{"replicate", mode})
		line := bytes.TrimSpace(j.out.Bytes())
		v, fail, err := jobio.ParseResult("replicate", line)
		switch mode {
		case "copy":
			if r, ok := v.(jobio.ReplResult); code != 0 || err != nil || !ok || r.Stopped != "upload-failed" {
				t.Errorf("copy: exit %d %v %s / %s", code, err, line, j.errb.String())
			}
			if !strings.Contains(j.errb.String(), "HTTP 500") {
				t.Errorf("copy: the reason is not on standard error: %q", j.errb.String())
			}
		case "rebuild":
			if code != 1 || fail == nil || fail.Code != "store" {
				t.Errorf("rebuild: exit %d %+v %v %s", code, fail, err, line)
			}
		}
		j.noKeys(t)
	}
}

// closedPort is a loopback port nothing listens on.
func closedPort(t *testing.T) netip.AddrPort {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddrPort(l.Addr().String())
	l.Close()
	return a
}

// An index file that does not read, or is not a regular file, fails the job
// with code index (the daemon writes the file again), before any request.
func TestReplicateCmd_AMalformedIndexIsCodeIndex(t *testing.T) {
	for _, body := range []string{"no tabs\n", "k\t1\t2\t3\t-"} {
		j := newReplJob(t, "copy", closedPort(t).String())
		os.WriteFile(replIndex, []byte(body), 0o600)
		newS3 = s3x.New
		if code := run([]string{"replicate", "copy"}); code != 1 || !strings.Contains(j.out.String(), `"code":"index"`) {
			t.Errorf("%q: exit %d %s", body, code, j.out.String())
		}
	}
	j := newReplJob(t, "copy", closedPort(t).String())
	os.Remove(replIndex)
	os.Symlink(replCred, replIndex)
	newS3 = s3x.New
	if code := run([]string{"replicate", "copy"}); code != 1 || !strings.Contains(j.out.String(), `"code":"index"`) {
		t.Errorf("a link: exit %d %s", code, j.out.String())
	}
	j.noKeys(t)
}

// Against a store that accepts connections and never answers, the copy ends
// at its own bound with a result line (stopped caps: the next job goes on), long before a
// call's own timeout.
func TestReplicateCmd_EndsAtItsOwnBoundWithAResult(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close() // held open, never answered
		}
	}()
	j := newReplJob(t, "copy", l.Addr().String())
	newS3 = s3x.New
	oldBound := replBound
	replBound = func(string) time.Duration { return 2 * time.Second }
	defer func() { replBound = oldBound }()
	start := time.Now()
	code := run([]string{"replicate", "copy"})
	v, _, err := jobio.ParseResult("replicate", bytes.TrimSpace(j.out.Bytes()))
	r, _ := v.(jobio.ReplResult)
	if code != 0 || err != nil || r.Stopped != "caps" || r.Complete {
		t.Errorf("exit %d %v %s", code, err, j.out.String())
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %v", d)
	}
}

// An input the copy refuses is code input.
func TestReplicateCmd_ACopyInputErrorIsCodeInput(t *testing.T) {
	j := newReplJob(t, "copy", closedPort(t).String())
	b, _ := os.ReadFile(filepath.Join(replJobDir, "input.json"))
	os.WriteFile(filepath.Join(replJobDir, "input.json"), bytes.Replace(b, []byte(`"stanza":"`+replRef+`-1"`), []byte(`"stanza":"zzzzzzzzzz0123456789-1"`), 1), 0o600)
	newS3 = s3x.New
	if code := run([]string{"replicate", "copy"}); code != 1 || !strings.Contains(j.out.String(), `"code":"input"`) {
		t.Errorf("exit %d %s", code, j.out.String())
	}
}

// A key echoed in part (an error code the client cut) is scrubbed too.
func TestReplicateCmd_ScrubsAPartlyEchoedKey(t *testing.T) {
	replKeys = []repl.Keys{{Access: replAccess, Secret: replSecret}}
	defer func() { replKeys = nil }()
	for _, s := range []string{"code " + replSecret[:12], replAccess[:9] + "x", "a" + replSecret + "b"} {
		if got := scrub(s); strings.Contains(got, replSecret[:scrubMin]) || strings.Contains(got, replAccess[:scrubMin]) {
			t.Errorf("scrub(%q) = %q", s, got)
		}
	}
	if got := scrub("short " + replSecret[:scrubMin-1]); !strings.Contains(got, replSecret[:scrubMin-1]) {
		t.Errorf("the stated limit moved: %q", got)
	}
}

// Every failure code the command prints is in the program's one list.
func TestReplicateCmd_EveryCodeIsInCodes(t *testing.T) {
	src, err := os.ReadFile("replicatecmd.go")
	if err != nil {
		t.Fatal(err)
	}
	all := append(append(repl.Codes("replicate"), repl.Codes("probe")...), repl.Codes("fetch")...)
	n := 0
	for _, m := range regexp.MustCompile(`replFail\("([a-z_-]+)"`).FindAllSubmatch(src, -1) {
		n++
		if !slices.Contains(all, string(m[1])) {
			t.Errorf("code %s is not in repl.Codes", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`"(copy|rebuild|probe)": "([a-z_-]+)"`).FindAllSubmatch(src, -1) {
		n++
		kind := "replicate"
		if string(m[1]) == "probe" {
			kind = "probe"
		}
		if !slices.Contains(repl.Codes(kind), string(m[2])) {
			t.Errorf("%s: code %s is not in repl.Codes(%s)", m[1], m[2], kind)
		}
	}
	for _, m := range regexp.MustCompile(`\{repl\.Err[A-Za-z]+, "([a-z_-]+)"\}`).FindAllSubmatch(src, -1) {
		n++
		if !slices.Contains(repl.Codes("fetch"), string(m[1])) {
			t.Errorf("fetch: code %s is not in repl.Codes(fetch)", m[1])
		}
	}
	if n < 12 {
		t.Errorf("the scan found %d codes", n)
	}
}

// newFetchJob is a fetch job's files: its input (by plan, or the control
// plane's list_current), its plan, one credential pair and an empty fetch
// directory.
func newFetchJob(t *testing.T, addrs string, in jobio.Input, plan []jobio.PlanRow) *replJob {
	t.Helper()
	j := newReplJob(t, "copy", addrs)
	b, err := jobio.MarshalInput(in)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(replJobDir, "input.json"), b, 0o600)
	if plan != nil {
		var p bytes.Buffer
		if err := jobio.WritePlan(&p, plan); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(replJobDir, "plan"), p.Bytes(), 0o600)
	}
	old := replFetch
	replFetch = filepath.Join(j.dir, "fetch")
	os.Mkdir(replFetch, 0o750)
	t.Cleanup(func() { replFetch = old })
	return j
}

func fetchInput(subject, stanza string, listCurrent bool) jobio.Input {
	in := jobio.Input{Job: 3, Kind: "fetch", Subject: subject, Stanza: stanza, UID: os.Getuid(), MaxBytes: 1 << 20, ListCurrent: listCurrent}
	if subject != "cp" {
		in.Timelines = []uint32{1}
	}
	return in
}

// A store that answers a GET of one version of one key.
func fetchStore(t *testing.T, key, vid, body string) (*httptest.Server, []byte) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/sp-projects/pre/"+key || r.URL.Query().Get("versionId") != vid {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-Amz-Version-Id", vid)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

// pointAt makes the job's endpoint the test server's name and port.
func (j *replJob) pointAt(srv *httptest.Server, ca []byte) {
	u, _ := url.Parse(srv.URL)
	os.WriteFile(filepath.Join(replJobDir, "ca.pem"), ca, 0o644)
	for i, kv := range j.env {
		switch {
		case strings.HasPrefix(kv, "SUPAPACE_S3_ENDPOINT="):
			j.env[i] = "SUPAPACE_S3_ENDPOINT=https://example.com:" + u.Port()
		case strings.HasPrefix(kv, "SUPAPACE_S3_ADDRS="):
			j.env[i] = "SUPAPACE_S3_ADDRS=" + u.Host
		}
	}
}

// The fetch mode reads its plan, holds one credential pair (the read-only
// one), writes below /fetch and prints a fetch result.
func TestReplicateCmd_FetchByPlan(t *testing.T) {
	rel := "archive/" + replRef + "-1/17-1/00000001.history"
	srv, ca := fetchStore(t, replRef+"/"+rel, "v1", "history 1")
	j := newFetchJob(t, closedPort(t).String(), fetchInput(replRef, replRef+"-1", false),
		[]jobio.PlanRow{{Key: rel, VersionID: "v1", SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("history 1"))), Size: 9}})
	j.pointAt(srv, ca)
	var timeout time.Duration
	newS3 = func(c s3x.Config) (*s3x.Client, error) { timeout = c.Timeout; return s3x.New(c) }
	code := run([]string{"replicate", "fetch"})
	v, _, err := jobio.ParseResult("fetch", bytes.TrimSpace(j.out.Bytes()))
	if r, ok := v.(jobio.FetchResult); code != 0 || err != nil || !ok || r.Files != 1 || r.Bytes != 9 {
		t.Fatalf("exit %d %v %s %s", code, err, j.out.String(), j.errb.String())
	}
	if b, _ := os.ReadFile(filepath.Join(replFetch, rel)); string(b) != "history 1" {
		t.Errorf("fetched %q", b)
	}
	// One call may move a whole set file: the client's bound is the program's.
	if timeout != repl.FetchBound(1<<20) {
		t.Errorf("the client's bound is %v", timeout)
	}
	j.noKeys(t)
}

// The fetch mode's refusals, each with its code: two key pairs (another
// role's file), list_current for a project, a plan that is a link, an
// absent object.
func TestReplicateCmd_FetchRefusals(t *testing.T) {
	rel := "archive/" + replRef + "-1/17-1/00000001.history"
	plan := []jobio.PlanRow{{Key: rel, VersionID: "v1", Size: 9}}
	srv, ca := fetchStore(t, replRef+"/"+rel, "v1", "history 1")
	for name, tc := range map[string]struct {
		input jobio.Input
		prep  func(j *replJob)
		code  string
	}{
		"two key pairs": {fetchInput(replRef, replRef+"-1", false), func(j *replJob) {
			os.WriteFile(replCred, []byte(replAccess+"\n"+replSecret+"\n"+replAccess+"\n"+replSecret), 0o600)
		}, "credential"},
		"list_current for a project": {fetchInput(replRef, replRef+"-1", true), nil, "path"},
		"the plan is a link": {fetchInput(replRef, replRef+"-1", false), func(j *replJob) {
			// A link to a good plan: refused for being a link.
			real := filepath.Join(j.dir, "plan.real")
			os.Rename(filepath.Join(replJobDir, "plan"), real)
			os.Symlink(real, filepath.Join(replJobDir, "plan"))
		}, "input"},
		"the plan is a FIFO": {fetchInput(replRef, replRef+"-1", false), func(j *replJob) { // it would read as an empty plan
			os.Remove(filepath.Join(replJobDir, "plan"))
			syscall.Mkfifo(filepath.Join(replJobDir, "plan"), 0o600)
		}, "input"},
		"no plan":                  {fetchInput(replRef, replRef+"-1", false), func(j *replJob) { os.Remove(filepath.Join(replJobDir, "plan")) }, "input"},
		"an input of another kind": {func() jobio.Input { in := fetchInput(replRef, replRef+"-1", false); in.Kind = "seed"; return in }(), nil, "input"},
		"a row outside the layout": {fetchInput(replRef, replRef+"-1", false), func(j *replJob) {
			var p bytes.Buffer
			jobio.WritePlan(&p, []jobio.PlanRow{{Key: "archive/" + replRef + "-1/x", Size: 1}})
			os.WriteFile(filepath.Join(replJobDir, "plan"), p.Bytes(), 0o600)
		}, "path"},
		"absent": {fetchInput(replRef, replRef+"-1", false), func(j *replJob) {
			var p bytes.Buffer
			jobio.WritePlan(&p, []jobio.PlanRow{{Key: rel, VersionID: "v2", Size: 9}})
			os.WriteFile(filepath.Join(replJobDir, "plan"), p.Bytes(), 0o600)
		}, "missing"},
		"control plane without a set": {fetchInput("cp", "cp-1", true), nil, "store"}, // the test server lists nothing
	} {
		var pl []jobio.PlanRow
		if !tc.input.ListCurrent {
			pl = plan
		}
		j := newFetchJob(t, closedPort(t).String(), tc.input, pl)
		j.pointAt(srv, ca)
		if tc.prep != nil {
			tc.prep(j)
		}
		newS3 = s3x.New
		if code := run([]string{"replicate", "fetch"}); code != 1 || !strings.Contains(j.out.String(), `"code":"`+tc.code+`"`) {
			t.Errorf("%s: exit %d %s %s", name, code, j.out.String(), j.errb.String())
		}
		j.noKeys(t)
	}
}
