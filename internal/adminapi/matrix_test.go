package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// TestAPI_StateMatrix drives every mutation against a project in every state
// and compares the response code with the state rules.
func TestAPI_StateMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	type row struct {
		ref   string
		op    int64 // the operation op retry is aimed at
		codes map[string]string
	}
	ok := ""
	conflict := "conflict"
	n := 0
	ref := func() string {
		n++
		return "mtx" + strings.Repeat("0", 17-len(strconv.Itoa(n))) + strconv.Itoa(n)
	}
	rows := map[string]row{}
	// provisioning, create pending
	r := ref()
	op := e.create(t, r).OperationID
	rows["provisioning/pending"] = row{r, op, map[string]string{"restart": conflict, "delete": conflict, "purge": conflict, "abort": ok, "retry": conflict}}
	// provisioning, create failed
	r = ref()
	op = e.create(t, r).OperationID
	e.failed(t, op, "internal: x")
	rows["provisioning/failed"] = row{r, op, map[string]string{"restart": conflict, "delete": conflict, "purge": conflict, "abort": ok, "retry": ok}}
	// provisioning, create aborting
	r = ref()
	op = e.create(t, r).OperationID
	if _, err := e.st.RequestAbort(ctx, r); err != nil {
		t.Fatal(err)
	}
	rows["provisioning/aborting"] = row{r, op, map[string]string{"restart": conflict, "delete": conflict, "purge": conflict, "abort": ok, "retry": conflict}}
	// active, idle
	r = ref()
	op = e.create(t, r).OperationID
	e.activate(t, r, op)
	rows["active"] = row{r, op, map[string]string{"restart": ok, "delete": ok, "purge": conflict, "abort": conflict, "retry": conflict}}
	// active with a pending restart
	r = ref()
	op = e.create(t, r).OperationID
	e.activate(t, r, op)
	rop, err := e.st.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
	must(t, err)
	rows["active/open-restart"] = row{r, rop, map[string]string{"restart": conflict, "delete": conflict, "purge": conflict, "abort": conflict, "retry": conflict}}
	// restarting, restart failed: a new restart, a delete or a retry leaves it
	// (each accepted cell gets a row of its own below)
	stranded := func() (string, int64) {
		r := ref()
		e.activate(t, r, e.create(t, r).OperationID)
		rop, err := e.st.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
		must(t, err)
		must(t, e.st.SetProjectState(ctx, r, "restarting"))
		e.failed(t, rop, "timeout: x")
		return r, rop
	}
	r, rop = stranded()
	rows["restarting/failed"] = row{r, rop, map[string]string{"restart": ok, "delete": ok, "purge": conflict, "abort": conflict, "retry": ok}}
	// deleting, delete failed
	r = ref()
	op = e.create(t, r).OperationID
	e.activate(t, r, op)
	dop, err := e.st.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
	must(t, err)
	must(t, e.st.SetProjectState(ctx, r, "deleting"))
	e.failed(t, dop, "timeout: x")
	rows["deleting/failed"] = row{r, dop, map[string]string{"restart": conflict, "delete": conflict, "purge": conflict, "abort": conflict, "retry": ok}}
	// deleted, purge pending
	r = ref()
	op = e.create(t, r).OperationID
	e.activate(t, r, op)
	pop := e.deleted(t, r)
	rows["deleted"] = row{r, pop, map[string]string{"restart": conflict, "delete": conflict, "purge": ok, "abort": conflict, "retry": conflict}}
	// purged
	r = ref()
	op = e.create(t, r).OperationID
	e.activate(t, r, op)
	pop = e.deleted(t, r)
	must(t, e.st.StartOperation(ctx, pop))
	must(t, e.st.FinishOperation(ctx, pop, "done", ""))
	must(t, e.st.MarkPurged(ctx, r))
	rows["purged"] = row{r, pop, map[string]string{"restart": conflict, "delete": conflict, "purge": conflict, "abort": conflict, "retry": conflict}}
	// aborted
	r = ref()
	op = e.create(t, r).OperationID
	if _, err := e.st.RequestAbort(ctx, r); err != nil {
		t.Fatal(err)
	}
	must(t, e.st.MarkAborted(ctx, r))
	rows["aborted"] = row{r, op, map[string]string{"restart": conflict, "delete": conflict, "purge": conflict, "abort": conflict, "retry": conflict}}

	// Every command is tried on every row; the expected answers above are
	// chosen so that no command changes the outcome of a later one on its row.
	for name, rw := range rows {
		for _, cmd := range []string{"restart", "delete", "purge", "abort", "retry"} {
			var method, path, body string
			switch cmd {
			case "restart":
				method, path, body = "POST", "/v1/projects/"+rw.ref+"/restart", `{}`
			case "delete":
				method, path = "DELETE", "/v1/projects/"+rw.ref
			case "purge":
				method, path = "POST", "/v1/projects/"+rw.ref+"/purge"
			case "abort":
				method, path = "POST", "/v1/projects/"+rw.ref+"/abort"
			case "retry":
				method, path = "POST", "/v1/operations/"+strconv.FormatInt(rw.op, 10)+"/retry"
			}
			// Only probe a mutation that is expected to be refused; an accepted
			// one would change the row for the next column. Accepted ones are
			// probed on a clone below.
			if rw.codes[cmd] == ok {
				continue
			}
			got, b := e.do(t, method, path, body)
			var eb errBody
			strict(t, b, &eb)
			if got != http.StatusConflict || eb.Code != rw.codes[cmd] {
				t.Errorf("%s × %s: %d %s, want conflict", name, cmd, got, b)
			}
		}
		// ref_exists in every state.
		e.wantCode(t, "POST", "/v1/projects", createBody(t, rw.ref), http.StatusConflict, "ref_exists")
		// Reads are served in every state.
		e.wantOK(t, "GET", "/v1/projects/"+rw.ref, "", 200)
	}
	// The accepted cells, each on its own row.
	for name, rw := range rows {
		for cmd, want := range rw.codes {
			if want != ok {
				continue
			}
			if name == "restarting/failed" {
				r, o := stranded()
				switch cmd {
				case "restart":
					e.wantOK(t, "POST", "/v1/projects/"+r+"/restart", `{}`, 202)
				case "delete":
					e.wantOK(t, "DELETE", "/v1/projects/"+r, "", 202)
				case "retry":
					e.wantOK(t, "POST", "/v1/operations/"+strconv.FormatInt(o, 10)+"/retry", "", 202)
				}
				continue
			}
			switch cmd {
			case "restart":
				e.wantOK(t, "POST", "/v1/projects/"+rw.ref+"/restart", `{}`, 202)
			case "delete":
				// active is the only row accepting both restart and delete;
				// restart above leaves an open operation, so delete is
				// checked on a second active project.
				r := ref()
				e.activate(t, r, e.create(t, r).OperationID)
				e.wantOK(t, "DELETE", "/v1/projects/"+r, "", 202)
			case "purge":
				e.wantOK(t, "POST", "/v1/projects/"+rw.ref+"/purge", "", 202)
			case "abort":
				e.wantOK(t, "POST", "/v1/projects/"+rw.ref+"/abort", "", 202)
			case "retry":
				// provisioning/failed accepts both abort and retry; abort
				// above moved it to aborting, so retry is checked on a
				// second failed create.
				if name == "provisioning/failed" {
					r := ref()
					o := e.create(t, r).OperationID
					e.failed(t, o, "internal: x")
					e.wantOK(t, "POST", "/v1/operations/"+strconv.FormatInt(o, 10)+"/retry", "", 202)
					continue
				}
				e.wantOK(t, "POST", "/v1/operations/"+strconv.FormatInt(rw.op, 10)+"/retry", "", 202)
			}
		}
	}
}

// TestAPI_HostileBodies sends odd requests to every route: each answer is one
// JSON document with a 4xx code and nothing reaches Ops.
func TestAPI_HostileBodies(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	bodies := []string{
		"\x00", "\xff\xfe", "{", "}", `"x"`, `1e999`, `{"name":"\ud800"}`, strings.Repeat("[", 100000),
		strings.Repeat(`{"a":`, 20000), `{"set":{"max_connections":null}}`, `{"set":[]}`, `{"disk_quota_mb":1e30}`,
		`{"disk_quota_mb":"8192"}`, `{"to":"latest\u0000"}`, `{"to":["latest"]}`, `{"set":{"max_connections":"200"},"set":{"fsync":"off"}}`,
		`{"name":"a","issuer_jwks":{"keys":[` + strings.Repeat(`{},`, 30000) + `{}]}}`,
	}
	routes := []struct{ method, path string }{
		{"POST", "/v1/projects"},
		{"POST", "/v1/projects/" + demoRef + "/restart"},
		{"POST", "/v1/projects/" + demoRef + "/restore"},
		{"DELETE", "/v1/projects/" + demoRef},
		{"POST", "/v1/projects/" + demoRef + "/check"},
		{"POST", "/v1/projects/" + demoRef + "/abort"},
		{"POST", "/v1/projects/" + demoRef + "/purge"},
		{"POST", "/v1/operations/1/retry"},
	}
	for _, rt := range routes {
		for _, b := range bodies {
			got, out := e.do(t, rt.method, rt.path, b)
			if got/100 != 4 {
				t.Errorf("%s %s %.30q: %d %s", rt.method, rt.path, b, got, out)
			}
		}
	}
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("hostile bodies reached Ops: %v", calls)
	}
}

// TestAPI_EveryResponseIsJSON: odd paths answer with a JSON body too. The
// router's own redirect for unclean paths does not (301 with an HTML body).
func TestAPI_EveryResponseIsJSON(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1//projects"},
		{"GET", "/v1/projects/../projects"},
		{"GET", "/v1/projects/"},
		{"POST", "/v1/operations/1/../2/retry"},
		{"CONNECT", "/v1/projects"},
	} {
		r := httptest.NewRequest(c.method, "http://supapace/", nil)
		r.URL.Path, r.RequestURI = c.path, c.path
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if !json.Valid(w.Body.Bytes()) || w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s %s: %d %q (%s)", c.method, c.path, w.Code, w.Body.String(), w.Header().Get("Content-Type"))
		}
	}
}

// TestAPI_ConcurrentCreatesSameRef: exactly one wins, the rest are ref_exists.
func TestAPI_ConcurrentCreatesSameRef(t *testing.T) {
	e := newEnv(t)
	body := createBody(t, demoRef)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "/v1/projects", strings.NewReader(body))
			w := httptest.NewRecorder()
			e.h.ServeHTTP(w, r)
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[202] != 1 || codes[409] != 15 {
		t.Fatalf("codes %v", codes)
	}
}

// TestAPI_ConcurrentRestarts: of many restarts on one idle project exactly
// one is queued.
func TestAPI_ConcurrentRestarts(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "/v1/projects/"+demoRef+"/restart", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			e.h.ServeHTTP(w, r)
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[202] != 1 || codes[409] != 15 {
		t.Fatalf("codes %v", codes)
	}
}

// TestAPI_CheckDuringContainmentFailure: project check is a read and is
// served while mutations are refused.
func TestAPI_CheckDuringContainmentFailure(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.ops.failed = true
	e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/check", "", 200)
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restart", `{}`, 503, "containment_failed")
}

// TestAPI_CreateStoresNormalisedKeySet: the create operation carries the
// parsed key set, not the request's bytes (skipped entries and extra members
// do not reach the worker).
func TestAPI_CreateStoresNormalisedKeySet(t *testing.T) {
	e := newEnv(t)
	one := jwks(t, 1)
	set := strings.Replace(one, `{"keys":[`, `{"keys":[{"kty":"EC","kid":"e","crv":"P-256","x":"AA","y":"AA"},`, 1)
	set = strings.Replace(set, `"kty":"RSA"`, `"kty":"RSA","x5u":"https://sp.test/k"`, 1)
	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects", `{"name":"demo","issuer_jwks":`+set+`}`, 202), &m)
	params := string(e.op(t, m.OperationID).Params)
	// Both quoted: a JSON member name or whole value, never a part of the
	// random key's base64, which may hold the letters x5u.
	if strings.Contains(params, `"EC"`) || strings.Contains(params, `"x5u"`) {
		t.Fatalf("params carry the raw key set: %s", params)
	}
}

// TestAPI_CheckSanitisesDriftName: a finding's name is outside text too.
func TestAPI_CheckSanitisesDriftName(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.ops.drift = []nodecfg.CheckResult{{Name: "conf\x1b]0;x\x07iguration" + strings.Repeat("n", 100), Detail: "d"}}
	var c struct {
		OK    bool `json:"ok"`
		Drift []Drift
	}
	strict(t, e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/check", "", 200), &c)
	if len(c.Drift) != 1 || strings.ContainsAny(c.Drift[0].Name, "\x1b\x07") || len(c.Drift[0].Name) > 64 {
		t.Fatalf("drift name %q", c.Drift)
	}
}
