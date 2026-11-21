package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/store"
)

// logCap is the daemon's two log capabilities: it answers what the test
// gives it and records what it was asked.
type logCap struct {
	mu    sync.Mutex
	calls []string
	got   Logs
	err   error
}

func (c *logCap) answer(kind, args string) (Logs, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, kind+" "+args)
	return c.got, c.err
}

func (c *logCap) Calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

func (c *logCap) Logs(_ context.Context, ref, container string, tail int) (Logs, error) {
	return c.answer("project", fmt.Sprintf("%s %q %d", ref, container, tail))
}

func (c *logCap) NodeLogs(_ context.Context, container string, tail int) (Logs, error) {
	return c.answer("node", fmt.Sprintf("%q %d", container, tail))
}

// withLogs gives the API an Ops with both log capabilities.
func (e *env) withLogs(t *testing.T) *logCap {
	t.Helper()
	c := &logCap{}
	e.h = New(e.st, e.kek, struct {
		*fakeOps
		*logCap
	}{e.ops, c}, "sp.test", e.p)
	return c
}

// logsT is the logs document, decoded strictly.
type logsT struct {
	Lines []struct {
		Container string `json:"container"`
		At        string `json:"at"`
		Text      string `json:"text"`
	} `json:"lines"`
	Notes []string `json:"notes"`
}

func (e *env) readLogs(t *testing.T, path string) logsT {
	t.Helper()
	var l logsT
	strict(t, e.wantOK(t, "GET", path, "", http.StatusOK), &l)
	if l.Lines == nil || l.Notes == nil {
		t.Fatalf("%s: lists must be [], never null", path)
	}
	return l
}

// at is the i-th second after a fixed time, in the answer's layout.
func at(i int) string {
	return time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(LogAtLayout)
}

// The text a project writes reaches the answer without a control
// character, a line or paragraph separator, a format character (bidi
// overrides among them) or a byte that is not UTF-8; printable text,
// non-ASCII letters included, is kept as it was.
func TestProjectLogs_ControlCharactersStripped(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	c := e.withLogs(t)
	hostile := "a\x1b[2J\x1b]0;title\x07b\rc\nd\te\x00f\u009b31mg h i‮j​k\xff\xfel"
	plain := "LOG:  checkpoint complete: wrote 3 buffers (0.0%); Größe ok"
	c.got = Logs{Lines: []LogLine{{"cluster", at(1), hostile}, {"rest", at(2), plain}},
		Notes: []string{"note\x1b[31m with\ncontrol"}}
	l := e.readLogs(t, "/v1/projects/"+demoRef+"/logs")
	if len(l.Lines) != 2 {
		t.Fatalf("lines %+v", l.Lines)
	}
	clean := func(s string) bool {
		if !utf8.ValidString(s) {
			return false
		}
		for _, r := range s {
			if r < 0x20 || r >= 0x7f && r <= 0x9f || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
				return false
			}
		}
		return true
	}
	for _, s := range append([]string{l.Lines[0].Text, l.Lines[1].Text}, l.Notes...) {
		if !clean(s) {
			t.Errorf("not clean: %q", s)
		}
	}
	if got := l.Lines[0].Text; got != "a[2J]0;titlebcd ef31mghijkl" {
		t.Errorf("hostile line %q", got)
	}
	// The control: printable text passes unchanged.
	if l.Lines[1].Text != plain || l.Lines[1].Container != "rest" || l.Lines[1].At != at(2) {
		t.Errorf("plain line %+v", l.Lines[1])
	}
	if l.Notes[0] != "note[31m withcontrol" {
		t.Errorf("notes %q", l.Notes)
	}
	// The node's route cleans in the same place.
	c.got = Logs{Lines: []LogLine{{"pooler", at(1), hostile}}}
	if got := e.readLogs(t, "/v1/node/logs?container=pooler").Lines[0].Text; got != "a[2J]0;titlebcd ef31mghijkl" {
		t.Errorf("node line %q", got)
	}
}

// The answer holds at most tail lines (default 100, at most 1,000), the
// newest, oldest first across containers; at most LogsMaxBytes of text, the
// newest kept; no line longer than LogLineMax. Each cut is named in notes;
// without one there is no note.
func TestProjectLogs_BoundedTail(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	c := e.withLogs(t)
	path := "/v1/projects/" + demoRef + "/logs"
	for _, q := range []string{"?tail=0", "?tail=1001", "?tail=-1", "?tail=x", "?tail=1&tail=2", "?tail=", "?tail=1e3"} {
		e.wantCode(t, "GET", path+q, "", 400, "bad_request")
	}
	if calls := c.Calls(); len(calls) != 0 {
		t.Fatalf("a refused tail reached the daemon: %q", calls)
	}
	e.readLogs(t, path)
	e.readLogs(t, path+"?tail=1000")
	if calls := c.Calls(); !slices.Equal(calls, []string{"project " + demoRef + ` "" 100`, "project " + demoRef + ` "" 1000`}) {
		t.Fatalf("calls %q", calls)
	}

	// Lines: the newest tail, merged by time across the two containers.
	var lines []LogLine
	for i := range 30 {
		lines = append(lines, LogLine{"cluster", at(2 * i), fmt.Sprint("c", 2*i)})
	}
	for i := range 30 {
		lines = append(lines, LogLine{"rest", at(2*i + 1), fmt.Sprint("r", 2*i+1)})
	}
	c.got = Logs{Lines: lines}
	l := e.readLogs(t, path+"?tail=5")
	var got []string
	for _, x := range l.Lines {
		got = append(got, x.Container+":"+x.Text)
	}
	if want := []string{"rest:r55", "cluster:c56", "rest:r57", "cluster:c58", "rest:r59"}; !slices.Equal(got, want) {
		t.Fatalf("tail 5: %q, want %q", got, want)
	}
	if len(l.Notes) != 1 || !strings.Contains(l.Notes[0], "older lines not shown") || !strings.Contains(l.Notes[0], "newest 5 lines") {
		t.Fatalf("notes %q", l.Notes)
	}
	// The control: everything fits, nothing is said to be cut.
	if l := e.readLogs(t, path+"?tail=60"); len(l.Lines) != 60 || len(l.Notes) != 0 {
		t.Fatalf("tail 60: %d lines, notes %q", len(l.Lines), l.Notes)
	}

	// Bytes: 1,000 lines of 2 KiB are more than LogsMaxBytes; the newest are kept.
	lines = nil
	for i := range 1000 {
		lines = append(lines, LogLine{"cluster", at(i), fmt.Sprintf("%04d", i) + strings.Repeat("x", 2044)})
	}
	c.got = Logs{Lines: lines}
	l = e.readLogs(t, path+"?tail=1000")
	n := 0
	for _, x := range l.Lines {
		n += len(x.Text)
	}
	if n > LogsMaxBytes || len(l.Lines) != LogsMaxBytes/2048 || !strings.HasPrefix(l.Lines[len(l.Lines)-1].Text, "0999") {
		t.Fatalf("%d lines, %d bytes, last %.4q", len(l.Lines), n, l.Lines[len(l.Lines)-1].Text)
	}
	if len(l.Notes) != 1 || !strings.Contains(l.Notes[0], "1 MiB") {
		t.Fatalf("notes %q", l.Notes)
	}

	// One line longer than LogLineMax is shortened, on a rune boundary.
	long := strings.Repeat("é", LogLineMax) // two bytes each
	c.got = Logs{Lines: []LogLine{{"rest", at(1), long}, {"rest", at(2), "short"}}}
	l = e.readLogs(t, path)
	if got := l.Lines[0].Text; len(got) != LogLineMax || !utf8.ValidString(got) || l.Lines[1].Text != "short" {
		t.Fatalf("long line: %d bytes, valid %v; second %q", len(got), utf8.ValidString(got), l.Lines[1].Text)
	}
	if len(l.Notes) != 1 || !strings.Contains(l.Notes[0], "1 line longer than 16384 bytes") {
		t.Fatalf("notes %q", l.Notes)
	}

	// The daemon's notes come first and are bounded too.
	var many []string
	for range 40 {
		many = append(many, strings.Repeat("n", 4000))
	}
	c.got = Logs{Lines: nil, Notes: many}
	l = e.readLogs(t, path)
	if len(l.Notes) != logsMaxNotes || len(l.Notes[0]) != maxMessage {
		t.Fatalf("%d notes, first %d bytes", len(l.Notes), len(l.Notes[0]))
	}
}

// Without the daemon's capability both routes answer conflict, after the
// request is validated, and nothing is read.
func TestLogs_ConflictWithoutTheCapability(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	for _, p := range []string{"/v1/projects/" + demoRef + "/logs", "/v1/projects/" + demoRef + "/logs?container=cluster&tail=10",
		"/v1/node/logs?container=gateway"} {
		eb := e.wantCode(t, "GET", p, "", http.StatusConflict, "conflict")
		if !strings.HasPrefix(eb.Message, "logs are not available on this node") {
			t.Errorf("%s: %q", p, eb.Message)
		}
	}
	e.wantCode(t, "GET", "/v1/node/logs?container=sp-gateway", "", 400, "bad_request")
	e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/logs?tail=0", "", 400, "bad_request")
	e.wantCode(t, "GET", "/v1/projects/zzzzzzzzzzzzzzzzzzzz/logs", "", 404, "not_found")
	// The control: with the capability the same request is served.
	e.withLogs(t)
	e.readLogs(t, "/v1/node/logs?container=gateway")
}

// The node's route takes a container from its closed list only, and passes
// the daemon nothing else; a project's takes cluster or rest, or none.
func TestNodeLogs_RouteTakesTheClosedListOnly(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	c := e.withLogs(t)
	for _, q := range []string{"", "?container=", "?container=sp-gateway", "?container=sp-pooler", "?container=Gateway",
		"?container=gateway%20", "?container=../gateway", "?container=cluster", "?container=rest", "?container=pg-" + demoRef,
		"?container=gateway&container=pooler", "?container=gateway&name=x", "?container=gateway&tail=0", "?%zz"} {
		e.wantCode(t, "GET", "/v1/node/logs"+q, "", 400, "bad_request")
	}
	for _, q := range []string{"?container=gateway", "?container=pooler", "?container=proxy", "?container=platform-db",
		"?container=cluster", "?container=postgrest", "?container=pg-" + demoRef, "?container=", "?ref=" + demoRef, "?foo=cluster"} {
		path := "/v1/projects/" + demoRef + "/logs" + q
		if q == "?container=gateway" || q == "?container=pooler" || q == "?container=proxy" || q == "?container=platform-db" ||
			q == "?container=postgrest" || q == "?container=pg-"+demoRef || q == "?container=" || q == "?ref="+demoRef || q == "?foo=cluster" {
			e.wantCode(t, "GET", path, "", 400, "bad_request")
			continue
		}
		e.readLogs(t, path)
	}
	for _, name := range NodeLogContainers {
		e.readLogs(t, "/v1/node/logs?container="+name+"&tail=7")
	}
	e.readLogs(t, "/v1/projects/"+demoRef+"/logs?container=rest")
	want := []string{"project " + demoRef + ` "cluster" 100`, `node "gateway" 7`, `node "pooler" 7`, `node "proxy" 7`,
		`node "platform-db" 7`, "project " + demoRef + ` "rest" 100`}
	if got := c.Calls(); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	if !slices.Equal(NodeLogContainers, []string{"gateway", "pooler", "proxy", "platform-db"}) ||
		!slices.Equal(ProjectLogContainers, []string{"cluster", "rest"}) {
		t.Fatalf("the lists changed: %q %q", NodeLogContainers, ProjectLogContainers)
	}
}

// A line the daemon attributes to a container the route does not serve — a
// shared container's under a project, another node container's, the other
// project container's when one was asked for — or with a time not in the
// answer's layout fails the whole answer: nothing of it is shown.
func TestLogs_LineOutsideTheRouteFailsTheAnswer(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	c := e.withLogs(t)
	b := logs(t)
	for _, tc := range []struct {
		path string
		line LogLine
	}{
		{"/v1/projects/" + demoRef + "/logs", LogLine{"pooler", at(1), "secret-of-another " + demoRef}},
		{"/v1/projects/" + demoRef + "/logs", LogLine{"gateway", at(1), "secret-of-another"}},
		{"/v1/projects/" + demoRef + "/logs?container=cluster", LogLine{"rest", at(1), "secret-of-another"}},
		{"/v1/node/logs?container=gateway", LogLine{"pooler", at(1), "secret-of-another"}},
		{"/v1/node/logs?container=gateway", LogLine{"cluster", at(1), "secret-of-another"}},
		{"/v1/projects/" + demoRef + "/logs", LogLine{"cluster", "2026-11-21T10:00:00Z", "secret-of-another"}},
		{"/v1/projects/" + demoRef + "/logs", LogLine{"cluster", "", "secret-of-another"}},
	} {
		c.got = Logs{Lines: []LogLine{tc.line}}
		_, body := e.do(t, "GET", tc.path, "")
		eb := e.wantCode(t, "GET", tc.path, "", 500, "internal")
		if strings.Contains(string(body), "secret-of-another") || eb.Message != "internal error" {
			t.Errorf("%s %+v: %s", tc.path, tc.line, body)
		}
	}
	if strings.Contains(b.String(), "secret-of-another") {
		t.Errorf("the line's text reached the log: %s", b)
	}
	// The control: the same lines under the routes that serve them.
	c.got = Logs{Lines: []LogLine{{"cluster", at(0), "fine"}, {"rest", at(1), "fine"}}}
	e.readLogs(t, "/v1/projects/"+demoRef+"/logs")
	c.got = Logs{Lines: []LogLine{{"pooler", at(0), "fine " + demoRef}}}
	e.readLogs(t, "/v1/node/logs?container=pooler")
}

// The daemon's refusal is answered as a conflict with its reason.
func TestLogs_DaemonConflictCarriesItsReason(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	c := e.withLogs(t)
	c.err = fmt.Errorf("%w: the pooler does not run on this node", store.ErrConflict)
	eb := e.wantCode(t, "GET", "/v1/node/logs?container=pooler", "", http.StatusConflict, "conflict")
	if eb.Message != "the pooler does not run on this node" {
		t.Fatalf("message %q", eb.Message)
	}
}
