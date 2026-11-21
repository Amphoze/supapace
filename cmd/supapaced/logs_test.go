package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/adminapi"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/store"
)

const (
	refA = "aaaaaaaaaaaaaaaaaaaa"
	refB = "bbbbbbbbbbbbbbbbbbbb"
)

// entry is one line a container wrote.
type entry struct {
	stderr bool
	at     time.Time
	text   string
}

// logHost is a fake Docker for the log reads: a table of containers and
// their logs. Its listing filters by label as Docker does; its docker logs
// answers the last N entries on two streams and applies dockerx's caps.
type logHost struct {
	mu    sync.Mutex
	cs    []dockerx.Container
	logs  map[string][]entry // by container id
	calls []string
	// run, when set, replaces the docker logs answer.
	run func(ctx context.Context, args []string) (string, string, error)
}

func (h *logHost) add(id, name string, labels map[string]string, es ...entry) {
	h.cs = append(h.cs, dockerx.Container{ID: id, Name: name, Labels: labels})
	h.logs[id] = es
}

func (h *logHost) record(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, s)
}

func (h *logHost) Calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

// fakeLogHost installs a fake host; the seams are restored at the end.
func fakeLogHost(t *testing.T) *logHost {
	t.Helper()
	h := &logHost{logs: map[string][]entry{}}
	list, inspect, run, bound, slots := logsList, logsInspect, logsRun, logsMax, logSlots
	t.Cleanup(func() { logsList, logsInspect, logsRun, logsMax, logSlots = list, inspect, run, bound, slots })
	logSlots = make(chan struct{}, 2)
	logsList = func(_ context.Context, filter string) ([]dockerx.Container, error) {
		h.record("ps " + filter)
		k, v, _ := strings.Cut(filter, "=")
		var out []dockerx.Container
		for _, c := range h.cs {
			if got, ok := c.Labels[k]; ok && got == v {
				out = append(out, c)
			}
		}
		return out, nil
	}
	logsInspect = func(_ context.Context, name string) (*dockerx.Container, error) {
		h.record("inspect " + name)
		for _, c := range h.cs {
			if c.Name == name {
				return &c, nil
			}
		}
		return nil, nil
	}
	logsRun = func(ctx context.Context, args ...string) (string, string, error) {
		h.record(strings.Join(args, " "))
		if h.run != nil {
			return h.run(ctx, args)
		}
		if len(args) != 6 || args[0] != "logs" || args[1] != "--timestamps" || args[2] != "--tail" || args[4] != "--" {
			return "", "", fmt.Errorf("unexpected docker call %q", args)
		}
		n, err := strconv.Atoi(args[3])
		es, ok := h.logs[args[5]]
		if err != nil || !ok {
			return "", "Error response from daemon: No such container: " + args[5], errors.New("exit status 1")
		}
		var out, errOut strings.Builder
		for _, e := range es[max(0, len(es)-n):] {
			w := &out
			if e.stderr {
				w = &errOut
			}
			w.WriteString(e.at.Format(time.RFC3339Nano) + " " + e.text + "\n")
		}
		if out.Len() > 4<<20 {
			return "", "", fmt.Errorf("docker logs: %w", dockerx.ErrOutputTooLarge)
		}
		s := errOut.String()
		return out.String(), s[:min(len(s), 64<<10)], nil
	}
	return h
}

var t0 = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

func line(i int, text string) entry {
	return entry{at: t0.Add(time.Duration(i) * time.Millisecond), text: text}
}

func errLine(i int, text string) entry {
	e := line(i, text)
	e.stderr = true
	return e
}

func texts(l adminapi.Logs) []string {
	var out []string
	for _, x := range l.Lines {
		out = append(out, x.Container+":"+x.Text)
	}
	slices.Sort(out)
	return out
}

func labels(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// A project's logs are read from the containers that carry its ref and the
// role cluster or postgrest, by id: not its task or job containers, not a
// container whose name looks like its own but whose label is another
// project's, never by a name. Each line is attributed by the container it
// was read from.
func TestProjectLogs_OnlyThatProjectsContainersByLabel(t *testing.T) {
	h := fakeLogHost(t)
	h.add("id-a-pg", "pg-"+refA, labels("supapace.ref", refA, "supapace.role", "cluster"), errLine(1, "A cluster"))
	h.add("id-a-rest", "postgrest-"+refA, labels("supapace.ref", refA, "supapace.role", "postgrest"), line(2, "A rest"))
	h.add("id-a-task", "task-"+refA+"-wipe", labels("supapace.ref", refA, "supapace.role", "task"), line(3, "A task"))
	h.add("id-a-job", "job-"+refA, labels("supapace.ref", refA, "supapace.role", "job"), line(4, "A job"))
	h.add("id-b-pg", "pg-"+refB, labels("supapace.ref", refB, "supapace.role", "cluster"), line(5, "B cluster"))
	h.add("id-b-look", "postgrest-"+refA+"-x", labels("supapace.ref", refB, "supapace.role", "postgrest"), line(6, "B rest"))
	h.add("id-gw", "sp-gateway", labels("supapace.role", "gateway"), line(7, "gateway "+refA))
	ctx := context.Background()

	got, err := projectLogs(ctx, refA, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cluster:A cluster", "rest:A rest"}; !slices.Equal(texts(got), want) {
		t.Fatalf("lines %q, want %q", texts(got), want)
	}
	want := []string{"ps supapace.ref=" + refA, "logs --timestamps --tail 101 -- id-a-pg", "logs --timestamps --tail 101 -- id-a-rest"}
	if calls := h.Calls(); !slices.Equal(calls, want) {
		t.Fatalf("calls %q, want %q", calls, want)
	}
	h.calls = nil
	if got, err := projectLogs(ctx, refA, "rest", 5); err != nil || !slices.Equal(texts(got), []string{"rest:A rest"}) {
		t.Fatalf("rest alone: %q %v", texts(got), err)
	}
	if calls := h.Calls(); !slices.Equal(calls, []string{"ps supapace.ref=" + refA, "logs --timestamps --tail 6 -- id-a-rest"}) {
		t.Fatalf("calls %q", calls)
	}
	// The control: the other project's own containers are its answer.
	if got, err := projectLogs(ctx, refB, "", 100); err != nil || !slices.Equal(texts(got), []string{"cluster:B cluster", "rest:B rest"}) {
		t.Fatalf("B: %q %v", texts(got), err)
	}
	// A listing that returns a container of another ref (it must not, but
	// the label is checked again) does not put it under this one.
	inner := logsList
	logsList = func(ctx context.Context, f string) ([]dockerx.Container, error) {
		cs, err := inner(ctx, f)
		return append(cs, h.cs[4]), err
	}
	if got, err := projectLogs(ctx, refA, "", 100); err != nil || !slices.Equal(texts(got), []string{"cluster:A cluster", "rest:A rest"}) {
		t.Fatalf("listing with a stranger: %q %v", texts(got), err)
	}
	// Refused before any call: a ref that is not one, a container outside
	// the project's two, a tail outside its bound.
	h.calls = nil
	for _, c := range []struct {
		ref, container string
		tail           int
	}{{"pg-" + refA, "", 1}, {refA + " ", "", 1}, {"", "", 1}, {refA, "postgrest", 1}, {refA, "gateway", 1}, {refA, "", 0}, {refA, "", 1001}} {
		if _, err := projectLogs(ctx, c.ref, c.container, c.tail); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if calls := h.Calls(); len(calls) != 0 {
		t.Fatalf("calls %q", calls)
	}
}

// A line of a shared service's log that names a project — the pooler
// writes refs into its own — is in the node's answer and in no project's.
func TestLogs_SharedServiceLinesNeverUnderAProject(t *testing.T) {
	h := fakeLogHost(t)
	pooler := []entry{line(1, "tenant "+refA+" pool started"), errLine(2, "error "+refA+": authentication failed")}
	h.add("id-pooler", "sp-pooler", labels("supapace.role", "pooler"), pooler...)
	h.add("id-a-pg", "pg-"+refA, labels("supapace.ref", refA, "supapace.role", "cluster"), line(3, "own line"))
	h.add("id-a-rest", "postgrest-"+refA, labels("supapace.ref", refA, "supapace.role", "postgrest"))
	ctx := context.Background()
	node, err := nodeLogs(ctx, "pooler", 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pooler:error " + refA + ": authentication failed", "pooler:tenant " + refA + " pool started"}
	if !slices.Equal(texts(node), want) {
		t.Fatalf("node: %q, want %q", texts(node), want)
	}
	h.calls = nil
	for _, c := range []string{"", "cluster", "rest"} {
		got, err := projectLogs(ctx, refA, c, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range got.Lines {
			if l.Container == "pooler" || strings.Contains(l.Text, "pool") || strings.Contains(l.Text, "authentication") {
				t.Fatalf("%q: a pooler line under the project: %+v", c, l)
			}
		}
		if c != "rest" && !slices.Contains(texts(got), "cluster:own line") {
			t.Fatalf("%q: the project's own line is missing: %q", c, texts(got))
		}
	}
	for _, c := range h.Calls() {
		if strings.Contains(c, "id-pooler") {
			t.Fatalf("the pooler's container reached a project read: %q", c)
		}
	}
}

// The node's containers are named by a closed list: each of its four names
// reads exactly its container; anything else is refused before Docker is
// asked anything. The list is the admin API's.
func TestNodeLogs_ContainerNamesAreAClosedList(t *testing.T) {
	h := fakeLogHost(t)
	for i, n := range []string{"sp-gateway", "sp-pooler", "sp-pgcap", "sp-platform-db", "pg-" + refA, "sp-cp-db", "sp-studio"} {
		h.add("id-"+n, n, nil, line(i, "from "+n))
	}
	ctx := context.Background()
	for c, name := range map[string]string{"gateway": "sp-gateway", "pooler": "sp-pooler", "proxy": "sp-pgcap", "platform-db": "sp-platform-db"} {
		h.calls = nil
		got, err := nodeLogs(ctx, c, 3)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(texts(got), []string{c + ":from " + name}) {
			t.Fatalf("%s: %q", c, texts(got))
		}
		if calls := h.Calls(); !slices.Equal(calls, []string{"inspect " + name, "logs --timestamps --tail 4 -- id-" + name}) {
			t.Fatalf("%s: calls %q", c, calls)
		}
	}
	h.calls = nil
	for _, c := range []string{"", "sp-gateway", "cluster", "rest", "pg-" + refA, "cp-db", "studio", "Gateway", "gateway ",
		"../gateway", "gateway\x00", "platform_db"} {
		if _, err := nodeLogs(ctx, c, 3); err == nil {
			t.Errorf("%q accepted", c)
		}
	}
	for _, tail := range []int{0, -1, 1001} {
		if _, err := nodeLogs(ctx, "gateway", tail); err == nil {
			t.Errorf("tail %d accepted", tail)
		}
	}
	if calls := h.Calls(); len(calls) != 0 {
		t.Fatalf("calls %q", calls)
	}
	if keys := slices.Sorted(maps.Keys(nodeLogNames)); !slices.Equal(keys, slices.Sorted(slices.Values(adminapi.NodeLogContainers))) {
		t.Fatalf("the daemon's list %q is not the admin API's %q", keys, adminapi.NodeLogContainers)
	}
	// A container of the list that does not run is a conflict saying so.
	h.cs = nil
	if _, err := nodeLogs(ctx, "pooler", 3); !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "sp-pooler") {
		t.Fatalf("absent: %v", err)
	}
}

// Both streams are read, each line keeps the time Docker recorded (in the
// answer's layout) and the text after it; a line without a time is left out
// and counted; a project container that does not exist is a note.
func TestLogs_ParsesStreamsTimesAndAbsence(t *testing.T) {
	h := fakeLogHost(t)
	h.add("id-a-pg", "pg-"+refA, labels("supapace.ref", refA, "supapace.role", "cluster"),
		line(1, "out one"), errLine(2, "err two"), line(3, ""), errLine(4, "  spaced  "))
	h.run = func(ctx context.Context, args []string) (string, string, error) {
		return "2026-11-21T10:00:00.001Z out one\n2026-11-21T10:00:00.003Z \nnot a time\n",
			"2026-11-21T10:00:00.002Z err two\n2026-11-21T12:00:00.004+02:00   spaced  \n2026-11-21T10:00:00Z", nil
	}
	got, err := projectLogs(context.Background(), refA, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []adminapi.LogLine{ll("2026-11-21T10:00:00.001000000Z", "out one"), ll("2026-11-21T10:00:00.003000000Z", ""),
		ll("2026-11-21T10:00:00.002000000Z", "err two"), ll("2026-11-21T10:00:00.004000000Z", "  spaced  "),
		ll("2026-11-21T10:00:00.000000000Z", "")}
	if !slices.Equal(got.Lines, want) {
		t.Fatalf("lines %+v,\nwant %+v", got.Lines, want)
	}
	if !slices.Equal(got.Notes, []string{"cluster: 1 line without a time left out", "rest: the project has no such container on this node"}) {
		t.Fatalf("notes %q", got.Notes)
	}
}

// A read whose output is over dockerx's caps — 4 MiB of standard output, 64
// KiB of standard error, whose start alone is kept — is asked again for half
// the lines, until it fits; the note says how many were read. At one line
// that still does not fit, the read fails.
func TestLogs_OutputOverTheCapsHalvesTheTail(t *testing.T) {
	h := fakeLogHost(t)
	var errs, outs []entry
	for i := range 1100 {
		errs = append(errs, errLine(i, fmt.Sprintf("%04d ", i)+strings.Repeat("e", 200)))
		outs = append(outs, line(i, fmt.Sprintf("%04d ", i)+strings.Repeat("o", 16<<10)))
	}
	h.add("id-a-pg", "pg-"+refA, labels("supapace.ref", refA, "supapace.role", "cluster"), errs...)
	h.add("id-a-rest", "postgrest-"+refA, labels("supapace.ref", refA, "supapace.role", "postgrest"), outs...)
	ctx := context.Background()
	got, err := projectLogs(ctx, refA, "cluster", 1000)
	if err != nil {
		t.Fatal(err)
	}
	var tails []string
	for _, c := range h.Calls() {
		if f := strings.Fields(c); f[0] == "logs" {
			tails = append(tails, f[3])
		}
	}
	if !slices.Equal(tails, []string{"1001", "500", "250"}) || len(got.Lines) != 250 || !strings.HasPrefix(got.Lines[249].Text, "1099 ") {
		t.Fatalf("tails %q, %d lines", tails, len(got.Lines))
	}
	if len(got.Notes) != 1 || !strings.Contains(got.Notes[0], "older lines of cluster not shown") || !strings.Contains(got.Notes[0], "only the newest 250 lines could be read of the 1000 asked") {
		t.Fatalf("notes %q", got.Notes)
	}
	h.calls = nil
	if got, err = projectLogs(ctx, refA, "rest", 1000); err != nil || len(got.Lines) != 250 {
		t.Fatalf("stdout: %d lines, %v", len(got.Lines), err)
	}
	// The control: a read that fits is made once, without a note.
	h.calls = nil
	if got, err = projectLogs(ctx, refA, "cluster", 100); err != nil || len(got.Lines) != 101 || len(got.Notes) != 0 || len(h.Calls()) != 2 {
		t.Fatalf("fits: %d lines, notes %q, calls %q, %v", len(got.Lines), got.Notes, h.Calls(), err)
	}
	// At tail 1 two lines are asked for and one is read: what was asked, without a note. At tail 2
	// three are asked for and one is read: noted, in the singular.
	h.logs["id-a-pg"] = []entry{errLine(1, strings.Repeat("e", 40<<10)), errLine(2, strings.Repeat("f", 40<<10))}
	if got, err = projectLogs(ctx, refA, "cluster", 1); err != nil || len(got.Lines) != 1 || len(got.Notes) != 0 ||
		!strings.HasPrefix(got.Lines[0].Text, "f") {
		t.Fatalf("tail 1: %d lines, notes %q, %v", len(got.Lines), got.Notes, err)
	}
	if got, err = projectLogs(ctx, refA, "cluster", 2); err != nil || len(got.Lines) != 1 || len(got.Notes) != 1 ||
		!strings.Contains(got.Notes[0], "only the newest 1 line could be read of the 2 asked") {
		t.Fatalf("tail 2: %d lines, notes %q, %v", len(got.Lines), got.Notes, err)
	}
	h.logs["id-a-rest"] = []entry{line(1, strings.Repeat("o", 5<<20))}
	if _, err := projectLogs(ctx, refA, "rest", 10); !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("one line over the cap: %v", err)
	}
}

// A Docker call that hangs ends at logsMax: the read answers a conflict
// that says so, and the call's context carried that deadline.
func TestLogs_HungDockerCallIsBounded(t *testing.T) {
	h := fakeLogHost(t)
	h.add("id-gw", "sp-gateway", nil)
	logsMax = 50 * time.Millisecond
	var left time.Duration
	h.run = func(ctx context.Context, _ []string) (string, string, error) {
		d, ok := ctx.Deadline()
		if !ok {
			return "", "", errors.New("no deadline")
		}
		left = time.Until(d)
		<-ctx.Done()
		return "", "", ctx.Err()
	}
	_, err := nodeLogs(context.Background(), "gateway", 10)
	if !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "within") || left > logsMax {
		t.Fatalf("err %v, deadline in %v", err, left)
	}
	// The control: the same read answers when Docker does.
	h.run = nil
	if _, err := nodeLogs(context.Background(), "gateway", 10); err != nil {
		t.Fatal(err)
	}
}

// At most two reads run at once; a third waits within its own bound and is
// then refused, having asked Docker nothing.
func TestLogs_ConcurrentReadsAreBounded(t *testing.T) {
	h := fakeLogHost(t)
	h.add("id-gw", "sp-gateway", nil, line(1, "gw"))
	entered, release := make(chan struct{}), make(chan struct{})
	h.run = func(ctx context.Context, _ []string) (string, string, error) {
		select {
		case entered <- struct{}{}:
		case <-ctx.Done(): // a third read that took a slot it should not have
			return "", "", ctx.Err()
		}
		<-release
		return "", "", nil
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := nodeLogs(context.Background(), "gateway", 1); err != nil {
				t.Error(err)
			}
		}()
		<-entered
	}
	n := len(h.Calls())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := nodeLogs(ctx, "gateway", 1)
	if !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "two log reads") || len(h.Calls()) != n {
		t.Fatalf("third: %v, calls %q", err, h.Calls()[n:])
	}
	close(release)
	wg.Wait()
	// The control: with the slots free the read is served.
	h.run = nil
	if _, err := nodeLogs(context.Background(), "gateway", 1); err != nil {
		t.Fatal(err)
	}
}

func ll(at, text string) adminapi.LogLine {
	return adminapi.LogLine{Container: "cluster", At: at, Text: text}
}

// A container that is gone by the time its log is read — a restore or a
// delete replaced it after the listing — or whose log cannot be read is a
// conflict naming the container, never an internal error carrying what
// docker printed on standard error (the container's own text among it).
func TestLogs_ContainerGoneDuringTheReadIsAConflict(t *testing.T) {
	h := fakeLogHost(t)
	h.add("id-a-pg", "pg-"+refA, labels("supapace.ref", refA, "supapace.role", "cluster"))
	h.run = func(_ context.Context, _ []string) (string, string, error) {
		return "", "tenant text\nError response from daemon: No such container: id-a-pg\n", errors.New("exit status 1")
	}
	_, err := projectLogs(context.Background(), refA, "cluster", 10)
	if !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "cluster") || strings.Contains(err.Error(), "tenant text") {
		t.Fatalf("err %v", err)
	}
}

// The daemon's log of such a failure is one fixed line: the container's
// role and the exit status, nothing Docker printed.
func TestLogs_FailedReadLogsNoDockerText(t *testing.T) {
	h := fakeLogHost(t)
	h.add("id-gw", "sp-gateway", nil)
	h.run = func(context.Context, []string) (string, string, error) {
		err := exec.Command("sh", "-c", "exit 3").Run()
		stderr := "tenant text\nError response from daemon: log driver cannot read"
		return "", stderr, fmt.Errorf("docker logs: %w: %s", err, stderr) // as dockerx words it
	}
	var b bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&b, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	_, err := nodeLogs(context.Background(), "gateway", 10)
	if !errors.Is(err, store.ErrConflict) || !strings.HasSuffix(err.Error(), ": the log of the gateway could not be read; try again") {
		t.Fatalf("err %v", err)
	}
	out := b.String()
	if strings.Count(out, "\n") != 1 || strings.Contains(out, "tenant") || strings.Contains(out, "daemon") ||
		!strings.Contains(out, "container=gateway") || !strings.Contains(out, "exit_status=3") {
		t.Fatalf("log %q", out)
	}
}
