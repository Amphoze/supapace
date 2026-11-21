package bkjob

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/arch"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
)

// A serve job as a process of its own, for the stop signal: this test binary
// with BKJOB_SERVE_CHILD set runs Serve until SIGTERM, as supapaced job serve
// does, and prints its result line.
func init() {
	if os.Getenv("BKJOB_SERVE_CHILD") == "" || filepath.Base(os.Args[0]) == "pgbackrest-act" {
		return
	}
	Tool, privRoot, servePoll = os.Getenv("BKJOB_TOOL"), os.Getenv("BKJOB_PRIV"), 10*time.Millisecond
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	r, err := Serve(ctx, jobio.Input{Kind: "serve", Subject: "ref", Stanza: "ref-1", UID: os.Getuid(), Timelines: []uint32{1}},
		os.Getenv("BKJOB_SERVE_CHILD"))
	if err != nil {
		os.Exit(3)
	}
	line, _ := jobio.MarshalResult(r)
	os.Stdout.Write(line)
	os.Exit(0)
}

const (
	seg1 = "000000010000000000000001"
	seg2 = "000000010000000000000002"
)

// slab is one serve job's world: a restore spool, the private directory and
// the fake.
type slab struct {
	t                      *testing.T
	rspool, req, out, priv string
	tool                   string
	cancel                 context.CancelFunc
	done                   chan struct{}
	res                    jobio.ServeResult
	err                    error
	startOnce, stopOnce    sync.Once
	input                  jobio.Input
	deadline               time.Duration
}

func newSlab(t *testing.T) *slab {
	t.Helper()
	d := t.TempDir()
	l := &slab{t: t, rspool: filepath.Join(d, "rspool"), priv: filepath.Join(d, "priv"), tool: actTool(t), deadline: 30 * time.Second,
		input: jobio.Input{Job: 4, Kind: "serve", Subject: "ref", Stanza: "ref-1", UID: os.Getuid(), Timelines: []uint32{1, 2}, MaxAnswers: bklimit.ServeMaxAnswers}}
	l.req, l.out = filepath.Join(l.rspool, "req"), filepath.Join(l.rspool, "out")
	for _, p := range []string{l.rspool, l.req, l.out, l.priv} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldPriv, oldPoll, oldRand := privRoot, servePoll, serveRand
	privRoot, servePoll = l.priv, 5*time.Millisecond
	t.Cleanup(func() { privRoot, servePoll, serveRand = oldPriv, oldPoll, oldRand })
	t.Cleanup(func() { l.stop() })
	// By default every archive-get answers with a file holding its name.
	setActs(t, l.tool, map[string][]act{"*": {{Write: map[string]string{"$DEST": "answer"}}}})
	return l
}

func (l *slab) start() {
	l.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		l.cancel, l.done = cancel, make(chan struct{})
		go func() {
			defer close(l.done)
			l.res, l.err = Serve(ctx, l.input, l.rspool)
		}()
	})
}

// stop ends the job and returns its result.
func (l *slab) stop() (jobio.ServeResult, error) {
	l.stopOnce.Do(func() {
		if l.cancel == nil {
			return
		}
		l.cancel()
		select {
		case <-l.done:
		case <-time.After(30 * time.Second):
			l.t.Fatal("Serve did not end on its context")
		}
	})
	return l.res, l.err
}

// ask makes a request as the archive binary does.
func (l *slab) ask(name string) {
	l.t.Helper()
	f, err := os.OpenFile(filepath.Join(l.req, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		l.t.Fatal(err)
	}
	f.Close()
}

// await waits until cond holds; failing the test after the lab's deadline.
func (l *slab) await(what string, cond func() bool) {
	l.t.Helper()
	end := time.Now().Add(l.deadline)
	for !cond() {
		if time.Now().After(end) {
			l.t.Fatalf("waited %v for %s", l.deadline, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// answered waits for the answer to name (file, or .none when none) and
// returns its bytes.
func (l *slab) answered(name string, none bool) string {
	l.t.Helper()
	p := filepath.Join(l.out, name)
	if none {
		p += ".none"
	}
	l.await("the answer to "+name, func() bool { return exists(p) })
	b, _ := os.ReadFile(p)
	return string(b)
}

// take consumes an answer as the archive binary does: the request, then the answer.
func (l *slab) take(name string) {
	os.Remove(filepath.Join(l.req, name))
	os.Remove(filepath.Join(l.out, name))
	os.Remove(filepath.Join(l.out, name+".none"))
}

func (l *slab) gets() []string {
	var out []string
	for _, c := range actCalls(l.tool) {
		if strings.HasPrefix(c.Key, "archive-get ") {
			out = append(out, c.Key[len("archive-get "):])
		}
	}
	return out
}

func (l *slab) outNames() []string {
	es, _ := os.ReadDir(l.out)
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestGetTimeoutEqualsLimit(t *testing.T) {
	if arch.GetTimeout != bklimit.GetTimeout {
		t.Errorf("the archive binary waits %v for an answer, the platform's limit is %v", arch.GetTimeout, bklimit.GetTimeout)
	}
}

// The tool writes its answer only below the job's private directory; the
// copy into out/ goes through a temporary name of out/ and a rename there.
func TestServe_AnswersSegmentThroughPrivateDir(t *testing.T) {
	l := newSlab(t)
	setActs(t, l.tool, map[string][]act{"*": {{Write: map[string]string{"$DEST": "segment bytes"}}}})
	l.start()
	l.ask(seg1)
	if got := l.answered(seg1, false); got != "segment bytes" {
		t.Errorf("answer %q", got)
	}
	c := actCalls(l.tool)[0]
	if len(c.Args) != 3 || c.Args[0] != "archive-get" || c.Args[1] != seg1 || !strings.HasPrefix(c.Args[2], l.priv+"/") {
		t.Errorf("argv %q: the tool must write below %s", c.Args, l.priv)
	}
	if got := l.outNames(); !slices.Equal(got, []string{seg1}) {
		t.Errorf("out/ holds %q: no temporary left", got)
	}
	if fi, _ := os.Lstat(filepath.Join(l.out, seg1)); !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("answer mode %v", fi.Mode())
	}
	r, _ := l.stop()
	if r.Served != 1 || r.Last != seg1 || r.LastNone || r.LastSegment != seg1 {
		t.Errorf("result %+v", r)
	}
	if left, _ := os.ReadDir(l.priv); len(left) != 0 {
		t.Errorf("the private directory is left: %v", left)
	}
}

func TestServe_NotFoundOnlyOnExit1(t *testing.T) {
	l := newSlab(t)
	setActs(t, l.tool, map[string][]act{"archive-get " + seg1: {{Exit: 1}}, "archive-get " + seg2: {{Exit: 3}},
		"archive-get 000000010000000000000003": {{Exit: 125}}})
	l.start()
	l.ask(seg1)
	l.ask(seg2)
	l.ask("000000010000000000000003")
	l.answered(seg1, true)
	l.await("retries of the other two", func() bool {
		g := l.gets()
		j := strings.Join(g, " ")
		return strings.Count(j, seg2) >= 2 && strings.Count(j, "000000010000000000000003") >= 2
	})
	r, _ := l.stop()
	for _, n := range []string{seg2, "000000010000000000000003"} {
		if exists(filepath.Join(l.out, n+".none")) || exists(filepath.Join(l.out, n)) {
			t.Errorf("%s answered after a failure other than exit 1", n)
		}
	}
	if !slices.Equal(r.None, []string{seg1}) || r.Served != 0 || r.Last != seg1 || !r.LastNone || r.LastSegment != "" {
		t.Errorf("result %+v", r)
	}
}

func TestServe_OtherErrorsRetried(t *testing.T) {
	l := newSlab(t)
	setActs(t, l.tool, map[string][]act{"archive-get " + seg1: {{Exit: 55}, {Kill: true}, {Write: map[string]string{"$DEST": "at last"}}}})
	l.start()
	l.ask(seg1)
	if got := l.answered(seg1, false); got != "at last" {
		t.Errorf("answer %q", got)
	}
	if g := l.gets(); len(g) != 3 {
		t.Errorf("%d calls, want 3", len(g))
	}
	if r, _ := l.stop(); r.Served != 1 || len(r.None) != 0 {
		t.Errorf("result %+v", r)
	}
}

// A name is answered at most max_answers times; a request past that is
// removed unanswered, so the archive binary times out above 125.
func TestServe_MaxAnswersPerName(t *testing.T) {
	for _, max := range []int{3, 0} { // 0: the platform's cap
		t.Run(fmt.Sprint(max), func(t *testing.T) {
			l := newSlab(t)
			l.input.MaxAnswers = max
			want := max
			if max == 0 {
				want = bklimit.ServeMaxAnswers
			}
			l.start()
			for range want {
				l.ask(seg1)
				l.answered(seg1, false)
				l.take(seg1)
			}
			l.ask(seg1)
			l.await("the request past the cap removed", func() bool { return !exists(filepath.Join(l.req, seg1)) })
			// Control: another name is still answered.
			l.ask(seg2)
			l.answered(seg2, false)
			r, _ := l.stop()
			if exists(filepath.Join(l.out, seg1)) || len(l.gets()) != want+1 || r.Refused != 1 || r.Served != want+1 {
				t.Errorf("calls %d, refused %d, served %d: want %d answers of %s", len(l.gets()), r.Refused, r.Served, want, seg1)
			}
		})
	}
}

// Only the archive binary's two request shapes are taken; anything else is
// removed unread and counted, the tool never runs for it.
func TestServe_RefusesOptionShapedName(t *testing.T) {
	l := newSlab(t)
	bad := []string{"--config=x", "-x", seg1 + ".partial", strings.ToLower("0000000100000000000000AB"), seg1 + ".00000028.backup", "00000001.HISTORY", ".tmp-" + seg1, "x"}
	for _, n := range bad {
		l.ask(n)
	}
	l.start()
	l.await("the refusals", func() bool {
		es, _ := os.ReadDir(l.req)
		return len(es) == 0
	})
	l.ask(seg2) // control
	l.answered(seg2, false)
	r, _ := l.stop()
	if g := l.gets(); !slices.Equal(g, []string{seg2}) {
		t.Errorf("the tool ran for %q", g)
	}
	if r.Refused != len(bad) {
		t.Errorf("refused %d, want %d", r.Refused, len(bad))
	}
}

// A link planted at the temporary name drawn is never written through: another
// name is drawn.
func TestServe_LinkAtTemporaryNameDrawsAnother(t *testing.T) {
	l := newSlab(t)
	draws := []string{"0000000000000000", "1111111111111111"}
	var mu sync.Mutex
	serveRand = func() string {
		mu.Lock()
		defer mu.Unlock()
		d := draws[0]
		if len(draws) > 1 {
			draws = draws[1:]
		}
		return d
	}
	target := filepath.Join(t.TempDir(), "target")
	l.start()
	// Planted after the start, which clears old temporaries.
	l.await("the start", func() bool { return exists(filepath.Join(l.priv)) && len(mustDir(t, l.priv)) == 1 })
	if err := os.Symlink(target, filepath.Join(l.out, ".tmp-"+seg1+"-0000000000000000")); err != nil {
		t.Fatal(err)
	}
	l.ask(seg1)
	if got := l.answered(seg1, false); got != "answer" {
		t.Errorf("answer %q", got)
	}
	if exists(target) {
		t.Error("the answer was written through the planted link")
	}
	if n := len(l.gets()); n != 1 {
		t.Errorf("%d tool runs: the answer must take the next name at once", n)
	}
	if fi, err := os.Lstat(filepath.Join(l.out, ".tmp-"+seg1+"-0000000000000000")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the planted link: %v %v", fi, err)
	}
}

func mustDir(t *testing.T, p string) []os.DirEntry {
	es, err := os.ReadDir(p)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// A request that is a link (to a file anywhere), a directory or a FIFO is not
// a request: nothing is answered for it and nothing it points to is touched.
func TestServe_RequestIsLinkIgnored(t *testing.T) {
	l := newSlab(t)
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("keep"), 0o600)
	os.Symlink(target, filepath.Join(l.req, seg1))
	os.Mkdir(filepath.Join(l.req, "000000010000000000000003"), 0o700)
	syscall.Mkfifo(filepath.Join(l.req, "000000010000000000000004"), 0o600)
	l.start()
	l.ask(seg2) // control
	l.answered(seg2, false)
	l.await("the link removed", func() bool { return !exists(filepath.Join(l.req, seg1)) })
	r, _ := l.stop()
	if g := l.gets(); !slices.Equal(g, []string{seg2}) {
		t.Errorf("the tool ran for %q", g)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the link's target holds %q", b)
	}
	if r.Refused != 2 { // the link and the FIFO; the directory stays
		t.Errorf("refused %d", r.Refused)
	}
}

// The job ends on the stop signal with its result line and exit 0.
func TestServe_ResultOnSIGTERM(t *testing.T) {
	l := newSlab(t)
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), "BKJOB_SERVE_CHILD="+l.rspool, "BKJOB_TOOL="+Tool, "BKJOB_PRIV="+l.priv)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	l.ask(seg1)
	l.answered(seg1, false)
	l.ask("00000009.history") // not admitted: "not in the archive"
	l.answered("00000009.history", true)
	cmd.Process.Signal(syscall.SIGTERM)
	sc := bufio.NewScanner(stdout)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	err := cmd.Wait()
	if err != nil || len(lines) != 1 {
		t.Fatalf("exit %v, stdout %q: want exit 0 and one line", err, lines)
	}
	v, fl, err := jobio.ParseResult("serve", []byte(lines[0]))
	r, _ := v.(jobio.ServeResult)
	if err != nil || fl != nil || !r.OK || r.Served != 1 || r.LastSegment != seg1 || r.Last != "00000009.history" || !r.LastNone {
		t.Errorf("result %s: %v %v", lines[0], err, fl)
	}
}

// last_segment is the highest segment number answered with a file: neither a
// history nor a "not in the archive" answer counts, and a higher timeline of
// a lower segment does not raise it.
func TestServe_LastSegmentIsTheHighestSegmentAnsweredWithAFile(t *testing.T) {
	l := newSlab(t)
	setActs(t, l.tool, map[string][]act{"archive-get 000000010000000000000009": {{Exit: 1}},
		"*": {{Write: map[string]string{"$DEST": "x"}}}})
	l.start()
	for _, n := range []struct {
		name string
		none bool
	}{{"000000010000000000000005", false}, {"000000010000000000000009", true}, {"00000002.history", false},
		{"000000020000000000000004", false}, {"000000010000000000000003", false}} {
		l.ask(n.name)
		l.answered(n.name, n.none)
		l.take(n.name)
	}
	r, _ := l.stop()
	if r.LastSegment != "000000010000000000000005" || r.Served != 4 || r.Last != "000000010000000000000003" {
		t.Errorf("result %+v", r)
	}
	l.stop()
	// None answered with a file: "".
	l2 := newSlab(t)
	setActs(t, l2.tool, map[string][]act{"*": {{Exit: 1}}})
	l2.start()
	l2.ask(seg1)
	l2.answered(seg1, true)
	if r, _ := l2.stop(); r.LastSegment != "" {
		t.Errorf("last_segment %q with no file answered", r.LastSegment)
	}
}

// A name of a timeline not admitted is "not in the archive", answered without
// the tool: the repository is never asked for it.
func TestServe_UnadmittedTimelineAnsweredNone(t *testing.T) {
	l := newSlab(t)
	l.input.Timelines = []uint32{1}
	l.start()
	for _, n := range []string{"000000020000000000000001", "00000002.history"} {
		l.ask(n)
		l.answered(n, true)
	}
	l.ask(seg1) // control: an admitted one asks the tool
	l.answered(seg1, false)
	r, _ := l.stop()
	if g := l.gets(); !slices.Equal(g, []string{seg1}) {
		t.Errorf("the tool ran for %q", g)
	}
	if !slices.Equal(r.None, []string{"000000020000000000000001", "00000002.history"}) {
		t.Errorf("none %q", r.None)
	}
	l.stop()
	// An empty list admits none.
	l2 := newSlab(t)
	l2.input.Timelines = []uint32{}
	l2.start()
	l2.ask(seg1)
	l2.answered(seg1, true)
	if g := l2.gets(); len(g) != 0 {
		t.Errorf("empty list: the tool ran for %q", g)
	}
}

// out/ replaced by a link before the job starts: the link is removed, not
// followed, and a directory made in its place takes the answers.
func TestServe_OutDirIsLinkNotFollowedAndReplaced(t *testing.T) {
	l := newSlab(t)
	elsewhere := t.TempDir()
	os.Remove(l.out)
	os.Symlink(elsewhere, l.out)
	l.start()
	l.ask(seg1)
	l.answered(seg1, false)
	if fi, err := os.Lstat(l.out); err != nil || !fi.IsDir() {
		t.Errorf("out/ is not a directory: %v %v", fi, err)
	}
	if es := mustDir(t, elsewhere); len(es) != 0 {
		t.Errorf("written through the link: %v", es)
	}
}

func TestServe_ReqDirIsFileReplaced(t *testing.T) {
	l := newSlab(t)
	os.Remove(l.req)
	os.WriteFile(l.req, []byte("not a directory"), 0o600)
	l.start()
	l.await("req/ made again", func() bool { fi, err := os.Lstat(l.req); return err == nil && fi.IsDir() })
	l.ask(seg1)
	l.answered(seg1, false)
	l.stop()
	// Neither can be replaced: the job ends with code rspool.
	l2 := newSlab(t)
	os.Remove(l2.req)
	os.WriteFile(l2.req, nil, 0o600)
	os.Chmod(l2.rspool, 0o500)
	t.Cleanup(func() { os.Chmod(l2.rspool, 0o700) })
	if os.Getuid() == 0 {
		t.Skip("as root the directory's mode does not stop the replacement")
	}
	if _, err := Serve(context.Background(), l2.input, l2.rspool); failCode(err) != serveRspool {
		t.Errorf("Serve = %v, want %s", err, serveRspool)
	}
}

// Once the job holds req/ and out/, a swap of the names — links in their
// place pointing elsewhere — redirects nothing: requests are still read from,
// and answers written to, the directories it opened.
func TestServe_DirSwappedWhileServingRedirectsNothing(t *testing.T) {
	l := newSlab(t)
	l.start()
	l.ask(seg1)
	l.answered(seg1, false)
	decoyReq, decoyOut := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(decoyReq, "000000010000000000000007"), nil, 0o600)
	oldReq, oldOut := l.req+".held", l.out+".held"
	if err := os.Rename(l.req, oldReq); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(l.out, oldOut); err != nil {
		t.Fatal(err)
	}
	os.Symlink(decoyReq, l.req)
	os.Symlink(decoyOut, l.out)
	os.WriteFile(filepath.Join(oldReq, seg2), nil, 0o600)
	l.await("the answer in the held out/", func() bool { return exists(filepath.Join(oldOut, seg2)) })
	l.stop()
	if es := mustDir(t, decoyOut); len(es) != 0 {
		t.Errorf("an answer went through the swapped out/: %v", es)
	}
	if slices.Contains(l.gets(), "000000010000000000000007") || !exists(filepath.Join(decoyReq, "000000010000000000000007")) {
		t.Error("a request was read through the swapped req/")
	}
}

// A flood of requests planted before the recovery cannot hold back the
// server's own: each pass answers the most recently made first.
func TestServe_FloodDoesNotStarveANewRequest(t *testing.T) {
	l := newSlab(t)
	for i := range 2000 {
		l.ask(fmt.Sprintf("00000001000000AA%08X", i))
		if i%2 == 0 {
			l.ask(fmt.Sprintf("--junk-%d", i))
		}
	}
	l.start()
	l.ask(seg1)
	l.answered(seg1, false)
	if n := len(l.gets()); n > 3*servePerPass {
		t.Errorf("%d answers before the new request's", n)
	}
}

// What a stopped job left in out/ — its temporaries — is removed at the
// start, by name, without following.
func TestServe_OldTemporariesRemovedAtStart(t *testing.T) {
	l := newSlab(t)
	target := filepath.Join(t.TempDir(), "t")
	os.WriteFile(target, []byte("keep"), 0o600)
	os.WriteFile(filepath.Join(l.out, ".tmp-"+seg1+"-0123456789abcdef"), []byte("half"), 0o600)
	os.Symlink(target, filepath.Join(l.out, ".tmp-"+seg2+"-0123456789abcdef"))
	os.WriteFile(filepath.Join(l.out, "000000010000000000000003"), []byte("an answer"), 0o600)
	l.start()
	l.await("the temporaries removed", func() bool { return len(l.outNames()) == 1 })
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Error("the link's target was changed")
	}
}

// max_answers above the platform's cap is the cap.
func TestServe_MaxAnswersAboveTheCap(t *testing.T) {
	l := newSlab(t)
	l.input.MaxAnswers = 100
	l.start()
	for range bklimit.ServeMaxAnswers {
		l.ask(seg1)
		l.answered(seg1, false)
		l.take(seg1)
	}
	l.ask(seg1)
	l.await("the request past the cap removed", func() bool { return !exists(filepath.Join(l.req, seg1)) })
	if n := len(l.gets()); n != bklimit.ServeMaxAnswers {
		t.Errorf("%d answers, want %d", n, bklimit.ServeMaxAnswers)
	}
}

// A tool that fails but leaves a file behind is not an answer.
func TestServe_FailedToolsFileIsNoAnswer(t *testing.T) {
	l := newSlab(t)
	setActs(t, l.tool, map[string][]act{"*": {{Exit: 3, Write: map[string]string{"$DEST": "partial"}}, {Write: map[string]string{"$DEST": "whole"}}}})
	l.start()
	l.ask(seg1)
	if got := l.answered(seg1, false); got != "whole" {
		t.Errorf("answer %q", got)
	}
}

// An answer larger than a segment can be is never handed over: the request
// is removed and counted refused.
func TestServe_OversizeAnswerRefused(t *testing.T) {
	l := newSlab(t)
	setActs(t, l.tool, map[string][]act{"archive-get " + seg1: {{Write: map[string]string{"$DEST": ""}, DestSize: bklimit.SegmentMax + 1}},
		"archive-get 00000001.history": {{Write: map[string]string{"$DEST": ""}, DestSize: bklimit.SmallMax + 1}}})
	l.start()
	l.ask(seg1)
	l.ask("00000001.history")
	l.await("the requests removed", func() bool {
		return !exists(filepath.Join(l.req, seg1)) && !exists(filepath.Join(l.req, "00000001.history"))
	})
	r, _ := l.stop()
	if len(l.outNames()) != 0 || r.Refused != 2 || r.Served != 0 {
		t.Errorf("out/ %q, result %+v", l.outNames(), r)
	}
}

// none keeps the last 64 names.
func TestServe_NoneKeepsTheLast64(t *testing.T) {
	l := newSlab(t)
	l.input.Timelines = []uint32{}
	l.start()
	for i := range 70 {
		n := fmt.Sprintf("0000000100000000%08X", i)
		l.ask(n)
	}
	l.await("70 answers", func() bool { return len(l.outNames()) == 70 })
	r, _ := l.stop()
	if len(r.None) != 64 {
		t.Errorf("none holds %d names, want 64", len(r.None))
	}
}

// A stopped job leaves the listing between batches: a planted backlog cannot
// hold it past the stop's grace. Control: a live listing reads every batch.
func TestServe_ListStopsBetweenBatches(t *testing.T) {
	old := serveBatch
	serveBatch = 10
	t.Cleanup(func() { serveBatch = old })
	for _, live := range []bool{false, true} {
		l := newSlab(t)
		for i := range 100 {
			l.ask(fmt.Sprintf("junk-%d", i))
		}
		fd, err := syscall.Open(l.req, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			t.Fatal(err)
		}
		s := &server{in: l.input, req: fd, out: -1, answers: map[string]int{}, max: 8}
		ctx, cancel := context.WithCancel(context.Background())
		if !live {
			cancel()
		}
		if _, err := s.list(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
		syscall.Close(fd)
		want := 10
		if live {
			want = 100
		}
		if s.res.Refused != want {
			t.Errorf("live %v: %d entries read, want %d", live, s.res.Refused, want)
		}
	}
}
