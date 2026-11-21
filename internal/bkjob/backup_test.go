package bkjob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
)

// The fake tool of these tests: this test binary run as "pgbackrest" from a
// directory holding bscript.json (else the other fake, in run_test.go,
// answers). Every command appends "start <what>" and "end <what>" to events
// beside it. archive-push stands for the real one: it refuses (103) while no
// stanza exists, takes bscript's "archive-push" step when there is one, and
// otherwise keeps a marker in pushed/ for the entry after PushMS; a second
// archive-push while one runs writes "overlap" and fails. Any other command
// takes the step of its name: it puts the files of Put (1 MiB each), waits
// for WaitFor to exist (exit 82 after 60 s), puts Then, prints Out and
// exits with Exit. stanza-create creates the stanza marker.
func init() {
	if filepath.Base(os.Args[0]) != "pgbackrest" {
		return
	}
	dir := filepath.Dir(os.Args[0])
	b, err := os.ReadFile(filepath.Join(dir, "bscript.json"))
	if err != nil {
		return
	}
	var sc map[string]bstep
	json.Unmarshal(b, &sc)
	ev := func(s string) {
		f, _ := os.OpenFile(filepath.Join(dir, "events"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		f.WriteString(s + "\n")
		f.Close()
	}
	args := os.Args[1:]
	if args[0] == "archive-push" {
		name := filepath.Base(args[len(args)-1])
		ev("start " + name)
		os.WriteFile(filepath.Join(dir, "inflight-"+name), nil, 0o600)
		f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			ev("overlap " + name)
			os.Exit(1)
		}
		f.Close()
		if _, err := os.Stat(filepath.Join(dir, "stanza")); err != nil {
			os.Remove(filepath.Join(dir, "lock"))
			fmt.Print("ERROR: [103]: unable to find a valid repository\n")
			os.Exit(103)
		}
		if s, ok := sc["archive-push"]; ok {
			os.Remove(filepath.Join(dir, "lock"))
			fmt.Print(s.Out)
			ev("end " + name)
			os.Exit(s.Exit)
		}
		time.Sleep(time.Duration(sc["push"].PushMS) * time.Millisecond)
		os.WriteFile(filepath.Join(dir, "pushed", name), nil, 0o600)
		os.Remove(filepath.Join(dir, "lock"))
		ev("end " + name)
		os.Exit(0)
	}
	cmd := args[0]
	ev("start " + cmd)
	s := sc[cmd]
	if cmd == "stanza-create" {
		os.WriteFile(filepath.Join(dir, "stanza"), nil, 0o600)
	}
	for _, p := range s.Put {
		putWhole(p)
	}
	if s.WaitFor != "" {
		for end := time.Now().Add(60 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(s.WaitFor); err == nil {
				break
			}
			if time.Now().After(end) {
				ev("end " + cmd)
				fmt.Print("ERROR: [082]: WAL segment was not archived before the 60000ms timeout\n")
				os.Exit(82)
			}
		}
	}
	for _, p := range s.Then {
		putWhole(p)
	}
	fmt.Print(s.Out)
	ev("end " + cmd)
	os.Exit(s.Exit)
}

type bstep struct {
	Exit      int
	Out       string
	Put, Then []string
	WaitFor   string
	PushMS    int
}

// blab is one job's world: data directory, spool, repository, the job's
// private directory and the fake tool.
type blab struct {
	t                            *testing.T
	data, spool, repo, tmp, tool string
	sc                           map[string]bstep
}

func newBlab(t *testing.T) *blab {
	t.Helper()
	d := t.TempDir()
	l := &blab{t: t, data: dataTree(t), spool: filepath.Join(d, "spool"), repo: filepath.Join(d, "repo"),
		tmp: filepath.Join(d, "tmp"), tool: fakeTool(t), sc: map[string]bstep{}}
	for _, p := range []string{l.spool, l.repo, l.tmp, filepath.Join(l.tool, "pushed")} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for v, p := range map[*string]string{&repoRoot: l.repo, &privRoot: l.tmp, &dataRoot: l.data, &spoolRoot: l.spool} {
		old := *v
		*v = p
		t.Cleanup(func() { *v = old })
	}
	oldEvery := pushEvery
	pushEvery = 20 * time.Millisecond
	t.Cleanup(func() { pushEvery = oldEvery })
	l.script()
	return l
}

func (l *blab) script() {
	l.t.Helper()
	b, _ := json.Marshal(l.sc)
	if err := os.WriteFile(filepath.Join(l.tool, "bscript.json"), b, 0o600); err != nil {
		l.t.Fatal(err)
	}
}

func (l *blab) set(cmd string, s bstep) {
	l.sc[cmd] = s
	l.script()
}

func (l *blab) stanza() { os.WriteFile(filepath.Join(l.tool, "stanza"), nil, 0o600) }

func (l *blab) put(name string) {
	l.t.Helper()
	if err := os.WriteFile(filepath.Join(l.spool, name), make([]byte, segmentMin), 0o600); err != nil {
		l.t.Fatal(err)
	}
}

func (l *blab) events() []string {
	b, _ := os.ReadFile(filepath.Join(l.tool, "events"))
	return strings.Fields(strings.ReplaceAll(string(b), " ", "_"))
}

func (l *blab) input(kind string) jobio.Input {
	in := jobio.Input{Job: 9, Kind: kind, Subject: "ref", Stanza: "ref-1", UID: os.Getuid(), Timelines: []uint32{1}}
	if kind == "backup" {
		in.Type = "full"
	}
	return in
}

func index(ev []string, s string) int { return slices.Index(ev, strings.ReplaceAll(s, " ", "_")) }

const (
	segA = "000000010000000000000003"
	segB = "000000010000000000000004"
	segC = "000000010000000000000005"
)

// infoJSON is the tool's info answer for stanza ref-1 with the given sets
// (label, start and stop segment, start and stop position).
func infoJSON(sets ...[5]string) string {
	var bs []string
	for i, s := range sets {
		bs = append(bs, fmt.Sprintf(`{"archive":{"start":%q,"stop":%q},"backrest":{"format":5,"version":"2.58.0"},`+
			`"database":{"id":1,"repo-key":1},"error":false,"info":{"delta":1,"repository":{"delta":1,"size":1},"size":1},`+
			`"label":%q,"lsn":{"start":%q,"stop":%q},"prior":null,"reference":null,`+
			`"timestamp":{"start":%d,"stop":%d},"type":"full"}`, s[1], s[2], s[0], s[3], s[4], 1794999175+100*i, 1794999181+100*i))
	}
	return `[{"archive":[{"database":{"id":1,"repo-key":1},"id":"17-1","max":"000000030000000000000005","min":"000000010000000000000003"}],` +
		`"backup":[` + strings.Join(bs, ",") + `],"cipher":"aes-256-cbc","db":[{"id":1,"repo-key":1,"system-id":7709462742190325781,"version":"17"}],` +
		`"name":"ref-1","repo":[{"cipher":"aes-256-cbc","key":1,"status":{"code":0,"message":"ok"}}],` +
		`"status":{"code":0,"lock":{"backup":{"held":false},"restore":{"held":false}},"message":"ok"}}]` + "\n"
}

var setOld = [5]string{"20261118-105255F", "000000010000000000000004", "000000010000000000000004", "0/4000028", "0/4000120"}
var setNew = [5]string{"20261118-115255F", "00000002000000000000000A", "00000002000000000000000B", "0/A000028", "0/B000120"}

// The B25 race: a push of the loop may still be running when the tool
// exits. The loop is stopped by a flag between passes and waited for; only
// then does the final push start — never two pushes at once, each entry once.
func TestBackup_PushLoopStopsBeforeFinalPush(t *testing.T) {
	l := newBlab(t)
	l.stanza()
	l.put(segA)
	l.set("push", bstep{PushMS: 300})
	// The tool puts B and exits while B's push is running; C arrives after.
	l.set("backup", bstep{Put: []string{filepath.Join(l.spool, segB)}, WaitFor: filepath.Join(l.tool, "inflight-"+segB),
		Then: []string{filepath.Join(l.spool, segC)}})
	l.set("info", bstep{Out: infoJSON(setNew)})

	r, err := Backup(context.Background(), l.input("backup"))
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	ev := l.events()
	if slices.ContainsFunc(ev, func(e string) bool { return strings.HasPrefix(e, "overlap") }) {
		t.Fatalf("two pushes ran at once: %q", ev)
	}
	for _, s := range []string{segA, segB, segC} {
		if n := slices.Index(ev, "start_"+s); n < 0 || slices.Index(ev[n+1:], "start_"+s) >= 0 {
			t.Fatalf("%s not pushed exactly once: %q", s, ev)
		}
	}
	// B's push had started before the tool ended and ended before C's began.
	if !(index(ev, "start "+segB) < index(ev, "end backup") && index(ev, "end "+segB) < index(ev, "start "+segC)) {
		t.Fatalf("order: %q", ev)
	}
	if es, _ := os.ReadDir(l.spool); len(es) != 0 || r.Push == nil || !r.Push.Complete {
		t.Fatalf("spool %d entries left, push %+v", len(es), r.Push)
	}
}

// The set comes from the tool's info answer: the newest label, its timeline,
// segments, positions and times.
func TestBackup_ResultFromInfoJSON(t *testing.T) {
	l := newBlab(t)
	l.stanza()
	l.set("info", bstep{Out: "WARN: a warning before the document\n" + infoJSON(setOld, setNew)})
	r, err := Backup(context.Background(), l.input("backup"))
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	want := jobio.BackupResult{OK: true, Label: setNew[0], Timeline: 2, StartSegment: setNew[1], StopSegment: setNew[2],
		StartLSN: setNew[3], StopLSN: setNew[4], Start: time.Unix(1794999275, 0).UTC(), Stop: time.Unix(1794999281, 0).UTC()}
	r.Push = nil
	if !r.Start.Equal(want.Start) || !r.Stop.Equal(want.Stop) {
		t.Fatalf("times %v %v", r.Start, r.Stop)
	}
	r.Start, r.Stop, want.Start, want.Stop = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	if r != want {
		t.Fatalf("result %+v\nwant   %+v", r, want)
	}
	ev := l.events()
	if index(ev, "end backup") > index(ev, "start info") {
		t.Fatalf("info before the backup ended: %q", ev)
	}
	// The result is a valid backup document for the recorder.
	line, err := jobio.MarshalResult(r)
	if _, f, err2 := jobio.ParseResult("backup", line); err != nil || err2 != nil || f != nil {
		t.Fatalf("result does not parse: %v %v", err, err2)
	}
}

// A label, segment or position of another form in the tool's answer fails
// the job; nothing of it is taken.
func TestBackup_LabelFormRefused(t *testing.T) {
	for name, s := range map[string][5]string{
		"label path":        {"20261118-115255F/../../x", setNew[1], setNew[2], setNew[3], setNew[4]},
		"label control":     {"20261118-115255F\n\x1b[31m", setNew[1], setNew[2], setNew[3], setNew[4]},
		"label incremental": {"20261118-115255F_20261118-125255I", setNew[1], setNew[2], setNew[3], setNew[4]},
		"segment":           {setNew[0], "../00000002000000000000000A", setNew[2], setNew[3], setNew[4]},
		"timeline 0":        {setNew[0], "00000000000000000000000A", "00000000000000000000000B", setNew[3], setNew[4]},
		"two timelines":     {setNew[0], "00000002000000000000000A", "00000003000000000000000B", setNew[3], setNew[4]},
		"position":          {setNew[0], setNew[1], setNew[2], "0/A000028; x", setNew[4]},
	} {
		t.Run(name, func(t *testing.T) {
			l := newBlab(t)
			l.stanza()
			l.set("info", bstep{Out: infoJSON(setOld, s)})
			_, err := Backup(context.Background(), l.input("backup"))
			var e *Error
			if !errors.As(err, &e) || e.Code != CodePgbackrest || strings.ContainsAny(e.Message, "\n\x1b") {
				t.Fatalf("Backup = %v", err)
			}
		})
	}
	// Not one answer: no set, another stanza, not JSON.
	for name, out := range map[string]string{
		"no set":        infoJSON(),
		"other stanza":  strings.Replace(infoJSON(setNew), `"name":"ref-1"`, `"name":"ref-2"`, 1),
		"not json":      "[{",
		"two stanzas":   strings.TrimSuffix(infoJSON(setNew), "]\n") + "," + strings.TrimPrefix(infoJSON(setNew), "["),
		"exit not zero": "",
	} {
		t.Run(name, func(t *testing.T) {
			l := newBlab(t)
			l.stanza()
			st := bstep{Out: out}
			if name == "exit not zero" {
				st = bstep{Exit: 41, Out: "ERROR: [041]: missing\n"}
			}
			l.set("info", st)
			if _, err := Backup(context.Background(), l.input("backup")); failCode(err) != CodePgbackrest {
				t.Fatalf("Backup = %v", err)
			}
		})
	}
}

// A login the server refuses is code login — whatever the exit — and the
// passphrase never reaches the message.
func TestBackup_LoginFailureCode(t *testing.T) {
	const pass = "planted-pass-0123456789"
	t.Setenv(PassName, pass)
	out := "WARN: unable to check pg1: [DbConnectError] unable to connect to 'dbname='postgres' port=5432 user='supapace_backup'" +
		" host='/var/run/postgresql'': connection to server failed: FATAL:  refused " + pass + "\n" +
		"ERROR: [056]: unable to find primary cluster - cannot proceed " + pass + "\n"
	for _, kind := range []string{"backup", "check", "stanza-create"} {
		l := newBlab(t)
		l.stanza()
		l.set(kind, bstep{Exit: 56, Out: out})
		err := runKind(kind, l.input(kind))
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeLogin || strings.Contains(e.Message, pass) || strings.Contains(e.Error(), pass) {
			t.Fatalf("%s: %v", kind, err)
		}
		if !strings.Contains(e.Message, "[056]") {
			t.Errorf("%s: the message does not name the tool's error: %q", kind, e.Message)
		}
		// Control: the same exit without a connection error is the tool's failure.
		l.set(kind, bstep{Exit: 56, Out: "ERROR: [056]: unable to find primary cluster - cannot proceed\n"})
		if got := failCode(runKind(kind, l.input(kind))); got != CodePgbackrest {
			t.Errorf("%s control: %s", kind, got)
		}
	}
}

// Exit 82 is the archive timeout; a failing push of the loop is named in
// the message, never passed through as the push's own code.
func TestBackup_Exit82IsArchiveTimeout(t *testing.T) {
	for _, kind := range []string{"backup", "check"} {
		l := newBlab(t)
		l.stanza()
		l.put(segA)
		l.set("archive-push", bstep{Exit: 104, Out: "ERROR: [104]: repo1: [FileWriteError] [122] Disk quota exceeded\n"})
		// The tool gives up once the loop has tried the push.
		l.set(kind, bstep{Exit: 82, Out: "ERROR: [082]: WAL segment " + segA + " was not archived before the 60000ms timeout\n",
			WaitFor: filepath.Join(l.tool, "inflight-"+segA)})
		err := runKind(kind, l.input(kind))
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeArchiveTimeout || !strings.Contains(e.Message, CodeRepositoryQuota) {
			t.Fatalf("%s: %v", kind, err)
		}
		if codes, _ := Codes(kind); !slices.Contains(codes, e.Code) {
			t.Fatalf("%s: code %s not among its kind's", kind, e.Code)
		}
	}
}

// A failure of the final push is the kind's own code, the push's code in
// the message.
func TestBackup_FinalPushFailureIsTheKindsCode(t *testing.T) {
	for _, kind := range []string{"backup", "check", "stanza-create"} {
		l := newBlab(t)
		l.stanza()
		l.put(segA)
		l.set("archive-push", bstep{Exit: 104, Out: "ERROR: [104]: repo1: [FileWriteError] [122] Disk quota exceeded\n"})
		err := runKind(kind, l.input(kind))
		var e *Error
		if !errors.As(err, &e) || e.Code != CodePgbackrest || !strings.Contains(e.Message, CodeRepositoryQuota) {
			t.Fatalf("%s: %v", kind, err)
		}
	}
}

// check passes only once the WAL it waits for has been pushed while it ran.
func TestCheck_PushesWhileWaiting(t *testing.T) {
	l := newBlab(t)
	l.stanza()
	l.set("check", bstep{Put: []string{filepath.Join(l.spool, segA)}, WaitFor: filepath.Join(l.tool, "pushed", segA)})
	r, err := Check(context.Background(), l.input("check"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	ev := l.events()
	if n := index(ev, "start "+segA); n < 0 || n > index(ev, "end check") || r.Push == nil || !r.OK {
		t.Fatalf("events %q, result %+v", ev, r)
	}
}

// stanza-create runs again on an existing stanza without harm, and no push
// runs before the stanza exists: the loop is not started for it.
func TestStanzaCreate_Idempotent(t *testing.T) {
	l := newBlab(t)
	l.put(segA)
	for i := range 2 {
		r, err := StanzaCreate(context.Background(), l.input("stanza-create"))
		if err != nil || !r.OK || r.Push == nil {
			t.Fatalf("run %d: %+v, %v", i, r, err)
		}
	}
	ev := l.events()
	if index(ev, "start "+segA) < index(ev, "end stanza-create") || strings.Count(strings.Join(ev, " "), "start_stanza-create") != 2 {
		t.Fatalf("events %q", ev)
	}
	if strings.Count(strings.Join(ev, " "), "start_"+segA) != 1 {
		t.Fatalf("the entry was not pushed once: %q", ev)
	}
}

// Every refusal of the tree pre-check comes before the tool runs, for each
// of the three kinds.
func TestPrecheckRunsBeforeTheTool(t *testing.T) {
	for _, kind := range []string{"backup", "check", "stanza-create"} {
		l := newBlab(t)
		l.stanza()
		os.Symlink("/etc/passwd", filepath.Join(l.data, "base", "x"))
		if got := failCode(runKind(kind, l.input(kind))); got != CodeSymlink || len(l.events()) != 0 {
			t.Fatalf("%s: %s, events %q", kind, got, l.events())
		}
	}
}

// The three kinds list exactly their codes.
func TestCodes_TheThreeKinds(t *testing.T) {
	want := []string{CodeLogin, CodeArchiveTimeout, CodePgbackrest, CodeTablespace, CodeSymlink}
	for _, kind := range []string{"stanza-create", "backup", "check"} {
		got, ok := Codes(kind)
		if !ok || !slices.Equal(got, want) {
			t.Errorf("%s: %v %v", kind, got, ok)
		}
	}
}

func runKind(kind string, in jobio.Input) error {
	var err error
	switch kind {
	case "backup":
		_, err = Backup(context.Background(), in)
	case "check":
		_, err = Check(context.Background(), in)
	case "stanza-create":
		_, err = StanzaCreate(context.Background(), in)
	}
	return err
}

// An entry a pass of the loop set aside is listed in the job's result, so
// that the record sees it although the final pass did not meet it.
func TestCheck_LoopQuarantinesAreListed(t *testing.T) {
	l := newBlab(t)
	l.stanza()
	other := "000000090000000000000001" // a timeline not admitted
	l.put(other)
	l.set("check", bstep{Put: []string{filepath.Join(l.spool, segA)}, WaitFor: filepath.Join(l.tool, "pushed", segA)})
	r, err := Check(context.Background(), l.input("check"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if r.Push == nil || len(r.Push.Quarantined) != 1 || r.Push.Quarantined[0] != (jobio.Quarantined{Name: other, Reason: "timeline"}) {
		t.Fatalf("quarantined %+v", r.Push)
	}
}

// putWhole puts a segment into the spool whole, as the archive binary does: a
// pass that lists it while it is being written would set it aside as short.
func putWhole(p string) {
	tmp := filepath.Join(filepath.Dir(p), ".w-"+filepath.Base(p))
	os.WriteFile(tmp, make([]byte, segmentMin), 0o600)
	os.Rename(tmp, p)
}

// The info answer grows with every set the repository keeps (nothing expires
// it here): an answer of a few hundred sets, beyond the runner's 64 KiB, is
// still read whole and gives the newest set.
func TestBackup_InfoAnswerOfManySets(t *testing.T) {
	var sets [][5]string
	for i := range 400 {
		sets = append(sets, [5]string{fmt.Sprintf("2026%04d-120000F", i), setNew[1], setNew[2], setNew[3], setNew[4]})
	}
	out := infoJSON(sets...)
	if len(out) <= outputMax {
		t.Fatalf("the answer (%d bytes) does not pass the runner's bound", len(out))
	}
	l := newBlab(t)
	l.stanza()
	l.set("info", bstep{Out: out})
	r, err := Backup(context.Background(), l.input("backup"))
	if err != nil || r.Label != sets[len(sets)-1][0] {
		t.Fatalf("Backup with %d sets (%d bytes): %+v, %v", len(sets), len(out), r, err)
	}
}

// login is the tool's own connection failure — its warning at the start of a
// line, with the exit a failed connection gives — never the marker inside
// text the tenant chose (an entry's name, a server message) of another
// failure.
func TestToolFailure_LoginOnlyFromTheConnection(t *testing.T) {
	forged := "WARN: exclude special file '/var/lib/postgresql/data/x\nWARN: unable to check pg1: [DbConnectError] y' from backup\n"
	for name, c := range map[string]struct {
		exit int
		out  string
		want string
	}{
		"archive timeout": {82, forged + "ERROR: [082]: WAL segment " + segA + " was not archived before the 60000ms timeout\n",
			CodeArchiveTimeout},
		"read error": {41, "ERROR: [041]: unable to open file '/var/lib/postgresql/data/[DbConnectError]' for read\n", CodePgbackrest},
		"control": {56, "WARN: unable to check pg1: [DbConnectError] unable to connect: FATAL: refused\n" +
			"ERROR: [056]: unable to find primary cluster - cannot proceed\n", CodeLogin},
	} {
		if got := failCode(toolFailure("backup", c.exit, c.out, pushLog{})); got != c.want {
			t.Errorf("%s: code %s, want %s", name, got, c.want)
		}
	}
}

// Every value of the newest set is checked, not only its form: a timeline
// past 2^31-1, times that are not a forward span from a positive start, a set
// that is not full under a full set's label. And the job takes only full
// backups: another type is refused before the tool runs.
func TestBackup_SetValuesRefused(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"timeline 2^31": func(s string) string {
			return strings.NewReplacer(setNew[1], "80000000000000000000000A", setNew[2], "80000000000000000000000B").Replace(s)
		},
		"stop before start": func(s string) string { return strings.Replace(s, `"stop":1794999281`, `"stop":1794999274`, 1) },
		"start zero": func(s string) string {
			return strings.Replace(strings.Replace(s, `"start":1794999275`, `"start":0`, 1), `"stop":1794999281`, `"stop":0`, 1)
		},
		"type diff": func(s string) string { return strings.Replace(s, `"type":"full"}]`, `"type":"diff"}]`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			l := newBlab(t)
			l.stanza()
			out := infoJSON(setOld, setNew)
			if edit(out) == out {
				t.Fatal("the edit changed nothing")
			}
			l.set("info", bstep{Out: edit(out)})
			if _, err := Backup(context.Background(), l.input("backup")); failCode(err) != CodePgbackrest {
				t.Fatalf("Backup = %v", err)
			}
		})
	}
	l := newBlab(t)
	l.stanza()
	in := l.input("backup")
	in.Type = "incr"
	if _, err := Backup(context.Background(), in); failCode(err) != CodePgbackrest || len(l.events()) != 0 {
		t.Fatalf("type incr: %v, events %q", err, l.events())
	}
}

// Above the info bound the job says the repository holds too many sets for
// this version — not that the tool failed.
func TestBackup_InfoAboveItsBound(t *testing.T) {
	l := newBlab(t)
	l.stanza()
	l.set("info", bstep{Out: strings.Repeat("x", infoMax+1)})
	_, err := Backup(context.Background(), l.input("backup"))
	if failCode(err) != CodePgbackrest || !strings.Contains(err.Error(), "too many sets for this version") {
		t.Fatalf("Backup = %v", err)
	}
}

// When the job fails after a loop pass set entries aside, the failure says how
// many: the failure document cannot list them.
func TestBackup_FailureCountsLoopQuarantines(t *testing.T) {
	for _, exit := range []int{41, 82} {
		l := newBlab(t)
		l.stanza()
		l.put("000000090000000000000001") // a timeline not admitted
		l.put(segA)
		l.set("check", bstep{Exit: exit, Out: "ERROR: [041]: failed\n", WaitFor: filepath.Join(l.tool, "pushed", segA)})
		_, err := Check(context.Background(), l.input("check"))
		if err == nil || !strings.HasPrefix(err.(*Error).Message, "1 entries set aside by the push meanwhile, unlisted; ") ||
			strings.Contains(err.Error(), "000000090000000000000001") {
			t.Fatalf("exit %d: %v", exit, err)
		}
	}
	// Control: nothing set aside, no count.
	l := newBlab(t)
	l.stanza()
	l.set("check", bstep{Exit: 41, Out: "ERROR: [041]: failed\n"})
	if _, err := Check(context.Background(), l.input("check")); err == nil || strings.Contains(err.Error(), "set aside") {
		t.Fatalf("control: %v", err)
	}
}
