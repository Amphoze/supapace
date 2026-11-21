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
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
)

// The acting fake tool: this test binary run as "pgbackrest-act" through a
// link. It records each call (its arguments and environment) in calls, and
// acts as acts.json says for its key — "archive-get <name>" or the
// subcommand, else "*" — taking the n-th act of the key's list on its n-th
// call (the last one from then on): files written (path "$DEST" is the last
// argument, other paths are below PGBACKREST_PG1_PATH), a file printed to
// stdout, a hang until killed, a kill of itself, an exit status.
func init() {
	if filepath.Base(os.Args[0]) != "pgbackrest-act" {
		return
	}
	dir := filepath.Dir(os.Args[0])
	args := os.Args[1:]
	key := "*"
	if len(args) > 0 {
		key = args[0]
	}
	if key == "archive-get" && len(args) > 1 {
		key += " " + args[1]
	}
	var acts map[string][]act
	if b, err := os.ReadFile(filepath.Join(dir, "acts.json")); err == nil {
		json.Unmarshal(b, &acts)
	}
	n := 0
	for _, c := range actCalls(dir) {
		if c.Key == key {
			n++
		}
	}
	b, _ := json.Marshal(actCall{Key: key, Args: args, Env: os.Environ()})
	f, err := os.OpenFile(filepath.Join(dir, "calls"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		os.Exit(99)
	}
	f.Write(append(b, '\n'))
	f.Close()
	list, ok := acts[key]
	if !ok {
		list = acts["*"]
	}
	var a act
	if len(list) > 0 {
		a = list[min(n, len(list)-1)]
	}
	for p, data := range a.Write {
		if p == "$DEST" {
			p = args[len(args)-1]
		} else {
			p = filepath.Join(os.Getenv("PGBACKREST_PG1_PATH"), p)
		}
		os.WriteFile(p, []byte(data), 0o600)
	}
	for _, p := range a.Mkdir {
		os.Mkdir(filepath.Join(os.Getenv("PGBACKREST_PG1_PATH"), p), 0o700)
	}
	if a.DestSize > 0 {
		os.Truncate(args[len(args)-1], a.DestSize)
	}
	if a.OutFile != "" {
		b, _ := os.ReadFile(a.OutFile)
		os.Stdout.Write(b)
	}
	os.Stdout.WriteString(a.Out)
	os.Stderr.WriteString(a.Err)
	if a.Hang {
		time.Sleep(time.Hour)
	}
	if a.Kill {
		syscall.Kill(os.Getpid(), syscall.SIGKILL)
	}
	os.Exit(a.Exit)
}

type act struct {
	Exit     int
	Out, Err string
	OutFile  string
	Write    map[string]string
	DestSize int64
	Mkdir    []string // directories made below PGBACKREST_PG1_PATH
	Hang     bool
	Kill     bool
}

type actCall struct {
	Key  string
	Args []string
	Env  []string
}

func actCalls(dir string) []actCall {
	b, _ := os.ReadFile(filepath.Join(dir, "calls"))
	var out []actCall
	for _, l := range strings.Split(string(b), "\n") {
		var c actCall
		if json.Unmarshal([]byte(l), &c) == nil {
			out = append(out, c)
		}
	}
	return out
}

// actTool puts the acting fake in place of the tool and returns its directory.
func actTool(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(exe, filepath.Join(dir, "pgbackrest-act")); err != nil {
		t.Fatal(err)
	}
	old := Tool
	Tool = filepath.Join(dir, "pgbackrest-act")
	t.Cleanup(func() { Tool = old })
	return dir
}

func setActs(t *testing.T, dir string, acts map[string][]act) {
	t.Helper()
	b, _ := json.Marshal(acts)
	if err := os.WriteFile(filepath.Join(dir, "acts.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

const (
	testSet  = "20261118-104332F"
	testPass = "lab-passphrase-0123456789abcdef"
	testSub  = "set-key-fedcba9876543210" // the set's own key, inside its manifest
)

// rlab is one restore job's world: an empty data directory and the fake.
type rlab struct {
	t          *testing.T
	data, tool string
}

func newRlab(t *testing.T) *rlab {
	t.Helper()
	l := &rlab{t: t, data: t.TempDir(), tool: actTool(t)}
	old := restoreData
	restoreData = l.data
	t.Cleanup(func() { restoreData = old })
	t.Setenv("PGBACKREST_PG1_PATH", l.data)
	t.Setenv("PGBACKREST_STANZA", "ref-1")
	t.Setenv(PassName, testPass)
	return l
}

// manifestText is a set's manifest as the tool prints it, with extra lines
// added to their sections ("section\tline").
func manifestText(extra ...string) string {
	sec := map[string][]string{
		"backrest":            {`backrest-format=5`, `backrest-version="2.58.0"`},
		"backup":              {`backup-label="` + testSet + `"`},
		"backup:target":       {`pg_data={"path":"/var/lib/postgresql/data","type":"path"}`},
		"cipher":              {`cipher-pass="` + testSub + `"`},
		"db":                  {`postgres={"db-id":5,"db-last-system-id":16383}`},
		"target:file":         {`pg_data/PG_VERSION={"checksum":"aa","size":3,"timestamp":1}`, `pg_data/base/1/1259={"size":8192,"timestamp":1}`},
		"target:file:default": {`group="postgres"`, `mode="0600"`, `user="postgres"`},
		"target:path":         {`pg_data={}`, `pg_data/base={}`, `pg_data/base/1={}`, `pg_data/pg_tblspc={}`},
	}
	order := []string{"backrest", "backup", "backup:target", "cipher", "db", "target:file", "target:file:default", "target:link", "target:path"}
	for _, e := range extra {
		s, l, _ := strings.Cut(e, "\t")
		sec[s] = append(sec[s], l)
	}
	var b strings.Builder
	for _, s := range order {
		if len(sec[s]) == 0 {
			continue
		}
		fmt.Fprintf(&b, "[%s]\n%s\n\n", s, strings.Join(sec[s], "\n"))
	}
	return b.String()
}

// acts sets the repo-get answer (the manifest, printed from a file) and the
// restore's act.
func (l *rlab) acts(manifest string, restore act) {
	l.t.Helper()
	p := filepath.Join(l.tool, "manifest")
	if err := os.WriteFile(p, []byte(manifest), 0o600); err != nil {
		l.t.Fatal(err)
	}
	setActs(l.t, l.tool, map[string][]act{"repo-get": {{OutFile: p}}, "restore": {restore}})
}

func (l *rlab) input(mode string, tl int) jobio.Input {
	return jobio.Input{Job: 9, Kind: "restore", Subject: "ref", Stanza: "ref-1", UID: os.Getuid(),
		Timelines: []uint32{1}, Set: testSet, Mode: mode, TargetTimeline: tl}
}

func (l *rlab) files() []string {
	l.t.Helper()
	es, err := os.ReadDir(l.data)
	if err != nil {
		l.t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func (l *rlab) keys() []string {
	var out []string
	for _, c := range actCalls(l.tool) {
		out = append(out, c.Key)
	}
	return out
}

// The manifest is read before anything is written: a tablespace entry,
// wherever the manifest names it, stops the job with nothing written and no
// restore run. Control: the same manifest without it restores.
func TestRestore_ManifestTablespaceRefusedBeforeAnyWrite(t *testing.T) {
	for name, extra := range map[string][]string{
		"target": {"backup:target\t" + `pg_tblspc/16667={"path":"/var/run/postgresql/x3ts","tablespace-id":"16667","tablespace-name":"x3ts","type":"link"}`,
			"target:file\t" + `pg_data/pg_tblspc/16667/PG_17_202406281/5/16668={"size":8192,"timestamp":1}`},
		"file only": {"target:file\t" + `pg_data/pg_tblspc/16667/PG_17_202406281/5/16668={"size":8192,"timestamp":1}`},
		"path only": {"target:path\t" + `pg_data/pg_tblspc/16667={}`},
	} {
		t.Run(name, func(t *testing.T) {
			l := newRlab(t)
			l.acts(manifestText(extra...), act{Write: map[string]string{"PG_VERSION": "17"}})
			_, err := Restore(context.Background(), l.input("none", 0))
			if failCode(err) != restoreTablespace {
				t.Fatalf("Restore = %v, want code %s", err, restoreTablespace)
			}
			if got := l.keys(); !slices.Equal(got, []string{"repo-get"}) {
				t.Errorf("tool calls %q: the restore must not run", got)
			}
			if f := l.files(); len(f) != 0 {
				t.Errorf("the data directory holds %q", f)
			}
		})
	}
	l := newRlab(t)
	l.acts(manifestText(), act{Write: map[string]string{"PG_VERSION": "17"}})
	if _, err := Restore(context.Background(), l.input("none", 0)); err != nil {
		t.Fatalf("control: %v", err)
	}
	if got := l.keys(); !slices.Equal(got, []string{"repo-get", "restore"}) {
		t.Errorf("control: tool calls %q", got)
	}
}

// Any link the manifest records — in [backup:target] or as a [target:link]
// entry — is refused like a tablespace, before anything is written.
func TestRestore_ManifestLinkRefused(t *testing.T) {
	for name, extra := range map[string][]string{
		"target":       {"backup:target\t" + `pg_data/pg_wal={"path":"/var/run/postgresql/wal","type":"link"}`},
		"target:link":  {"target:link\t" + `pg_data/x={"destination":"/etc"}`},
		"pg_data link": {"backup:target\t" + `pg_data/base={"path":"/tmp","type":"link"}`},
	} {
		t.Run(name, func(t *testing.T) {
			l := newRlab(t)
			l.acts(manifestText(extra...), act{Write: map[string]string{"PG_VERSION": "17"}})
			_, err := Restore(context.Background(), l.input("none", 0))
			if failCode(err) != restoreTablespace {
				t.Fatalf("Restore = %v, want code %s", err, restoreTablespace)
			}
			if got := l.keys(); !slices.Equal(got, []string{"repo-get"}) || len(l.files()) != 0 {
				t.Errorf("tool calls %q, data %q: nothing may run or be written", got, l.files())
			}
		})
	}
	// The data directory's own entry as a link.
	l := newRlab(t)
	m := strings.Replace(manifestText(), `"type":"path"}`, `"type":"link"}`, 1)
	l.acts(m, act{})
	if _, err := Restore(context.Background(), l.input("none", 0)); failCode(err) != restoreTablespace {
		t.Errorf("pg_data as a link: %v", err)
	}
}

func TestRestore_ModeNoneWritesRecoverySignal(t *testing.T) {
	l := newRlab(t)
	l.acts(manifestText(), act{Write: map[string]string{"PG_VERSION": "17", "postgresql.auto.conf": "work_mem = '7MB'\n"}})
	r, err := Restore(context.Background(), l.input("none", 0))
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Mode != "none" {
		t.Errorf("result %+v", r)
	}
	if got := l.files(); !slices.Equal(got, []string{"PG_VERSION", "postgresql.auto.conf", "recovery.signal"}) {
		t.Errorf("data %q, want the restored files and recovery.signal", got)
	}
	if fi, err := os.Lstat(filepath.Join(l.data, "recovery.signal")); err != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
		t.Errorf("recovery.signal: %v %v", fi, err)
	}
	cs := actCalls(l.tool)
	if want := []string{"restore", "--set=" + testSet, "--type=none"}; !slices.Equal(cs[1].Args, want) {
		t.Errorf("argv %q, want %q", cs[1].Args, want)
	}
}

func TestRestore_ModeStandbySwapsSignal(t *testing.T) {
	l := newRlab(t)
	l.acts(manifestText(), act{Write: map[string]string{"PG_VERSION": "17", "standby.signal": ""}})
	r, err := Restore(context.Background(), l.input("standby", 1))
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode != "standby" {
		t.Errorf("mode %q", r.Mode)
	}
	if got := l.files(); !slices.Equal(got, []string{"PG_VERSION", "recovery.signal"}) {
		t.Errorf("data %q: standby.signal must give way to recovery.signal", got)
	}
	cs := actCalls(l.tool)
	if want := []string{"restore", "--set=" + testSet, "--type=standby", "--target-timeline=1"}; !slices.Equal(cs[1].Args, want) {
		t.Errorf("argv %q, want %q", cs[1].Args, want)
	}
	// The tool wrote no standby.signal: the job fails, nothing signals recovery.
	l2 := newRlab(t)
	l2.acts(manifestText(), act{Write: map[string]string{"PG_VERSION": "17"}})
	if _, err := Restore(context.Background(), l2.input("standby", 3)); failCode(err) != restoreTool {
		t.Errorf("no standby.signal: %v", err)
	}
	if slices.Contains(l2.files(), "recovery.signal") {
		t.Errorf("recovery.signal without a standby restore's signal")
	}
}

func TestRestore_Exit58IsHistoryMismatch(t *testing.T) {
	l := newRlab(t)
	l.acts(manifestText(), act{Exit: 58, Out: "ERROR: [058]: target timeline 2 forked from backup timeline 1 at 0/5000318 which is before backup lsn of 0/6000028\n"})
	_, err := Restore(context.Background(), l.input("none", 0))
	if failCode(err) != restoreHistory || !strings.Contains(err.Error(), "[058]") {
		t.Fatalf("Restore = %v, want %s with the tool's line", err, restoreHistory)
	}
	if slices.Contains(l.files(), "recovery.signal") {
		t.Errorf("recovery.signal after a failed restore")
	}
	// Control: another failure is pgbackrest.
	l.acts(manifestText(), act{Exit: 40, Out: "ERROR: [040]: something\n"})
	if _, err := Restore(context.Background(), l.input("none", 0)); failCode(err) != restoreTool {
		t.Errorf("exit 40: %v", err)
	}
}

// The tool killed by a signal (pgBackRest 2.58 can crash on a set whose files
// are partial) and its 75 are set_invalid; nothing signals recovery.
func TestRestore_SignalIsSetInvalid(t *testing.T) {
	for name, a := range map[string]act{"signal": {Write: map[string]string{"PG_VERSION": "17"}, Kill: true}, "exit 75": {Exit: 75, Out: "ERROR: [075]: x\n"}} {
		t.Run(name, func(t *testing.T) {
			l := newRlab(t)
			l.acts(manifestText(), a)
			_, err := Restore(context.Background(), l.input("none", 0))
			if failCode(err) != restoreSetInvalid {
				t.Fatalf("Restore = %v, want %s", err, restoreSetInvalid)
			}
			if slices.Contains(l.files(), "recovery.signal") {
				t.Errorf("recovery.signal after a failed restore")
			}
		})
	}
}

// The set is on every restore's command line; an input without a set label
// (or with another argument's shape) runs nothing.
func TestRestore_SetAlwaysPassed(t *testing.T) {
	for _, c := range []struct {
		mode string
		tl   int
	}{{"none", 0}, {"standby", 2}} {
		l := newRlab(t)
		l.acts(manifestText(), act{Write: map[string]string{"standby.signal": ""}})
		if _, err := Restore(context.Background(), l.input(c.mode, c.tl)); err != nil {
			t.Fatalf("%s: %v", c.mode, err)
		}
		args := actCalls(l.tool)[1].Args
		n := 0
		for _, a := range args {
			if strings.HasPrefix(a, "--set=") {
				n++
			}
		}
		if n != 1 || args[1] != "--set="+testSet {
			t.Errorf("%s: argv %q", c.mode, args)
		}
	}
	for _, in := range []jobio.Input{
		{Stanza: "ref-1", Set: "", Mode: "none"},
		{Stanza: "ref-1", Set: "--type=standby", Mode: "none"},
		{Stanza: "ref-1", Set: "latest", Mode: "none"},
		{Stanza: "ref-1", Set: testSet + "/../x", Mode: "none"},
		{Stanza: "ref-1", Set: testSet, Mode: "standby"},                     // no target timeline
		{Stanza: "ref-1", Set: testSet, Mode: "none", TargetTimeline: 2},     // none takes none
		{Stanza: "ref-1", Set: testSet, Mode: "immediate"},                   // another type
		{Stanza: "../x", Set: testSet, Mode: "none"},                         // a stanza that is no name
		{Stanza: "ref-1", Set: testSet, Mode: "standby", TargetTimeline: -1}, // not a timeline
	} {
		l := newRlab(t)
		l.acts(manifestText(), act{})
		if _, err := Restore(context.Background(), in); err == nil || len(l.keys()) != 0 {
			t.Errorf("input %+v: %v, calls %q", in, err, l.keys())
		}
	}
}

// The manifest comes from the tool's repo-get with the set's path relative to
// the repository and nothing else on the command line — never --raw — in the
// job's own environment. A repo-get that fails (a wrong passphrase) is
// set_invalid with nothing written.
func TestManifest_RepoGetFormAndItsEnvironment(t *testing.T) {
	l := newRlab(t)
	l.acts(manifestText(), act{})
	if _, err := Restore(context.Background(), l.input("none", 0)); err != nil {
		t.Fatal(err)
	}
	c := actCalls(l.tool)[0]
	if want := []string{"repo-get", "backup/ref-1/" + testSet + "/backup.manifest"}; !slices.Equal(c.Args, want) {
		t.Errorf("argv %q, want %q", c.Args, want)
	}
	for _, kv := range []string{PassName + "=" + testPass, "PGBACKREST_STANZA=ref-1", "PGBACKREST_PG1_PATH=" + l.data} {
		if !slices.Contains(c.Env, kv) {
			t.Errorf("the tool's environment lacks %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
	// A wrong passphrase: the tool's error, on its console.
	l2 := newRlab(t)
	setActs(t, l2.tool, map[string][]act{"repo-get": {{Exit: 55, Out: "ERROR: [055]: unable to load info file '/repo/backup/ref-1/backup.info' … has a stanza-create been performed?\n"}},
		"restore": {{Write: map[string]string{"PG_VERSION": "17"}}}})
	_, err := Restore(context.Background(), l2.input("none", 0))
	if failCode(err) != restoreSetInvalid || !strings.Contains(err.Error(), "[055]") {
		t.Fatalf("wrong passphrase: %v, want %s with the tool's line", err, restoreSetInvalid)
	}
	if got := l2.keys(); !slices.Equal(got, []string{"repo-get"}) || len(l2.files()) != 0 {
		t.Errorf("calls %q, data %q", got, l2.files())
	}
	// Killed by a signal.
	l3 := newRlab(t)
	setActs(t, l3.tool, map[string][]act{"repo-get": {{Kill: true}}})
	if _, err := Restore(context.Background(), l3.input("none", 0)); failCode(err) != restoreSetInvalid {
		t.Errorf("repo-get killed: %v", err)
	}
}

// Every path the manifest names is checked before anything is written; a
// manifest that is malformed or too large is refused the same way.
func TestManifest_PlantedPathsRefused(t *testing.T) {
	bad := map[string][]string{
		"absolute":         {"target:file\t" + `/etc/passwd={"size":1}`},
		"dot-dot":          {"target:file\t" + `pg_data/../../etc/passwd={"size":1}`},
		"dot":              {"target:file\t" + `pg_data/./x={"size":1}`},
		"empty part":       {"target:path\t" + `pg_data//x={}`},
		"outside pg_data":  {"target:file\t" + `pg_datax/y={"size":1}`},
		"another root":     {"target:file\t" + `pg_wal/y={"size":1}`},
		"space":            {"target:file\t" + `pg_data/a b={"size":1}`},
		"too long":         {"target:file\t" + `pg_data/` + strings.Repeat("a", 513) + `={"size":1}`},
		"pg_data as file":  {"target:file\t" + `pg_data={"size":1}`},
		"no key=value":     {"target:file\t" + `pg_data/x`},
		"value not object": {"target:file\t" + `pg_data/x=1`},
		"second target":    {"backup:target\t" + `pg_data2={"path":"/x","type":"path"}`},
		"two types":        {"backup:target\t" + `pg_x={"type":"path","type":"path"}`},
		"case-folded type": {"backup:target\t" + `pg_data/x={"Type":"path","type":"x"}`},
		"a set file name":  {"target:file\t" + `backup.manifest={"size":1}`},
	}
	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			l := newRlab(t)
			l.acts(manifestText(extra...), act{Write: map[string]string{"PG_VERSION": "17"}})
			_, err := Restore(context.Background(), l.input("none", 0))
			if c := failCode(err); c != restoreSetInvalid && c != restoreTablespace {
				t.Fatalf("Restore = %v, want a refusal", err)
			}
			if got := l.keys(); !slices.Equal(got, []string{"repo-get"}) || len(l.files()) != 0 {
				t.Errorf("calls %q, data %q", got, l.files())
			}
		})
	}
	// No data directory entry at all.
	l := newRlab(t)
	l.acts(strings.Replace(manifestText(), `pg_data={"path":"/var/lib/postgresql/data","type":"path"}`, "", 1), act{})
	if _, err := Restore(context.Background(), l.input("none", 0)); failCode(err) != restoreSetInvalid {
		t.Errorf("no target: %v", err)
	}
}

func TestManifest_Bounds(t *testing.T) {
	// A line above the line bound.
	l := newRlab(t)
	old := manifestLineMax
	manifestLineMax = 1 << 10
	t.Cleanup(func() { manifestLineMax = old })
	l.acts(manifestText("target:file\t"+`pg_data/x={"size":1,"checksum-page-error":[`+strings.Repeat("1,", 600)+`1]}`), act{})
	if _, err := Restore(context.Background(), l.input("none", 0)); failCode(err) != restoreSetInvalid || len(l.keys()) != 1 {
		t.Errorf("a long line: %v, calls %q", err, l.keys())
	}
	manifestLineMax = old
	// A manifest above the byte bound, and its control just under it.
	m := manifestText()
	oldMax := manifestMax
	t.Cleanup(func() { manifestMax = oldMax })
	manifestMax = int64(len(m)) - 1
	l2 := newRlab(t)
	l2.acts(m, act{})
	if _, err := Restore(context.Background(), l2.input("none", 0)); failCode(err) != restoreSetInvalid || len(l2.keys()) != 1 {
		t.Errorf("too large: %v, calls %q", err, l2.keys())
	}
	manifestMax = int64(len(m))
	l3 := newRlab(t)
	l3.acts(m, act{})
	if _, err := Restore(context.Background(), l3.input("none", 0)); err != nil {
		t.Errorf("control at the bound: %v", err)
	}
}

// Neither the passphrase nor the set's own key reaches a failure's message,
// whatever the tool prints and wherever the manifest is refused.
func TestRestore_PassphraseInNoMessage(t *testing.T) {
	cases := map[string]func(l *rlab){
		"restore output": func(l *rlab) {
			l.acts(manifestText(), act{Exit: 58, Out: "ERROR: [058]: " + testPass + " " + testSub + "\n"})
		},
		"repo-get output": func(l *rlab) {
			setActs(t, l.tool, map[string][]act{"repo-get": {{Exit: 41, Out: "ERROR: [041]: pass " + testPass + "\n", Err: testPass}}})
		},
		"refused key": func(l *rlab) {
			l.acts(manifestText("target:file\t"+`pg_data/`+testPass+`!={"size":1}`, "target:link\t"+testSub+`={}`), act{})
		},
		"tablespace key": func(l *rlab) {
			l.acts(manifestText("target:link\tpg_data/"+testPass+`={}`), act{})
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			l := newRlab(t)
			set(l)
			_, err := Restore(context.Background(), l.input("none", 0))
			if err == nil {
				t.Fatal("no failure")
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("not a job failure: %v", err)
			}
			line, merr := jobio.MarshalResult(jobio.Failure{Code: e.Code, Message: e.Message})
			if merr != nil {
				t.Fatal(merr)
			}
			if strings.Contains(string(line), testPass) || strings.Contains(string(line), testSub) {
				t.Errorf("the failure carries a secret: %s", line)
			}
		})
	}
}

// A data directory that is not empty — a failed restore's leftovers — is
// refused before the tool runs, so a restore starts only on a wiped directory.
func TestRestore_NotEmptyRefusedBeforeTheTool(t *testing.T) {
	l := newRlab(t)
	l.acts(manifestText(), act{Write: map[string]string{"PG_VERSION": "17"}, Kill: true})
	if _, err := Restore(context.Background(), l.input("none", 0)); failCode(err) != restoreSetInvalid {
		t.Fatalf("first run: %v", err)
	}
	if _, err := Restore(context.Background(), l.input("none", 0)); failCode(err) != restoreTool || len(l.keys()) != 2 {
		t.Errorf("a run over the leftovers: %v, calls %q", err, l.keys())
	}
	// Control: once the directory is wiped, it restores.
	os.Remove(filepath.Join(l.data, "PG_VERSION"))
	l.acts(manifestText(), act{Write: map[string]string{"PG_VERSION": "17"}})
	if _, err := Restore(context.Background(), l.input("none", 0)); err != nil {
		t.Errorf("after the wipe: %v", err)
	}
}

// A job stopped (SIGTERM: its context ends) while the tool runs ends with a
// failure, never a result, and writes no recovery signal.
func TestRestore_StoppedWhileTheToolRuns(t *testing.T) {
	l := newRlab(t)
	l.acts(manifestText(), act{Write: map[string]string{"PG_VERSION": "17"}, Hang: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := Restore(ctx, l.input("none", 0)); done <- err }()
	deadline := time.Now().Add(20 * time.Second)
	for !slices.Contains(l.keys(), "restore") {
		if time.Now().After(deadline) {
			t.Fatal("the restore never ran")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stopped restore succeeded")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the restore did not end on its stop")
	}
	if slices.Contains(l.files(), "recovery.signal") {
		t.Error("recovery.signal after a stop")
	}
}

// A set key cut by the message's bound leaves none of itself behind.
func TestRestore_HideCutKey(t *testing.T) {
	msg := strings.Repeat("x", 250) + testSub // cut at 256: the key's first 6 bytes stay
	err := hide(fail(restoreTool, "%s", msg), testSub)
	var e *Error
	if !errors.As(err, &e) || strings.Contains(e.Message, testSub[:6]) || e.Message != strings.Repeat("x", 250) {
		t.Errorf("message %q", e.Message)
	}
	if err := hide(fail(restoreTool, "plain"), testSub); err.(*Error).Message != "plain" {
		t.Errorf("a message without the key changed: %v", err)
	}
}

// The codes each of the three programs can end with: the one list the
// recorder takes.
func TestRestoreServeSeed_CodesAreTheirKinds(t *testing.T) {
	for kind, want := range map[string][]string{
		"restore": {"tablespace", "history_mismatch", "set_invalid", "pgbackrest"},
		"serve":   {"rspool"},
		"seed":    {"seed"},
	} {
		if got, ok := Codes(kind); !ok || !slices.Equal(got, want) {
			t.Errorf("Codes(%s) = %v, %v; want %v", kind, got, ok, want)
		}
	}
}

// The rules of [backup:target] each hold alone: an entry under pg_tblspc is a
// tablespace whatever its type, and the data directory's entry carries one
// "type" member (a second one, which a decoder keeping the last would read as
// "path", is refused).
func TestManifest_TargetRules(t *testing.T) {
	for name, c := range map[string]struct {
		line, code string
	}{
		"tablespace of type path": {`pg_tblspc/16667={"path":"/x","type":"path"}`, restoreTablespace},
		"two types on pg_data":    {`pg_data={"type":"link","type":"path"}`, restoreSetInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			l := newRlab(t)
			m := strings.Replace(manifestText(), `pg_data={"path":"/var/lib/postgresql/data","type":"path"}`, c.line, 1)
			if c.code == restoreTablespace {
				m = manifestText("backup:target\t" + c.line)
			}
			l.acts(m, act{})
			if _, err := Restore(context.Background(), l.input("none", 0)); failCode(err) != c.code || len(l.keys()) != 1 {
				t.Errorf("Restore = %v, calls %q; want %s", err, l.keys(), c.code)
			}
		})
	}
}

// A refusal naming a manifest entry never carries the set's own key.
func TestManifest_RefusalHidesTheSetKey(t *testing.T) {
	l := newRlab(t)
	l.acts(manifestText("target:link\tpg_data/"+testSub+`={}`), act{})
	_, err := Restore(context.Background(), l.input("none", 0))
	if failCode(err) != restoreTablespace || strings.Contains(err.Error(), testSub) {
		t.Errorf("Restore = %v", err)
	}
}

// standby.signal that is not a regular file is not made the recovery signal.
func TestRestore_StandbySignalMustBeAFile(t *testing.T) {
	l := newRlab(t)
	l.acts(manifestText(), act{Mkdir: []string{"standby.signal"}})
	if _, err := Restore(context.Background(), l.input("standby", 2)); failCode(err) != restoreTool {
		t.Errorf("Restore = %v", err)
	}
	if slices.Contains(l.files(), "recovery.signal") {
		t.Error("a directory became recovery.signal")
	}
}

// The passphrase is replaced before the message is cut to its bound, so none
// of it is left at the cut.
func TestRestore_PassphraseAtTheCutLeavesNothing(t *testing.T) {
	t.Setenv(PassName, testPass)
	err := failQuiet(restoreTool, "%s%s", strings.Repeat("x", 250), testPass)
	var e *Error
	if !errors.As(err, &e) || strings.Contains(e.Message, testPass[:6]) {
		t.Errorf("message %q", e.Message)
	}
}

// A refusal stops the tool: a repo-get that would go on printing (or hang)
// after the refused entry does not hold the job.
func TestManifest_RefusalStopsTheTool(t *testing.T) {
	l := newRlab(t)
	p := filepath.Join(l.tool, "manifest")
	if err := os.WriteFile(p, []byte(manifestText("target:link\tpg_data/x={}")), 0o600); err != nil {
		t.Fatal(err)
	}
	setActs(t, l.tool, map[string][]act{"repo-get": {{OutFile: p, Hang: true}}})
	done := make(chan error, 1)
	go func() { _, err := Restore(context.Background(), l.input("none", 0)); done <- err }()
	select {
	case err := <-done:
		if failCode(err) != restoreTablespace {
			t.Errorf("Restore = %v, want %s", err, restoreTablespace)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the job waited for the tool after its verdict")
	}
}

// The tool's fallback copy of the manifest, when the repository holds one,
// passes the same rules: a link in it alone refuses the set; a copy with
// another key too. Control: no copy, one read.
func TestManifest_CopyCheckedByTheSameRules(t *testing.T) {
	setRepo := func(t *testing.T, withCopy bool) {
		d := t.TempDir()
		old := repoRoot
		repoRoot = d
		t.Cleanup(func() { repoRoot = old })
		if withCopy {
			p := filepath.Join(d, "backup", "ref-1", testSet)
			os.MkdirAll(p, 0o750)
			os.WriteFile(filepath.Join(p, "backup.manifest.copy"), []byte("encrypted"), 0o640)
		}
	}
	two := func(l *rlab, main, cp string) {
		pm, pc := filepath.Join(l.tool, "m"), filepath.Join(l.tool, "c")
		os.WriteFile(pm, []byte(main), 0o600)
		os.WriteFile(pc, []byte(cp), 0o600)
		setActs(t, l.tool, map[string][]act{"repo-get": {{OutFile: pm}, {OutFile: pc}}, "restore": {{}}})
	}
	for name, c := range map[string]struct {
		copy string
		code string
	}{
		"link in the copy":  {manifestText("target:link\t" + `pg_data/x={"destination":"/etc"}`), restoreTablespace},
		"another key":       {strings.Replace(manifestText(), testSub, "other-key-0123456789", 1), restoreSetInvalid},
		"copy without root": {strings.Replace(manifestText(), `pg_data={"path":"/var/lib/postgresql/data","type":"path"}`, "", 1), restoreSetInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			l := newRlab(t)
			setRepo(t, true)
			two(l, manifestText(), c.copy)
			_, err := Restore(context.Background(), l.input("none", 0))
			if failCode(err) != c.code || !slices.Equal(l.keys(), []string{"repo-get", "repo-get"}) {
				t.Errorf("Restore = %v, calls %q", err, l.keys())
			}
			if strings.Contains(fmt.Sprint(err), testSub) || strings.Contains(fmt.Sprint(err), "other-key") {
				t.Errorf("a key in the message: %v", err)
			}
			cs := actCalls(l.tool)
			if want := "backup/ref-1/" + testSet + "/backup.manifest.copy"; cs[1].Args[1] != want || len(cs[1].Args) != 2 {
				t.Errorf("second read %q", cs[1].Args)
			}
		})
	}
	// Both good: restores, two reads. No copy: one read.
	l := newRlab(t)
	setRepo(t, true)
	two(l, manifestText(), manifestText())
	if _, err := Restore(context.Background(), l.input("none", 0)); err != nil || !slices.Equal(l.keys(), []string{"repo-get", "repo-get", "restore"}) {
		t.Errorf("both good: %v, calls %q", err, l.keys())
	}
	l2 := newRlab(t)
	setRepo(t, false)
	l2.acts(manifestText(), act{})
	if _, err := Restore(context.Background(), l2.input("none", 0)); err != nil || !slices.Equal(l2.keys(), []string{"repo-get", "restore"}) {
		t.Errorf("no copy: %v, calls %q", err, l2.keys())
	}
}
