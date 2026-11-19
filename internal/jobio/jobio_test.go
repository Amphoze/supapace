package jobio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
)

const ref = "abcdefghij0123456789"

func inputs() map[string]Input {
	tl := []uint32{1, 2}
	base := func(kind string) Input {
		return Input{Job: 7, Kind: kind, Subject: ref, Stanza: ref + "-1", UID: 700001, Timelines: tl}
	}
	m := map[string]Input{}
	for _, k := range []string{"stanza-create", "check", "seed"} {
		m[k] = base(k)
	}
	in := base("push")
	in.MaxEntries = 56
	m["push"] = in
	in = base("backup")
	in.Type = "full"
	m["backup"] = in
	in = base("restore")
	in.Set, in.Mode, in.TargetTimeline = "20261119-101500F", "standby", 3
	m["restore"] = in
	in = base("serve")
	in.MaxAnswers = 8
	m["serve"] = in
	in = base("replicate")
	in.Repl = &ReplInput{Mode: "copy", MaxFiles: 2048, MaxEntries: 250000, MaxBytes: 1280 << 20, BudgetBytes: 0, BudgetObjects: -1,
		InfoSHA256: map[string]string{"archive.info": strings.Repeat("a", 64)}}
	m["replicate"] = in
	in = base("replicate")
	in.Repl = &ReplInput{Mode: "rebuild", KeyMarker: "archive/x", VersionMarker: "v1", PageRows: 4000}
	m["replicate-rebuild"] = in
	in = base("fetch")
	in.MaxBytes = 8192 << 20
	m["fetch"] = in
	in = Input{Job: 9, Kind: "fetch", Subject: "cp", Stanza: "cp-7", UID: 70, MaxBytes: 1 << 30, ListCurrent: true}
	m["fetch-cp"] = in
	in = Input{Job: 0, Kind: "probe", Subject: "probe-projects", Repl: &ReplInput{Mode: "probe"}}
	m["probe"] = in
	return m
}

func TestInput_StrictRoundTrip(t *testing.T) {
	for name, in := range inputs() {
		b, err := MarshalInput(in)
		if err != nil {
			t.Fatalf("%s: MarshalInput: %v", name, err)
		}
		got, err := ParseInput(b)
		if err != nil {
			t.Fatalf("%s: ParseInput(%s): %v", name, b, err)
		}
		if !reflect.DeepEqual(got, in) {
			t.Errorf("%s: round trip\n got %+v\nwant %+v", name, got, in)
		}
	}
	// Members of other kinds are omitted when zero; zero budgets are not (0 means none left).
	b, _ := MarshalInput(inputs()["check"])
	if want := `{"job":7,"kind":"check","subject":"` + ref + `","stanza":"` + ref + `-1","uid":700001,"timelines":[1,2]}`; string(b) != want {
		t.Errorf("check input = %s\nwant %s", b, want)
	}
	b, _ = MarshalInput(inputs()["replicate"])
	if !bytes.Contains(b, []byte(`"budget_bytes":0,"budget_objects":-1`)) {
		t.Errorf("copy input lost its zero budget: %s", b)
	}

	good := `{"job":1,"kind":"push","subject":"` + ref + `","stanza":"s","uid":1,"timelines":[1],"max_entries":56}`
	if _, err := ParseInput([]byte(good)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, doc := range map[string]string{
		"unknown member":         strings.Replace(good, `"max_entries"`, `"surprise":1,"max_entries"`, 1),
		"unknown repl member":    `{"job":1,"kind":"replicate","subject":"cp","stanza":"s","uid":1,"timelines":null,"repl":{"mode":"copy","x":1}}`,
		"trailing data":          good + `{}`,
		"trailing garbage":       good + ` x`,
		"unknown kind":           strings.Replace(good, `"push"`, `"expire"`, 1),
		"recover is no job kind": strings.Replace(good, `"push"`, `"recover"`, 1),
		"not an object":          `[]`,
		"empty":                  ``,
		"negative timeline":      strings.Replace(good, `[1]`, `[-1]`, 1),
		// A project's timelines may never be null or missing: nil admits every timeline.
		"project timelines null":    strings.Replace(good, `[1]`, `null`, 1),
		"project timelines missing": strings.Replace(good, `,"timelines":[1]`, ``, 1),
	} {
		if _, err := ParseInput([]byte(doc)); err == nil {
			t.Errorf("%s: ParseInput accepted %s", name, doc)
		}
	}
	// An empty list stays an empty list (admits none), never nil.
	in, err := ParseInput([]byte(strings.Replace(good, `[1]`, `[]`, 1)))
	if err != nil || in.Timelines == nil || len(in.Timelines) != 0 {
		t.Errorf("empty timelines: %#v, %v", in.Timelines, err)
	}
	// The control plane passes null: every timeline.
	in, err = ParseInput([]byte(strings.Replace(strings.Replace(good, `[1]`, `null`, 1), ref, "cp", 1)))
	if err != nil || in.Timelines != nil {
		t.Errorf("control plane timelines: %#v, %v", in.Timelines, err)
	}
	// Marshal refuses what Parse would refuse.
	bad := inputs()["push"]
	bad.Timelines = nil
	if _, err := MarshalInput(bad); err == nil {
		t.Error("MarshalInput accepted a project input without timelines")
	}
	bad = inputs()["push"]
	bad.Kind = "nope"
	if _, err := MarshalInput(bad); err == nil {
		t.Error("MarshalInput accepted an unknown kind")
	}
}

func TestResult_OneLineAtMostOneMiB(t *testing.T) {
	if resultMax != bklimit.ResultMax {
		t.Fatalf("resultMax %d differs from bklimit.ResultMax %d", resultMax, bklimit.ResultMax)
	}
	r := ServeResult{OK: true, Served: 2, None: []string{"line\none", "x"}, Last: "a\r\nb"}
	b, err := MarshalResult(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(b, []byte("\n")) != 1 || b[len(b)-1] != '\n' || bytes.ContainsRune(b, '\r') {
		t.Fatalf("not one terminated line: %q", b)
	}
	v, fail, err := ParseResult("serve", b)
	if err != nil || fail != nil || !reflect.DeepEqual(v, r) {
		t.Fatalf("round trip = %+v, %v, %v", v, fail, err)
	}
	// The bound: the line without its newline is at most ResultMax.
	fit := SeedResult{OK: true}
	empty, _ := MarshalResult(fit)
	pad := ServeResult{OK: true, Last: strings.Repeat("x", resultMax-len(`{"ok":true,"served":0,"none":null,"refused":0,"last":"","last_none":false,"last_segment":""}`))}
	b, err = MarshalResult(pad)
	if err != nil || len(b) != resultMax+1 {
		t.Fatalf("line of exactly ResultMax: len %d, %v (empty seed %q)", len(b), err, empty)
	}
	pad.Last += "x"
	if _, err := MarshalResult(pad); err == nil {
		t.Fatal("MarshalResult accepted a line above ResultMax")
	}
	// A valid document padded with white space past the bound, and one spread over two lines.
	seed := []byte(`{"ok":true,"files":1,"bytes":1}`)
	if _, _, err := ParseResult("seed", seed); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, _, err := ParseResult("seed", append(append([]byte{}, seed...), bytes.Repeat([]byte{' '}, resultMax)...)); err == nil {
		t.Fatal("ParseResult accepted a line above ResultMax")
	}
	if _, _, err := ParseResult("seed", []byte("{\"ok\":true,\n\"files\":1,\"bytes\":1}\n")); err == nil {
		t.Fatal("ParseResult accepted a document over two lines")
	}
}

func TestParseResult_PerKind_AndFailure(t *testing.T) {
	at := time.Date(2026, 11, 19, 10, 15, 0, 123456000, time.UTC)
	push := PushResult{OK: true, Complete: true, Pushed: 3, First: "000000010000000000000001", Last: "000000010000000000000003",
		Newest: map[string]string{"00000001": "000000010000000000000003"}, Quarantined: []Quarantined{{Name: "x.history", Reason: "shape"}},
		SpoolEntries: 0, SpoolOldest: &at, Histories: []string{"00000002.history"}}
	row := Row{Key: "archive/s/00000001.history", Size: 40, SHA256: strings.Repeat("b", 64), Ino: 12, CtimeNS: 99, VersionID: "v", At: at}
	cases := []struct {
		kind string
		v    any
	}{
		{"push", push},
		{"stanza-create", CheckJobResult{OK: true, Push: &push}},
		{"check", CheckJobResult{OK: true, Push: &push}},
		{"backup", BackupResult{OK: true, Label: "20261119-101500F", Timeline: 2, Start: at, Stop: at, StartSegment: "a", StopSegment: "b",
			StartLSN: "0/3000028", StopLSN: "0/3000100", Push: &push}},
		{"restore", RestoreResult{OK: true, Mode: "none"}},
		{"serve", ServeResult{OK: true, Served: 4, None: []string{"00000002.history"}, Refused: 1, Last: "x", LastNone: true, LastSegment: "000000010000000000000004"}},
		{"seed", SeedResult{OK: true, Files: 3, Bytes: 4096}},
		{"replicate", ReplResult{OK: true, Mode: "copy", Complete: true, Uploaded: []Row{row}, Adopted: []Row{row},
			Info: []InfoVersion{{Name: "archive.info", VersionID: "v", SHA256: "c", At: at}}, SetsComplete: []string{"20261119-101500F"},
			Bytes: 40, Objects: 1, Walked: 9, Held: 1, Notices: []Notice{{Code: "unlisted-entry", Count: 2, Detail: "d"}}}},
		{"replicate", ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", Rows: []Row{{Key: "k", Size: 1, VersionID: "v", At: at}},
			NextKeyMarker: "k", NextVersionMarker: "v"}},
		{"probe", ReplResult{OK: true, Mode: "probe", ProbeRows: []ProbeRow{{Name: "write-cannot-delete", OK: true, Detail: "denied"}}}},
		{"fetch", FetchResult{OK: true, Files: 2, Bytes: 10, NewestSegment: "000000010000000000000004", NewestSet: "20261119-101500F"}},
	}
	for _, c := range cases {
		b, err := MarshalResult(c.v)
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		v, fail, err := ParseResult(c.kind, b)
		if err != nil || fail != nil {
			t.Fatalf("%s: ParseResult(%s) = %v, %v", c.kind, b, fail, err)
		}
		if !reflect.DeepEqual(v, c.v) {
			t.Errorf("%s: round trip\n got %+v\nwant %+v", c.kind, v, c.v)
		}
		// A document of the right shape with an unknown member is refused.
		if _, _, err := ParseResult(c.kind, bytes.Replace(b, []byte(`{"ok":true`), []byte(`{"ok":true,"surprise":1`), 1)); err == nil {
			t.Errorf("%s: unknown member accepted", c.kind)
		}
	}
	// Probe rows and rebuild rows share the member name; each mode reads its own shape.
	if _, _, err := ParseResult("replicate", []byte(`{"ok":true,"mode":"rebuild","rows":[{"name":"x","ok":true,"detail":""}]}`)); err == nil {
		t.Error("probe rows accepted as rebuild rows")
	}
	if _, _, err := ParseResult("probe", []byte(`{"ok":true,"mode":"probe","rows":[{"key":"k","size":1}]}`)); err == nil {
		t.Error("rebuild rows accepted as probe rows")
	}
	// A replicate job copies or rebuilds; only a probe job probes.
	for _, c := range [][2]string{{"replicate", "probe"}, {"replicate", "fetch"}, {"replicate", ""}, {"probe", "copy"}, {"probe", "rebuild"}} {
		if _, _, err := ParseResult(c[0], []byte(`{"ok":true,"mode":"`+c[1]+`"}`)); err == nil {
			t.Errorf("mode %q accepted in a %s result", c[1], c[0])
		}
	}
	// The plan's histories are the runner's, never the fetch job's.
	if _, _, err := ParseResult("fetch", []byte(`{"ok":true,"files":1,"bytes":1,"histories":["00000009.history"]}`)); err == nil {
		t.Error("a fetch job's own histories accepted")
	}

	// Failure documents.
	f, _ := MarshalResult(Failure{Code: "repository_quota", Message: "quota exceeded"})
	if string(f) != `{"ok":false,"code":"repository_quota","message":"quota exceeded"}`+"\n" {
		t.Errorf("failure line = %s", f)
	}
	for _, kind := range []string{"push", "fetch", "probe"} {
		v, fail, err := ParseResult(kind, f)
		if err != nil || v != nil || fail == nil || *fail != (Failure{Code: "repository_quota", Message: "quota exceeded"}) {
			t.Errorf("%s: failure = %v, %+v, %v", kind, v, fail, err)
		}
	}
	for name, doc := range map[string]string{
		"no ok":            `{"pushed":1}`,
		"ok null":          `{"ok":null}`,
		"ok string":        `{"ok":"true"}`,
		"failure no code":  `{"ok":false,"message":"m"}`,
		"failure bad code": `{"ok":false,"code":"Bad Code","message":"m"}`,
		"failure extra":    `{"ok":false,"code":"x","message":"m","detail":1}`,
		"message too long": `{"ok":false,"code":"x","message":"` + strings.Repeat("m", 257) + `"}`,
		"two documents":    `{"ok":true}{"ok":true}`,
		"two lines":        "{\"ok\":true}\n{\"ok\":true}\n",
		"not json":         `ok`,
		"empty":            ``,
	} {
		if _, _, err := ParseResult("seed", []byte(doc)); err == nil {
			t.Errorf("%s: accepted %q", name, doc)
		}
	}
	if _, _, err := ParseResult("recover", []byte(`{"ok":true}`)); err == nil {
		t.Error("unknown result kind accepted")
	}
	if _, _, err := ParseResult("seed", []byte(`{"ok":false,"code":"x","message":"`+strings.Repeat("m", 256)+`"}`)); err != nil {
		t.Errorf("control: a 256-byte message: %v", err)
	}
}

func TestIndexRow_RoundTrip_MalformedRefused(t *testing.T) {
	rows := []IndexRow{
		{Key: "archive/s-1/archive.info", Size: 370, Ino: 131, CtimeNS: 1763547300123456789, SHA256: strings.Repeat("0f", 32)},
		{Key: "backup/s-1/20261119-101500F/pg_data/base/1/2.zst", Size: 0, Ino: 1, CtimeNS: 0},
	}
	var file []byte
	for _, r := range rows {
		var err error
		if file, err = AppendIndexRow(file, r); err != nil {
			t.Fatal(err)
		}
	}
	want := "archive/s-1/archive.info\t370\t131\t1763547300123456789\t" + strings.Repeat("0f", 32) + "\n" +
		"backup/s-1/20261119-101500F/pg_data/base/1/2.zst\t0\t1\t0\t-\n"
	if string(file) != want {
		t.Fatalf("index file\n%q\nwant\n%q", file, want)
	}
	for i, line := range bytes.SplitAfter(file, []byte("\n"))[:2] {
		got, err := ParseIndexRow(line)
		if err != nil || got != rows[i] {
			t.Errorf("line %d: %+v, %v", i, got, err)
		}
	}
	good := "k\t1\t2\t3\t-\n"
	if _, err := ParseIndexRow([]byte(good)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, line := range []string{
		"", "\n", "k\t1\t2\t3\n", "k\t1\t2\t3\t-\tx\n", "\t1\t2\t3\t-\n",
		"k\t-1\t2\t3\t-\n", "k\t+1\t2\t3\t-\n", "k\t1 \t2\t3\t-\n", "k\t\t2\t3\t-\n", "k\t1\t2\t99999999999999999999\t-\n",
		"k\t1\t2\t3\t" + strings.Repeat("A", 64) + "\n", "k\t1\t2\t3\t" + strings.Repeat("a", 63) + "\n", "k\t1\t2\t3\t\n",
		"k\r\t1\t2\t3\t-\n", "k\x00\t1\t2\t3\t-\n", "k\t1\t2\t3\t-\n\n", "k\t1\t2\t3\t-\r\n",
	} {
		if r, err := ParseIndexRow([]byte(line)); err == nil {
			t.Errorf("ParseIndexRow(%q) = %+v, nil", line, r)
		}
	}
}

func TestPlan_RoundTrip_MalformedRefused(t *testing.T) {
	rows := []PlanRow{
		{Key: "archive/s-1/archive.info", VersionID: "3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY", SHA256: strings.Repeat("ab", 32), Size: 370},
		{Key: "archive/s-1/00000002.history", Size: 41},
	}
	var buf bytes.Buffer
	if err := WritePlan(&buf, rows); err != nil {
		t.Fatal(err)
	}
	want := "archive/s-1/archive.info\t3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY\t" + strings.Repeat("ab", 32) + "\t370\n" +
		"archive/s-1/00000002.history\t-\t-\t41\n"
	if buf.String() != want {
		t.Fatalf("plan\n%q\nwant\n%q", buf.String(), want)
	}
	var got []PlanRow
	if err := ReadPlan(bytes.NewReader(buf.Bytes()), func(r PlanRow) error { got = append(got, r); return nil }); err != nil || !reflect.DeepEqual(got, rows) {
		t.Fatalf("ReadPlan = %+v, %v", got, err)
	}
	stop := errors.New("stop")
	if err := ReadPlan(bytes.NewReader(buf.Bytes()), func(PlanRow) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("the callback's error is not returned: %v", err)
	}
	if err := ReadPlan(strings.NewReader(""), func(PlanRow) error { return nil }); err != nil {
		t.Errorf("empty plan: %v", err)
	}
	for _, plan := range []string{
		"k\t-\t-\t1", // no terminating newline: a cut file
		"k\t-\t-\n", "k\t-\t-\t1\tx\n", "\t-\t-\t1\n", "k\t\t-\t1\n", "k\t-\t-\t-1\n", "k\t-\t-\tx\n",
		"k\t-\t" + strings.Repeat("g", 64) + "\t1\n", "k\x01\t-\t-\t1\n", "k\t-\t-\t1\r\n",
		strings.Repeat("k", 5000) + "\t-\t-\t1\n", // longer than any key
		"k\t-\t-\t1\n\n",
	} {
		n := 0
		if err := ReadPlan(strings.NewReader(plan), func(PlanRow) error { n++; return nil }); err == nil {
			t.Errorf("ReadPlan(%.40q) accepted", plan)
		}
	}
	for _, r := range []PlanRow{{Key: ""}, {Key: "a\tb"}, {Key: "a\nb"}, {Key: "k", VersionID: "-"}, {Key: "k", VersionID: "a\tb"},
		{Key: "k", SHA256: "xyz"}, {Key: "k", Size: -1}} {
		if err := WritePlan(&bytes.Buffer{}, []PlanRow{r}); err == nil {
			t.Errorf("WritePlan(%+v) accepted", r)
		}
	}
}

func TestJobio_ImportsOnlyStdlib(t *testing.T) {
	out, err := exec.Command("go", "list", "-buildvcs=false", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	if got := strings.Fields(string(out)); len(got) != 1 || got[0] != "github.com/Amphoze/supapace/internal/jobio" {
		t.Fatalf("non-standard dependencies %v, want only the package itself", got)
	}
}

// The counts a job promises are bounds here, where its line becomes a value
// the daemon keeps. Each bound has its control at the bound itself.
func TestParseResult_CountBounds(t *testing.T) {
	if pushMaxEntries != bklimit.PushMaxEntries || rebuildPageRows != bklimit.RebuildPageRows {
		t.Fatal("a count bound differs from its bklimit constant")
	}
	quarantined := func(n int) []Quarantined {
		q := make([]Quarantined, n)
		for i := range q {
			q[i] = Quarantined{Name: "x", Reason: "shape"}
		}
		return q
	}
	newest := func(n int) map[string]string {
		m := map[string]string{}
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("%08X", i+1)] = "000000010000000000000001"
		}
		return m
	}
	names := func(n int) []string { return make([]string, n) }
	rows := func(n int) []Row {
		r := make([]Row, n)
		for i := range r {
			r[i] = Row{Key: "k", VersionID: "v"}
		}
		return r
	}
	for _, c := range []struct {
		name     string
		kind     string
		at, over any
	}{
		{"quarantined", "push", PushResult{OK: true, Quarantined: quarantined(56)}, PushResult{OK: true, Quarantined: quarantined(57)}},
		{"newest", "push", PushResult{OK: true, Newest: newest(64)}, PushResult{OK: true, Newest: newest(65)}},
		{"check's push", "check", CheckJobResult{OK: true, Push: &PushResult{OK: true, Quarantined: quarantined(56)}},
			CheckJobResult{OK: true, Push: &PushResult{OK: true, Quarantined: quarantined(57)}}},
		{"backup's push", "backup", BackupResult{OK: true, Push: &PushResult{OK: true, Newest: newest(64)}},
			BackupResult{OK: true, Push: &PushResult{OK: true, Newest: newest(65)}}},
		{"none", "serve", ServeResult{OK: true, None: names(64)}, ServeResult{OK: true, None: names(65)}},
		{"rows", "replicate", ReplResult{OK: true, Mode: "rebuild", Rows: rows(4000)}, ReplResult{OK: true, Mode: "rebuild", Rows: rows(4001)}},
	} {
		at, err := MarshalResult(c.at)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ParseResult(c.kind, at); err != nil {
			t.Errorf("%s at its bound: %v", c.name, err)
		}
		over, _ := MarshalResult(c.over)
		if _, _, err := ParseResult(c.kind, over); err == nil {
			t.Errorf("%s above its bound accepted", c.name)
		}
	}
}

// Every row list of a replication result is checked, not only uploaded.
func TestParseResult_EveryRowListChecked(t *testing.T) {
	good := `{"key":"k","size":1,"version_id":"v","at":"2026-11-19T10:15:00Z"}`
	bad := `{"key":"k\tx","size":1,"version_id":"v","at":"2026-11-19T10:15:00Z"}`
	for _, doc := range []string{`{"ok":true,"mode":"copy","adopted":[%s]}`, `{"ok":true,"mode":"rebuild","rows":[%s]}`} {
		if _, _, err := ParseResult("replicate", []byte(fmt.Sprintf(doc, good))); err != nil {
			t.Errorf("control %s: %v", doc, err)
		}
		if _, _, err := ParseResult("replicate", []byte(fmt.Sprintf(doc, bad))); err == nil {
			t.Errorf("%s: a row with a tab in its key accepted", doc)
		}
	}
}

// A copy reports uploaded and adopted rows, never "rows".
func TestParseResult_CopyHasNoRows(t *testing.T) {
	row := `{"key":"k","size":1,"version_id":"v","at":"2026-11-19T10:15:00Z"}`
	if _, _, err := ParseResult("replicate", []byte(`{"ok":true,"mode":"rebuild","rows":[`+row+`]}`)); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, _, err := ParseResult("replicate", []byte(`{"ok":true,"mode":"copy","rows":[`+row+`]}`)); err == nil {
		t.Error("a copy result with rows accepted")
	}
}

// The recover document is the runner's own: written with MarshalResult, never
// parsed from a job.
func TestRecoverResult_Shape(t *testing.T) {
	b, err := MarshalResult(RecoverResult{OK: true, Promoted: true})
	if err != nil || string(b) != `{"ok":true,"promoted":true,"serve":null}`+"\n" {
		t.Errorf("recover line %q, %v", b, err)
	}
	b, _ = MarshalResult(RecoverResult{OK: true, Promoted: true, Serve: &ServeResult{OK: true, LastSegment: "000000010000000000000004"}})
	if !bytes.Contains(b, []byte(`"serve":{"ok":true,`)) || !bytes.Contains(b, []byte(`"last_segment":"000000010000000000000004"`)) {
		t.Errorf("recover line %s", b)
	}
	if _, _, err := ParseResult("recover", b); err == nil {
		t.Error("ParseResult took kind recover")
	}
	if b, _ := MarshalResult(RecoverResult{OK: true}); string(b) != `{"ok":true,"promoted":false,"serve":null}`+"\n" {
		t.Errorf("a recovery that did not promote: %q", b)
	}
}

// An index row that would not read back is not written.
func TestAppendIndexRow_RefusesWhatCannotReadBack(t *testing.T) {
	good := IndexRow{Key: "k", Size: 1, Ino: 2, CtimeNS: 3}
	if got, err := AppendIndexRow([]byte("x"), good); err != nil || string(got) != "xk\t1\t2\t3\t-\n" {
		t.Fatalf("control: %q, %v", got, err)
	}
	for _, r := range []IndexRow{{Key: ""}, {Key: "a\tb"}, {Key: "a\nb"}, {Key: "a\x7f"}, {Key: strings.Repeat("k", 1025)},
		{Key: "k", Size: -1}, {Key: "k", Ino: -1}, {Key: "k", CtimeNS: -1}, {Key: "k", SHA256: "zz"}, {Key: "k", SHA256: strings.Repeat("A", 64)}} {
		if got, err := AppendIndexRow([]byte("x"), r); err == nil || string(got) != "x" {
			t.Errorf("AppendIndexRow(%+v) = %q, %v: want an error and nothing written", r, got, err)
		}
	}
	if _, err := ParseIndexRow([]byte(strings.Repeat("k", 1025) + "\t1\t2\t3\t-\n")); err == nil {
		t.Error("an index key over 1,024 bytes read")
	}
	if _, err := ParseIndexRow([]byte(strings.Repeat("k", 1024) + "\t1\t2\t3\t-\n")); err != nil {
		t.Errorf("control, a 1,024-byte key: %v", err)
	}
}

// Nesting is bounded before decoding.
func TestParseResult_DepthBounded(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	// The check's push sits at depth 2; a value nested 15 deep inside a member is still read by names (and refused by the decoder for its type).
	if err := names(json.NewDecoder(strings.NewReader(deep(16))), 0); err != nil {
		t.Errorf("16 levels refused: %v", err)
	}
	if err := names(json.NewDecoder(strings.NewReader(deep(17))), 0); err == nil {
		t.Error("17 levels accepted")
	}
}
