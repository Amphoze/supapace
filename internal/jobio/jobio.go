// Package jobio defines every document that crosses the boundary between the
// daemon and a backup job: the input file, the one result line, the
// replicator's index file and the fetch plan. Nothing else defines a type for
// them. It imports the standard library only, so the job side stays small.
package jobio

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
)

// resultMax is bklimit.ResultMax (a test keeps the two equal): the longest
// result line, without its newline.
const resultMax = 1 << 20

// Count bounds a job's result keeps: a push quarantines at most its entry cap
// (bklimit.PushMaxEntries) and names at most 64 timelines in newest; a serve
// lists the last 64 names; a rebuild returns at most one page
// (bklimit.RebuildPageRows). A test keeps the two copies equal.
const (
	pushMaxEntries  = 56
	newestMax       = 64
	serveNoneMax    = 64
	rebuildPageRows = 4000
)

// Input is /job/input.json. Members of other kinds are omitted when zero.
type Input struct {
	Job     int64  `json:"job"`
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Stanza  string `json:"stanza"`
	UID     int    `json:"uid"`
	// Timelines admitted; nil admits every timeline and is accepted only for
	// subject "cp" and kind probe, empty admits none.
	Timelines      []uint32   `json:"timelines"`
	MaxEntries     int        `json:"max_entries,omitempty"`     // push
	Type           string     `json:"type,omitempty"`            // backup
	Set            string     `json:"set,omitempty"`             // restore
	Mode           string     `json:"mode,omitempty"`            // restore
	TargetTimeline int        `json:"target_timeline,omitempty"` // restore, standby only
	MaxAnswers     int        `json:"max_answers,omitempty"`     // serve
	MaxBytes       int64      `json:"max_bytes,omitempty"`       // fetch
	ListCurrent    bool       `json:"list_current,omitempty"`    // fetch, control plane only
	Repl           *ReplInput `json:"repl,omitempty"`            // replicate, probe
}

// ReplInput is the replicator's part of the input. Budgets: 0 = none left,
// -1 = no budget, so no member is omitted.
type ReplInput struct {
	Mode          string            `json:"mode"` // copy, rebuild, probe
	MaxFiles      int               `json:"max_files"`
	MaxEntries    int               `json:"max_entries"`
	MaxBytes      int64             `json:"max_bytes"`
	BudgetBytes   int64             `json:"budget_bytes"`
	BudgetObjects int               `json:"budget_objects"`
	InfoSHA256    map[string]string `json:"info_sha256"`
	KeyMarker     string            `json:"key_marker"`
	VersionMarker string            `json:"version_marker"`
	PageRows      int               `json:"page_rows"`
}

var inputKinds = map[string]bool{"push": true, "stanza-create": true, "backup": true, "check": true, "restore": true,
	"serve": true, "seed": true, "replicate": true, "fetch": true, "probe": true}

func (in Input) check() error {
	if !inputKinds[in.Kind] {
		return fmt.Errorf("jobio: unknown job kind %q", in.Kind)
	}
	// Only the control plane admits every timeline; a probe reads none.
	if in.Timelines == nil && in.Subject != "cp" && in.Kind != "probe" {
		return errors.New("jobio: the input needs a timeline list")
	}
	return nil
}

func MarshalInput(in Input) ([]byte, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	return json.Marshal(in)
}

// ParseInput reads an input document strictly: unknown members and trailing
// data are errors.
func ParseInput(b []byte) (Input, error) {
	var in Input
	if err := strict(b, &in); err != nil {
		return Input{}, fmt.Errorf("jobio: input: %w", err)
	}
	if err := in.check(); err != nil {
		return Input{}, err
	}
	return in, nil
}

// strict decodes one document into v: member names exact and unique, no
// unknown member, nothing after it.
func strict(b []byte, v any) error {
	if err := names(json.NewDecoder(bytes.NewReader(b)), 0); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// Results: one type per kind; "ok" is true in each.

type PushResult struct {
	OK           bool              `json:"ok"`
	Complete     bool              `json:"complete"`
	Pushed       int               `json:"pushed"`
	First        string            `json:"first"`
	Last         string            `json:"last"`
	Newest       map[string]string `json:"newest"` // timeline (8 hex) → newest segment in the repository (24 hex)
	Quarantined  []Quarantined     `json:"quarantined"`
	Remaining    int               `json:"remaining"`
	OtherEntries int               `json:"other_entries"`
	SpoolEntries int               `json:"spool_entries"`
	SpoolBytes   int64             `json:"spool_bytes"`
	SpoolOldest  *time.Time        `json:"spool_oldest"`
	Histories    []string          `json:"histories"`
}

type Quarantined struct {
	Name   string `json:"name"`
	Reason string `json:"reason"` // timeline, shape, refused-44, refused-45, refused-46
}

// bounded checks the counts a push promises; a nil push (none reported) passes.
func (r *PushResult) bounded() error {
	if r == nil {
		return nil
	}
	if len(r.Quarantined) > pushMaxEntries || len(r.Newest) > newestMax {
		return fmt.Errorf("push lists %d quarantined and %d timelines, at most %d and %d",
			len(r.Quarantined), len(r.Newest), pushMaxEntries, newestMax)
	}
	return nil
}

// CheckJobResult is the result of check and of stanza-create.
type CheckJobResult struct {
	OK   bool        `json:"ok"`
	Push *PushResult `json:"push"`
}

type BackupResult struct {
	OK           bool        `json:"ok"`
	Label        string      `json:"label"`
	Timeline     uint32      `json:"timeline"`
	Start        time.Time   `json:"start"`
	Stop         time.Time   `json:"stop"`
	StartSegment string      `json:"start_segment"`
	StopSegment  string      `json:"stop_segment"`
	StartLSN     string      `json:"start_lsn"`
	StopLSN      string      `json:"stop_lsn"`
	Push         *PushResult `json:"push"`
}

type RestoreResult struct {
	OK   bool   `json:"ok"`
	Mode string `json:"mode"`
}

type ServeResult struct {
	OK          bool     `json:"ok"`
	Served      int      `json:"served"`
	None        []string `json:"none"` // names answered "not in the archive", the last 64
	Refused     int      `json:"refused"`
	Last        string   `json:"last"`
	LastNone    bool     `json:"last_none"`
	LastSegment string   `json:"last_segment"` // highest segment answered with a file; "" when none
}

type SeedResult struct {
	OK    bool  `json:"ok"`
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

// Row is one uploaded or listed object: a rebuilt row has no hash, inode or ctime.
type Row struct {
	Key       string    `json:"key"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256,omitempty"`
	Ino       int64     `json:"ino,omitempty"`
	CtimeNS   int64     `json:"ctime_ns,omitempty"`
	VersionID string    `json:"version_id"`
	At        time.Time `json:"at"`
}

type InfoVersion struct {
	Name      string    `json:"name"`
	VersionID string    `json:"version_id"`
	SHA256    string    `json:"sha256"`
	At        time.Time `json:"at"`
}

type Notice struct {
	Code   string `json:"code"`
	Count  int64  `json:"count"`
	Detail string `json:"detail"`
}

// ProbeRow is one row of an off-site check.
type ProbeRow struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// ReplResult is the result of a copy, rebuild or probe. On the wire both Rows
// (rebuild) and ProbeRows (probe) are the member "rows"; Mode selects which.
type ReplResult struct {
	OK                bool          `json:"ok"`
	Mode              string        `json:"mode"`
	Complete          bool          `json:"complete"`
	Stopped           string        `json:"stopped"`
	Uploaded          []Row         `json:"uploaded"`
	Adopted           []Row         `json:"adopted"`
	Info              []InfoVersion `json:"info"`
	SetsComplete      []string      `json:"sets_complete"`
	Bytes             int64         `json:"bytes"`
	Objects           int           `json:"objects"`
	Walked            int           `json:"walked"`
	Truncated         bool          `json:"truncated"`
	Held              int           `json:"held"`
	Notices           []Notice      `json:"notices"`
	Rows              []Row         `json:"-"`
	ProbeRows         []ProbeRow    `json:"-"`
	NextKeyMarker     string        `json:"next_key_marker"`
	NextVersionMarker string        `json:"next_version_marker"`
	Last              bool          `json:"last"`
}

type replWire struct {
	replAlias
	Rows json.RawMessage `json:"rows,omitempty"`
}

type replAlias ReplResult // no methods: plain encoding of the other members

func (r ReplResult) MarshalJSON() ([]byte, error) {
	w := replWire{replAlias: replAlias(r)}
	var rows any
	if r.Mode == "probe" {
		if len(r.ProbeRows) > 0 {
			rows = r.ProbeRows
		}
	} else if len(r.Rows) > 0 {
		rows = r.Rows
	}
	if rows != nil {
		b, err := json.Marshal(rows)
		if err != nil {
			return nil, err
		}
		w.Rows = b
	}
	return json.Marshal(w)
}

func (r *ReplResult) UnmarshalJSON(b []byte) error {
	var w replWire
	if err := strict(b, &w); err != nil {
		return err
	}
	*r = ReplResult(w.replAlias)
	var err error
	switch {
	case len(w.Rows) == 0:
	case r.Mode == "probe":
		err = strict(w.Rows, &r.ProbeRows)
	case r.Mode == "copy":
		err = errors.New("a copy result has no rows")
	default:
		err = strict(w.Rows, &r.Rows)
	}
	if err != nil {
		return err
	}
	// Every row may become a line of the index file: refuse one that cannot.
	for _, rows := range [][]Row{r.Uploaded, r.Adopted, r.Rows} {
		for _, row := range rows {
			if !rowFits(row.Key, row.VersionID, row.SHA256, row.Size, row.Ino, row.CtimeNS) {
				return fmt.Errorf("row %.64q does not fit the index", row.Key)
			}
		}
	}
	return nil
}

// rowFits: a key of 1 to 1,024 bytes and a version id, neither holding a
// control byte; numbers not negative; a hash empty or lower-case hex.
func rowFits(key, version, sha string, nums ...int64) bool {
	if key == "" || len(key) > 1024 || hasControl(key) || hasControl(version) || (sha != "" && !hexRE.MatchString(sha)) {
		return false
	}
	for _, n := range nums {
		if n < 0 {
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// nameRE: how a member name is spelled, lower case, or eight upper-case hex
// digits (the timelines that key a push result's newest).
var nameRE = regexp.MustCompile(`^([a-z0-9_.]{1,64}|[0-9A-F]{8})$`)

// maxDepth bounds the nesting of a document; the deepest declared one is 4.
const maxDepth = 16

// names refuses a member name spelled otherwise and a name given twice in one
// object: encoding/json matches names without regard to case (also through
// Unicode folding) and keeps the last of two equal names, so a later reader of
// the line would see another document than the one decoded.
func names(dec *json.Decoder, depth int) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxDepth {
		return errors.New("nested too deep")
	}
	seen := map[string]bool{}
	for dec.More() {
		if d == '{' {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			s, _ := k.(string)
			if seen[s] || !nameRE.MatchString(s) {
				return fmt.Errorf("member %.70q", s)
			}
			seen[s] = true
		}
		if err := names(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// FetchResult: NewestSegment and NewestSet in the control plane's mode only.
// Histories is added by the daemon from its own plan; a job's result carrying
// it is refused.
type FetchResult struct {
	OK            bool     `json:"ok"`
	Files         int      `json:"files"`
	Bytes         int64    `json:"bytes"`
	NewestSegment string   `json:"newest_segment,omitempty"`
	NewestSet     string   `json:"newest_set,omitempty"`
	Histories     []string `json:"histories,omitempty"`
}

// RecoverResult is the runner's own document for a recover job; it is written
// with MarshalResult and never parsed from a job.
type RecoverResult struct {
	OK       bool         `json:"ok"`
	Promoted bool         `json:"promoted"`
	Serve    *ServeResult `json:"serve"`
}

// Failure is an "ok":false document: a code and a message of at most 256 bytes.
type Failure struct{ Code, Message string }

var codeRE = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

type failureWire struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (f Failure) check() error {
	if !codeRE.MatchString(f.Code) || len(f.Message) > 256 {
		return errors.New("jobio: a failure needs a code of [a-z0-9_-] and a message of at most 256 bytes")
	}
	return nil
}

func (f Failure) MarshalJSON() ([]byte, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	return json.Marshal(failureWire{Code: f.Code, Message: f.Message})
}

// MarshalResult encodes v as the job's one result line: no newline inside, a
// newline at the end, at most ResultMax bytes before it.
func MarshalResult(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > resultMax {
		return nil, fmt.Errorf("jobio: result of %d bytes is above %d", len(b), resultMax)
	}
	return append(b, '\n'), nil
}

// ParseResult reads a job's result line (with or without its newline) for
// kind. It returns either the kind's result as a value (PushResult,
// CheckJobResult for check and stanza-create, BackupResult, RestoreResult,
// ServeResult, SeedResult, ReplResult for replicate and probe, FetchResult)
// or the failure. Decoding is strict, and the counts a job promises are
// bounds. Callers store the parsed value re-encoded with MarshalResult, never
// the line as received. There is no kind recover (RecoverResult is the
// runner's own).
func ParseResult(kind string, line []byte) (v any, fail *Failure, err error) {
	line = bytes.TrimSuffix(line, []byte("\n"))
	if len(line) > resultMax || bytes.IndexByte(line, '\n') >= 0 {
		return nil, nil, errors.New("jobio: result is not one line of at most 1 MiB")
	}
	var head struct {
		OK *bool `json:"ok"`
	}
	if err := json.Unmarshal(line, &head); err != nil || head.OK == nil {
		return nil, nil, errors.New("jobio: result has no boolean ok")
	}
	if !*head.OK {
		var f failureWire
		if err := strict(line, &f); err != nil {
			return nil, nil, fmt.Errorf("jobio: failure: %w", err)
		}
		fl := Failure{Code: f.Code, Message: f.Message}
		if err := fl.check(); err != nil {
			return nil, nil, err
		}
		return nil, &fl, nil
	}
	decode := func(p any) error { return strict(line, p) }
	switch kind {
	case "push":
		var r PushResult
		if err = decode(&r); err == nil {
			err = r.bounded()
		}
		v = r
	case "stanza-create", "check":
		var r CheckJobResult
		if err = decode(&r); err == nil {
			err = r.Push.bounded()
		}
		v = r
	case "backup":
		var r BackupResult
		if err = decode(&r); err == nil {
			err = r.Push.bounded()
		}
		v = r
	case "restore":
		var r RestoreResult
		err, v = decode(&r), r
	case "serve":
		var r ServeResult
		if err = decode(&r); err == nil && len(r.None) > serveNoneMax {
			err = fmt.Errorf("%d names in none, at most %d", len(r.None), serveNoneMax)
		}
		v = r
	case "seed":
		var r SeedResult
		err, v = decode(&r), r
	case "replicate", "probe":
		var r ReplResult
		if err = decode(&r); err == nil {
			want := r.Mode == "copy" || r.Mode == "rebuild" // a replicate job's modes
			if kind == "probe" {
				want = r.Mode == "probe"
			}
			if !want {
				err = fmt.Errorf("mode %q in a %s result", r.Mode, kind)
			} else if len(r.Rows) > rebuildPageRows {
				err = fmt.Errorf("%d rows, at most %d", len(r.Rows), rebuildPageRows)
			}
		}
		v = r
	case "fetch":
		var r FetchResult
		if err = decode(&r); err == nil && r.Histories != nil {
			err = errors.New("histories are the daemon's")
		}
		v = r
	default:
		return nil, nil, fmt.Errorf("jobio: unknown result kind %q", kind)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("jobio: %s result: %w", kind, err)
	}
	return v, nil, nil
}

// IndexRow is one line of the replicator's index file:
// <key>\t<size>\t<ino>\t<ctime_ns>\t<sha256 hex or ->\n.
type IndexRow struct {
	Key                string
	Size, Ino, CtimeNS int64
	SHA256             string
}

// AppendIndexRow appends r's line. A row that would not read back as itself
// (an empty or over-long key, a control byte, a negative number, a hash that
// is not lower-case hex) is an error and dst comes back unchanged: a row
// dropped in silence would leave the file's row count wrong for good. Rows
// that came through ParseResult always fit.
func AppendIndexRow(dst []byte, r IndexRow) ([]byte, error) {
	if !rowFits(r.Key, "", r.SHA256, r.Size, r.Ino, r.CtimeNS) {
		return dst, fmt.Errorf("jobio: index row %.64q would not read back", r.Key)
	}
	dst = append(dst, r.Key...)
	for _, n := range []int64{r.Size, r.Ino, r.CtimeNS} {
		dst = strconv.AppendInt(append(dst, '\t'), n, 10)
	}
	return append(append(append(dst, '\t'), dash(r.SHA256)...), '\n'), nil
}

func ParseIndexRow(line []byte) (IndexRow, error) {
	f, err := fields(line, 5)
	if err != nil {
		return IndexRow{}, fmt.Errorf("jobio: index row: %w", err)
	}
	var r IndexRow
	r.Key = f[0]
	if len(r.Key) > 1024 {
		return IndexRow{}, errors.New("jobio: index row: key longer than 1,024 bytes")
	}
	for i, p := range []*int64{&r.Size, &r.Ino, &r.CtimeNS} {
		if *p, err = number(f[i+1]); err != nil {
			return IndexRow{}, fmt.Errorf("jobio: index row: %w", err)
		}
	}
	if r.SHA256, err = hash(f[4]); err != nil {
		return IndexRow{}, fmt.Errorf("jobio: index row: %w", err)
	}
	return r, nil
}

// PlanRow is one line of /job/plan: <key>\t<version id or ->\t<sha256 hex or ->\t<size>\n.
type PlanRow struct {
	Key, VersionID, SHA256 string
	Size                   int64
}

func WritePlan(w io.Writer, rows []PlanRow) error {
	bw := bufio.NewWriter(w)
	for _, r := range rows {
		line := r.Key + "\t" + dash(r.VersionID) + "\t" + dash(r.SHA256) + "\t" + strconv.FormatInt(r.Size, 10) + "\n"
		// The written line must read back as the same row.
		if got, err := parsePlanRow([]byte(line)); err != nil || got != r {
			return fmt.Errorf("jobio: plan row %q does not survive its format", r.Key)
		}
		bw.WriteString(line)
	}
	return bw.Flush()
}

// planLineMax bounds a plan line: a key of at most 1,024 bytes, a version id,
// a hash and a size fit with room to spare.
const planLineMax = 4096

// ReadPlan calls fn for each row in order; a malformed or unterminated line,
// or fn's error, ends it.
func ReadPlan(r io.Reader, fn func(PlanRow) error) error {
	br := bufio.NewReaderSize(r, planLineMax)
	for {
		line, err := br.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			return nil
		}
		if err != nil {
			return fmt.Errorf("jobio: plan: %w", err)
		}
		row, err := parsePlanRow(line)
		if err != nil {
			return err
		}
		if err := fn(row); err != nil {
			return err
		}
	}
}

func parsePlanRow(line []byte) (PlanRow, error) {
	f, err := fields(line, 4)
	if err != nil {
		return PlanRow{}, fmt.Errorf("jobio: plan row: %w", err)
	}
	r := PlanRow{Key: f[0], VersionID: f[1]}
	if r.VersionID == "-" {
		r.VersionID = ""
	}
	if r.SHA256, err = hash(f[2]); err == nil {
		r.Size, err = number(f[3])
	}
	if err != nil {
		return PlanRow{}, fmt.Errorf("jobio: plan row: %w", err)
	}
	return r, nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// fields splits one line (an optional final newline) into n tab-separated
// fields, none empty, none holding a control character.
func fields(line []byte, n int) ([]string, error) {
	line = bytes.TrimSuffix(line, []byte("\n"))
	f := bytes.Split(line, []byte("\t"))
	if len(f) != n {
		return nil, fmt.Errorf("%d fields, want %d", len(f), n)
	}
	out := make([]string, n)
	for i, b := range f {
		if len(b) == 0 {
			return nil, fmt.Errorf("field %d empty", i+1)
		}
		for _, c := range b {
			if c < 0x20 || c == 0x7f {
				return nil, fmt.Errorf("field %d holds a control character", i+1)
			}
		}
		out[i] = string(b)
	}
	return out, nil
}

var digitsRE = regexp.MustCompile(`^[0-9]{1,19}$`)

func number(s string) (int64, error) {
	if !digitsRE.MatchString(s) {
		return 0, fmt.Errorf("%q is not a decimal count", s)
	}
	return strconv.ParseInt(s, 10, 64)
}

var hexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func hash(s string) (string, error) {
	if s == "-" {
		return "", nil
	}
	if !hexRE.MatchString(s) {
		return "", fmt.Errorf("%q is not a SHA-256 in lower-case hex", s)
	}
	return s, nil
}
