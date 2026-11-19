package jobio

import (
	"strings"
	"testing"
)

// The checks below each have a valid control beside them, so a refusal for
// another reason cannot pass them.
func TestParseResult_RefusalsHaveControls(t *testing.T) {
	// A document without ok is refused even when every other member is valid.
	if _, _, err := ParseResult("seed", []byte(`{"ok":true,"files":1,"bytes":1}`)); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, _, err := ParseResult("seed", []byte(`{"files":1,"bytes":1}`)); err == nil {
		t.Error("a result without ok accepted")
	}
	// Only the one final newline is taken off.
	if _, _, err := ParseResult("seed", []byte(`{"ok":true,"files":1,"bytes":1}`+"\n\n")); err == nil {
		t.Error("a result with an empty line after it accepted")
	}
	// A failure that breaks the code or message rule cannot be written either.
	for _, f := range []Failure{{Code: "Bad Code", Message: "m"}, {Code: "", Message: "m"}, {Code: "x", Message: strings.Repeat("m", 257)}} {
		if b, err := MarshalResult(f); err == nil {
			t.Errorf("MarshalResult(%+v) = %s", f, b)
		}
	}
	// DEL is a control character in both line formats.
	if _, err := ParseIndexRow([]byte("k\x7f\t1\t2\t3\t-\n")); err == nil {
		t.Error("an index key holding DEL accepted")
	}
	if err := ReadPlan(strings.NewReader("k\t-\t\x7f\t1\n"), func(PlanRow) error { return nil }); err == nil {
		t.Error("a plan hash holding DEL accepted")
	}
}

// Member names are matched exactly: encoding/json alone matches a member name
// without regard to case (also through Unicode folding) and keeps the last of
// two equal names, so the document decoded would not be the one a reader of
// the stored line sees.
func TestParseResult_MemberNamesExact(t *testing.T) {
	if _, _, err := ParseResult("seed", []byte(`{"ok":true,"files":1,"bytes":1}`)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, doc := range map[string]string{
		"upper case":        `{"OK":true,"Files":1,"bytes":1}`,
		"kelvin sign":       "{\"oK\":true,\"files\":1,\"bytes\":1}",
		"duplicate member":  `{"ok":true,"files":1,"files":2,"bytes":1}`,
		"duplicate ok":      `{"ok":true,"ok":false,"code":"x","message":"m"}`,
		"long s, histories": "{\"ok\":true,\"files\":1,\"bytes\":1,\"hiſtories\":null}",
	} {
		kind := "seed"
		if strings.Contains(name, "histories") {
			kind = "fetch"
		}
		if v, f, err := ParseResult(kind, []byte(doc)); err == nil {
			t.Errorf("%s: accepted %q as %+v %+v", name, doc, v, f)
		}
	}
	// Map keys keep their own spelling: the timelines of newest are upper-case hex.
	if _, _, err := ParseResult("push", []byte(`{"ok":true,"newest":{"0000000A":"0000000A0000000000000001"}}`)); err != nil {
		t.Errorf("newest with upper-case keys: %v", err)
	}
	if _, _, err := ParseResult("push", []byte(`{"ok":true,"newest":{"00000001":"a"},"NEWEST":{"00000002":"b"}}`)); err == nil {
		t.Error("two spellings of newest accepted")
	}
}

// A row a job reports is later written into the replicator's index file by
// AppendIndexRow, which cannot refuse it, so a row that would not read back is
// refused when the result is parsed.
func TestParseResult_RowsFitTheIndex(t *testing.T) {
	good := `{"key":"archive/s-1/00000001.history","size":40,"sha256":"` + strings.Repeat("b", 64) + `","ino":12,"ctime_ns":99,"version_id":"v","at":"2026-11-19T10:15:00Z"}`
	doc := func(row string) []byte { return []byte(`{"ok":true,"mode":"copy","uploaded":[` + row + `]}`) }
	if _, _, err := ParseResult("replicate", doc(good)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, row := range map[string]string{
		"tab in key":     strings.Replace(good, `00000001.history`, `a\tb`, 1),
		"newline in key": strings.Replace(good, `00000001.history`, `a\nb\t1\t2\t3\t-`, 1),
		"empty key":      strings.Replace(good, `archive/s-1/00000001.history`, ``, 1),
		"negative size":  strings.Replace(good, `"size":40`, `"size":-1`, 1),
		"negative ino":   strings.Replace(good, `"ino":12`, `"ino":-12`, 1),
		"bad hash":       strings.Replace(good, strings.Repeat("b", 64), "zz", 1),
		"tab in version": strings.Replace(good, `"version_id":"v"`, `"version_id":"v\t"`, 1),
	} {
		if _, _, err := ParseResult("replicate", doc(row)); err == nil {
			t.Errorf("%s: row accepted", name)
		}
	}
}

// Only the control plane passes a null timeline list (and a probe, which reads
// no timeline): for any other subject it would admit every timeline.
func TestInput_NilTimelinesOnlyForControlPlane(t *testing.T) {
	for _, subject := range []string{"", "ABCDEFGHIJ0123456789", "abcdefghij012345678", "cp-1"} {
		doc := `{"job":1,"kind":"push","subject":"` + subject + `","stanza":"s","uid":1,"timelines":null}`
		if _, err := ParseInput([]byte(doc)); err == nil {
			t.Errorf("subject %q with null timelines accepted", subject)
		}
	}
	if _, err := ParseInput([]byte(`{"job":1,"kind":"push","subject":"cp","stanza":"s","uid":1,"timelines":null}`)); err != nil {
		t.Errorf("control, the control plane: %v", err)
	}
}
