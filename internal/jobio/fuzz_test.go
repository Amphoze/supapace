package jobio

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

var resultKinds = []string{"push", "stanza-create", "check", "backup", "restore", "serve", "seed", "replicate", "probe", "fetch"}

// Whatever a job prints, ParseResult neither panics nor accepts a value that
// does not survive its own encoding.
func FuzzParseResult(f *testing.F) {
	for _, s := range []string{`{"ok":true,"files":1,"bytes":2}`, `{"ok":false,"code":"x","message":"m"}`,
		`{"ok":true,"mode":"rebuild","rows":[{"key":"k","size":1,"version_id":"v","at":"2026-11-19T10:15:00Z"}]}`,
		`{"ok":true,"mode":"probe","rows":[{"name":"n","ok":true,"detail":"d"}]}`,
		`{"ok":true,"newest":{"00000001":"000000010000000000000003"},"spool_oldest":"2026-11-19T10:15:00.5+05:30"}`,
		`{"ok":true,"push":{"ok":true,"histories":["00000002.history"]},"timeline":2}`} {
		for i := range resultKinds {
			f.Add(uint8(i), []byte(s))
		}
	}
	f.Fuzz(func(t *testing.T, k uint8, line []byte) {
		kind := resultKinds[int(k)%len(resultKinds)]
		v, fail, err := ParseResult(kind, line)
		if err != nil {
			if v != nil || fail != nil {
				t.Fatalf("an error with a value: %v %v", v, fail)
			}
			return
		}
		if (v == nil) == (fail == nil) {
			t.Fatalf("exactly one of value and failure: %v %v", v, fail)
		}
		var enc any = v
		if fail != nil {
			enc = *fail
		}
		b1, err := MarshalResult(enc)
		if err != nil {
			t.Fatalf("an accepted %s result does not encode: %v", kind, err)
		}
		v2, fail2, err := ParseResult(kind, b1)
		if err != nil {
			t.Fatalf("re-parse of %s: %v", b1, err)
		}
		var enc2 any = v2
		if fail2 != nil {
			enc2 = *fail2
		}
		b2, _ := MarshalResult(enc2)
		if !bytes.Equal(b1, b2) {
			t.Fatalf("not stable:\n%s\n%s", b1, b2)
		}
	})
}

func FuzzParseIndexRow(f *testing.F) {
	f.Add([]byte("k\t1\t2\t3\t-\n"))
	f.Add([]byte("archive/s-1/archive.info\t370\t131\t1763547300123456789\t" + strings.Repeat("0f", 32) + "\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		r, err := ParseIndexRow(line)
		if err != nil {
			return
		}
		b, err := AppendIndexRow(nil, r)
		if err != nil {
			t.Fatalf("%q parsed to %+v, which does not append: %v", line, r, err)
		}
		r2, err := ParseIndexRow(b)
		if err != nil || r2 != r {
			t.Fatalf("%q -> %+v -> %q -> %+v, %v", line, r, b, r2, err)
		}
		if bytes.Count(b, []byte("\n")) != 1 {
			t.Fatalf("not one line: %q", b)
		}
	})
}

func FuzzReadPlan(f *testing.F) {
	f.Add([]byte("k\t-\t-\t1\nk2\tv\t" + strings.Repeat("ab", 32) + "\t0\n"))
	f.Fuzz(func(t *testing.T, plan []byte) {
		var rows []PlanRow
		if err := ReadPlan(bytes.NewReader(plan), func(r PlanRow) error { rows = append(rows, r); return nil }); err != nil {
			return
		}
		var buf bytes.Buffer
		if err := WritePlan(&buf, rows); err != nil {
			t.Fatalf("rows read do not write: %v", err)
		}
		var again []PlanRow
		if err := ReadPlan(&buf, func(r PlanRow) error { again = append(again, r); return nil }); err != nil || !reflect.DeepEqual(again, rows) {
			t.Fatalf("plan not stable: %v", err)
		}
	})
}

func FuzzParseInput(f *testing.F) {
	for _, in := range inputs() {
		b, _ := MarshalInput(in)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		in, err := ParseInput(b)
		if err != nil {
			return
		}
		if in.Timelines == nil && in.Subject != "cp" && in.Kind != "probe" {
			t.Fatal("an input other than the control plane's or a probe's admits every timeline")
		}
		b2, err := MarshalInput(in)
		if err != nil {
			t.Fatalf("accepted input does not encode: %v", err)
		}
		in2, err := ParseInput(b2)
		if err != nil || !reflect.DeepEqual(in, in2) {
			t.Fatalf("not stable: %v\n%+v\n%+v", err, in, in2)
		}
	})
}
