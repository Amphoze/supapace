package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// One argument, the table's path; a table that cannot be read ends the program
// with an error before it serves anything.
func TestRun_ArgumentsAndAnUnreadableTable(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{nil, {"a", "b"}} {
		out.Reset()
		if code := run(args, &out); code != 2 || !strings.Contains(out.String(), "usage") {
			t.Fatalf("%q: %d %q", args, code, out.String())
		}
	}
	out.Reset()
	if code := run([]string{filepath.Join(t.TempDir(), "missing.json")}, &out); code != 1 || !strings.HasPrefix(out.String(), "pgcap: ") {
		t.Fatalf("missing table: %d %q", code, out.String())
	}
}
