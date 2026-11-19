package pgcap

import (
	"strings"
	"testing"
)

// The strict reading leaves a table one meaning: nothing follows the document,
// every member name is spelled as the format spells it and appears once, and
// no member is null where a number or a truth value belongs.
func TestTable_Strict_OneMeaning(t *testing.T) {
	good := metaJSON(metaSlices)
	for _, c := range []struct{ name, from, to string }{
		{"a closing brace after the document", `}}}`, `}}}}`},
		{"a closing bracket and more after the document", `}}}`, `}}}]{"max_conns":1}`},
		{"a member twice", `"max_conns":64`, `"max_conns":64,"max_conns":100000`},
		{"a class member twice", `"window_bytes":12582912`, `"window_bytes":12582912,"window_bytes":1099511627776`},
		{"a member in another case", `"max_conns":64`, `"max_conns":64,"MAX_CONNS":100000`},
		{"a class member in another case", `"row_fields_max":1664`, `"row_fields_max":1664,"Row_Fields_Max":65535`},
		{"a slice twice", `"7":{"meta":5}`, `"7":{"meta":5},"7":{"meta":0}`},
		{"null for a cap", `"message_bytes":0`, `"message_bytes":null`},
		{"null for a truth value", `"drop_notices":true`, `"drop_notices":null`},
		{"null for the wall clock", `"wall_ms":55000`, `"wall_ms":null`},
	} {
		if !strings.Contains(good, c.from) {
			t.Fatalf("%s: %q not in the table", c.name, c.from)
		}
		if _, err := ParseTable([]byte(strings.Replace(good, c.from, c.to, 1))); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// Allowances that no node has are refused, not summed past the integers into a
// term below the ceiling.
func TestTable_Strict_AllowancesCannotWrap(t *testing.T) {
	in := strings.Replace(metaJSON(`{"3":{"meta":9223372036854775807},"7":{"meta":9223372036854775807}}`),
		`"conns_per_peer":16`, `"conns_per_peer":0`, 1)
	if tb, err := ParseTable([]byte(in)); err == nil {
		a, b, r := tb.Terms()
		t.Errorf("accepted with terms %d %d %d under a ceiling of %d", a, b, r, tb.MaxConns)
	}
}

// The field cap is a cap on one row description — the most columns a server
// can describe at once — not on the sum over a window: a request whose
// statements together describe more than the cap, each within it, passes.
func TestRowDescription_FieldCapIsPerMessage(t *testing.T) {
	run, ch := script(t, login, rowDesc(1664), readyMsg, rowDesc(1664), rowDesc(1), readyMsg)
	p := relayTo(t, metaClass(), run)
	p.read(t, len(login)+2*len(rowDesc(1664))+len(rowDesc(1))+2*len(readyMsg))
	p.open(t, <-ch)
}
