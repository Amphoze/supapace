package pgcap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// metaJSON is the table of the dashboard's class for the given slices.
func metaJSON(slices string) string {
	return `{"listen":"10.212.0.6","project_block":"10.213.0.0/16","slice_prefix":26,` +
		`"max_conns":64,"preamble_ms":2000,` +
		`"classes":[{"name":"meta","port_base":20000,"peers":["10.212.0.4","10.212.0.5"],` +
		`"conns_per_peer":16,"cancels_per_project":2,"cancels_per_peer":8,"cancel_ms":2000,` +
		`"conns_per_second":20,"conns_burst":10,"refusals_max":16,` +
		`"copy_buf_bytes":65536,"sock_buf_bytes":32768,` +
		`"message_bytes":0,"window":"connection","window_bytes":12582912,"stream":null,` +
		`"dial_ms":3000,"auth_ms":10000,"wall_ms":55000,` +
		`"scram_iter_min":4096,"scram_iter_max":4096,` +
		`"param_status_max":64,"row_fields_max":1664,"notices_max":0,"drop_notices":true}],` +
		`"slices":` + slices + `}`
}

const metaSlices = `{"3":{"meta":5},"7":{"meta":5}}`

// replica is a second class that every later class looks like: a response
// window, a stream window, no per-peer caps.
const replica = `{"name":"replica","port_base":30000,"peers":["10.212.0.7"],` +
	`"conns_per_peer":0,"cancels_per_project":2,"cancels_per_peer":0,"cancel_ms":2000,` +
	`"conns_per_second":20,"conns_burst":10,"refusals_max":16,` +
	`"copy_buf_bytes":16384,"sock_buf_bytes":16384,` +
	`"message_bytes":1048576,"window":"response","window_bytes":8388608,` +
	`"stream":{"conns_per_project":1,"bytes_per_interval":1048576,"interval_ms":100},` +
	`"dial_ms":3000,"auth_ms":10000,"wall_ms":0,` +
	`"scram_iter_min":4096,"scram_iter_max":4096,` +
	`"param_status_max":64,"row_fields_max":1664,"notices_max":1000,"drop_notices":false}`

func TestTable_ParsesTheMetaTable(t *testing.T) {
	tb, err := ParseTable([]byte(metaJSON(metaSlices)))
	if err != nil {
		t.Fatal(err)
	}
	c := tb.Classes[0]
	if tb.Listen.String() != "10.212.0.6" || tb.ProjectBlock.String() != "10.213.0.0/16" || c.Name != "meta" ||
		len(c.Peers) != 2 || c.WindowBytes != 12582912 || c.Stream != nil || tb.Slices["7"]["meta"] != 5 {
		t.Fatalf("%+v", tb)
	}
}

// One case per rule of the table's strict reading, each against the valid
// table it alters (the control).
func TestTable_Strict(t *testing.T) {
	good := metaJSON(metaSlices)
	two := strings.Replace(good, `"drop_notices":true}]`, `"drop_notices":true},`+replica+`]`, 1)
	for _, ok := range []string{good, two} {
		if _, err := ParseTable([]byte(ok)); err != nil {
			t.Fatalf("control refused: %v", err)
		}
	}
	for _, c := range []struct{ name, base, from, to string }{
		{"unknown member", good, `"max_conns"`, `"extra":1,"max_conns"`},
		{"unknown class member", good, `"name":"meta"`, `"name":"meta","extra":1`},
		{"unknown stream member", two, `"interval_ms":100`, `"interval_ms":100,"extra":1`},
		{"trailing data", good, `}}}`, `}}} {}`},
		{"two classes sharing a name", two, `"name":"replica"`, `"name":"meta"`},
		{"overlapping port ranges", two, `"port_base":30000`, `"port_base":20063`},
		{"a port past 65535", good, `"port_base":20000`, `"port_base":65500`},
		{"iteration floor above the cap", good, `"scram_iter_min":4096`, `"scram_iter_min":4097`},
		{"an IPv6 peer", good, `"10.212.0.5"`, `"2001:db8::5"`},
		{"an IPv4-mapped peer", good, `"10.212.0.5"`, `"::ffff:10.212.0.5"`},
		{"a peer that is no address", good, `"10.212.0.5"`, `"pgmeta"`},
		{"an unknown window", good, `"window":"connection"`, `"window":"statement"`},
		{"a stream with a rate of 0", two, `"bytes_per_interval":1048576`, `"bytes_per_interval":0`},
		{"a stream interval of 9 ms", two, `"interval_ms":100`, `"interval_ms":9`},
		{"a stream interval of 1001 ms", two, `"interval_ms":100`, `"interval_ms":1001`},
		{"a slice index outside the block", good, `"7":{`, `"1024":{`},
		{"a negative slice index", good, `"7":{`, `"-1":{`},
		{"a slice index with a leading zero", good, `"7":{`, `"07":{`},
		{"a slice index that is no number", good, `"7":{`, `"x":{`},
		{"a class name no class has", good, `"7":{"meta":5}`, `"7":{"pooler":5}`},
		{"a negative allowance", good, `"7":{"meta":5}`, `"7":{"meta":-1}`},
		{"a copy buffer below 4 KiB", good, `"copy_buf_bytes":65536`, `"copy_buf_bytes":4095`},
		{"a copy buffer above 1 MiB", good, `"copy_buf_bytes":65536`, `"copy_buf_bytes":1048577`},
		{"a socket buffer below 4 KiB", good, `"sock_buf_bytes":32768`, `"sock_buf_bytes":4095`},
		{"a socket buffer above 1 MiB", good, `"sock_buf_bytes":32768`, `"sock_buf_bytes":1048577`},
		{"max_conns below the terms", good, `"max_conns":64`, `"max_conns":25`},
		{"a block that is not a network", good, `"10.213.0.0/16"`, `"10.213.0.1/16"`},
		{"an IPv6 block", good, `"10.213.0.0/16"`, `"2001:db8::/48"`},
		{"a slice prefix too long for a cluster and a proxy address", good, `"slice_prefix":26`, `"slice_prefix":30`},
		{"a slice prefix not inside the block", good, `"slice_prefix":26`, `"slice_prefix":16`},
		{"an IPv6 listen address", good, `"listen":"10.212.0.6"`, `"listen":"::1"`},
		{"an empty class name", good, `"name":"meta"`, `"name":""`},
		{"a window of 0 bytes", good, `"window_bytes":12582912`, `"window_bytes":0`},
		{"no dial deadline", good, `"dial_ms":3000`, `"dial_ms":0`},
		{"no authentication deadline", good, `"auth_ms":10000`, `"auth_ms":0`},
		{"no preamble deadline", good, `"preamble_ms":2000`, `"preamble_ms":0`},
		{"no cancel deadline", good, `"cancel_ms":2000`, `"cancel_ms":0`},
		{"no connection rate", good, `"conns_per_second":20`, `"conns_per_second":0`},
		{"no burst", good, `"conns_burst":10`, `"conns_burst":0`},
		{"no refusal pool", good, `"refusals_max":16`, `"refusals_max":0`},
		{"an iteration floor of 0", good, `"scram_iter_min":4096`, `"scram_iter_min":0`},
		{"a negative cap", good, `"notices_max":0`, `"notices_max":-1`},
		{"a negative wall clock", good, `"wall_ms":55000`, `"wall_ms":-1`},
		{"a negative message cap", good, `"message_bytes":0`, `"message_bytes":-1`},
		{"a stream with no connections", two, `"conns_per_project":1`, `"conns_per_project":0`},
		{"not an object", good, good, `[]`},
		{"a count above 2^30", good, `"conns_per_peer":16`, `"conns_per_peer":1073741825`},
		{"a deadline above 2^30", good, `"dial_ms":3000`, `"dial_ms":1073741825`},
		{"max_conns above 2^30", good, `"max_conns":64`, `"max_conns":1073741825`},
	} {
		if !strings.Contains(c.base, c.from) {
			t.Fatalf("%s: %q not in the table", c.name, c.from)
		}
		if _, err := ParseTable([]byte(strings.Replace(c.base, c.from, c.to, 1))); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestTable_MarshalIsCanonical(t *testing.T) {
	// Classes out of name order, slices whose string order differs from their
	// numeric order, white space.
	in := strings.Replace(metaJSON(`{"10":{"meta":5},"3":{"meta":5},"7":{"replica":2,"meta":5}}`),
		`"drop_notices":true}]`, `"drop_notices":true},`+replica+`]`, 1)
	in = strings.Replace(in, `{"name":"meta"`, `{"name":"zeta"`, 1)
	in = strings.ReplaceAll(strings.ReplaceAll(in, `"meta":5`, `"zeta":5`), `,`, ", ")
	if _, err := ParseTable([]byte(in)); err == nil {
		t.Fatal("a table not in the canonical form was accepted")
	}
	var tb Table // the same table read without the canonical-form rule
	if err := json.Unmarshal([]byte(in), &tb); err != nil {
		t.Fatal(err)
	}
	b, err := tb.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tb2, err := ParseTable(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := tb2.Marshal()
	if !bytes.Equal(b, b2) {
		t.Fatalf("not stable:\n%s\n%s", b, b2)
	}
	s := string(b)
	if strings.ContainsAny(s, " \n\t") {
		t.Errorf("white space in %s", s)
	}
	if !(strings.Index(s, `"name":"replica"`) < strings.Index(s, `"name":"zeta"`)) {
		t.Errorf("classes not by name: %s", s)
	}
	if !strings.HasSuffix(s, `"slices":{"3":{"zeta":5},"7":{"replica":2,"zeta":5},"10":{"zeta":5}}}`) {
		t.Errorf("slices not in numeric order: %s", s)
	}
	if !strings.HasPrefix(s, `{"listen":"10.212.0.6","project_block":"10.213.0.0/16","slice_prefix":26,"max_conns":64,"preamble_ms":2000,"classes":[{"name":"replica","port_base":30000,`) {
		t.Errorf("member order: %s", s)
	}
	// The dashboard class's table, written without white space, is already canonical.
	want := metaJSON(metaSlices)
	tb3, _ := ParseTable([]byte(want))
	if b3, _ := tb3.Marshal(); string(b3) != want {
		t.Errorf("canonical form\n%s\nwant\n%s", b3, want)
	}
	// Marshal leaves its receiver's classes in their order.
	if tb.Classes[0].Name != "zeta" {
		t.Error("Marshal reordered the caller's classes")
	}
	var any map[string]any
	if err := json.Unmarshal(b, &any); err != nil {
		t.Fatal(err)
	}
}

func slicesJSON(n int, class string, allowance int) string {
	var parts []string
	for i := range n {
		parts = append(parts, fmt.Sprintf(`"%d":{"%s":%d}`, i, class, allowance))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func TestTerms_MetaAlone(t *testing.T) {
	for _, c := range []struct{ slices, conns, cancels, refusals int }{{28, 32, 16, 16}, {3, 15, 6, 16}, {8, 32, 16, 16}, {0, 0, 0, 16}} {
		tb, err := ParseTable([]byte(metaJSON(slicesJSON(c.slices, "meta", 5))))
		if err != nil {
			t.Fatal(err)
		}
		if a, b, r := tb.Terms(); a != c.conns || b != c.cancels || r != c.refusals {
			t.Errorf("%d slices: %d %d %d, want %d %d %d", c.slices, a, b, r, c.conns, c.cancels, c.refusals)
		}
	}
}

func TestTerms_ClassWithoutPerPeerCap(t *testing.T) {
	in := strings.Replace(metaJSON(`{"1":{"meta":5,"replica":3},"2":{"meta":5,"replica":4},"3":{"meta":5}}`),
		`"drop_notices":true}]`, `"drop_notices":true},`+replica+`]`, 1)
	in = strings.Replace(in, `"max_conns":64`, `"max_conns":100`, 1)
	tb, err := ParseTable([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	// meta: min(15, 32) = 15, cancels min(6, 16) = 6; replica: 3 + 4 = 7
	// connections, 2 per project of its 2 projects = 4 cancels; pools 16 + 16.
	if a, b, r := tb.Terms(); a != 22 || b != 10 || r != 32 {
		t.Fatalf("%d %d %d, want 22 10 32", a, b, r)
	}
}

func TestConnBytes(t *testing.T) {
	if got := (Class{CopyBufBytes: 65536, SockBufBytes: 32768}).ConnBytes(); got != 384<<10 {
		t.Errorf("meta: %d", got)
	}
	if got := (Class{CopyBufBytes: 16384, SockBufBytes: 16384}).ConnBytes(); got != 160<<10 {
		t.Errorf("default: %d", got)
	}
}
