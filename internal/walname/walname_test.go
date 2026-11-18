package walname

import (
	"strings"
	"testing"
)

const (
	seg  = "00000002000000010000003F"
	hist = "00000003.history"
	lbl  = "00000002000000010000003F.00000028.backup"
)

func TestSpool_Names(t *testing.T) {
	for _, c := range []struct {
		name string
		kind Kind
		tli  uint32
	}{
		{seg, Segment, 2},
		{"FFFFFFFFFFFFFFFFFFFFFFFF", Segment, 0xFFFFFFFF},
		{hist, History, 3},
		{"0000000A.history", History, 10},
		{lbl, Label, 2},
	} {
		k, tli, ok := Spool(c.name)
		if !ok || k != c.kind || tli != c.tli {
			t.Errorf("Spool(%q) = %v %d %v, want %v %d true", c.name, k, tli, ok, c.kind, c.tli)
		}
	}
	for _, n := range refusedNames() {
		if k, tli, ok := Spool(n); ok || k != None || tli != 0 {
			t.Errorf("Spool(%q) = %v %d %v, want refused", n, k, tli, ok)
		}
	}
}

func refusedNames() []string {
	return []string{
		"", "0000000200000001000000\x003F", strings.ToLower(seg), "00000002000000010000003f",
		seg + ".partial", "-" + seg[1:], "--config=x", "-" + seg,
		"00000002/00000001000003F", "../" + seg, "..", ".", seg + "0", seg[:23],
		"0000003.history", "00000003.HISTORY", "00000003.history.tmp", "00000003a.history",
		seg + ".0000002.backup", seg + ".00000028.backup.zst", seg + ".0000002g.backup",
		"latest", "archive.info", " " + seg, seg + "\n", ".tmp-" + seg + "-0123456789abcdef",
	}
}

func TestRequest_Names(t *testing.T) {
	for _, c := range []struct {
		name string
		kind Kind
		tli  uint32
	}{{seg, Segment, 2}, {hist, History, 3}} {
		k, tli, ok := Request(c.name)
		if !ok || k != c.kind || tli != c.tli {
			t.Errorf("Request(%q) = %v %d %v, want %v %d true", c.name, k, tli, ok, c.kind, c.tli)
		}
	}
	// A label is a valid spool name but never something recovery asks for.
	if _, _, ok := Spool(lbl); !ok {
		t.Fatal("control: label must be a spool name")
	}
	for _, n := range append(refusedNames(), lbl) {
		if k, tli, ok := Request(n); ok || k != None || tli != 0 {
			t.Errorf("Request(%q) = %v %d %v, want refused", n, k, tli, ok)
		}
	}
}

func TestRepoPath_Table(t *testing.T) {
	const s = "abcdefghijklmnopqrst"
	const (
		a   = "archive/" + s + "/17-1/"
		sha = "0123456789abcdef0123456789abcdef01234567"
		L   = "20261119-120000F"
	)
	ok := []struct {
		rel   string
		kind  Kind
		tli   uint32
		label string
	}{
		{"archive/" + s + "/archive.info", Info, 0, ""},
		{"archive/" + s + "/archive.info.copy", Info, 0, ""},
		{"backup/" + s + "/backup.info", Info, 0, ""},
		{"backup/" + s + "/backup.info.copy", Info, 0, ""},
		{a + hist, History, 3, ""},
		{"archive/" + s + "/16-123/" + hist, History, 3, ""},
		{a + seg[:16] + "/" + seg + "-" + sha + ".zst", Segment, 2, ""},
		{a + seg[:16] + "/" + lbl, Label, 2, ""},
		{"backup/" + s + "/backup.history/2026/" + L + ".manifest.gz", HistoryManifest, 0, L},
		{"backup/" + s + "/" + L + "/backup.manifest", SetManifest, 0, L},
		{"backup/" + s + "/" + L + "/backup.manifest.copy", SetManifestCopy, 0, L},
		{"backup/" + s + "/" + L + "/pg_data/PG_VERSION", SetFile, 0, L},
		{"backup/" + s + "/" + L + "/pg_data/base/1/1259.zst", SetFile, 0, L},
		{"backup/" + s + "/" + L + "/pg_data/global/pg_control", SetFile, 0, L},
		{"backup/" + s + "/" + L + "/pg_data/a+b_c-d.e/" + strings.Repeat("x", 502), SetFile, 0, L},
		{"backup/" + s + "/" + L + "/pg_data/.x/..y/-z", SetFile, 0, L},
	}
	for _, c := range ok {
		k, tli, label, good := RepoPath(s, c.rel)
		if !good || k != c.kind || tli != c.tli || label != c.label {
			t.Errorf("RepoPath(%q) = %v %d %q %v, want %v %d %q true", c.rel, k, tli, label, good, c.kind, c.tli, c.label)
		}
	}

	refused := []string{
		"", "latest", "--config=x", "-archive/" + s + "/archive.info",
		"archive/" + s + "/archive.info.tmp", "archive/" + s + "/backup.info", "backup/" + s + "/archive.info",
		"archive/" + s + "//archive.info", "/archive/" + s + "/archive.info", "archive/" + s + "/archive.info/",
		"archive/" + s + "/../" + s + "/archive.info", "archive/./" + s + "/archive.info",
		"archive/" + s + "x/archive.info", "archive/" + s[:19] + "/archive.info", // another stanza; a prefix
		"archive/" + s + "/archive.info\x00",
		"archive/" + s + "/1-1/" + hist, "archive/" + s + "/17-1234/" + hist, "archive/" + s + "/17_1/" + hist,
		"archive/" + s + "/latest/" + hist,
		a + "00000003.HISTORY", a + strings.ToLower(hist[:8]) + "x.history",
		a + seg[:16] + "/" + seg + "-" + sha,                           // not compressed
		a + seg[:16] + "/" + seg + "-" + sha + ".gz",                   // other compression
		a + seg[:16] + "/" + seg + "-" + strings.ToUpper(sha) + ".zst", // upper-case checksum
		a + seg[:16] + "/" + seg + "-" + sha[:39] + ".zst",
		a + seg[:16] + "/" + strings.ToLower(seg) + "-" + sha + ".zst",
		a + "000000020000000F/" + seg + "-" + sha + ".zst", // wrong 16-digit directory
		a + "000000020000000F/" + lbl,
		a + seg[:16] + "/" + seg + ".partial-" + sha + ".zst",
		a + seg[:16] + "/" + seg + "0-" + sha + ".zst", // a 25th digit
		a + seg[:16] + "/" + seg,                       // bare segment
		a + seg[:16] + "/" + hist,
		a + seg + "-" + sha + ".zst", // no directory
		"backup/" + s + "/backup.history/2026/" + L + ".manifest",
		"backup/" + s + "/backup.history/202/" + L + ".manifest.gz",
		"backup/" + s + "/backup.history/2025/" + L + ".manifest.gz", // year of another label
		"backup/" + s + "/backup.history/2026/20261119-120000D.manifest.gz",
		"backup/" + s + "/latest/backup.manifest",
		"backup/" + s + "/20261119-120000/backup.manifest",
		"backup/" + s + "/20261119-120000F_20261119-130000D/backup.manifest",
		"backup/" + s + "/2026111-120000F/backup.manifest",
		"backup/" + s + "/20261119-120000D/backup.manifest", // only full sets
		"backup/" + s + "/20261119-120000I/pg_data/PG_VERSION",
		"backup/" + s + "/" + L + "/backup.manifest.gz",
		"backup/" + s + "/" + L + "/pg_data",
		"backup/" + s + "/" + L + "/pg_data/",
		"backup/" + s + "/" + L + "/pg_data//x",
		"backup/" + s + "/" + L + "/pg_data/x/",
		"backup/" + s + "/" + L + "/pg_data/./x",
		"backup/" + s + "/" + L + "/pg_data/x/..",
		"backup/" + s + "/" + L + "/pg_data/../x",
		"backup/" + s + "/" + L + "/pg_data/x\x00y",
		"backup/" + s + "/" + L + "/pg_data/x y",
		"backup/" + s + "/" + L + "/pg_data/x\\y",
		"backup/" + s + "/" + L + "/pg_data/" + strings.Repeat("x", 513),
		"backup/" + s + "/" + L + "/pg_tblspc/16384/x",
		"backup/" + s + "/" + L + "/other",
	}
	for _, rel := range refused {
		if k, tli, label, good := RepoPath(s, rel); good || k != None || tli != 0 || label != "" {
			t.Errorf("RepoPath(%q) = %v %d %q %v, want refused", rel, k, tli, label, good)
		}
	}

	// A stanza that is a prefix of another: each sees only its own tree.
	if _, _, _, good := RepoPath("p-1", "archive/p-10/archive.info"); good {
		t.Error("p-1 accepted p-10's path")
	}
	if _, _, _, good := RepoPath("p-10", "archive/p-1/archive.info"); good {
		t.Error("p-10 accepted p-1's path")
	}
	if _, _, _, good := RepoPath("p-10", "archive/p-10/archive.info"); !good {
		t.Error("control: p-10 refused its own path")
	}
	for _, st := range []string{"", "a/b", "..", "."} {
		if _, _, _, good := RepoPath(st, "archive/"+st+"/archive.info"); good {
			t.Errorf("stanza %q accepted", st)
		}
	}
}

func TestSegmentOf(t *testing.T) {
	for in, want := range map[string]string{seg: seg, lbl: seg, hist: "", "x": "", seg + ".partial": ""} {
		if got := SegmentOf(in); got != want {
			t.Errorf("SegmentOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAdmitted(t *testing.T) {
	if !Admitted(7, nil) {
		t.Error("nil must admit all")
	}
	if Admitted(7, []uint32{}) {
		t.Error("empty list admitted")
	}
	if !Admitted(2, []uint32{1, 2}) || Admitted(3, []uint32{1, 2}) {
		t.Error("membership wrong")
	}
}

func TestPartial_Names(t *testing.T) {
	if !Partial(seg + ".partial") {
		t.Errorf("Partial(%q) refused", seg+".partial")
	}
	for _, n := range []string{
		"", ".partial", strings.ToLower(seg) + ".partial", seg[:23] + ".partial", seg + "0.partial",
		"-" + seg[1:] + ".partial", "--config=x.partial", "x/" + seg + ".partial", "../" + seg + ".partial",
		seg + ".partial.partial", lbl + ".partial", hist + ".partial", seg + ".partial\x00", seg + "\x00.partial",
		seg + ".partial\n", seg, seg + ".PARTIAL", seg + "partial", seg + "-partial", seg + "/partial",
	} {
		if Partial(n) {
			t.Errorf("Partial(%q) admitted", n)
		}
	}
	// The other name functions keep refusing it.
	if _, _, ok := Spool(seg + ".partial"); ok {
		t.Error("Spool admitted a .partial name")
	}
	if _, _, ok := Request(seg + ".partial"); ok {
		t.Error("Request admitted a .partial name")
	}
}
