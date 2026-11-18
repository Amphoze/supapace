package walname

import (
	"strings"
	"testing"
)

// Shapes a hostile cluster or repository can produce that look close to a
// listed name: look-alike digits, line ends, white space, edges of the fields.
func TestNames_HostileShapes(t *testing.T) {
	for _, n := range []string{
		seg + "\n", seg + "\r", "\n" + seg, seg + "\x00", seg + " ", "\t" + seg,
		hist + "\n", lbl + "\n", "00000003.history\x00",
		"０0000002000000010000003F",  // a full-width digit
		"00000002000000010000003Ｆ",  // a full-width letter
		"00000002000000010000003́F", // a combining mark
		strings.Repeat("0", 4096),
		"-00000003.history", "-" + lbl[1:], "--" + seg[2:],
		seg + "-00000028.backup", seg + ".00000028-backup", "00000003-history",
	} {
		if _, _, ok := Spool(n); ok {
			t.Errorf("Spool(%q) admitted", n)
		}
		if _, _, ok := Request(n); ok {
			t.Errorf("Request(%q) admitted", n)
		}
		if SegmentOf(n) != "" {
			t.Errorf("SegmentOf(%q) not empty", n)
		}
	}
	// Field edges: the timeline is read from the first eight digits only.
	for n, want := range map[string]uint32{
		"000000000000000000000000":                 0,
		"FFFFFFFF00000000000000FF":                 0xFFFFFFFF,
		"00000001FFFFFFFFFFFFFFFF":                 1,
		"FFFFFFFF.history":                         0xFFFFFFFF,
		"FFFFFFFFFFFFFFFFFFFFFFFF.FFFFFFFF.backup": 0xFFFFFFFF,
	} {
		if _, tli, ok := Spool(n); !ok || tli != want {
			t.Errorf("Spool(%q) = %d %v, want %d", n, tli, ok, want)
		}
	}
	const s = "st"
	for _, rel := range []string{
		"archive/st/archive.info\n", "archive/st\n/archive.info", "archive/st/17-1\n/" + hist,
		"archive/st/17-1/" + seg[:16] + "/" + seg + "-0123456789abcdef0123456789abcdef01234567.zst\n",
		"backup/st/20261119-120000F\n/backup.manifest", "backup/st/20261119-120000F/pg_data/x\n",
		"backup/st/backup.history/2026\n/20261119-120000F.manifest.gz",
		"backup/st/20261119-120000F/pg_data/ｘ", "ARCHIVE/st/archive.info", "archive/ST/archive.info",
		"archive/st/１7-1/" + hist,
	} {
		if _, _, _, ok := RepoPath(s, rel); ok {
			t.Errorf("RepoPath(%q) admitted", rel)
		}
	}
}
