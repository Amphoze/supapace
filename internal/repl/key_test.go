package repl

import (
	"errors"
	"strings"
	"testing"
)

func TestKey_PrefixSubjectRel(t *testing.T) {
	for _, c := range []struct{ prefix, subject, rel, want string }{
		{"pre/fix", ref, seg(1, 1), "pre/fix/" + ref + "/" + seg(1, 1)},
		{"", ref, pArchInfo, ref + "/" + pArchInfo},
		{"p", "cp", "backup/cp-7437201938442670123/backup.info", "p/cp/backup/cp-7437201938442670123/backup.info"},
		{"p", ref, pSetFile, "p/" + ref + "/" + pSetFile},
	} {
		got, err := Key(c.prefix, c.subject, c.rel)
		if err != nil || got != c.want {
			t.Errorf("Key(%q, %q, %q) = %q, %v; want %q", c.prefix, c.subject, c.rel, got, err, c.want)
		}
	}
}

func TestKey_RefusesUnlistedAndTraversal(t *testing.T) {
	long := strings.Repeat("a", 257)
	for _, c := range []struct{ prefix, subject, rel string }{
		{"p", ref, "archive/" + stanza + "/../" + stanza + "/archive.info"},
		{"p", ref, "../" + pArchInfo},
		{"p", ref, "/" + pArchInfo},
		{"p", ref, pLatest},
		{"p", ref, "archive/" + stanza + "/17-1/000000010000000000000001.partial"},
		{"p", ref, "hx/many/000001"},
		{"p", ref, pSetFile + "/"},
		{"p", ref, "backup/" + stanza + "/" + label + "/pg_data/a//b"},
		{"p", ref, ""},
		{"/p", ref, pArchInfo},
		{"p/", ref, pArchInfo},
		{"p//q", ref, pArchInfo},
		{"p/../q", ref, pArchInfo},
		{long, ref, pArchInfo},
		{"p\n", ref, pArchInfo},
		{"p", "", pArchInfo},
		{"p", "../x", pArchInfo},
		{"p", "ABCDEFGHIJ0123456789", pArchInfo},
		{strings.Repeat("abcdefgh/", 29) + "x", ref, pArchInfo}, // 262 bytes of short segments
	} {
		if got, err := Key(c.prefix, c.subject, c.rel); !errors.Is(err, ErrPath) {
			t.Errorf("Key(%q, %q, %q) = %q, %v; want ErrPath", c.prefix, c.subject, c.rel, got, err)
		}
	}
}

// The subject of a key is the job's, never a name from the tree: a path of
// another project's stanza, or of the control plane's, is refused for this
// subject, and so is a stanza that only begins like the subject's.
func TestKey_SubjectNeverFromTree(t *testing.T) {
	other := "zzzzzzzzzz0123456789"
	for _, rel := range []string{
		"archive/" + other + "-1/archive.info",
		"archive/cp-1/archive.info",
		"archive/" + ref + "x-1/archive.info",
		"archive/" + ref + "/archive.info",
	} {
		if _, err := Key("p", ref, rel); !errors.Is(err, ErrPath) {
			t.Errorf("Key(%q) for subject %s: %v, want ErrPath", rel, ref, err)
		}
	}
	// In a copy, such a path in the tree is unlisted and nothing goes up under it.
	root := t.TempDir()
	mk(t, root, "archive/"+other+"-1/archive.info", "other")
	mk(t, root, pArchInfo, "own")
	f := newFake()
	r := run(t, root, input(), nil, f)
	if n := noticeOf(r, "unlisted-entry"); n == nil || n.Count != 1 {
		t.Errorf("unlisted-entry = %+v, want 1", n)
	}
	for k := range f.objs {
		if !strings.HasPrefix(k, "pre/fix/"+ref+"/archive/"+stanza+"/") {
			t.Errorf("uploaded %q", k)
		}
	}
	if len(f.objs) != 1 {
		t.Errorf("uploaded %d objects, want the own info file only", len(f.objs))
	}
}
