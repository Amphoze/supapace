package bkjob

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/walname"
)

// lab is one push job's world: a spool, a repository, the job's private
// temporary directory and the fake tool.
type lab struct {
	t                      *testing.T
	spool, repo, tmp, tool string
}

func newLab(t *testing.T) *lab {
	t.Helper()
	d := t.TempDir()
	l := &lab{t: t, spool: filepath.Join(d, "spool"), repo: filepath.Join(d, "repo"), tmp: filepath.Join(d, "tmp"), tool: fakeTool(t)}
	for _, p := range []string{l.spool, l.repo, l.tmp} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := repoRoot
	repoRoot = l.repo
	t.Cleanup(func() { repoRoot = old })
	oldPriv := privRoot
	privRoot = l.tmp
	t.Cleanup(func() { privRoot = oldPriv })
	t.Setenv("TMPDIR", t.TempDir()) // not followed: the private copy goes below privRoot
	return l
}

// input is a project's push input admitting tls (an empty list admits none).
func (l *lab) input(tls ...uint32) jobio.Input {
	return jobio.Input{Job: 7, Kind: "push", Subject: "ref", Stanza: "ref-1", UID: os.Getuid(),
		Timelines: append([]uint32{}, tls...), MaxEntries: bklimit.PushMaxEntries}
}

// put writes a spool entry; a segment is padded with zeros to the smallest
// segment size, so that only its first bytes need be given.
func (l *lab) put(name, data string) {
	l.t.Helper()
	p := filepath.Join(l.spool, name)
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		l.t.Fatal(err)
	}
	if k, _, _ := walname.Spool(name); k == walname.Segment && len(data) < segmentMin {
		if err := os.Truncate(p, segmentMin); err != nil {
			l.t.Fatal(err)
		}
	}
}

// head is the first n bytes of the spool entry name.
func (l *lab) head(name string, n int) string {
	b, _ := os.ReadFile(filepath.Join(l.spool, name))
	return string(b[:min(len(b), n)])
}

// pushed is the base names the tool was handed, in order.
func (l *lab) pushed() []string {
	var out []string
	for _, c := range calls(l.t, l.tool) {
		out = append(out, filepath.Base(c.Args[len(c.Args)-1]))
	}
	return out
}

// entries is the spool's names.
func (l *lab) entries() []string {
	l.t.Helper()
	es, err := os.ReadDir(l.spool)
	if err != nil {
		l.t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// moved is the spool entry a quarantine renamed name to ("" when none).
func (l *lab) moved(name string) string {
	for _, e := range l.entries() {
		if e != name && strings.HasPrefix(e, name) {
			return e
		}
	}
	return ""
}

func (l *lab) push(in jobio.Input) jobio.PushResult {
	l.t.Helper()
	r, err := Push(context.Background(), in, l.spool)
	if err != nil {
		l.t.Fatalf("Push: %v", err)
	}
	return r
}

func reasons(r jobio.PushResult) map[string]string {
	m := map[string]string{}
	for _, q := range r.Quarantined {
		m[q.Name] = q.Reason
	}
	return m
}

func failCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprintf("not a job failure: %v", err)
}

// lutimes sets a path's times without following a link.
func lutimes(t *testing.T, p string, at time.Time) {
	t.Helper()
	b, err := syscall.BytePtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	ts := [2]syscall.Timespec{syscall.NsecToTimespec(at.UnixNano()), syscall.NsecToTimespec(at.UnixNano())}
	const atSymlinkNoFollow = 0x100
	cwd := -100 // AT_FDCWD
	if _, _, e := syscall.Syscall6(syscall.SYS_UTIMENSAT, uintptr(cwd), uintptr(unsafe.Pointer(b)),
		uintptr(unsafe.Pointer(&ts[0])), atSymlinkNoFollow, 0, 0); e != 0 {
		t.Fatal(e)
	}
}

func TestPush_OldestFirst_HistoryBeforeSegments(t *testing.T) {
	l := newLab(t)
	names := []string{"000000020000000000000004", "000000010000000000000003", "00000002.history",
		"000000010000000000000002.00000028.backup", "000000010000000000000002", "00000001.history"}
	for _, n := range names {
		l.put(n, n)
	}
	r := l.push(l.input(1, 2))
	want := []string{"00000001.history", "00000002.history", "000000010000000000000002",
		"000000010000000000000002.00000028.backup", "000000010000000000000003", "000000020000000000000004"}
	if got := l.pushed(); !slices.Equal(got, want) {
		t.Errorf("order %q, want %q", got, want)
	}
	if r.Pushed != 6 || r.First != want[0] || r.Last != want[5] {
		t.Errorf("pushed %d, first %q, last %q", r.Pushed, r.First, r.Last)
	}
}

func TestPush_CopiesToPrivateDirAndPassesThatPath(t *testing.T) {
	l := newLab(t)
	l.put("000000010000000000000001", "segment bytes")
	l.push(l.input(1))
	cs := calls(t, l.tool)
	if len(cs) != 1 {
		t.Fatalf("%d calls", len(cs))
	}
	p := cs[0].Args[len(cs[0].Args)-1]
	if cs[0].Args[0] != "archive-push" || len(cs[0].Args) != 2 {
		t.Errorf("argv %q", cs[0].Args)
	}
	if strings.HasPrefix(p, l.spool) || !strings.HasPrefix(p, l.tmp+"/") || filepath.Base(p) != "000000010000000000000001" {
		t.Errorf("the tool was handed %q, want a copy under %s with the entry's name", p, l.tmp)
	}
	if string(cs[0].Data[:13]) != "segment bytes" || cs[0].Size != segmentMin {
		t.Errorf("the copy holds %q…, %d bytes", cs[0].Data, cs[0].Size)
	}
	if left, _ := os.ReadDir(l.tmp); len(left) != 0 {
		t.Errorf("the private directory is left behind: %v", left)
	}
}

func TestPush_DeletesOnlyAfterExit0(t *testing.T) {
	l := newLab(t)
	script(t, l.tool, map[string]step{"000000010000000000000002": {Exit: 1, Out: "ERROR: [055]: something\n"}})
	l.put("000000010000000000000001", "a")
	l.put("000000010000000000000002", "b")
	_, err := Push(context.Background(), l.input(1), l.spool)
	if failCode(err) != CodeRepository {
		t.Fatalf("Push = %v", err)
	}
	if got := l.entries(); !slices.Equal(got, []string{"000000010000000000000002"}) {
		t.Errorf("spool %q: the pushed entry must be gone and the failed one kept", got)
	}
	if b := l.head("000000010000000000000002", 2); b != "b\x00" {
		t.Errorf("the failed entry holds %q", b)
	}
}

func TestPush_MaxEntries(t *testing.T) {
	l := newLab(t)
	for i := range 60 {
		l.put(fmt.Sprintf("0000000100000000%08X", i+1), "s")
	}
	r := l.push(l.input(1))
	if r.Pushed != 56 || r.Remaining != 4 || r.Complete || len(l.entries()) != 4 {
		t.Errorf("pushed %d, remaining %d, complete %v, left %d", r.Pushed, r.Remaining, r.Complete, len(l.entries()))
	}
	if r.Last != "000000010000000000000038" || r.SpoolEntries != 4 || r.SpoolBytes != 4*segmentMin || r.SpoolOldest == nil {
		t.Errorf("last %q, spool %d entries %d bytes oldest %v", r.Last, r.SpoolEntries, r.SpoolBytes, r.SpoolOldest)
	}
	in := l.input(1)
	in.MaxEntries = 3
	if r := l.push(in); r.Pushed != 3 || r.Remaining != 1 {
		t.Errorf("max 3: pushed %d, remaining %d", r.Pushed, r.Remaining)
	}
	// Above the platform's cap, or unset: the cap.
	for i := range 60 {
		l.put(fmt.Sprintf("0000000100000001%08X", i+1), "s")
	}
	in.MaxEntries = 1000
	if r := l.push(in); r.Pushed != 56 {
		t.Errorf("max 1000: pushed %d, want the cap of 56", r.Pushed)
	}
	in.MaxEntries = 0
	if r := l.push(in); r.Pushed != 5 || !r.Complete {
		t.Errorf("max 0: pushed %d, complete %v", r.Pushed, r.Complete)
	}
}

// Quarantined entries count against the cap and towards completeness.
func TestPush_CompleteFlag(t *testing.T) {
	l := newLab(t)
	l.put("000000010000000000000001", "a")
	l.put("000000030000000000000001", "not admitted")
	r := l.push(l.input(1))
	if !r.Complete || r.Remaining != 0 || r.Pushed != 1 || len(r.Quarantined) != 1 {
		t.Errorf("complete %v, remaining %d, pushed %d, quarantined %v", r.Complete, r.Remaining, r.Pushed, r.Quarantined)
	}
	if r.SpoolEntries != 0 || r.SpoolBytes != 0 || r.SpoolOldest != nil {
		t.Errorf("an emptied spool reports %d entries, %d bytes, oldest %v", r.SpoolEntries, r.SpoolBytes, r.SpoolOldest)
	}
	l.put("000000010000000000000002", "a")
	l.put("000000030000000000000002", "not admitted")
	in := l.input(1)
	in.MaxEntries = 1
	if r := l.push(in); r.Complete || r.Remaining != 1 {
		t.Errorf("capped: complete %v, remaining %d", r.Complete, r.Remaining)
	}
	if r := l.push(l.input(1)); !r.Complete {
		t.Error("the rest: not complete")
	}
}

func TestPush_SymlinkEntryQuarantined(t *testing.T) {
	l := newLab(t)
	secret := filepath.Join(t.TempDir(), "environ")
	os.WriteFile(secret, []byte("SECRET"), 0o600)
	for _, n := range []string{"000000010000000000000001", "00000002.history"} {
		if err := os.Symlink(secret, filepath.Join(l.spool, n)); err != nil {
			t.Fatal(err)
		}
	}
	l.put("000000010000000000000002", "own")
	r := l.push(l.input(1, 2))
	if got := l.pushed(); !slices.Equal(got, []string{"000000010000000000000002"}) {
		t.Errorf("pushed %q: only the regular entry", got)
	}
	for _, n := range []string{"000000010000000000000001", "00000002.history"} {
		if reasons(r)[n] != "shape" {
			t.Errorf("%s: reason %q, want shape", n, reasons(r)[n])
		}
		if to, _ := os.Readlink(filepath.Join(l.spool, l.moved(n))); to != secret {
			t.Errorf("%s: the link itself must be set aside (got %q)", n, l.moved(n))
		}
	}
	for _, c := range calls(t, l.tool) {
		if strings.Contains(string(c.Data), "SECRET") {
			t.Error("the link's target reached the tool")
		}
	}
}

func TestPush_FifoAndDirectoryQuarantined(t *testing.T) {
	l := newLab(t)
	if err := syscall.Mkfifo(filepath.Join(l.spool, "000000010000000000000001"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(l.spool, "000000010000000000000002"), 0o700)
	l.put("000000010000000000000003", "own")
	r := l.push(l.input(1))
	if reasons(r)["000000010000000000000001"] != "shape" || reasons(r)["000000010000000000000002"] != "shape" {
		t.Errorf("quarantined %v", r.Quarantined)
	}
	if got := l.pushed(); !slices.Equal(got, []string{"000000010000000000000003"}) {
		t.Errorf("pushed %q", got)
	}
	if fi, err := os.Lstat(filepath.Join(l.spool, l.moved("000000010000000000000002"))); err != nil || !fi.IsDir() {
		t.Errorf("the directory was not set aside (%v)", err)
	}
}

func TestPush_ForeignOwnerQuarantined(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to give a file another owner")
	}
	l := newLab(t)
	l.put("000000010000000000000001", "foreign")
	l.put("000000010000000000000002", "own")
	if err := os.Lchown(filepath.Join(l.spool, "000000010000000000000001"), 12345, 12345); err != nil {
		t.Fatal(err)
	}
	r := l.push(l.input(1))
	if reasons(r)["000000010000000000000001"] != "shape" {
		t.Errorf("quarantined %v", r.Quarantined)
	}
	if got := l.pushed(); !slices.Equal(got, []string{"000000010000000000000002"}) {
		t.Errorf("pushed %q", got)
	}
}

func TestPush_OversizeQuarantined(t *testing.T) {
	l := newLab(t)
	size := func(name string, n int64) {
		l.put(name, "")
		if err := os.Truncate(filepath.Join(l.spool, name), n); err != nil {
			t.Fatal(err)
		}
	}
	size("000000010000000000000001", bklimit.SegmentMax+1)
	size("000000010000000000000002", bklimit.SegmentMax)
	size("00000001.history", bklimit.SmallMax+1)
	size("000000010000000000000003.00000028.backup", bklimit.SmallMax+1)
	size("000000010000000000000004.00000028.backup", bklimit.SmallMax)
	r := l.push(l.input(1))
	want := map[string]string{"000000010000000000000001": "shape", "00000001.history": "shape", "000000010000000000000003.00000028.backup": "shape"}
	if !maps.Equal(reasons(r), want) {
		t.Errorf("quarantined %v, want %v", reasons(r), want)
	}
	if got := l.pushed(); !slices.Equal(got, []string{"000000010000000000000002", "000000010000000000000004.00000028.backup"}) {
		t.Errorf("pushed %q: the entries at their bound must pass", got)
	}
}

// The size that counts is the opened entry's, not the listing's.
func TestPush_SizeIsCheckedOnTheOpenedEntry(t *testing.T) {
	l := newLab(t)
	p := filepath.Join(l.spool, "00000001.history")
	l.put("00000001.history", "small")
	listed = func() {
		f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
		f.Write(make([]byte, bklimit.SmallMax))
		f.Close()
	}
	t.Cleanup(func() { listed = nil })
	r := l.push(l.input(1))
	if reasons(r)["00000001.history"] != "shape" || len(l.pushed()) != 0 {
		t.Errorf("quarantined %v, pushed %q", r.Quarantined, l.pushed())
	}
}

func TestPush_CraftedNamesIgnoredAndCounted(t *testing.T) {
	l := newLab(t)
	crafted := []string{"--config=x", "00000001000000ff000000fe", "000000010000000000000001.partial", "00000001.HISTORY", "x"}
	for _, n := range crafted {
		l.put(n, "x")
	}
	l.put("000000010000000000000001", "s")
	r := l.push(l.input(1))
	if r.OtherEntries != len(crafted) || r.Pushed != 1 || len(r.Quarantined) != 0 {
		t.Errorf("other %d, pushed %d, quarantined %v", r.OtherEntries, r.Pushed, r.Quarantined)
	}
	if got := l.entries(); !slices.Equal(got, slices.Sorted(slices.Values(crafted))) {
		t.Errorf("spool %q: the crafted names must be left as they are", got)
	}
	if got := l.pushed(); !slices.Equal(got, []string{"000000010000000000000001"}) {
		t.Errorf("pushed %q", got)
	}
}

func TestPush_TemporariesIgnoredAndRemovedWhenOld(t *testing.T) {
	l := newLab(t)
	old := time.Now().Add(-bklimit.SpoolTmpAge - time.Minute)
	path := func(n string) string { return filepath.Join(l.spool, n) }
	exists := func(n string) bool { _, err := os.Lstat(path(n)); return err == nil }

	l.put(".tmp-young", "y")
	// Old: a FIFO (opening it would block) and an unreadable file — removed
	// without being opened or read.
	syscall.Mkfifo(path(".tmp-oldfifo"), 0o600)
	l.put(".tmp-oldfile", "o")
	os.Chmod(path(".tmp-oldfile"), 0)
	// A link: its own time counts, never its target's.
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("t"), 0o600)
	os.Chtimes(target, old, old)
	os.Symlink(target, path(".tmp-younglink"))
	os.Symlink(target, path(".tmp-oldlink"))
	os.Mkdir(path(".tmp-olddir"), 0o700)
	for _, n := range []string{".tmp-oldfifo", ".tmp-oldfile", ".tmp-oldlink", ".tmp-olddir"} {
		lutimes(t, path(n), old)
	}
	// .partial is never in a spool; planted, it is an ordinary other entry.
	l.put("000000010000000000000001.partial", "p")
	lutimes(t, path("000000010000000000000001.partial"), old)

	r := l.push(l.input(1))
	for n, want := range map[string]bool{".tmp-young": true, ".tmp-oldfifo": false, ".tmp-oldfile": false,
		".tmp-younglink": true, ".tmp-oldlink": false, ".tmp-olddir": true, "000000010000000000000001.partial": true} {
		if exists(n) != want {
			t.Errorf("%s: present %v, want %v", n, exists(n), want)
		}
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the old link's target was removed: %v", err)
	}
	if r.OtherEntries != 4 || len(l.pushed()) != 0 {
		t.Errorf("other entries %d (want the young file, the young link, the directory, the .partial), pushed %q", r.OtherEntries, l.pushed())
	}

	// At most 1,024 a pass; the rest the next pass, counted meanwhile.
	l2 := newLab(t)
	for i := range 1025 {
		p := filepath.Join(l2.spool, fmt.Sprintf(".tmp-%04d", i))
		os.WriteFile(p, nil, 0o600)
		os.Chtimes(p, old, old)
	}
	r = l2.push(l2.input(1))
	if n := len(l2.entries()); n != 1 || r.OtherEntries != 1 {
		t.Errorf("after one pass: %d left, %d counted; want 1 and 1", n, r.OtherEntries)
	}
	if r = l2.push(l2.input(1)); len(l2.entries()) != 0 || r.OtherEntries != 0 {
		t.Errorf("after the second pass: %d left", len(l2.entries()))
	}
}

func TestPush_UnadmittedTimelineQuarantined(t *testing.T) {
	l := newLab(t)
	bad := []string{"00000003.history", "000000030000000000000001", "000000030000000000000001.00000028.backup"}
	for _, n := range bad {
		l.put(n, n)
	}
	l.put("000000020000000000000001", "ok")
	r := l.push(l.input(1, 2))
	for _, n := range bad {
		if reasons(r)[n] != "timeline" || l.moved(n) == "" {
			t.Errorf("%s: reason %q, moved to %q", n, reasons(r)[n], l.moved(n))
		}
	}
	if got := l.pushed(); !slices.Equal(got, []string{"000000020000000000000001"}) {
		t.Errorf("pushed %q", got)
	}
	// An empty list admits none.
	l.put("000000010000000000000009", "x")
	if r := l.push(l.input()); reasons(r)["000000010000000000000009"] != "timeline" {
		t.Errorf("an empty timeline list: %v", r.Quarantined)
	}
}

func TestPush_Refused44_45_46Quarantined_OthersFailJob(t *testing.T) {
	l := newLab(t)
	script(t, l.tool, map[string]step{
		"000000010000000000000001": {Exit: 44, Out: "ERROR: [044]: system-id mismatch\n"},
		"000000010000000000000002": {Exit: 45, Out: "ERROR: [045]: already exists\n"},
		"000000010000000000000003": {Exit: 46, Out: "ERROR: [046]: unexpected WAL magic\n"},
		"000000010000000000000005": {Exit: 47, Out: "ERROR: [047]: other\n"},
	})
	for i := 1; i <= 4; i++ {
		l.put(fmt.Sprintf("00000001000000000000000%d", i), "s")
	}
	r := l.push(l.input(1))
	want := map[string]string{"000000010000000000000001": "refused-44", "000000010000000000000002": "refused-45", "000000010000000000000003": "refused-46"}
	if !maps.Equal(reasons(r), want) || r.Pushed != 1 || !r.Complete {
		t.Errorf("quarantined %v, pushed %d, complete %v", reasons(r), r.Pushed, r.Complete)
	}
	for n := range want {
		if l.head(l.moved(n), 2) != "s\x00" {
			t.Errorf("%s: set aside without its bytes", n)
		}
	}
	l.put("000000010000000000000005", "s")
	if _, err := Push(context.Background(), l.input(1), l.spool); failCode(err) != CodeRepository {
		t.Errorf("exit 47: %v", err)
	}
	if !slices.Contains(l.entries(), "000000010000000000000005") {
		t.Error("the entry of a failed push was moved")
	}
}

func TestPush_Exit104NamingAQuotaErrorIsRepositoryQuota(t *testing.T) {
	l := newLab(t)
	script(t, l.tool, map[string]step{"*": {Exit: 104, Out: "repo1: [FileWriteError] unable to write '/repo/x.pgbackrest.tmp': [122] Quota exceeded\nERROR: [104]: archive-push command encountered error(s)\n"}})
	l.put("000000010000000000000001", "s")
	if _, err := Push(context.Background(), l.input(1), l.spool); failCode(err) != CodeRepositoryQuota {
		t.Errorf("104 with [122]: %v", err)
	}
	if !slices.Equal(l.entries(), []string{"000000010000000000000001"}) {
		t.Errorf("spool %q: the entry stays", l.entries())
	}
	script(t, l.tool, map[string]step{"*": {Exit: 104, Out: "repo1: [FileMoveError] unable to move\nERROR: [104]: archive-push command encountered error(s)\n"}})
	if _, err := Push(context.Background(), l.input(1), l.spool); failCode(err) != CodeRepository {
		t.Errorf("104 without [122]: %v", err)
	}
}

func TestPush_QuarantineNameLeavesPattern(t *testing.T) {
	l := newLab(t)
	script(t, l.tool, map[string]step{"*": {Exit: 45}})
	names := []string{"00000001.history", "000000010000000000000001", "000000010000000000000001.00000028.backup", "00000005.history"}
	for _, n := range names {
		l.put(n, "s")
	}
	r := l.push(l.input(1))
	if len(r.Quarantined) != 4 || r.Pushed != 0 {
		t.Fatalf("quarantined %v", r.Quarantined)
	}
	if got := l.entries(); len(got) != 4 {
		t.Fatalf("spool %q", got)
	}
	for _, e := range l.entries() {
		_, _, ok := walname.Spool(e)
		if ok || strings.HasPrefix(e, ".tmp-") || walname.Partial(e) {
			t.Errorf("quarantined as %q: inside a pattern", e)
		}
	}
	for _, q := range r.Quarantined {
		if !slices.Contains(names, q.Name) {
			t.Errorf("reported %q, want the entry's own name", q.Name)
		}
	}
	// A second pass takes nothing of them.
	if r := l.push(l.input(1)); r.OtherEntries != 4 || len(calls(t, l.tool)) != 3 {
		t.Errorf("second pass: other %d, calls %d", r.OtherEntries, len(calls(t, l.tool)))
	}
}

func TestPush_EntrySwappedAfterListing(t *testing.T) {
	l := newLab(t)
	secret := filepath.Join(t.TempDir(), "environ")
	os.WriteFile(secret, []byte("SECRET"), 0o600)
	p := filepath.Join(l.spool, "000000010000000000000001")
	l.put("000000010000000000000001", "regular at listing")
	listed = func() {
		os.Remove(p)
		os.Symlink(secret, p)
	}
	t.Cleanup(func() { listed = nil })
	r := l.push(l.input(1))
	if reasons(r)["000000010000000000000001"] != "shape" || len(calls(t, l.tool)) != 0 {
		t.Errorf("quarantined %v, calls %d", r.Quarantined, len(calls(t, l.tool)))
	}
	if to, _ := os.Readlink(filepath.Join(l.spool, l.moved("000000010000000000000001"))); to != secret {
		t.Error("the link was not set aside as a link")
	}
}

// repoFile creates rel below the repository (directories as needed).
func (l *lab) repoFile(rel string) {
	l.t.Helper()
	p := filepath.Join(l.repo, rel)
	os.MkdirAll(filepath.Dir(p), 0o750)
	if err := os.WriteFile(p, nil, 0o640); err != nil {
		l.t.Fatal(err)
	}
}

func seg(name string) string {
	return name[:16] + "/" + name + "-0123456789abcdef0123456789abcdef01234567.zst"
}

func TestPush_ReportsHistoriesInRepo(t *testing.T) {
	l := newLab(t)
	for _, rel := range []string{"archive/ref-1/17-1/00000002.history", "archive/ref-1/17-2/00000004.history",
		"archive/ref-1/17-2/00000002.history", // the same name under a second archive id: once
		"archive/ref-1/17-1/00000003.history.bak", "archive/ref-1/17-1/0000000a.history",
		"archive/ref-10/17-1/00000009.history", "archive/ref-1/archive.info"} {
		l.repoFile(rel)
	}
	os.MkdirAll(filepath.Join(l.repo, "archive/ref-1/17-1/00000005.history"), 0o750)
	r := l.push(l.input(1, 2)) // timeline 4 is not admitted: held all the same
	if want := []string{"00000002.history", "00000004.history"}; !slices.Equal(r.Histories, want) {
		t.Errorf("histories %q, want %q", r.Histories, want)
	}
	// None at all: an empty list.
	l2 := newLab(t)
	if r := l2.push(l2.input(1)); r.Histories == nil || len(r.Histories) != 0 || r.Newest == nil || len(r.Newest) != 0 {
		t.Errorf("an empty repository: histories %v, newest %v", r.Histories, r.Newest)
	}
}

func TestPush_NewestIsReadFromTheRepository_AlsoWhenNothingWasPushed(t *testing.T) {
	l := newLab(t)
	for _, rel := range []string{
		"archive/ref-1/17-1/" + seg("000000010000000000000005"),
		"archive/ref-1/17-1/" + seg("0000000100000001000000A0"),
		"archive/ref-1/17-1/" + seg("000000010000000100000003"),
		"archive/ref-1/17-1/" + seg("000000020000000000000007"),
		"archive/ref-1/17-1/" + seg("000000030000000000000009"), // not admitted
		// Outside the pattern, each with a higher number: not counted.
		"archive/ref-1/17-1/0000000100000002/0000000100000002000000FF-0123.zst",
		"archive/ref-1/17-1/0000000100000002/0000000100000002000000FE-0123456789abcdef0123456789abcdef01234567.zst.pgbackrest.tmp",
		"archive/ref-1/17-1/0000000100000003/0000000100000004000000FF-0123456789abcdef0123456789abcdef01234567.zst",
		"archive/ref-1/17-x/" + seg("000000010000000500000001"),
		"archive/ref-2/17-1/" + seg("000000010000000600000001"),
		// A label is no segment.
		"archive/ref-1/17-1/0000000200000000/000000020000000000000009.00000028.backup",
	} {
		l.repoFile(rel)
	}
	r := l.push(l.input(1, 2))
	want := map[string]string{"00000001": "0000000100000001000000A0", "00000002": "000000020000000000000007"}
	if !maps.Equal(r.Newest, want) || len(calls(t, l.tool)) != 0 {
		t.Errorf("newest %v, want %v", r.Newest, want)
	}
	// What a push adds counts at once.
	l.repoFile("archive/ref-1/17-2/" + seg("000000020000000000000010"))
	if r := l.push(l.input(1, 2)); r.Newest["00000002"] != "000000020000000000000010" {
		t.Errorf("a second archive id: newest %v", r.Newest)
	}
}

// More than 64 timelines in the repository: the 64 highest.
func TestPush_NewestAndHistoriesAtMost64(t *testing.T) {
	l := newLab(t)
	var tls []uint32
	for tl := uint32(1); tl <= 70; tl++ {
		tls = append(tls, tl)
		l.repoFile(fmt.Sprintf("archive/ref-1/17-1/%08X.history", tl))
		l.repoFile("archive/ref-1/17-1/" + seg(fmt.Sprintf("%08X0000000000000001", tl)))
	}
	r := l.push(l.input(tls...))
	if len(r.Newest) != 64 || r.Newest["00000046"] == "" || r.Newest["00000006"] != "" || r.Newest["00000007"] == "" {
		t.Errorf("newest has %d timelines (6: %q, 7: %q, 70: %q)", len(r.Newest), r.Newest["00000006"], r.Newest["00000007"], r.Newest["00000046"])
	}
	if len(r.Histories) != 64 || r.Histories[0] != "00000007.history" || r.Histories[63] != "00000046.history" {
		t.Errorf("histories: %d, from %q", len(r.Histories), r.Histories)
	}
	if _, err := jobio.MarshalResult(r); err != nil {
		t.Fatal(err)
	}
}

func TestPush_ControlPlaneAdmitsAll(t *testing.T) {
	l := newLab(t)
	in := l.input()
	in.Subject, in.Stanza, in.Timelines = "cp", "cp-1", nil
	l.put("000000050000000000000001", "s")
	l.put("00000005.history", "h")
	l.repoFile("archive/cp-1/17-1/" + seg("000000070000000000000002"))
	r := l.push(in)
	if r.Pushed != 2 || len(r.Quarantined) != 0 || r.Newest["00000007"] != "000000070000000000000002" {
		t.Errorf("pushed %d, quarantined %v, newest %v", r.Pushed, r.Quarantined, r.Newest)
	}
}

// Every failure the push job can end with carries one of its kind's codes.
func TestPush_FailureCodesAreItsKinds(t *testing.T) {
	codes, ok := Codes("push")
	if !ok || !slices.Equal(codes, []string{CodeRepositoryQuota, CodeRepository, CodeSpool, CodeStopped}) {
		t.Fatalf("Codes(push) = %v, %v", codes, ok)
	}
	l := newLab(t)
	_, err := Push(context.Background(), l.input(1), filepath.Join(l.spool, "absent"))
	if failCode(err) != CodeSpool {
		t.Errorf("an absent spool: %v", err)
	}
	for _, k := range []string{"seed", "replicate", "fetch", "recover"} {
		if _, ok := Codes(k); ok {
			t.Errorf("Codes(%s) is known before its program exists", k)
		}
	}
}

// An entry gone between the listing and its turn is neither pushed nor
// reported as quarantined, and the job goes on.
func TestPush_EntryGoneAfterListing(t *testing.T) {
	l := newLab(t)
	for _, n := range []string{"000000010000000000000001", "000000030000000000000001", "000000010000000000000002"} {
		l.put(n, "s")
	}
	listed = func() {
		os.Remove(filepath.Join(l.spool, "000000010000000000000001"))
		os.Remove(filepath.Join(l.spool, "000000030000000000000001")) // not admitted: its quarantine finds nothing
	}
	t.Cleanup(func() { listed = nil })
	r := l.push(l.input(1))
	if len(r.Quarantined) != 0 || r.Pushed != 1 || !r.Complete || !slices.Equal(l.pushed(), []string{"000000010000000000000002"}) {
		t.Errorf("quarantined %v, pushed %d %q, complete %v", r.Quarantined, r.Pushed, l.pushed(), r.Complete)
	}
}

// A segment whose first page is no WAL long header is refused with 29: the
// entry is quarantined (shape), not retried for ever.
func TestPush_Refused29WalHeaderQuarantined(t *testing.T) {
	l := newLab(t)
	script(t, l.tool, map[string]step{"*": {Exit: 29, Out: "ERROR: [029]: first page header in WAL file is expected to be in long format\n"}})
	l.put("0000000100000000000000F0", "random")
	r := l.push(l.input(1))
	if reasons(r)["0000000100000000000000F0"] != "shape" || l.moved("0000000100000000000000F0") == "" {
		t.Errorf("quarantined %v", r.Quarantined)
	}
}

// A segment is never shorter than PostgreSQL's smallest segment size: a
// shorter one is quarantined before the tool reads it (the tool would fail on
// a short read and stall the spool on it).
func TestPush_ShortSegmentQuarantined(t *testing.T) {
	l := newLab(t)
	l.put("000000010000000000000001", "")
	os.Truncate(filepath.Join(l.spool, "000000010000000000000001"), segmentMin-1)
	l.put("000000010000000000000002", "")
	l.put("00000001.history", "1\t0/3000000\tsmall is fine\n")
	r := l.push(l.input(1))
	if !maps.Equal(reasons(r), map[string]string{"000000010000000000000001": "shape"}) {
		t.Errorf("quarantined %v", r.Quarantined)
	}
	if got := l.pushed(); !slices.Equal(got, []string{"00000001.history", "000000010000000000000002"}) {
		t.Errorf("pushed %q: a segment of the smallest size and a small history pass", got)
	}
}

// The pinned tool refuses a segment whose first page names an invalid segment
// size with exit 29 and its own message (not the long-header one). That is the
// entry's content, not the repository: the entry is set aside and the entries
// after it still flow. Red until such a segment is quarantined.
func TestReview_SegmentSizeRefusalIsQuarantinedNotAStall(t *testing.T) {
	l := newLab(t)
	script(t, l.tool, map[string]step{"000000010000000000000001": {Exit: 29,
		Out: "ERROR: [029]: wal segment size is 3 but must be a power of two between 1048576 and 1073741824 inclusive\n"}})
	l.put("000000010000000000000001", "")
	l.put("000000010000000000000002", "")
	r, err := Push(context.Background(), l.input(1), l.spool)
	if err != nil {
		t.Fatalf("the job failed (%v): the spool stalls on this entry for good", err)
	}
	if reasons(r)["000000010000000000000001"] != "shape" || l.moved("000000010000000000000001") == "" {
		t.Errorf("quarantined %v", r.Quarantined)
	}
	if r.Pushed != 1 || r.Last != "000000010000000000000002" {
		t.Errorf("pushed %d, last %q: the entry after it must flow", r.Pushed, r.Last)
	}
}

// An entry set aside in a pass that then fails is reported nowhere: the
// failure document carries no quarantine list, so the runner records no gap
// while the entry has left the pattern for good. Either the pass ends without
// setting it aside (the next pass decides again) or it ends with a result that
// lists it. Red until one of the two holds.
func TestReview_NoEntrySetAsideUnreportedWhenThePassFails(t *testing.T) {
	for _, tc := range []struct{ name, bad string }{
		{"link", "000000010000000000000001"},
		{"timeline", "000000030000000000000001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t)
			if tc.name == "link" {
				if err := os.Symlink("/proc/self/environ", filepath.Join(l.spool, tc.bad)); err != nil {
					t.Fatal(err)
				}
			} else {
				l.put(tc.bad, "")
			}
			l.put("000000040000000000000002", "")
			script(t, l.tool, map[string]step{"000000040000000000000002": {Exit: 1, Out: "ERROR: [055]: something\n"}})
			r, err := Push(context.Background(), l.input(1, 4), l.spool)
			_, lerr := os.Lstat(filepath.Join(l.spool, tc.bad))
			switch {
			case err != nil && lerr != nil:
				t.Errorf("the job failed (%v) and %s was set aside to %q, reported nowhere", err, tc.bad, l.moved(tc.bad))
			case err == nil && reasons(r)[tc.bad] == "" && lerr != nil:
				t.Errorf("%s set aside but not listed: %v", tc.bad, r.Quarantined)
			}
		})
	}
}

// A FIFO or a directory under a history or a label name is set aside by its
// type: those kinds have no smallest size that would catch it otherwise.
func TestReview_FifoAndDirectoryUnderSmallNamesQuarantined(t *testing.T) {
	l := newLab(t)
	if err := syscall.Mkfifo(filepath.Join(l.spool, "00000001.history"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(l.spool, "000000010000000000000002.00000028.backup"), 0o700)
	r := l.push(l.input(1))
	want := map[string]string{"00000001.history": "shape", "000000010000000000000002.00000028.backup": "shape"}
	if !maps.Equal(reasons(r), want) || len(l.pushed()) != 0 {
		t.Errorf("quarantined %v, pushed %q", r.Quarantined, l.pushed())
	}
}

// A pass stopped by its context ends with the code that says so, and sets
// nothing aside it had decided before the stop: the next pass decides again.
func TestPush_StoppedPassSetsNothingAside(t *testing.T) {
	l := newLab(t)
	if err := os.Symlink("/proc/self/environ", filepath.Join(l.spool, "000000010000000000000001")); err != nil {
		t.Fatal(err)
	}
	l.put("000000010000000000000002", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Push(ctx, l.input(1), l.spool)
	if failCode(err) != CodeStopped {
		t.Fatalf("a stopped pass: %v", err)
	}
	if got := l.entries(); !slices.Equal(got, []string{"000000010000000000000001", "000000010000000000000002"}) {
		t.Errorf("spool %q: nothing may be set aside or removed", got)
	}
	// Control: an unstopped pass sets the link aside and lists it.
	if r := l.push(l.input(1)); reasons(r)["000000010000000000000001"] != "shape" || r.Pushed != 1 {
		t.Errorf("control: quarantined %v, pushed %d", r.Quarantined, r.Pushed)
	}
}

// A spool of very many entries is read in batches: what the pass keeps after
// the listing is the lowest candidates up to the cap, not every entry; the
// rest is counted.
func TestPush_LargeSpoolKeepsOnlyTheLowestCandidates(t *testing.T) {
	l := newLab(t)
	const n = 50000
	for i := range n {
		f, err := os.Create(filepath.Join(l.spool, fmt.Sprintf("0000000100000000%08X", n-i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	l.put("00000001.history", "h")
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var kept uint64
	listed = func() {
		runtime.GC()
		runtime.ReadMemStats(&ms)
		kept = ms.HeapAlloc - min(ms.HeapAlloc, base)
	}
	t.Cleanup(func() { listed = nil })
	r := l.push(l.input(1))
	if kept > 1<<20 {
		t.Errorf("%d bytes kept after listing %d entries; want the lowest candidates only", kept, n)
	}
	if r.Pushed != 1 || r.First != "00000001.history" || len(r.Quarantined) != 55 ||
		r.Quarantined[0].Name != "000000010000000000000001" || r.Quarantined[54].Name != "000000010000000000000037" {
		t.Errorf("pushed %d (%q), quarantined %d from %v", r.Pushed, r.First, len(r.Quarantined), r.Quarantined[:min(2, len(r.Quarantined))])
	}
	if r.Remaining != n-55 || r.SpoolEntries != n-55 || r.Complete || r.SpoolOldest == nil {
		t.Errorf("remaining %d, spool entries %d, complete %v", r.Remaining, r.SpoolEntries, r.Complete)
	}
}

// The message names the tool's error line also when the console prefixes it
// with a timestamp and a hint follows it.
func TestPush_MessageNamesTheToolsErrorLine(t *testing.T) {
	out := "2026-01-02 03:04:05.678 P00  ERROR: [103]: unable to load info file\n                                    HINT: use --no-archive-check\n"
	if got := errorLine(out); !strings.Contains(got, "ERROR: [103]") {
		t.Errorf("errorLine = %q", got)
	}
}
