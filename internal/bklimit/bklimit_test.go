package bklimit

import (
	"math"
	"testing"
	"time"
)

func TestDeadline_Table(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		at8192 time.Duration // disk and repository quota 8,192 MiB (the default tier)
		at1024 time.Duration
	}{
		{"push", 120 * time.Second, 120 * time.Second},
		{"replicate", 300 * time.Second, 300 * time.Second},
		{"stanza-create", 180 * time.Second, 180 * time.Second},
		{"check", 180 * time.Second, 180 * time.Second},
		{"backup", 710 * time.Second, 352 * time.Second},    // 300 + ceil(Qd/20)
		{"restore", 710 * time.Second, 352 * time.Second},   // 300 + ceil(Qd/20)
		{"fetch", 2348 * time.Second, 556 * time.Second},    // 300 + Qr/4
		{"seed", 284 * time.Second, 141 * time.Second},      // 120 + ceil(Qr/50)
		{"recover", 6232 * time.Second, 1304 * time.Second}, // 600 + Qr*11/16
		{"serve", 6232 * time.Second, 1304 * time.Second},   // the recover job's
		{"probe", 120 * time.Second, 120 * time.Second},
	} {
		for _, q := range []struct {
			mb   int
			want time.Duration
		}{{8192, tc.at8192}, {1024, tc.at1024}} {
			got, err := Deadline(tc.kind, q.mb, q.mb)
			if err != nil || got != q.want {
				t.Errorf("Deadline(%q, %d, %d) = %v, %v; want %v", tc.kind, q.mb, q.mb, got, err, q.want)
			}
		}
	}
	// The disk quota sizes backup and restore, the repository quota the rest.
	if d, _ := Deadline("backup", 2000, 8192); d != 400*time.Second {
		t.Errorf("backup with Qd 2000 = %v, want 400s", d)
	}
	if d, _ := Deadline("fetch", 8192, 400); d != 400*time.Second {
		t.Errorf("fetch with Qr 400 = %v, want 400s", d)
	}
}

func TestDeadline_UnknownKindIsAnError(t *testing.T) {
	for _, k := range []string{"", "Push", "copy", "rebuild", "expire", "verify", "push "} {
		if d, err := Deadline(k, 8192, 8192); err == nil {
			t.Errorf("Deadline(%q) = %v, nil; want an error", k, d)
		}
	}
	// Control on the same path: the two kinds that are not queue kinds are known.
	for _, k := range []string{"serve", "probe"} {
		if _, err := Deadline(k, 8192, 8192); err != nil {
			t.Errorf("Deadline(%q) = %v", k, err)
		}
	}
	for _, q := range [][2]int{{-1, 8192}, {8192, -1}} {
		if _, err := Deadline("push", q[0], q[1]); err == nil {
			t.Errorf("Deadline with quotas %v: want an error", q)
		}
	}
}

func TestPushLoopMax(t *testing.T) {
	for mb, want := range map[int]int{8192: 12, 1024: 4, 896: 3, 897: 4, 0: 2} {
		if got := PushLoopMax(mb); got != want {
			t.Errorf("PushLoopMax(%d) = %d, want %d", mb, got, want)
		}
	}
}

func TestReplLoopMax(t *testing.T) {
	for mb, want := range map[int]int{8192: 18, 1280: 6, 1281: 8, 1024: 6, 0: 4} {
		if got := ReplLoopMax(mb); got != want {
			t.Errorf("ReplLoopMax(%d) = %d, want %d", mb, got, want)
		}
	}
}

func TestBudgets_Defaults(t *testing.T) {
	b, o := Budgets(8192, 0, 0)
	if b != 17179869184 || o != 32768 {
		t.Errorf("Budgets(8192) = %d, %d; want 17179869184, 32768", b, o)
	}
	// The object floor: 2 × 1,024 MiB is 4,096 objects of 0.5 MiB, below 7,500.
	if b, o := Budgets(1024, 0, 0); b != 2<<30 || o != 7500 {
		t.Errorf("Budgets(1024) = %d, %d; want %d, 7500", b, o, int64(2<<30))
	}
	// Overrides: bytes in MiB a day; objects as given; objects follow the overridden bytes when only bytes are set.
	if b, o := Budgets(8192, 1000, 0); b != 1000<<20 || o != 7500 {
		t.Errorf("Budgets(8192, 1000, 0) = %d, %d", b, o)
	}
	if b, o := Budgets(8192, 65536, 0); b != 65536<<20 || o != 131072 {
		t.Errorf("Budgets(8192, 65536, 0) = %d, %d", b, o)
	}
	if b, o := Budgets(8192, 0, 100); b != 17179869184 || o != 100 {
		t.Errorf("Budgets(8192, 0, 100) = %d, %d", b, o)
	}
}

func TestReplMemMB(t *testing.T) {
	for rows, want := range map[int64]int{0: 256, 1: 256, 2_560_000: 256, 2_560_001: 257, 2_949_120: 276, 2_950_000: 276, 20_000_000: 1128} {
		if got := ReplMemMB(rows); got != want {
			t.Errorf("ReplMemMB(%d) = %d, want %d", rows, got, want)
		}
	}
}

func TestFetchMargin(t *testing.T) {
	base := 60*time.Second + PushLagShown + ReplLagShown // 960 s
	for extra, want := range map[int]time.Duration{0: base, 1: 2 * base, 2: 4 * base, 3: 8 * base, -1: base} {
		if got := FetchMargin(60*time.Second, extra); got != want {
			t.Errorf("FetchMargin(60s, %d) = %v, want %v", extra, got, want)
		}
	}
	for _, extra := range []int{4, 5, 64, math.MaxInt} {
		if got := FetchMargin(60*time.Second, extra); got != WholeArchive {
			t.Errorf("FetchMargin(60s, %d) = %v, want the whole archive", extra, got)
		}
	}
}

func TestConstants(t *testing.T) {
	// The archive binary's restore timeout must equal GetTimeout; the serving side compares the two.
	if GetTimeout != 120*time.Second || PushMaxEntries*16 != 896 || ResultMax != 1<<20 {
		t.Error("a fixed figure changed")
	}
	if SegmentMax != 16<<20+1<<10 || SetFileMax != 1<<30+16<<20 || SmallMax != 1<<20 {
		t.Error("an object bound changed")
	}
}

// Each kind reads its own quota: backup and restore the disk quota, fetch, seed,
// recover and serve the repository quota.
func TestDeadline_EachKindItsQuota(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want time.Duration // disk quota 2,000 MiB, repository quota 8,192 MiB
	}{
		{"backup", 400 * time.Second}, {"restore", 400 * time.Second},
		{"fetch", 2348 * time.Second}, {"seed", 284 * time.Second},
		{"recover", 6232 * time.Second}, {"serve", 6232 * time.Second},
	} {
		if got, err := Deadline(tc.kind, 2000, 8192); err != nil || got != tc.want {
			t.Errorf("Deadline(%q, 2000, 8192) = %v, %v; want %v", tc.kind, got, err, tc.want)
		}
	}
}

// Every fixed figure, as the limits table states it.
func TestConstants_All(t *testing.T) {
	for name, c := range map[string][2]int64{
		"PushInterval":      {int64(PushInterval), int64(60 * time.Second)},
		"SchedulerTick":     {int64(SchedulerTick), int64(5 * time.Second)},
		"PushMaxEntries":    {PushMaxEntries, 56},
		"ReplMaxFiles":      {ReplMaxFiles, 2048},
		"ReplMaxBytes":      {ReplMaxBytes, 1280 << 20},
		"ReplMaxEntries":    {ReplMaxEntries, 250000},
		"RebuildPageRows":   {RebuildPageRows, 4000},
		"RebuildMaxPages":   {RebuildMaxPages, 2048},
		"PartSize":          {PartSize, 32 << 20},
		"ServeMaxAnswers":   {ServeMaxAnswers, 8},
		"PushLagShown":      {int64(PushLagShown), int64(300 * time.Second)},
		"ReplLagShown":      {int64(ReplLagShown), int64(600 * time.Second)},
		"DrainPushWait":     {int64(DrainPushWait), int64(60 * time.Second)},
		"RecordHorizonDays": {RecordHorizonDays, 90},
		"JobRowAge":         {int64(JobRowAge), int64(48 * time.Hour)},
		"PruneBatch":        {PruneBatch, 10000},
		"PruneEvery":        {int64(PruneEvery), int64(time.Hour)},
		"SpoolTmpAge":       {int64(SpoolTmpAge), int64(time.Hour)},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %d, want %d", name, c[0], c[1])
		}
	}
}
