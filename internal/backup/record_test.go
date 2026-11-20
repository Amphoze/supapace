package backup

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/store"
)

// push runs one push of ref whose result is v.
func (e *env) push(ref string, res agent.JobResult) jobRow {
	e.t.Helper()
	e.ag.setScript("push", func(context.Context, agent.JobSpec) (agent.JobResult, error) { return res, nil })
	id := e.submit(ref, "push")
	if !e.turn("push") {
		e.t.Fatal("not picked")
	}
	return e.job(id)
}

func (e *env) state(ref string) store.BackupState {
	e.t.Helper()
	bs, err := e.st.GetBackupState(context.Background(), ref)
	must(e.t, err)
	return bs
}

func TestRecord_PushUpdatesLagOnlyWhenComplete(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	p := okPush()
	p.Complete = false
	e.push(ref, agent.JobResult{Result: line(p)})
	if bs := e.state(ref); bs.LastPushOK != nil || bs.SpoolEntries == nil || *bs.SpoolEntries != 2 {
		t.Fatalf("after an incomplete push: last ok %v, spool %v", bs.LastPushOK, bs.SpoolEntries)
	}
	e.push(ref, agent.JobResult{Result: line(okPush())})
	if bs := e.state(ref); bs.LastPushOK == nil {
		t.Fatal("a complete push did not update the push lag")
	}
}

func TestRecord_PushStoresQuotaUse(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.ag.quota = agent.QuotaUse{DiskUsedKB: 11, DiskHardKB: 22, RepoUsedKB: 33, RepoHardKB: 44}
	e.push(ref, agent.JobResult{Result: line(okPush())})
	bs := e.state(ref)
	if bs.DiskUsedKB == nil || *bs.DiskUsedKB != 11 || *bs.DiskHardKB != 22 || *bs.RepoUsedKB != 33 || *bs.RepoHardKB != 44 || bs.QuotaAt == nil {
		t.Fatalf("quota not stored: %+v", bs)
	}
	uid := e.pr.specs[ref].UID
	if !strings.Contains(strings.Join(e.ag.called(), ","), "QuotaUse "+strconv.Itoa(uid)) {
		t.Fatalf("calls %q: the quota must be read for the project's uid", e.ag.called())
	}
}

func TestRecord_PushRepositoryQuotaRaisesItsNotice(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	if got := e.push(ref, agent.JobResult{ExitCode: 1, Result: failLine("repository", "x")}); got.Code != "repository" {
		t.Fatalf("job %+v", got)
	}
	if n := e.notices(ref, "repo-quota-full"); n != 0 {
		t.Fatal("notice for another failure (control)")
	}
	if got := e.push(ref, agent.JobResult{ExitCode: 1, Result: failLine("repository_quota", "quota exceeded")}); got.Code != "repository_quota" {
		t.Fatalf("job %+v", got)
	}
	if n := e.notices(ref, "repo-quota-full"); n != 1 {
		t.Fatalf("%d repo-quota-full notices", n)
	}
}

func TestRecord_PushNewestIsTheHighestTimelinesEntry(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	_, err := e.db.Exec(context.Background(), `insert into backup_timeline (subject, tli, state, launch) values ($1, 2, 'recorded', 1), ($1, 3, 'abandoned', 0)`, ref)
	must(t, err)
	p := okPush()
	p.Newest = map[string]string{"00000001": "0000000100000000000000FF", "00000003": "000000030000000000000002", "00000002": "000000020000000000000010"}
	e.push(ref, agent.JobResult{Result: line(p)})
	if bs := e.state(ref); bs.NewestSegment != "000000030000000000000002" {
		t.Fatalf("newest segment %q", bs.NewestSegment)
	}
}

func TestRecord_DoneSeedSetsSeededAt(t *testing.T) {
	e := newEnv(t)
	ref := e.project("restoring")
	_, id := e.parked(ref, "seed", "")
	e.turn("backup")
	if bs := e.state(ref); e.job(id).State != "done" || bs.SeededAt == nil || !bs.SeededAt.Equal(e.clock.Now().Truncate(time.Microsecond)) {
		t.Fatalf("job %+v, seeded at %v", e.job(id), bs.SeededAt)
	}
}

func TestRecord_QuarantineMakesGapNoticeForcedFull(t *testing.T) {
	e := newEnv(t)
	quarantining(e)
	ref := e.project("active")
	e.submit(ref, "push")
	e.turn("push")
	gaps, _, err := e.st.ListGaps(context.Background(), ref)
	must(t, err)
	if len(gaps) != 1 || gaps[0].Cause != "quarantine" || gaps[0].First != "000000030000000000000001" {
		t.Fatalf("gaps %+v", gaps)
	}
	if e.notices(ref, "quarantine") != 1 || e.jobs(ref, "backup") != 1 {
		t.Fatalf("notices %d, forced fulls %d", e.notices(ref, "quarantine"), e.jobs(ref, "backup"))
	}
}

func TestRecord_BackupMakesSet_LabelValidated(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.ag.setScript("backup", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{Result: line(okBackup())}, nil
	})
	id := e.submit(ref, "backup")
	e.turn("backup")
	sets, err := e.st.ListSets(context.Background(), ref)
	must(t, err)
	if len(sets) != 1 || sets[0].Label != "20261118-104332F" || sets[0].JobID != id || sets[0].TLI != 1 {
		t.Fatalf("sets %+v", sets)
	}
	for _, bad := range []func(*jobio.BackupResult){
		func(b *jobio.BackupResult) { b.Label = "20261118-104333F/../x" },
		func(b *jobio.BackupResult) { b.Label = "20261118-104333D" },
		func(b *jobio.BackupResult) { b.StopSegment = "00000001000000000000000g" },
		func(b *jobio.BackupResult) { b.StartLSN = "0/4000028; x" },
		func(b *jobio.BackupResult) { b.Timeline = 0 },
		func(b *jobio.BackupResult) { b.Timeline = 1 << 31 },
		func(b *jobio.BackupResult) { b.StartSegment = "0000000100000000000000" },
	} {
		b := okBackup()
		b.Label = "20261119-000000F"
		b.Push.SpoolEntries = 99 // a refused result records nothing, its push neither
		bad(&b)
		e.ag.setScript("backup", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{Result: line(b)}, nil
		})
		id := e.submit(ref, "backup")
		e.turn("backup")
		sets, _ := e.st.ListSets(context.Background(), ref)
		if got := e.job(id); got.Code != "crashed" || len(sets) != 1 || *e.state(ref).SpoolEntries != 2 {
			t.Fatalf("%+v: job %+v, %d sets", b, got, len(sets))
		}
	}
}

func TestRecord_StanzaMarksTimelineOne(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	_, err := e.db.Exec(context.Background(), `delete from backup_timeline where subject = $1`, ref)
	must(t, err)
	_, err = e.db.Exec(context.Background(), `update backup_state set stanza_created = false where subject = $1`, ref)
	must(t, err)
	// No timeline is admitted before the stanza exists: the push names none.
	e.ag.setScript("stanza-create", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		p := okPush()
		p.Newest = map[string]string{}
		return agent.JobResult{Result: line(jobio.CheckJobResult{OK: true, Push: &p})}, nil
	})
	_, id := e.parked(ref, "stanza-create", "")
	e.turn("backup")
	tls, err := e.st.Timelines(context.Background(), ref)
	must(t, err)
	if e.job(id).State != "done" || !e.state(ref).StanzaCreated || len(tls) != 1 || tls[0].TLI != 1 || tls[0].State != "recorded" {
		t.Fatalf("job %+v, timelines %+v", e.job(id), tls)
	}
}

func TestRecord_StoresTheReEncodedValueNeverTheRawLine(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	raw := `{ "ok":true, "complete":true, "pushed":1, "newest":{"00000001":"000000010000000000000003"},` +
		` "spool_entries":1, "spool_bytes":5, "spool_oldest":"2026-11-18T10:00:00+00:00", "histories":[] }` + "\n"
	got := e.push(ref, agent.JobResult{Result: []byte(raw)})
	if got.State != "done" || strings.Contains(string(got.Result), "+00:00") || !strings.Contains(string(got.Result), `"2026-11-18T10:00:00Z"`) {
		t.Fatalf("stored %s", got.Result)
	}
	for _, l := range []string{
		`{"ok":true,"complete":true,"complete":false}`,
		`{"ok":true,"Complete":true}`,
	} {
		if got := e.push(ref, agent.JobResult{Result: []byte(l + "\n")}); got.Code != "crashed" || got.Result != nil {
			t.Fatalf("%s: job %+v", l, got)
		}
	}
}

func TestRecord_NewestKeysAndValuesAreShapeChecked(t *testing.T) {
	for name, newest := range map[string]map[string]string{
		"hex case":       {"0000000a": "0000000A0000000000000003", "0000000A": "0000000A0000000000000004"},
		"lower-case key": {"0000000a": "0000000A0000000000000003"},
		"other timeline": {"00000001": "000000020000000000000003"},
		"not a segment":  {"00000001": "00000001.history"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			ref := e.project("active")
			p := okPush()
			p.Newest = newest
			if got := e.push(ref, agent.JobResult{Result: line(p)}); got.Code != "crashed" {
				t.Fatalf("job %+v", got)
			}
			if bs := e.state(ref); bs.SpoolEntries != nil || bs.NewestSegment != "" {
				t.Fatalf("recorded although refused: %+v", bs)
			}
		})
	}
}

func TestRecord_PushWithAnUnknownGapCauseOrAMalformedSegmentIsCrashed(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	p := okPush()
	p.Quarantined = []jobio.Quarantined{{Name: "000000010000000000000009", Reason: "spool-drop"}}
	if got := e.push(ref, agent.JobResult{Result: line(p)}); got.Code != "crashed" {
		t.Fatalf("unknown reason: %+v", got)
	}
	p = okPush()
	p.Newest = map[string]string{"00000001": "00000001000000000000003"}
	if got := e.push(ref, agent.JobResult{Result: line(p)}); got.Code != "crashed" {
		t.Fatalf("malformed segment: %+v", got)
	}
	if bs := e.state(ref); bs.SpoolEntries != nil {
		t.Fatal("a refused push was recorded")
	}
	gaps, _, _ := e.st.ListGaps(context.Background(), ref)
	if len(gaps) != 0 {
		t.Fatalf("gaps %+v", gaps)
	}
}
