package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
)

// A recovery that followed a history which leaves an older timeline and never
// reads the newest one did not lose the end of the archive: it was led past
// it. The history the promotion wrote shows it — a timeline is missing from
// its lines. That is the store denying the recovery, not a shortfall an
// operator can accept.
func TestRecover_AHistoryThatSkipsATimelineIsADenialNotAShortfall(t *testing.T) {
	real2 := "1\t0/6000000\tno recovery target specified\n"
	for _, args := range [][]string{nil, {"--accept-shortfall"}} {
		r := newRecNode(t)
		r.fetch(jobio.FetchResult{OK: true, Files: 16, Bytes: 4100, NewestSegment: segName(3, 8), NewestSet: recSet}, 2, real2, 3, real2)
		// As a server wrote it: promoted to timeline 4, timeline 2 never followed.
		r.ag.endTLI, r.ag.history = 3, real2+"\n3\t0/6000000\tno recovery target specified\n"
		code, _, errs := r.recover(args...)
		if code != 1 || !strings.Contains(errs, "the store denies this recovery") || strings.Contains(errs, "shortfall:") || r.opens != 0 {
			t.Errorf("%v: exit %d, the restored database opened %d times, stderr %q", args, code, r.opens, errs)
		}
	}
	// Control: a history that names every timeline below its own is the archive's.
	r := newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 14, Bytes: 3900, NewestSegment: segName(2, 7), NewestSet: recSet}, 2, real2)
	r.ag.endTLI, r.ag.history = 2, real2+"\n2\t0/8000000\tno recovery target specified\n"
	if out := r.mustRecover(); !strings.Contains(out, "reached segment "+segName(2, 7)) {
		t.Fatalf("control: output %s", out)
	}
	if in := r.input("restore"); in.TargetTimeline != 2 {
		t.Fatalf("control: the restore was told timeline %d", in.TargetTimeline)
	}
}

// The command that continues a rebuild opens the control-plane database as
// the other commands do: not with settings the client library would take
// from the environment.
func TestOffsiteRebuildContinue_RefusesClientLibrarySettingsInTheEnvironment(t *testing.T) {
	n, _ := storeNode(t)
	stuckRebuild(t, n.p, "cp", 5000)
	dbExec(t, n.p, "update cp_meta set epoch = epoch + 1")
	before := stateRow(t, n.p, "cp")
	t.Setenv("PGOPTIONS", "-c statement_timeout=1")
	code, out, errs := n.run("", "offsite", "rebuild-continue", "--subject", "cp")
	os.Unsetenv("PGOPTIONS") // the test's own sessions read the environment too
	if code != 1 || out != "" || !strings.Contains(errs, "PGOPTIONS") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if after := stateRow(t, n.p, "cp"); after != before {
		t.Errorf("the row changed:\n%s\n%s", before, after)
	}
}

// A link at the node directory's path is refused whatever it points at: one
// to a directory of the right owner and mode too (a temporary directory may
// be group-writable, and would then be refused for that alone).
func TestRecover_ALinkToAProperDirectoryIsNotTheNodeDirectory(t *testing.T) {
	r := newRecNode(t)
	elsewhere := t.TempDir()
	if err := os.Chmod(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, r.etc()); err != nil {
		t.Fatal(err)
	}
	r.refused("a link to a directory of the right shape", "must be a real directory of uid")
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Fatalf("written through the link: %v", ents)
	}
}

// The daemon's lock is held for the whole run, not only taken: a daemon
// cannot start while a job of the recovery runs.
func TestRecover_HoldsTheDaemonsLockForTheRun(t *testing.T) {
	r := newRecNode(t)
	asked := 0
	for _, kind := range []string{"fetch/cp", "restore/cp", "serve/cp"} {
		job := r.ag.script[kind]
		r.ag.script[kind] = func(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
			asked++
			if lock, err := claimRunDir(r.p.AdminSock()); err == nil {
				lock.Close()
				t.Errorf("during the %s job a daemon could take the lock", j.Kind)
			}
			return job(ctx, j)
		}
	}
	r.mustRecover()
	if asked != 3 {
		t.Fatalf("control: the lock was tried in %d jobs, want 3", asked)
	}
	// Released when the run has ended.
	lock, err := claimRunDir(r.p.AdminSock())
	if err != nil {
		t.Fatalf("after the run: %v", err)
	}
	lock.Close()
}

// A promoted database whose WAL directory holds no history of a new timeline
// is no pass: where replay ended is not known.
func TestRecover_APromotionWithoutAHistoryIsNoPass(t *testing.T) {
	r := newRecNode(t)
	serve := r.ag.script["serve/cp"]
	r.ag.script["serve/cp"] = func(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
		wal := filepath.Join(r.p.CPProjectDir(), "data", "pg_wal")
		ents, _ := os.ReadDir(wal)
		for _, e := range ents {
			os.Remove(filepath.Join(wal, e.Name()))
		}
		return serve(ctx, j)
	}
	code, _, errs := r.recover("--accept-shortfall")
	if code != 1 || !strings.Contains(errs, "where replay ended is not known") || r.opens != 0 {
		t.Fatalf("exit %d, the restored database opened %d times, stderr %q", code, r.opens, errs)
	}
}

// The count of a shortfall is in segments, also across the position where
// the high half of a segment's number changes (every 256 segments of 16 MiB).
func TestRecover_ShortfallCountsSegmentsAcrossTheHighHalf(t *testing.T) {
	r := newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 12, Bytes: 3400, NewestSegment: "000000010000000100000000", NewestSet: recSet})
	r.replayed(1, 0xFF) // replay ended in 0000000100000000000000FF, the segment before
	code, _, errs := r.recover()
	if code != 1 || !strings.Contains(errs, "replay ended in segment 0000000100000000000000FF") || !strings.Contains(errs, ": 1 segments were not replayed") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}

// A finish that fails leaves the run unfinished: the recovery start is
// stopped all the same, and the marker stays for the next run.
func TestRecover_AFailedFinishStillStopsTheRecoveryStart(t *testing.T) {
	r := newRecNode(t)
	r.ag.fail["finish"] = errors.New("forced: finish")
	code, _, errs := r.recover()
	if code != 1 || !strings.Contains(errs, "forced: finish") {
		t.Fatalf("exit %d, %q", code, errs)
	}
	if last := r.ag.calls[len(r.ag.calls)-1]; last != "recovery-stop" || !exists(r.p.CPRestoring()) {
		t.Fatalf("after a failed finish the last call is %q; calls %v", last, r.ag.calls)
	}
}

// stopCtx records the context the recovery start is stopped with.
type stopCtx struct {
	*recAgent
	errs []error
}

func (s *stopCtx) StopControlPlaneRecovery(ctx context.Context) error {
	s.errs = append(s.errs, ctx.Err())
	return s.recAgent.StopControlPlaneRecovery(ctx)
}

// A signal ends the run; the recovery start is then stopped with a context
// that has not ended, or nothing would stop it.
func TestRecover_ASignalStillStopsTheRecoveryStart(t *testing.T) {
	r := newRecNode(t)
	ag := &stopCtx{recAgent: r.ag}
	newRecoverAgent = func(c nodecfg.Config) recoverAgent { r.ag.cfg = c; return ag }
	r.ag.promoted, r.ag.recovering = false, true // replaying until the signal
	r.ag.script["serve/cp"] = func(ctx context.Context, _ agent.JobSpec) (agent.JobResult, error) {
		// The command has asked for SIGTERM by now: it is delivered to its context.
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Error(err)
		}
		<-ctx.Done()
		return agent.JobResult{ExitCode: 143}, ctx.Err()
	}
	code, _, _ := r.recover()
	if code != 1 || !r.ag.has("recovery-start") {
		t.Fatalf("exit %d, calls %v", code, r.ag.calls)
	}
	if len(ag.errs) == 0 || ag.errs[len(ag.errs)-1] != nil {
		t.Fatalf("the recovery start was stopped with contexts %v, want a live one last", ag.errs)
	}
	if last := r.ag.calls[len(r.ag.calls)-1]; last != "recovery-stop" {
		t.Fatalf("the last call is %q; calls %v", last, r.ag.calls)
	}
}

// An escrow file is read as a regular file within its bound, whatever the
// path names.
func TestRecover_AnEscrowFileIsReadWithinItsBound(t *testing.T) {
	r := newRecNode(t)
	big := filepath.Join(r.dir, "big.json")
	if err := os.WriteFile(big, make([]byte, maxPairFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := r.run("", "recover", "--escrow", big); code != 1 || out != "" || !strings.Contains(errs, "is larger than") {
		t.Fatalf("an oversized file: exit %d, %q", code, errs)
	}
	if code, _, errs := r.run("", "recover", "--escrow", r.dir); code != 1 || !strings.Contains(errs, "is not a regular file") {
		t.Fatalf("a directory: exit %d, %q", code, errs)
	}
	if len(r.ag.calls) != 0 || exists(r.etc()) {
		t.Fatalf("something was done: %v", r.ag.calls)
	}
}

// A load that failed because its time ran out is still a load that failed,
// not a busy lock.
func TestOffsiteCheck_ALoadThatTimedOutIsNotABusyLock(t *testing.T) {
	c := newCheckNode(t)
	c.instErr = fmt.Errorf("nft: %w: %w", nft.ErrUnverified, context.DeadlineExceeded)
	code, _, errs := c.run("", "offsite", "check")
	if code != 1 || !strings.Contains(errs, "the ruleset could not be loaded") || strings.Contains(errs, "busy") {
		t.Fatalf("exit %d, %q", code, errs)
	}
}

// A comment in the promoted history is no switch line, whatever it quotes.
func TestRecover_ACommentInTheHistoryIsNoSwitchLine(t *testing.T) {
	r := newRecNode(t)
	r.ag.history = "1\t0/A000000\tno recovery target specified\n# was 1\t0/3000000\tbefore\n"
	if out := r.mustRecover(); !strings.Contains(out, "reached segment "+segName(1, 9)) {
		t.Fatalf("output %s", out)
	}
}

// A declaration on the node that addresses the store in the other style
// names another location too.
func TestRecover_ADeclarationOfTheOtherAddressingStyleIsRefused(t *testing.T) {
	r := newRecNode(t)
	if err := os.Mkdir(r.etc(), 0o700); err != nil {
		t.Fatal(err)
	}
	d := r.d
	d.PathStyle = !d.PathStyle
	if err := offsite.Save(r.p, r.k, d); err != nil {
		t.Fatal(err)
	}
	r.refused("the other addressing style", "names another control-plane location than the escrow document")
}

// lateKill fails the removal of the job containers once the finish has been
// tried: the removal of an unfinished run's clean-up.
type lateKill struct {
	*recAgent
	err error
}

func (l *lateKill) KillJobs(ctx context.Context, subject string) error {
	if l.recAgent.has("finish") {
		l.recAgent.KillJobs(ctx, subject)
		return l.err
	}
	return l.recAgent.KillJobs(ctx, subject)
}

// The clean-up's own warnings are scrubbed like every other line: the one
// about the job containers too.
func TestRecover_AFailedRemovalOfTheJobContainersShowsNoSecret(t *testing.T) {
	r := newRecNode(t)
	ag := &lateKill{recAgent: r.ag, err: errors.New("docker: env PGBACKREST_REPO1_CIPHER_PASS=" + r.pass)}
	newRecoverAgent = func(c nodecfg.Config) recoverAgent { r.ag.cfg = c; return ag }
	r.ag.fail["finish"] = errors.New("forced: finish")
	code, out, errs := r.recover()
	if code != 1 || strings.Contains(out+errs, r.pass) || !strings.Contains(errs, "removing the control plane's job containers: docker: env PGBACKREST_REPO1_CIPHER_PASS=[secret]") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}

// The recovery opens the database of its own marked restore; the commands
// that must not see an unchecked database are refused by that same marker.
func TestRecover_OpensTheDatabaseOfItsOwnMarkedRestore(t *testing.T) {
	n, _ := storeNode(t)
	if err := os.WriteFile(n.p.CPRestoring(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(n.p.CPRestoring()) })
	st, err := openRecovered(context.Background())
	if err != nil {
		t.Fatalf("the recovery's own opening: %v", err)
	}
	st.Close()
	if st, err := openCPStore(context.Background()); err == nil {
		st.Close()
		t.Fatal("control: the guarded opening passed a marked restore")
	}
}
