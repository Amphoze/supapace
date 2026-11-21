package saga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/store"
)

// submitRestore applies the restore's rules — target, source, quota, in that
// order — from the store's record and the host's quota report, and only then
// queues the operation. params are {"to","timeline","from"}: to is latest, an
// RFC 3339 time or lsn:<hex>/<hex>; timeline 0 is the newest recorded one;
// from "" is the default. Every refusal wraps store.ErrConflict (a target the
// recovery pins refuse also pgconf.ErrGUCValue), except a target outside the
// window, which is a *store.WindowError. Nothing is written on a refusal.
func (r *Runner) submitRestore(ctx context.Context, ref string, params json.RawMessage) (int64, error) {
	var in struct {
		To       string `json:"to"`
		Timeline int    `json:"timeline"`
		From     string `json:"from"`
	}
	// The decoder's text quotes the input: a fixed text instead.
	if strictJSON(params, &in) != nil || in.Timeline < 0 || in.Timeline > 1<<31-1 || in.From != "" && in.From != "local" && in.From != "offsite" {
		return 0, fmt.Errorf("%w: restore parameters: want to, a timeline 1 to 2147483647 (0: the newest recorded) and from local or offsite", store.ErrConflict)
	}
	p, err := r.st.GetProject(ctx, ref)
	if err != nil {
		return 0, err
	}
	if p.State != "active" && p.State != "restarting" && p.State != "restoring" {
		return 0, fmt.Errorf("%w: restore needs an active project; it is %s", store.ErrConflict, p.State)
	}
	if p.Config.Layout != 2 {
		return 0, fmt.Errorf("%w: no completed backup yet; the first full backup follows the project's stanza; see 'supapace project backups %s'", store.ErrConflict, ref)
	}
	tls, err := r.st.Timelines(ctx, ref)
	if err != nil {
		return 0, err
	}
	if newestRecorded(tls) == 0 { // no stanza yet
		return 0, fmt.Errorf("%w: no completed backup yet; the first full backup follows the project's stanza; see 'supapace project backups %s'", store.ErrConflict, ref)
	}
	if in.Timeline > 0 && !recordedTimeline(tls, in.Timeline) {
		return 0, fmt.Errorf("%w: timeline %d is not a recorded timeline", store.ErrConflict, in.Timeline)
	}
	t, err := renderTarget(in.To, in.Timeline, tls)
	if errors.Is(err, pgconf.ErrGUCValue) {
		return 0, fmt.Errorf("%w: %w", store.ErrConflict, err)
	}
	if err != nil {
		return 0, err
	}
	follow := in.Timeline
	if follow == 0 {
		follow = newestRecorded(tls)
	}
	bs, err := r.st.GetBackupState(ctx, ref)
	if errors.Is(err, store.ErrNotFound) {
		return 0, fmt.Errorf("%w: no completed backup yet; the first full backup follows the project's stanza; see 'supapace project backups %s'", store.ErrConflict, ref)
	}
	if err != nil {
		return 0, err
	}
	all, err := r.st.ListSets(ctx, ref)
	if err != nil {
		return 0, err
	}
	if len(all) == 0 {
		return 0, fmt.Errorf("%w: no completed backup yet; the first full backup follows the project's stanza; see 'supapace project backups %s'", store.ErrConflict, ref)
	}
	window := &store.WindowError{From: all[0].StopAt}
	if bs.LastPushOK != nil {
		window.To = *bs.LastPushOK
	}
	if !t.Time.IsZero() && t.Time.After(time.Now()) {
		return 0, window
	}
	sets, err := r.lineage(ctx, all, tls, follow)
	if err != nil {
		return 0, err
	}
	set, ok := chooseSet(sets, t, false)
	if !ok {
		return 0, window
	}

	// Source: forced off-site on a node that holds nothing of the project,
	// and for a set that stopped before the stanza was seeded.
	spec, err := r.SpecFor(ctx, ref)
	if err != nil {
		return 0, err
	}
	hs, err := r.ag.HostState(ctx, spec)
	if err != nil {
		return 0, err
	}
	from := in.From
	if from == "" {
		from = "local"
	}
	if !hs.StateFile { // no cluster of the project was ever started here (T1 makes the directory)
		from = "offsite"
	}
	if bs.SeededAt != nil && set.StopAt.Before(*bs.SeededAt) {
		if in.From == "local" {
			return 0, fmt.Errorf("%w: this backup set is restorable from the off-site store only; restore without --from local", store.ErrConflict)
		}
		from = "offsite"
	}
	if from == "offsite" {
		state := "undeclared"
		if r.jobs != nil {
			state = r.jobs.Offsite()
		}
		switch state {
		case "declared":
		case "partial":
			return 0, fmt.Errorf("%w: off-site store partly declared; run 'supapaced offsite set' on this node to give the projects' bucket its credentials", store.ErrConflict)
		default:
			return 0, fmt.Errorf("%w: off-site store not declared; restore without --from offsite, or declare it with 'supapaced offsite set'", store.ErrConflict)
		}
		if _, any := chooseSet(sets, pgconf.RecoveryTarget{}, true); !any {
			return 0, fmt.Errorf("%w: no backup of the project is completely off-site yet", store.ErrConflict)
		}
		if set, ok = chooseSet(sets, t, true); !ok {
			return 0, window
		}
	}
	if hs.QuotaFull {
		return 0, fmt.Errorf("%w: disk quota full; restart the project with a larger quota first", store.ErrConflict)
	}
	// What T4p and T4r must do before the wipe, refused here while it cannot
	// succeed: neither the budget nor the quota can be raised once the project
	// is restoring (no restart takes it). The repository is full when the
	// newest push job found it so, or the last push's quota report says so —
	// a figure of this node's own repository: not on a node that never
	// started the project (a replaced node restores from off-site).
	if hs.StateFile {
		full := bs.RepoHardKB != nil && bs.RepoUsedKB != nil && *bs.RepoHardKB > 0 && *bs.RepoUsedKB+4 >= *bs.RepoHardKB
		if j, ok, err := r.st.LastJob(ctx, ref, "push"); err != nil {
			return 0, err
		} else if ok && j.State == "failed" && j.Code == "repository_quota" {
			full = true
		}
		switch {
		case full && p.State == "restoring":
			return 0, fmt.Errorf("%w: repository quota full; a project left restoring takes no restart to raise it: "+
				"'supapace project delete %s' removes it", store.ErrConflict, ref)
		case full:
			return 0, fmt.Errorf("%w: repository quota full; restart the project with a larger quota first", store.ErrConflict)
		}
	}
	if r.jobs != nil && r.jobs.Offsite() == "declared" && bs.ReplPausedUntil != nil && bs.ReplPausedUntil.After(time.Now()) {
		return 0, fmt.Errorf("%w: replication is paused for the project's daily upload budget until %s; a restore replicates "+
			"before it wipes: submit it again after then", store.ErrConflict, bs.ReplPausedUntil.UTC().Format(time.RFC3339))
	}
	out, err := json.Marshal(map[string]any{"to": in.To, "timeline": in.Timeline, "from": from, "set": set.Label,
		"set_start_segment": set.StartSegment})
	if err != nil {
		return 0, err
	}
	id, _, err := r.st.SubmitRestore(ctx, ref, out)
	return id, err
}

// chooseSet is the newest of sets (oldest first) that serves target t: any
// for the end of the archive, else the newest that stopped at or before the
// time or position. offsite: only sets replicated and listed.
func chooseSet(sets []store.BackupSet, t pgconf.RecoveryTarget, offsite bool) (store.BackupSet, bool) {
	for i := len(sets) - 1; i >= 0; i-- {
		s := sets[i]
		switch {
		case offsite && (!s.Replicated || s.ListedAt == nil):
		case !t.Time.IsZero() && s.StopAt.After(t.Time):
		case t.LSN != "" && lsnValue(s.StopLSN) > lsnValue(t.LSN):
		default:
			return s, true
		}
	}
	return store.BackupSet{}, false
}

// lsnValue is a position hex/hex as a number; a malformed one is the
// highest, so that no set is taken on its word.
func lsnValue(s string) uint64 {
	hi, lo, ok := strings.Cut(s, "/")
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if !ok || err1 != nil || err2 != nil {
		return 1<<64 - 1
	}
	return h<<32 | l
}

func recordedTimeline(tls []store.Timeline, tli int) bool {
	for _, t := range tls {
		if t.TLI == tli && t.State == "recorded" {
			return true
		}
	}
	return false
}

// newestRecorded is the highest recorded timeline, 0 when none is.
func newestRecorded(tls []store.Timeline) int {
	n := 0
	for _, t := range tls {
		if t.State == "recorded" {
			n = max(n, t.TLI)
		}
	}
	return n
}

// renderTarget is the restore's stored target as the recovery start takes
// it, checked by pgconf.RecoveryPins — the same at the submit, at T1 and at
// T7: to parsed from its stored text, timeline 0 resolved to the newest
// recorded timeline, rendered as its decimal for every target.
func renderTarget(to string, timeline int, tls []store.Timeline) (pgconf.RecoveryTarget, error) {
	var t pgconf.RecoveryTarget
	switch lsn, isLSN := strings.CutPrefix(to, "lsn:"); {
	case to == "latest":
	case isLSN:
		t.LSN = lsn
	default:
		tm, err := time.Parse(time.RFC3339, to)
		if err != nil {
			return t, fmt.Errorf("%w: restore target %.40q: want latest, an RFC 3339 time or lsn:<hex>/<hex>", pgconf.ErrGUCValue, to)
		}
		t.Time = tm
	}
	// The timeline followed, as its decimal, for every target: with "latest"
	// the server would follow the newest history the archive holds, a branch
	// no restore finished included.
	switch {
	case timeline > 0:
		t.Timeline = strconv.Itoa(timeline)
	default:
		n := newestRecorded(tls)
		if n == 0 {
			return t, fmt.Errorf("%w: no recorded timeline", store.ErrConflict)
		}
		t.Timeline = strconv.Itoa(n)
	}
	_, err := pgconf.RecoveryPins(t)
	return t, err
}

// lineage is the sets that lead to timeline k, oldest first: the sets taken
// on k and, when a restore recorded k, the lineage of the set that restore
// was made from, cut at that set's stop — read down the chain from the
// record (the timeline row names its operation, whose parameters name its
// set). A timeline no known restore made (timeline 1, a row without its
// operation) contributes its own sets only.
func (r *Runner) lineage(ctx context.Context, all []store.BackupSet, tls []store.Timeline, k int) ([]store.BackupSet, error) {
	var out []store.BackupSet
	cut := time.Time{} // zero: no cut yet
	for range tls {    // each turn goes to an older timeline: at most one a row
		for _, s := range all {
			if s.TLI == k && (cut.IsZero() || !s.StopAt.After(cut)) {
				out = append(out, s)
			}
		}
		i := slices.IndexFunc(tls, func(t store.Timeline) bool { return t.TLI == k })
		if k <= 1 || i < 0 || tls[i].OpID == 0 {
			break
		}
		op, err := r.st.GetOperation(ctx, tls[i].OpID)
		if errors.Is(err, store.ErrNotFound) {
			break
		}
		if err != nil {
			return nil, err
		}
		var p struct {
			Set string `json:"set"`
		}
		json.Unmarshal(op.Params, &p)
		j := slices.IndexFunc(all, func(s store.BackupSet) bool { return s.Label == p.Set && s.TLI < k })
		if j < 0 || !cut.IsZero() && all[j].StopAt.After(cut) {
			break
		}
		cut, k = all[j].StopAt, all[j].TLI
	}
	slices.SortStableFunc(out, func(a, b store.BackupSet) int { return a.StopAt.Compare(b.StopAt) })
	return out, nil
}
