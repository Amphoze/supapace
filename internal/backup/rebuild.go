package backup

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/store"
)

// The record's rebuild in a new epoch is paged across jobs: each job lists one
// page from the markers stored when it is launched — never from a result or a
// marker kept in memory — and its page is merged with the next markers in one
// transaction. The oldest-version rule of the merge holds only if pages are
// merged once and in order, which the store does not check.

// buildRebuild is the input of a rebuild job from the stored markers; past
// bklimit.RebuildMaxPages pages no job is launched. The subject then stays
// without uploads and fetch plans until an operator continues the rebuild
// (`supapaced offsite rebuild-continue`): the refusal raises the notice
// rebuild-page-cap, which `project backups` shows, and an alert row of that
// code with severity page — a notice alone is delivered as a warning.
func (r *Runner) buildRebuild(ctx context.Context, bs store.BackupState, in *jobio.Input) error {
	if bs.RebuildPages >= bklimit.RebuildMaxPages {
		r.noticeFailed(bs.Subject, "rebuild-page-cap", r.st.Notice(ctx, bs.Subject, "rebuild-page-cap", strconv.Itoa(bs.RebuildPages)+" pages merged"))
		if err := r.st.RaiseAlert(ctx, bs.Subject, "rebuild-page-cap", "page", map[string]int64{"pages": int64(bs.RebuildPages)}); err != nil {
			r.log.Error("raising an alert", "subject", bs.Subject, "code", "rebuild-page-cap", "err", clean(err.Error()))
		}
		return jobErr("internal", "the record's rebuild is above its page cap")
	}
	in.Repl = &jobio.ReplInput{Mode: "rebuild", KeyMarker: bs.RebuildKeyMarker, VersionMarker: bs.RebuildVersionMarker,
		PageRows: bklimit.RebuildPageRows}
	return nil
}

// recordRebuild merges one page and raises its notices (unlisted-entry only).
// A page that carries a copy's lists or another notice, is not
// what a page says it is (the last one complete and without a stop, every
// other one incomplete, stopped "rebuild" and with a next key marker — an
// empty one would list from the start again), or does not advance past the
// markers it was launched with (stored, and unchanged since: only this
// subject's pages write them), is an error. A page for a
// record already rebuilt for the epoch is late, and done; the last page
// rebuilds the index file.
func (r *Runner) recordRebuild(ctx context.Context, j store.Job, v jobio.ReplResult, bs store.BackupState, epoch int64) (json.RawMessage, error) {
	if len(v.Uploaded)+len(v.Adopted)+len(v.Info)+len(v.SetsComplete) > 0 {
		return nil, errors.New("a rebuild page carries a copy's lists")
	}
	if err := checkNotices(v.Notices, rebuildNotices); err != nil {
		return nil, err
	}
	if !(v.Last && v.Complete && v.Stopped == "") && !(!v.Last && !v.Complete && v.Stopped == "rebuild" && v.NextKeyMarker != "") {
		return nil, errors.New("a rebuild page out of shape: last, complete, stopped and its next marker disagree")
	}
	// Keys list in byte order; a key's versions continue under the same key.
	if !v.Last && (v.NextKeyMarker < bs.RebuildKeyMarker || v.NextKeyMarker == bs.RebuildKeyMarker && v.NextVersionMarker == bs.RebuildVersionMarker) {
		return nil, errors.New("a rebuild page does not advance past the markers it was launched with")
	}
	rows := make([]store.ObjectRow, len(v.Rows))
	for i, x := range v.Rows {
		rows[i] = store.ObjectRow{Key: x.Key, Size: x.Size, VersionID: x.VersionID, UploadedAt: x.At}
	}
	err := r.st.MergeListing(ctx, j.Subject, store.ListingPage{Rows: rows, NextKeyMarker: v.NextKeyMarker,
		NextVersionMarker: v.NextVersionMarker, Last: v.Last, Launch: j.Launch}, epoch)
	switch {
	case errors.Is(err, store.ErrConflict):
		r.log.Info("a late rebuild page", "subject", j.Subject, "job", j.ID)
	case err != nil:
		return nil, err
	default:
		r.raiseNotices(ctx, j, v.Notices)
		if v.Last {
			if err := r.rebuildIndex(ctx, j.Subject); err != nil {
				r.log.Error("writing an index file", "subject", j.Subject, "err", clean(err.Error()))
			}
		}
	}
	return stored(v, v.Complete)
}
