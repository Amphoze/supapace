package repl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
)

// Rebuild lists one page of the versions under the subject's prefix, from
// the markers the daemon stored, and returns one row per key of the page —
// the last listed, which is the key's oldest version on the page (versions
// are listed newest first) — with the markers to continue from. At most
// page_rows entries are taken (delete markers included, which are never a
// row); a key the layout does not admit is counted, never returned. The
// paging is bounded by the page: each call must move the markers.
func Rebuild(ctx context.Context, in jobio.Input, st Store) (jobio.ReplResult, error) {
	if in.Repl == nil || in.Repl.Mode != "rebuild" || !subjectRE.MatchString(in.Subject) || !validPrefix(st.Prefix()) {
		return jobio.ReplResult{}, fmt.Errorf("%w: not a rebuild input for this subject and prefix", ErrInput)
	}
	pageRows := in.Repl.PageRows
	if pageRows <= 0 || pageRows > bklimit.RebuildPageRows {
		pageRows = bklimit.RebuildPageRows
	}
	list := base(st.Prefix(), in.Subject) + "/"
	r := jobio.ReplResult{OK: true, Mode: "rebuild", Rows: []jobio.Row{}}
	at := map[string]int{} // key → its row on this page
	km, vm := in.Repl.KeyMarker, in.Repl.VersionMarker
	var listed, unlisted, size int
	last := false
	for listed < pageRows && !last {
		page, nk, nv, err := st.ListVersions(ctx, list, km, vm)
		if err != nil && ctx.Err() != nil && listed > 0 {
			goto cut // the program's bound: the page so far, with its markers
		}
		if err != nil {
			return jobio.ReplResult{}, err
		}
		if len(page) == 0 && nk != "" {
			return jobio.ReplResult{}, errors.New("repl: an empty listing page that is not the last")
		}
		for _, o := range page {
			b, _ := json.Marshal(jobio.Row{Key: o.Key, Size: o.Size, VersionID: o.VersionID, At: o.Modified})
			if listed == pageRows || size+len(b)+1 > bklimit.ResultMax-resultRoom {
				goto cut
			}
			listed++
			km, vm = o.Key, o.VersionID
			if o.DeleteMarker {
				continue
			}
			rel, under := strings.CutPrefix(o.Key, list)
			if _, err := Key(st.Prefix(), in.Subject, rel); !under || err != nil || !validVersion(o.VersionID) || o.Size < 0 {
				unlisted++
				continue
			}
			row := jobio.Row{Key: rel, Size: o.Size, VersionID: o.VersionID, At: o.Modified.UTC()}
			if i, ok := at[rel]; ok {
				r.Rows[i] = row
				continue
			}
			at[rel] = len(r.Rows)
			r.Rows = append(r.Rows, row)
			size += len(b) + 1
		}
		km, vm, last = nk, nv, nk == ""
	}
cut:
	if unlisted > 0 {
		r.Notices = []jobio.Notice{{Code: "unlisted-entry", Count: int64(unlisted), Detail: "listed keys outside the layout"}}
	}
	r.Last, r.Complete = last, last
	if last {
		km, vm = "", ""
	} else {
		r.Stopped = "rebuild"
	}
	r.NextKeyMarker, r.NextVersionMarker = km, vm
	return r, nil
}
