package bkjob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/walname"
)

// The push job's failure codes.
const (
	CodeRepositoryQuota = "repository_quota" // the tool's exit 104 naming error 122: the repository quota is full
	CodeRepository      = "repository"       // any other failure of the tool, or of reading the repository
	CodeSpool           = "spool"            // the spool could not be listed, copied from or changed
	CodeStopped         = "stopped"          // the pass was stopped (its context ended: SIGTERM or the launcher's stop)
)

var (
	// repoRoot is where the repository is mounted (PGBACKREST_REPO1_PATH).
	repoRoot = "/repo"
	// privRoot holds the job's private copies: the job's own tmpfs, never TMPDIR.
	privRoot = "/tmp"
	// listed, when set, runs once the spool has been listed. Tests only.
	listed func()
)

const (
	tmpMaxPerPass = 1024    // old .tmp- entries one pass removes
	segmentMin    = 1 << 20 // PostgreSQL's smallest WAL segment size: no segment is shorter
	newestMax     = 64      // timelines in newest, history names in histories
)

// candidate is a spool entry whose name passes walname.Spool.
type candidate struct {
	name  string
	kind  walname.Kind
	tli   uint32
	size  int64
	mtime time.Time
}

// Push pushes the spool into the repository: it lists the spool once and
// takes its entries in order — history files first, then segments and labels
// by name, the oldest first — at most in.MaxEntries (bklimit.PushMaxEntries
// when unset or above it), each counting whether pushed or quarantined.
//
// An entry is opened without following a link and must be a regular file of
// the project's uid within its kind's bound; it is copied into the job's own
// temporary directory and that copy is handed to the tool, so the tool never
// reads the spool. It is removed from the spool only after the tool exits 0.
// An entry of a timeline not admitted, of another shape (a segment under 1 MiB
// among them), or refused by the tool for its bytes (29, 44, 45, 46) is
// quarantined: renamed, with its bytes, to a name outside every pattern — once
// the pass has its result, which lists it. Any other failure, or a stop (code
// stopped), ends the job with its code; nothing is set aside then and the
// entries stay for the next pass.
//
// Names outside the pattern are counted and left, except the archive binary's
// old temporaries, which are removed (at most 1,024 a pass) without being
// opened. newest and histories are read from the repository when the job ends.
func Push(ctx context.Context, in jobio.Input, spool string) (jobio.PushResult, error) {
	res := jobio.PushResult{OK: true, Quarantined: []jobio.Quarantined{}}
	d, err := os.Open(spool)
	if err != nil {
		return res, fail(CodeSpool, "opening the spool: %v", err)
	}
	defer d.Close()
	dfd := int(d.Fd())

	limit := in.MaxEntries
	if limit <= 0 || limit > bklimit.PushMaxEntries {
		limit = bklimit.PushMaxEntries
	}
	// The spool is read in batches and only the lowest candidates up to the
	// cap are kept; the others are only counted, so a spool of any number of
	// entries costs a bounded amount of memory.
	var cands []candidate
	total := 0
	removed, now := 0, time.Now()
	for {
		ents, err := d.ReadDir(1024)
		for _, e := range ents {
			name := e.Name()
			if k, tli, ok := walname.Spool(name); ok {
				c := candidate{name: name, kind: k, tli: tli}
				if fi, err := e.Info(); err == nil { // lstat: a link's own figures
					c.size, c.mtime = fi.Size(), fi.ModTime()
				}
				total++
				if cands = append(cands, c); len(cands) >= 2*limit {
					cands = keepLowest(cands, limit, &res)
				}
				continue
			}
			// A temporary whose writer is gone: its own time, read without
			// following a link, unlinked by name; nothing of it is opened. A
			// directory is not removed: unlinkat without AT_REMOVEDIR refuses one.
			if strings.HasPrefix(name, ".tmp-") && removed < tmpMaxPerPass {
				if fi, err := e.Info(); err == nil && now.Sub(fi.ModTime()) > bklimit.SpoolTmpAge &&
					syscall.Unlinkat(dfd, name) == nil {
					removed++
					continue
				}
			}
			res.OtherEntries++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, fail(CodeSpool, "listing the spool: %v", err)
		}
	}
	cands = keepLowest(cands, limit, &res)
	if listed != nil {
		listed()
	}

	priv, err := os.MkdirTemp(privRoot, "push-")

	if err != nil {
		return res, fail(CodeSpool, "making the private directory: %v", err)
	}
	defer os.RemoveAll(priv)

	// Nothing is set aside while the pass runs: an entry is renamed only once
	// the pass has its result, which lists it. A pass that fails sets nothing
	// aside, and the next pass decides each entry again.
	var aside []jobio.Quarantined
	taken := 0
	for _, c := range cands {
		taken++
		reason := ""
		if !walname.Admitted(c.tli, in.Timelines) {
			reason = "timeline"
		} else {
			path, gone, why, err := copyEntry(dfd, c, in.UID, priv)
			switch {
			case err != nil:
				return res, fail(CodeSpool, "copying %s: %v", c.name, err)
			case gone:
				continue
			case why != "":
				reason = why
			default:
				exit, out, err := Run(ctx, "archive-push", path)
				os.Remove(path)
				switch {
				case err != nil && ctx.Err() != nil:
					return res, fail(CodeStopped, "the pass was stopped at %s: %v", c.name, ctx.Err())
				case err != nil:
					return res, fail(CodeRepository, "archive-push %s: %v", c.name, err)
				case exit == 0:
					if err := syscall.Unlinkat(dfd, c.name); err != nil && err != syscall.ENOENT {
						return res, fail(CodeSpool, "removing %s after its push: %v", c.name, err)
					}
					if res.First == "" {
						res.First = c.name
					}
					res.Pushed++
					res.Last = c.name
					continue
				case exit == 44 || exit == 45 || exit == 46:
					reason = "refused-" + strconv.Itoa(exit)
				case exit == 29:
					// 2.58's archive-push exits 29 only for the entry's first page (no
					// long header, or an invalid segment size); a damaged repository
					// (archive.info truncated, random or unencrypted) gives 103, an
					// unwritable one 104. Re-check when the tool's version changes: a damaged
					// archive.info must not exit 29.
					reason = "shape"
				case exit == 104 && strings.Contains(out, "[122]"):
					return res, fail(CodeRepositoryQuota, "archive-push %s: the repository quota is full: %s", c.name, errorLine(out))
				default:
					return res, fail(CodeRepository, "archive-push %s: exit %d: %s", c.name, exit, errorLine(out))
				}
			}
		}
		aside = append(aside, jobio.Quarantined{Name: c.name, Reason: reason})
	}
	if res.Newest, res.Histories, err = readRepo(in); err != nil {
		return res, fail(CodeRepository, "reading the repository: %v", err)
	}
	// The result is decided: set the entries aside. One already gone is not
	// listed; a rename that fails stops the renames, and the entries left are
	// decided again by the next pass (they count as remaining).
	left := 0
	for i, q := range aside {
		err := quarantine(dfd, q.Name)
		if err == syscall.ENOENT {
			continue
		}
		if err != nil {
			left = len(aside) - i
			break
		}
		res.Quarantined = append(res.Quarantined, q)
	}
	res.Remaining = total - taken + left
	res.Complete = res.Remaining == 0
	res.SpoolEntries += len(cands) - taken + left // with the ones counted at the listing: remaining
	for _, c := range cands[taken:] {
		res.SpoolBytes += c.size
		oldest(&res, c.mtime)
	}
	return res, nil
}

// keepLowest keeps the limit lowest candidates — history files first, then by
// name — and counts the others into res's spool figures.
func keepLowest(cands []candidate, limit int, res *jobio.PushResult) []candidate {
	slices.SortFunc(cands, func(a, b candidate) int {
		if ah, bh := a.kind == walname.History, b.kind == walname.History; ah != bh {
			if ah {
				return -1
			}
			return 1
		}
		return strings.Compare(a.name, b.name)
	})
	if len(cands) <= limit {
		return cands
	}
	for _, c := range cands[limit:] {
		res.SpoolEntries++
		res.SpoolBytes += c.size
		oldest(res, c.mtime)
	}
	return append(cands[:0:0], cands[:limit]...)
}

// oldest lowers res's spool_oldest to t.
func oldest(res *jobio.PushResult, t time.Time) {
	if res.SpoolOldest == nil || t.Before(*res.SpoolOldest) {
		res.SpoolOldest = &t
	}
}

// copyEntry copies spool entry c into dir under its own name and returns the
// copy's path. gone: the entry no longer exists. why: it is not a regular
// file of uid within its kind's bounds (a segment of at least the smallest
// segment size), or cannot be opened (a link among them) — it is then not
// read.
func copyEntry(dfd int, c candidate, uid int, dir string) (path string, gone bool, why string, err error) {
	fd, err := syscall.Openat(dfd, c.name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		return "", true, "", nil
	}
	if err != nil {
		return "", false, "shape", nil
	}
	f := os.NewFile(uintptr(fd), c.name)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return "", false, "", err
	}
	max := int64(bklimit.SmallMax)
	if c.kind == walname.Segment {
		max = bklimit.SegmentMax
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != uid || st.Size > max ||
		c.kind == walname.Segment && st.Size < segmentMin {
		return "", false, "shape", nil
	}
	path = filepath.Join(dir, c.name)
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", false, "", err
	}
	n, err := io.Copy(w, io.LimitReader(f, max+1)) // a file that grew past its bound is not copied whole
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		os.Remove(path)
		return "", false, "shape", nil
	}
	if err != nil {
		os.Remove(path)
		return "", false, "", err
	}
	return path, false, "", nil
}

// quarantine renames spool entry name, whatever it is, to a name no pattern
// takes: neither a spool name nor a temporary.
func quarantine(dfd int, name string) error {
	var r [8]byte
	rand.Read(r[:])
	return syscall.Renameat(dfd, name, dfd, name+".quarantined-"+hex.EncodeToString(r[:]))
}

// readRepo reads, from the repository's archive of in's stanza, the newest
// segment of each admitted timeline and every history name, each name taken
// only when walname.RepoPath classifies its path. At most 64 of each, the
// highest. Only names are read; no file is opened.
func readRepo(in jobio.Input) (map[string]string, []string, error) {
	newest := map[uint32]string{}
	hist := map[string]bool{}
	base := filepath.Join(repoRoot, "archive", in.Stanza)
	ids, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		ids, err = nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for _, id := range ids {
		if !id.IsDir() {
			continue
		}
		dir := filepath.Join(base, id.Name())
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, err
		}
		// Directories of a timeline, highest first: the first holding a
		// segment of the pattern holds the newest.
		byTLI := map[uint32][]string{}
		for _, e := range ents {
			rel := "archive/" + in.Stanza + "/" + id.Name() + "/" + e.Name()
			if !e.IsDir() {
				if k, _, _, ok := walname.RepoPath(in.Stanza, rel); ok && k == walname.History {
					hist[e.Name()] = true
				}
				continue
			}
			if len(e.Name()) != 16 {
				continue
			}
			t, err := strconv.ParseUint(e.Name()[:8], 16, 32)
			if err == nil && walname.Admitted(uint32(t), in.Timelines) {
				byTLI[uint32(t)] = append(byTLI[uint32(t)], e.Name())
			}
		}
		for t, dirs := range byTLI {
			slices.Sort(dirs)
			for _, sub := range slices.Backward(dirs) {
				top, err := newestIn(in.Stanza, id.Name(), sub, filepath.Join(dir, sub), t)
				if err != nil {
					return nil, nil, err
				}
				if top != "" {
					if top > newest[t] {
						newest[t] = top
					}
					break
				}
			}
		}
	}
	tls := slices.Sorted(maps.Keys(newest))
	out := map[string]string{}
	for _, t := range tls[max(0, len(tls)-newestMax):] {
		out[fmt.Sprintf("%08X", t)] = newest[t]
	}
	names := slices.Sorted(maps.Keys(hist))
	return out, append([]string{}, names[max(0, len(names)-newestMax):]...), nil
}

// newestIn is the highest segment of timeline t in one archive directory
// ("" when none passes the pattern).
func newestIn(stanza, id, sub, dir string, t uint32) (string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	top := ""
	for _, e := range ents {
		k, tli, _, ok := walname.RepoPath(stanza, "archive/"+stanza+"/"+id+"/"+sub+"/"+e.Name())
		if ok && k == walname.Segment && tli == t && !e.IsDir() && e.Name()[:24] > top {
			top = e.Name()[:24]
		}
	}
	return top, nil
}

// errorLine is the tool's last line holding "ERROR: [nnn]" (the console may put
// a timestamp before it and a hint after it), else its last line.
func errorLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, l := range slices.Backward(lines) {
		if strings.Contains(l, "ERROR: [") {
			return strings.TrimSpace(l)
		}
	}
	return strings.TrimSpace(lines[len(lines)-1])
}
