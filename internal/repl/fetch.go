package repl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
	"github.com/Amphoze/supapace/internal/walname"
)

// ListCurrentMaxPages bounds every version listing of a fetch: pages of up
// to 1,000 versions (another unit than a rebuild's page). The client bounds
// no paging; past this the fetch fails with code store, never too_large.
const ListCurrentMaxPages = 2048

// fetchRate is the rate a fetch job's deadline assumes from the store: each
// GET is bounded at CallTimeout plus its object's bound at that rate.
const fetchRate = 4 << 20

// fetchMaxRows bounds the plan held in memory, at about 300 bytes a row, so
// that a whole plan is checked before the first request.
// ponytail: a plan above 262,144 rows is refused too_large; a second pass
// over a re-readable plan file lifts it if a repository ever holds more.
const fetchMaxRows = 1 << 18

// Failure codes of a fetch, besides ErrPath (path) and ErrInput (input);
// any other error is code store.
var (
	ErrMissing  = errors.New("repl: not in the store")
	ErrMismatch = errors.New("repl: the store's object is not the one recorded")
	ErrQuota    = errors.New("repl: the fetch directory's quota is full")
	ErrTooLarge = errors.New("repl: above the fetch's byte limit")
)

// fileWrite writes to a fetched file: a seam for the tests.
var fileWrite = (*os.File).Write

// FetchBound is a fetch program's own time bound: its job's deadline at a
// repository quota of maxBytes, less one call's bound, so that it ends with
// its own result or failure before the launcher kills it.
func FetchBound(maxBytes int64) time.Duration {
	mb := (min(max(maxBytes, 0), 1<<50) + 1<<20 - 1) >> 20 // whole MiB, rounded up; at most 1 PiB
	d, _ := bklimit.Deadline("fetch", 0, int(mb))
	return d - CallTimeout
}

// Fetch writes objects of the store below dest, the job's fetch directory,
// with the job's read-only credential. By plan, each row is a repository
// path with its recorded version id (none: the oldest version that is an
// object), hash (none for a rebuilt row) and size (for an info file its
// kind's bound); the whole plan is checked before the first request, and
// every byte against the row. With in.ListCurrent — the control plane only,
// and without a plan — it lists the versions under the stanza's two trees and
// takes each write-once key at its oldest version and each info file at its
// newest, a delete marker never being a version; it reports the newest set
// whose manifest it fetched and the fetched segment of the highest number.
// Every key passes Key and walname.RepoPath for the job's stanza; files are
// created exclusively, never through a link, 0640 in directories 2750; no
// more than in.MaxBytes bytes are written.
func Fetch(ctx context.Context, in jobio.Input, plan io.Reader, dest string, st Store) (jobio.FetchResult, error) {
	if in.ListCurrent && in.Subject != "cp" {
		return jobio.FetchResult{}, fmt.Errorf("%w: list_current is the control plane's alone", ErrPath)
	}
	if in.Kind != "fetch" || in.Repl != nil || in.MaxBytes <= 0 || in.ListCurrent == (plan != nil) || !subjectRE.MatchString(in.Subject) ||
		!stanzaRE.MatchString(in.Stanza) || !strings.HasPrefix(in.Stanza, in.Subject+"-") || !validPrefix(st.Prefix()) {
		return jobio.FetchResult{}, fmt.Errorf("%w: not a fetch input for this subject's stanza and prefix", ErrInput)
	}
	f := &fetcher{ctx: ctx, in: in, st: st, base: base(st.Prefix(), in.Subject), r: jobio.FetchResult{OK: true}}
	var rows []planned
	if !in.ListCurrent {
		var err error
		if rows, err = f.readPlan(plan); err != nil {
			return jobio.FetchResult{}, err
		}
	}
	root, err := syscall.Open(dest, dirFlags, 0)
	if err != nil {
		return jobio.FetchResult{}, fmt.Errorf("%w: the fetch directory: %v", ErrPath, err)
	}
	defer syscall.Close(root)
	f.root = root
	if in.ListCurrent {
		return f.listCurrent()
	}
	for _, p := range rows {
		if p.vid == "" {
			if p.vid, err = f.oldest(p.key); err != nil {
				return jobio.FetchResult{}, err
			}
		}
		if err := f.get(p); err != nil {
			return jobio.FetchResult{}, err
		}
	}
	return f.r, nil
}

type fetcher struct {
	ctx  context.Context
	in   jobio.Input
	st   Store
	base string // "<prefix>/<subject>"
	root int
	r    jobio.FetchResult
}

// planned is one object to fetch: its repository path and key, the version,
// the hash to verify ("" none), and its size — exact, or a bound only.
type planned struct {
	rel, key, vid, sum string
	kind               walname.Kind
	size               int64
	exact              bool
}

// check admits rel for the job's stanza and timelines and builds its key.
func (f *fetcher) check(rel string) (string, walname.Kind, bool) {
	k, tli, _, ok := walname.RepoPath(f.in.Stanza, rel)
	key, err := Key(f.st.Prefix(), f.in.Subject, rel)
	if (k == walname.Segment || k == walname.History || k == walname.Label) && !walname.Admitted(tli, f.in.Timelines) {
		ok = false
	}
	return key, k, ok && err == nil
}

// readPlan reads and checks the whole plan: every row a path of the job's
// stanza and an admitted timeline, once, within its kind's bound.
func (f *fetcher) readPlan(plan io.Reader) ([]planned, error) {
	var rows []planned
	seen := map[string]bool{}
	err := jobio.ReadPlan(plan, func(r jobio.PlanRow) error {
		if len(rows) == fetchMaxRows {
			return fmt.Errorf("%w: a plan of more than %d rows", ErrTooLarge, fetchMaxRows)
		}
		key, k, ok := f.check(r.Key)
		if !ok || seen[r.Key] || r.VersionID != "" && !validVersion(r.VersionID) || r.Size > sizeMax(k) {
			return fmt.Errorf("%w: plan row %.80q", ErrPath, clean(r.Key))
		}
		seen[r.Key] = true
		rows = append(rows, planned{rel: r.Key, key: key, vid: r.VersionID, sum: r.SHA256, kind: k, size: r.Size, exact: k != walname.Info})
		return nil
	})
	if err != nil && !errors.Is(err, ErrPath) && !errors.Is(err, ErrTooLarge) {
		err = fmt.Errorf("%w: the plan: %v", ErrInput, err)
	}
	return rows, err
}

// list calls fn for each version under prefix, in the store's order, at most
// ListCurrentMaxPages pages in all for this fetch.
func (f *fetcher) list(prefix string, pages *int, fn func(s3x.Object) error) error {
	km, vm := "", ""
	for {
		if *pages == ListCurrentMaxPages {
			return fmt.Errorf("repl: listing above %d pages", ListCurrentMaxPages)
		}
		*pages++
		ctx, cancel := context.WithTimeout(f.ctx, CallTimeout)
		page, nk, nv, err := f.st.ListVersions(ctx, prefix, km, vm)
		cancel()
		if err != nil {
			return err
		}
		for _, o := range page {
			if err := fn(o); err != nil {
				return err
			}
		}
		if nk == "" {
			return nil
		}
		km, vm = nk, nv
	}
}

// oldest is the version id of key's oldest version that is an object.
func (f *fetcher) oldest(key string) (string, error) {
	vid, pages := "", 0
	err := f.list(key, &pages, func(o s3x.Object) error {
		if o.Key == key && !o.DeleteMarker {
			vid = o.VersionID // newest first: the last is the oldest
		}
		return nil
	})
	switch {
	case err != nil:
		return "", err
	case vid == "":
		return "", fmt.Errorf("%w: no version of %.80q", ErrMissing, clean(key))
	case !validVersion(vid):
		return "", fmt.Errorf("%w: a listed version id out of shape", ErrMismatch)
	}
	return vid, nil
}

// listCurrent fetches the control plane's two trees of the stanza.
func (f *fetcher) listCurrent() (jobio.FetchResult, error) {
	pages := 0
	for _, tree := range []string{"archive", "backup"} {
		prefix := f.base + "/" + tree + "/" + f.in.Stanza + "/"
		var cur string
		var oldest, newest *s3x.Object
		flush := func() error {
			if cur == "" {
				return nil
			}
			defer func() { cur, oldest, newest = "", nil, nil }()
			rel := strings.TrimPrefix(cur, f.base+"/")
			key, k, ok := f.check(rel)
			pick := oldest
			if k == walname.Info {
				pick = newest
			}
			if !ok || key != cur || pick == nil { // refused (a key that is not the one built), or markers only: absent
				return nil
			}
			if !validVersion(pick.VersionID) || pick.Size < 0 || pick.Size > sizeMax(k) {
				return fmt.Errorf("%w: the listed version of %.80q is out of shape", ErrMismatch, clean(rel))
			}
			return f.get(planned{rel: rel, key: key, vid: pick.VersionID, kind: k, size: pick.Size, exact: true})
		}
		err := f.list(prefix, &pages, func(o s3x.Object) error {
			if o.Key != cur {
				if err := flush(); err != nil {
					return err
				}
				cur = o.Key
			}
			if !o.DeleteMarker {
				if newest == nil {
					newest = &o
				}
				oldest = &o
			}
			return nil
		})
		if err == nil {
			err = flush()
		}
		if err != nil {
			return jobio.FetchResult{}, err
		}
	}
	if f.r.NewestSet == "" {
		return jobio.FetchResult{}, fmt.Errorf("%w: no backup set with its manifest", ErrMissing)
	}
	return f.r, nil
}

// get fetches p into its path below the root, created exclusively; a file
// that fails is removed again.
func (f *fetcher) get(p planned) error {
	dir, name, err := f.mkdirs(p.rel)
	if err != nil {
		return err
	}
	defer syscall.Close(dir)
	fd, err := syscall.Openat(dir, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o640)
	if err != nil {
		return fmt.Errorf("%w: create %.80q: %v", ErrPath, clean(p.rel), err)
	}
	file := os.NewFile(uintptr(fd), name)
	done := false
	defer func() {
		file.Close()
		if !done {
			syscall.Unlinkat(dir, name)
		}
	}()
	if err := file.Chmod(0o640); err != nil {
		return fmt.Errorf("%w: %v", ErrPath, err)
	}
	s := &sink{f: file, h: sha256.New(), left: f.in.MaxBytes - f.r.Bytes}
	ctx, cancel := context.WithTimeout(f.ctx, CallTimeout+time.Duration(p.size/fetchRate+1)*time.Second)
	o, err := f.st.Get(ctx, p.key, p.vid, s, p.size)
	cancel()
	switch {
	case errors.Is(s.err, errOver):
		return fmt.Errorf("%w: %.80q would pass %d bytes", ErrTooLarge, clean(p.rel), f.in.MaxBytes)
	case errors.Is(s.err, syscall.EDQUOT), errors.Is(s.err, syscall.ENOSPC):
		return fmt.Errorf("%w: %v", ErrQuota, s.err)
	case s.err != nil:
		return fmt.Errorf("%w: write %.80q: %v", ErrPath, clean(p.rel), s.err)
	case errors.Is(err, s3x.ErrNotFound):
		return fmt.Errorf("%w: %.80q version %.80q", ErrMissing, clean(p.rel), clean(p.vid))
	case err != nil && o.Size > p.size:
		return fmt.Errorf("%w: %.80q is larger than recorded", ErrMismatch, clean(p.rel))
	case err != nil:
		return err
	case s.n > p.size, p.exact && s.n != p.size, o.VersionID != p.vid, p.sum != "" && hex.EncodeToString(s.h.Sum(nil)) != p.sum:
		return fmt.Errorf("%w: %.80q", ErrMismatch, clean(p.rel))
	}
	done = true
	f.r.Files++
	f.r.Bytes += s.n
	if !f.in.ListCurrent {
		return nil
	}
	if p.kind == walname.Segment && (f.r.NewestSegment == "" || path.Base(p.rel)[8:24] > f.r.NewestSegment[8:]) {
		f.r.NewestSegment = path.Base(p.rel)[:24]
	}
	if label := strings.Split(p.rel, "/")[2]; p.kind == walname.SetManifest && label > f.r.NewestSet {
		f.r.NewestSet = label
	}
	return nil
}

// mkdirs opens the directory of rel below the root, one level at a time,
// never through a link, creating what is missing at 2750. It returns that
// directory and the file's name.
func (f *fetcher) mkdirs(rel string) (int, string, error) {
	parts := strings.Split(rel, "/")
	fd, err := syscall.Dup(f.root)
	if err != nil {
		return -1, "", err
	}
	for _, p := range parts[:len(parts)-1] {
		next, err := syscall.Openat(fd, p, dirFlags, 0)
		if err == syscall.ENOENT {
			if err = syscall.Mkdirat(fd, p, 0o750); err == nil {
				if next, err = syscall.Openat(fd, p, dirFlags, 0); err == nil {
					err = syscall.Fchmod(next, 0o2750)
				}
			}
		}
		syscall.Close(fd)
		if err != nil {
			if next > 0 {
				syscall.Close(next)
			}
			return -1, "", fmt.Errorf("%w: directory %.80q of %.80q: %v", ErrPath, clean(p), clean(rel), err)
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

var errOver = errors.New("over the byte limit")

// sink writes a fetched body to its file and hashes it, refusing any write
// past the job's byte limit; the first write error is kept.
type sink struct {
	f       *os.File
	h       hash.Hash
	n, left int64
	err     error
}

func (s *sink) Write(b []byte) (int, error) {
	if int64(len(b)) > s.left-s.n {
		s.err = errOver
		return 0, s.err
	}
	n, err := fileWrite(s.f, b)
	s.h.Write(b[:n])
	s.n += int64(n)
	if err != nil {
		s.err = err
	}
	return n, err
}
