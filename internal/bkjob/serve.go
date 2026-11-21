package bkjob

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/walname"
)

// The serve job's failure code.
const serveRspool = "rspool" // the restore spool's directories could not be opened, made or listed

const (
	servePerPass  = 8       // requests answered in one pass, the newest first
	serveUnlinks  = 1024    // refused requests removed in one pass
	serveNoneMax  = 64      // names kept in the result's none
	serveNamesMax = 1 << 16 // names whose answers are counted
	serveDraws    = 8       // temporary names tried for one answer
)

var (
	// servePoll is the pause after a pass that answered nothing.
	servePoll = 100 * time.Millisecond
	// serveBatch is how many entries of req/ one read takes.
	serveBatch = 1024
	// serveRand draws a temporary name's 16 hex digits. Tests replace it.
	serveRand = func() string {
		var b [8]byte
		rand.Read(b[:])
		return hex.EncodeToString(b[:])
	}
)

// request is one entry of req/ that may be answered.
type request struct {
	name  string
	kind  walname.Kind
	tli   uint32
	ctime int64
}

// server is one serve job: the two directories it holds open and its result.
type server struct {
	in             jobio.Input
	req, out       int // descriptors of req/ and out/
	priv           string
	max            int
	answers        map[string]int
	res            jobio.ServeResult
	lastSegmentNum string
}

// Serve answers the recovering server's requests for archived WAL until ctx
// ends — the stop signal, or the launcher's stop at promotion — and then
// returns its result. Everything in rspool is the cluster's to write.
//
// req/ and out/ are opened once, from rspool, without following a link; an
// entry of either name that is not a directory is removed and the directory
// made again. Every request is then read, and every answer written, through
// those two descriptors only, so a later swap of the names redirects nothing.
//
// A request is a regular file of the job's uid under a name walname.Request
// takes; anything else is removed unread (a directory stays), and so is a
// request for a name already answered in.MaxAnswers times (bklimit's
// ServeMaxAnswers when unset or above it). A name of a timeline not admitted
// is answered "not in the archive" without the tool. The others are fetched
// with the tool's archive-get into the job's private directory and copied into
// out/ under a fresh temporary name (exclusive, never through a link), then
// renamed to the request's name; only the tool's exit 1 is answered "not in
// the archive" (<name>.none), any other failure is retried later. Each pass
// answers at most eight requests that have no answer waiting, the most
// recently made first, so requests left from before cannot hold back the
// server's own.
func Serve(ctx context.Context, in jobio.Input, rspool string) (jobio.ServeResult, error) {
	s := &server{in: in, req: -1, out: -1, answers: map[string]int{},
		res: jobio.ServeResult{OK: true, None: []string{}}}
	s.max = in.MaxAnswers
	if s.max <= 0 || s.max > bklimit.ServeMaxAnswers {
		s.max = bklimit.ServeMaxAnswers
	}
	defer func() {
		for _, fd := range []int{s.req, s.out} {
			if fd >= 0 {
				syscall.Close(fd)
			}
		}
	}()
	rfd, err := syscall.Open(rspool, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return s.res, fail(serveRspool, "opening the restore spool: %v", err)
	}
	s.req, err = serveDir(rfd, "req")
	if err == nil {
		s.out, err = serveDir(rfd, "out")
	}
	syscall.Close(rfd)
	if err != nil {
		return s.res, fail(serveRspool, "%v", err)
	}
	s.dropTemporaries()
	if s.priv, err = os.MkdirTemp(privRoot, "serve-"); err != nil {
		return s.res, fail(serveRspool, "making the private directory: %v", err)
	}
	defer os.RemoveAll(s.priv)

	for ctx.Err() == nil {
		reqs, err := s.list(ctx)
		if err != nil {
			return s.res, fail(serveRspool, "listing the requests: %v", err)
		}
		answered := 0
		for _, r := range reqs {
			if ctx.Err() != nil {
				break
			}
			if s.answer(ctx, r) {
				answered++
			}
		}
		if answered == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(servePoll):
			}
		}
	}
	return s.res, nil
}

// serveDir opens dir name of rfd, never through a link. An entry of that name
// that is not a directory is removed and a directory made in its place.
func serveDir(rfd int, name string) (int, error) {
	const flags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	fd, err := syscall.Openat(rfd, name, flags, 0)
	if err == nil {
		return fd, nil
	}
	if err != syscall.ENOTDIR && err != syscall.ELOOP && err != syscall.ENOENT {
		return -1, &os.PathError{Op: "open", Path: name, Err: err}
	}
	if err != syscall.ENOENT {
		if err := syscall.Unlinkat(rfd, name); err != nil {
			return -1, &os.PathError{Op: "remove", Path: name, Err: err}
		}
	}
	if err := syscall.Mkdirat(rfd, name, 0o700); err != nil {
		return -1, &os.PathError{Op: "make", Path: name, Err: err}
	}
	fd, err = syscall.Openat(rfd, name, flags, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return fd, nil
}

// dirFile is a fresh descriptor of the directory fd, read from its start.
func dirFile(fd int, name string) (*os.File, error) {
	d, err := syscall.Openat(fd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(d), name), nil
}

// dropTemporaries removes what a stopped serve job left in out/: entries of
// the temporary pattern, by name, unopened (at most serveUnlinks).
func (s *server) dropTemporaries() {
	d, err := dirFile(s.out, "out")
	if err != nil {
		return
	}
	defer d.Close()
	n := 0
	for n < serveUnlinks {
		ents, err := d.ReadDir(1024)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".tmp-") && n < serveUnlinks && syscall.Unlinkat(s.out, e.Name()) == nil {
				n++
			}
		}
		if err != nil {
			return
		}
	}
}

// list reads req/ in batches and returns the newest servePerPass requests
// that may be answered now. It stops between batches once ctx ends. It removes what may not be answered (at most
// serveUnlinks a pass) and keeps no more than servePerPass entries.
func (s *server) list(ctx context.Context) ([]request, error) {
	d, err := dirFile(s.req, "req")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	var top []request
	unlinked := 0
	refuse := func(name string) {
		if unlinked < serveUnlinks && syscall.Unlinkat(s.req, name) == nil {
			unlinked++
			s.res.Refused++
		}
	}
	for {
		ents, err := d.ReadDir(serveBatch)
		for _, e := range ents {
			name := e.Name()
			k, tli, ok := walname.Request(name)
			if !ok {
				refuse(name)
				continue
			}
			var st syscall.Stat_t
			if err := statNoFollow(s.req, name, &st); err != nil {
				continue // gone
			}
			if st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != s.in.UID {
				refuse(name)
				continue
			}
			if s.waiting(name) {
				continue
			}
			if s.answers[name] >= s.max {
				refuse(name)
				continue
			}
			top = append(top, request{name: name, kind: k, tli: tli, ctime: st.Ctim.Nano()})
			if len(top) > servePerPass {
				top = newest(top)
			}
		}
		if err == io.EOF {
			return newest(top), nil
		}
		if ctx.Err() != nil { // stopped: a planted backlog must not outlast the stop's grace
			return newest(top), nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// newest keeps the servePerPass most recently made requests, newest first.
func newest(rs []request) []request {
	slices.SortFunc(rs, func(a, b request) int {
		return cmp.Or(cmp.Compare(b.ctime, a.ctime), strings.Compare(a.name, b.name))
	})
	return rs[:min(len(rs), servePerPass)]
}

// waiting: an answer for name is in out/ and has not been taken yet.
func (s *server) waiting(name string) bool {
	var st syscall.Stat_t
	return statNoFollow(s.out, name, &st) == nil ||
		statNoFollow(s.out, name+".none", &st) == nil
}

// answer answers one request and reports whether it did.
func (s *server) answer(ctx context.Context, r request) bool {
	if !walname.Admitted(r.tli, s.in.Timelines) {
		return s.none(r.name)
	}
	dest := filepath.Join(s.priv, r.name)
	defer os.Remove(dest)
	exit, _, err := Run(ctx, "archive-get", r.name, dest)
	switch {
	case err != nil || exit > 1:
		return false // retried in a later pass
	case exit == 1:
		return s.none(r.name)
	}
	max := int64(bklimit.SmallMax)
	if r.kind == walname.Segment {
		max = bklimit.SegmentMax
	}
	ok, err := s.file(r.name, dest, max)
	if err != nil {
		return false
	}
	if !ok { // larger than any answer can be
		if syscall.Unlinkat(s.req, r.name) == nil {
			s.res.Refused++
		}
		return false
	}
	s.count(r.name, false)
	s.res.Served++
	if r.kind == walname.Segment {
		if n := r.name[8:]; n > s.lastSegmentNum || n == s.lastSegmentNum && r.name > s.res.LastSegment {
			s.lastSegmentNum, s.res.LastSegment = n, r.name
		}
	}
	return true
}

// none answers name "not in the archive".
func (s *server) none(name string) bool {
	fd, err := syscall.Openat(s.out, name+".none", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	s.count(name, true)
	if s.res.None = append(s.res.None, name); len(s.res.None) > serveNoneMax {
		s.res.None = slices.Delete(s.res.None, 0, len(s.res.None)-serveNoneMax)
	}
	return true
}

// count records an answer for name.
func (s *server) count(name string, none bool) {
	if len(s.answers) >= serveNamesMax {
		// ponytail: the per-name cap forgets every name past 65,536 distinct
		// ones; a bounded LRU if a recovery ever asks for more.
		clear(s.answers)
	}
	s.answers[name]++
	s.res.Last, s.res.LastNone = name, none
}

// file copies the tool's answer at src (in the private directory) into out/
// under a fresh temporary name — created exclusively, never through a link —
// and renames it to name within out/. ok is false for an answer above max.
func (s *server) file(name, src string, max int64) (ok bool, err error) {
	f, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() > max {
		return false, err
	}
	var tmp string
	fd := -1
	for range serveDraws {
		tmp = ".tmp-" + name + "-" + serveRand()
		fd, err = syscall.Openat(s.out, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
		if err != syscall.EEXIST {
			break
		}
	}
	if err != nil {
		return false, err
	}
	w := os.NewFile(uintptr(fd), tmp)
	n, err := io.Copy(w, io.LimitReader(f, max+1))
	if err == nil {
		err = w.Sync()
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		syscall.Unlinkat(s.out, tmp)
		return false, nil
	}
	if err == nil {
		err = syscall.Renameat(s.out, tmp, s.out, name)
	}
	if err != nil {
		syscall.Unlinkat(s.out, tmp)
		return false, err
	}
	return true, nil
}

// oPath is O_PATH (amd64, arm64): a descriptor that names an entry, a link
// itself included, without opening it.
const oPath = 0x200000

// statNoFollow is the status of entry name of dirfd, a link's own.
func statNoFollow(dirfd int, name string, st *syscall.Stat_t) error {
	fd, err := syscall.Openat(dirfd, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fstat(fd, st)
}
