package repl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
	"github.com/Amphoze/supapace/internal/walname"
)

// Store is what the replication program asks of the object store: the
// calls of *s3x.Client it makes, and the declared prefix of the bucket.
// Nothing in it deletes an object or a version.
type Store interface {
	Prefix() string
	Put(ctx context.Context, key string, body []byte, meta map[string]string, ifAbsent bool) (versionID string, err error)
	Head(ctx context.Context, key, versionID string) (s3x.Object, error)
	Get(ctx context.Context, key, versionID string, w io.Writer, max int64) (s3x.Object, error)
	CreateMultipart(ctx context.Context, key string, meta map[string]string) (uploadID string, err error)
	UploadPart(ctx context.Context, key, uploadID string, n int, body []byte) (etag string, err error)
	CompleteMultipart(ctx context.Context, key, uploadID string, etags []string, ifAbsent bool) (versionID string, err error)
	AbortMultipart(ctx context.Context, key, uploadID string) error
	ListVersions(ctx context.Context, prefix, keyMarker, versionMarker string) (page []s3x.Object, nextKey, nextVersion string, err error)
}

// resultRoom is what the result line keeps free beside its rows: the info
// versions, the set labels and the notices.
const resultRoom = 128 << 10

// versionMax bounds a version id the store hands back.
const versionMax = 1024

// Warn, when set, is told why a copy stopped, raw (the program scrubs every
// key from it, then cleans it, before it writes it to its standard error).
var Warn func(string)

// errStopped ends the copy at the first failed upload.
var errStopped = errors.New("upload failed")

// Copy copies the finished files of the repository at repo to the store, in
// ascending key order, and returns the new rows. The four info files are read
// before anything else is walked and go up last, and only when they changed
// and nothing else stopped the job; a segment or label of a timeline above 1
// goes up only once that timeline's history is recorded or went up earlier in
// this job. Data files are written once (a conditional create); a key that
// exists is compared with the local file by HEAD, adopted when equal, never
// overwritten. The job stops at the first failed upload, at its caps and at
// the day's budget.
func Copy(ctx context.Context, in jobio.Input, repo string, index io.Reader, st Store) (jobio.ReplResult, error) {
	if in.Repl == nil || in.Repl.Mode != "copy" || !stanzaRE.MatchString(in.Stanza) || !strings.HasPrefix(in.Stanza, in.Subject+"-") ||
		!subjectRE.MatchString(in.Subject) || !validPrefix(st.Prefix()) {
		return jobio.ReplResult{}, fmt.Errorf("%w: not a copy input for this subject's stanza and prefix", ErrInput)
	}
	ix, err := loadIndex(index)
	if err != nil {
		return jobio.ReplResult{}, err
	}
	root, err := syscall.Open(repo, dirFlags, 0)
	if err != nil {
		return jobio.ReplResult{}, fmt.Errorf("repl: the repository: %w", err)
	}
	defer syscall.Close(root)

	c := &copier{ctx: ctx, in: in, st: st, ix: ix, root: root, buf: make([]byte, bklimit.PartSize),
		maxFiles: min(max(in.Repl.MaxFiles, 0), bklimit.ReplMaxFiles), maxBytes: min(max(in.Repl.MaxBytes, 0), bklimit.ReplMaxBytes),
		hist: map[string]bool{}, setTotal: map[string]int{}, setDone: map[string]int{}, notice: map[string]*jobio.Notice{}}
	c.r = jobio.ReplResult{OK: true, Mode: "copy", Uploaded: []jobio.Row{}, Adopted: []jobio.Row{}, Info: []jobio.InfoVersion{},
		SetsComplete: []string{}, Notices: []jobio.Notice{}}

	// The info files first: every set they list was complete on disk when read.
	infos := c.readInfos()

	maxEntries := bklimit.ReplMaxEntries
	if n := in.Repl.MaxEntries; n > 0 && n < maxEntries {
		maxEntries = n
	}
	w := &walk{root: root, uid: in.UID, stanza: in.Stanza, timelines: in.Timelines, max: maxEntries}
	w.run()
	c.r.Walked, c.r.Truncated = w.walked, w.truncated
	c.unreadable += w.unreadable
	if w.unlisted > 0 {
		c.note("unlisted-entry", w.unlisted, w.firstBad)
	}
	if w.unreadable > 0 {
		c.note("unreadable-entry", 0, w.firstBad)
	}
	if w.truncated {
		c.note("walk-truncated", 1, "")
	}
	slices.SortFunc(w.files, func(a, b file) int { return strings.Compare(a.rel, b.rel) })
	for _, f := range w.files {
		if isSetKind(f.kind) {
			c.setTotal[f.label]++
		}
	}
	for _, f := range w.files {
		if err := c.one(f); err != nil {
			break
		}
	}
	if c.r.Stopped == "" && !w.truncated && c.unreadable == 0 && c.changed == 0 && c.r.Held == 0 {
		c.uploadInfos(infos)
	}
	if c.r.Stopped == "" && c.r.Held > 0 {
		c.r.Stopped = "held"
	}
	c.r.Complete = c.r.Stopped == "" && !w.truncated && c.unreadable == 0 && c.changed == 0
	if !w.truncated {
		for label, n := range c.setTotal {
			if c.setDone[label] == n && c.manifest[label] && len(c.r.SetsComplete) < bklimit.ReplMaxFiles {
				c.r.SetsComplete = append(c.r.SetsComplete, label)
			}
		}
		slices.Sort(c.r.SetsComplete)
	}
	for _, code := range []string{"unlisted-entry", "history-rewritten", "offsite-differs", "walk-truncated", "unreadable-entry", "segment-without-history"} {
		if n := c.notice[code]; n != nil {
			if code == "unreadable-entry" {
				n.Count = c.unreadable
			}
			c.r.Notices = append(c.r.Notices, *n)
		}
	}
	return c.r, nil
}

type copier struct {
	ctx  context.Context
	in   jobio.Input
	st   Store
	ix   *index
	root int
	buf  []byte

	maxFiles            int
	maxBytes            int64
	spentBytes          int64 // uploaded and adopted: what the day's budget is charged
	resultBytes         int
	hist                map[string]bool // history files recorded by this job
	setTotal, setDone   map[string]int
	manifest            map[string]bool
	notice              map[string]*jobio.Notice
	unreadable, changed int64
	r                   jobio.ReplResult
}

func isSetKind(k walname.Kind) bool {
	return k == walname.SetManifest || k == walname.SetManifestCopy || k == walname.SetFile
}

func (c *copier) note(code string, n int64, detail string) {
	x := c.notice[code]
	if x == nil {
		x = &jobio.Notice{Code: code, Detail: clean(detail)}
		c.notice[code] = x
	}
	x.Count += n
}

// clean makes a name from the tree fit a notice: printable ASCII, 256 bytes.
func clean(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch < 0x20 || ch > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) > 256 {
		b = b[:256]
	}
	return string(b)
}

// done marks f as off-site, for the completeness of its set.
func (c *copier) done(f file) {
	if isSetKind(f.kind) {
		c.setDone[f.label]++
		if f.kind == walname.SetManifest {
			if c.manifest == nil {
				c.manifest = map[string]bool{}
			}
			c.manifest[f.label] = true
		}
	}
	if f.kind == walname.History {
		c.hist[f.rel] = true
	}
}

// one copies f, or tells why not. An error stops the job.
func (c *copier) one(f file) error {
	if err := c.ctx.Err(); err != nil { // the program's bound: stop with what went up
		return c.stop("upload-failed", err)
	}
	if (f.kind == walname.Segment || f.kind == walname.Label) && f.tli > 1 {
		parts := strings.Split(f.rel, "/") // archive/<stanza>/<archive id>/…
		h := strings.Join(parts[:3], "/") + "/" + fmt.Sprintf("%08X", f.tli) + ".history"
		if !c.hist[h] {
			_, ok, err := c.ix.lookup(h)
			if err != nil {
				return c.stop("upload-failed", err)
			}
			if !ok {
				c.r.Held++
				c.note("segment-without-history", 1, f.rel)
				return nil
			}
		}
	}
	key, err := Key(c.st.Prefix(), c.in.Subject, f.rel)
	if err != nil {
		return c.stop("upload-failed", err)
	}
	h, ok, err := c.ix.lookup(f.rel)
	if err != nil {
		return c.stop("upload-failed", err)
	}
	if ok && h.hasHash {
		if h.size == f.size && h.ino == int64(f.ino) && h.ctimeNS == f.ctimeNS {
			c.done(f)
			return nil
		}
		c.note("history-rewritten", 1, f.rel)
		return nil
	}
	if f.size > sizeMax(f.kind) {
		c.unreadable++
		c.note("unreadable-entry", 0, f.rel)
		return nil
	}
	if stop := c.room(f); stop != "" {
		return c.stop(stop, nil)
	}
	src, err := c.open(f)
	if src == nil {
		return err
	}
	defer src.Close()
	sum, err := c.hash(src, f)
	if sum == "" {
		return err
	}
	row := jobio.Row{Key: f.rel, Size: f.size, SHA256: sum, Ino: int64(f.ino), CtimeNS: f.ctimeNS}
	if ok { // recorded without a hash: compare before it is skipped
		return c.compare(f, key, row)
	}
	vid, err := c.upload(src, f, key, sum)
	if errors.Is(err, s3x.ErrExists) {
		return c.compare(f, key, row)
	}
	if err != nil {
		return c.stop("upload-failed", err)
	}
	if vid == "" { // changed during the read: skipped for the cycle
		return nil
	}
	row.VersionID, row.At = vid, time.Now().UTC()
	c.add(&c.r.Uploaded, row)
	c.r.Bytes += f.size
	c.r.Objects++
	c.done(f)
	return nil
}

// room tells whether one more row fits the job's caps, the day's budget and
// the result line; "" when it does.
func (c *copier) room(f file) string {
	rowBytes := len(f.rel) + 300 + versionMax
	switch {
	case len(c.r.Uploaded)+len(c.r.Adopted) >= c.maxFiles, c.r.Bytes+f.size > c.maxBytes,
		c.resultBytes+rowBytes > bklimit.ResultMax-resultRoom:
		return "caps"
	case c.in.Repl.BudgetBytes >= 0 && c.spentBytes+f.size > c.in.Repl.BudgetBytes,
		c.in.Repl.BudgetObjects >= 0 && len(c.r.Uploaded)+len(c.r.Adopted)+1 > c.in.Repl.BudgetObjects:
		return "budget"
	}
	return ""
}

func (c *copier) add(list *[]jobio.Row, row jobio.Row) {
	b, _ := json.Marshal(row)
	c.resultBytes += len(b) + 1
	c.spentBytes += row.Size
	*list = append(*list, row)
}

func (c *copier) stop(why string, err error) error {
	if errors.Is(c.ctx.Err(), context.DeadlineExceeded) {
		why = "caps" // the program's own bound: what went up is recorded, the rest is the next job's
	}
	if c.r.Stopped == "" {
		c.r.Stopped = why
	}
	if err != nil && Warn != nil {
		Warn(err.Error())
	}
	return errStopped
}

// compare settles a key that exists in the store by HEAD: the object's size
// and the sha256 its writer set equal the local file's → adopted, with the
// version id HEAD answered; otherwise notice offsite-differs and nothing
// written.
func (c *copier) compare(f file, key string, row jobio.Row) error {
	o, err := c.st.Head(c.ctx, key, "")
	if err != nil {
		return c.stop("upload-failed", err)
	}
	if o.DeleteMarker || o.Size != row.Size || o.Meta["sha256"] != row.SHA256 || !validVersion(o.VersionID) {
		c.note("offsite-differs", 1, f.rel)
		return nil
	}
	row.VersionID, row.At = o.VersionID, time.Now().UTC()
	c.add(&c.r.Adopted, row)
	c.done(f)
	return nil
}

func validVersion(v string) bool { return v != "" && len(v) <= versionMax && !hasControl(v) }

// open opens f again by its path from the root, never following a link:
// it must still be a regular file of the project's uid with the listed
// inode, size and times. nil, nil: skipped for this cycle.
func (c *copier) open(f file) (*os.File, error) {
	fd, err := openRel(c.root, f.rel)
	if err != nil {
		if err == syscall.ENOENT {
			c.changed++
		} else {
			c.unreadable++
			c.note("unreadable-entry", 0, f.rel)
		}
		return nil, nil
	}
	s := os.NewFile(uintptr(fd), path.Base(f.rel))
	if !c.same(s, f) {
		s.Close()
		c.changed++
		return nil, nil
	}
	return s, nil
}

// same: still regular, owned by the project, with the listed inode, size,
// modification and change times.
func (c *copier) same(s *os.File, f file) bool {
	fi, err := s.Stat()
	if err != nil {
		return false
	}
	st := fi.Sys().(*syscall.Stat_t)
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG && int(st.Uid) == c.in.UID && st.Ino == f.ino && st.Size == f.size &&
		st.Ctim.Nano() == f.ctimeNS && st.Mtim.Nano() == f.mtimeNS
}

// hash reads f whole through a bounded reader and returns its SHA-256 in
// lower-case hex; "" when it changed during the read.
func (c *copier) hash(s *os.File, f file) (string, error) {
	h := sha256.New()
	n, err := io.CopyBuffer(h, io.NewSectionReader(s, 0, f.size+1), c.buf)
	if err != nil {
		c.unreadable++
		c.note("unreadable-entry", 0, f.rel)
		return "", nil
	}
	if n != f.size || !c.same(s, f) {
		c.changed++
		return "", nil
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// upload writes f under key once: one conditional PUT up to the part size,
// else a multipart upload with the condition at its completion, aborted when
// the completion is refused or fails. "" with no error: the file changed
// while it was sent, and nothing was written.
func (c *copier) upload(s *os.File, f file, key, sum string) (string, error) {
	meta := map[string]string{"sha256": sum}
	if f.size <= bklimit.PartSize {
		body := c.buf[:f.size]
		if _, err := s.ReadAt(body, 0); err != nil && err != io.EOF {
			return "", err
		}
		if !c.same(s, f) || hexSum(body) != sum {
			c.changed++
			return "", nil
		}
		vid, err := c.st.Put(c.ctx, key, body, meta, true)
		if err == nil && !validVersion(vid) {
			err = errors.New("repl: the store answered a version id out of shape")
		}
		return vid, err
	}
	id, err := c.st.CreateMultipart(c.ctx, key, meta)
	if err != nil {
		return "", err
	}
	vid, err := c.parts(s, f, key, id, sum)
	if err != nil || vid == "" {
		// A refused or failed completion leaves the upload and its parts: abort
		// it (an upload this job opened; never an object or a version).
		actx, cancel := context.WithTimeout(context.WithoutCancel(c.ctx), cleanupMax)
		c.st.AbortMultipart(actx, key, id)
		cancel()
	}
	return vid, err
}

func (c *copier) parts(s *os.File, f file, key, id, sum string) (string, error) {
	h := sha256.New()
	var etags []string
	for off, n := int64(0), 1; off < f.size; off, n = off+bklimit.PartSize, n+1 {
		body := c.buf[:min(bklimit.PartSize, f.size-off)]
		if _, err := s.ReadAt(body, off); err != nil && err != io.EOF {
			return "", err
		}
		h.Write(body)
		etag, err := c.st.UploadPart(c.ctx, key, id, n, body)
		if err != nil {
			return "", err
		}
		etags = append(etags, etag)
	}
	if hex.EncodeToString(h.Sum(nil)) != sum || !c.same(s, f) {
		c.changed++
		return "", nil
	}
	vid, err := c.st.CompleteMultipart(c.ctx, key, id, etags, true)
	if err == nil && !validVersion(vid) {
		err = errors.New("repl: the store answered a version id out of shape")
	}
	return vid, err
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// info is one info file as read before the walk.
type info struct {
	rel, name, sum string
	body           []byte
}

var infoNames = []string{"archive.info", "archive.info.copy", "backup.info", "backup.info.copy"}

// readInfos snapshots the four info files: regular, the project's, at most
// 1 MiB, unchanged while read. A missing one is no error (no stanza yet).
func (c *copier) readInfos() []info {
	var out []info
	for _, n := range infoNames {
		rel := "archive/" + c.in.Stanza + "/" + n
		if strings.HasPrefix(n, "backup") {
			rel = "backup/" + c.in.Stanza + "/" + n
		}
		fd, err := openRel(c.root, rel)
		if err != nil {
			if err != syscall.ENOENT && err != syscall.ELOOP && err != syscall.ENOTDIR {
				c.unreadable++
				c.note("unreadable-entry", 0, rel)
			}
			continue // a link or another type is counted by the walk
		}
		s := os.NewFile(uintptr(fd), n)
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != c.in.UID {
			s.Close()
			continue
		}
		f := file{rel: rel, kind: walname.Info, ino: st.Ino, size: st.Size, ctimeNS: st.Ctim.Nano(), mtimeNS: st.Mtim.Nano()}
		if f.size > bklimit.SmallMax {
			s.Close()
			c.unreadable++
			c.note("unreadable-entry", 0, rel)
			continue
		}
		body := make([]byte, f.size)
		_, err = s.ReadAt(body, 0)
		ok := (err == nil || err == io.EOF) && c.same(s, f)
		s.Close()
		if !ok {
			c.changed++
			continue
		}
		out = append(out, info{rel: rel, name: n, sum: hexSum(body), body: body})
	}
	return out
}

// uploadInfos puts each info file whose hash differs from the last recorded
// version: the one overwrite of the copy, a new version each time.
func (c *copier) uploadInfos(infos []info) {
	r := &c.r
	for _, i := range infos {
		if err := c.ctx.Err(); err != nil {
			c.stop("upload-failed", err)
			return
		}
		if c.in.Repl.InfoSHA256[i.name] == i.sum {
			continue
		}
		size := int64(len(i.body))
		if c.r.Bytes+size > c.maxBytes || len(c.r.Uploaded)+len(c.r.Adopted)+len(r.Info) >= c.maxFiles {
			c.stop("caps", nil)
			return
		}
		if c.in.Repl.BudgetBytes >= 0 && c.spentBytes+size > c.in.Repl.BudgetBytes ||
			c.in.Repl.BudgetObjects >= 0 && len(c.r.Uploaded)+len(c.r.Adopted)+len(r.Info)+1 > c.in.Repl.BudgetObjects {
			c.stop("budget", nil)
			return
		}
		key, err := Key(c.st.Prefix(), c.in.Subject, i.rel)
		if err != nil {
			c.stop("upload-failed", err)
			return
		}
		vid, err := c.st.Put(c.ctx, key, i.body, map[string]string{"sha256": i.sum}, false)
		if err == nil && !validVersion(vid) {
			err = errors.New("repl: the store answered a version id out of shape")
		}
		if err != nil {
			c.stop("upload-failed", err)
			return
		}
		r.Info = append(r.Info, jobio.InfoVersion{Name: i.name, VersionID: vid, SHA256: i.sum, At: time.Now().UTC()})
		c.r.Bytes += size
		c.r.Objects++
		c.spentBytes += size
	}
}
