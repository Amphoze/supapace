package adminapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"syscall"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// The dashboard's audit log of SQL statements, as Studio writes it in its
// data volume: <DataDir>/<ref>/audit.log and the rolled audit.log.1. Studio's
// uid owns the directory, so the files and the path are untrusted: each
// directory is opened without following a link, relative to the one before
// it; a file is opened without following a link and without blocking (a
// FIFO), and read only when the open descriptor is a regular file; at most
// auditMaxBytes are read, the newest first; a line that is not one record of
// at most auditMaxLine bytes is counted in skipped; every text is cleaned.

const (
	auditMaxBytes    = 16 << 20
	auditMaxLine     = 4 << 10
	auditDefaultTail = 100
	auditMaxTail     = 1000
	auditField       = 255 // bytes kept of each member
)

type auditRecord struct {
	T         string `json:"t"`
	Ref       string `json:"ref"`
	Iss       string `json:"iss"`
	Sub       string `json:"sub"`
	Role      string `json:"role"`
	Login     string `json:"login"`
	Kind      string `json:"kind"`
	SQLSHA256 string `json:"sql_sha256,omitempty"`
}

type auditJSON struct {
	Ref       string        `json:"ref"`
	Records   []auditRecord `json:"records"`
	Skipped   int           `json:"skipped"`
	Truncated bool          `json:"truncated"`
}

func (a *api) audit(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, badRequest("query: %v", err)
	}
	tail := auditDefaultTail
	for k, v := range q {
		if k != "tail" || len(v) != 1 {
			return nil, badRequest("the only query parameter is one tail")
		}
		if tail, err = strconv.Atoi(v[0]); err != nil || tail < 1 || tail > auditMaxTail {
			return nil, badRequest("tail must be 1 to %d", auditMaxTail)
		}
	}
	if _, err := a.st.GetProject(r.Context(), ref); err != nil {
		return nil, err
	}
	out, err := readAudit(dashcfg.PathsFor(a.paths).DataDir(), ref, tail)
	if err != nil {
		return nil, err
	}
	out.Ref = ref
	return out, nil
}

const openFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// errAbsent is a directory or file that does not exist: nothing recorded.
var errAbsent = errors.New("absent")

// openAt opens name relative to the directory dirfd (a path when dirfd is
// -1) without following a link.
func openAt(dirfd int, name string, flags int) (int, error) {
	var fd int
	var err error
	if dirfd < 0 {
		fd, err = syscall.Open(name, openFlags|flags, 0)
	} else {
		fd, err = syscall.Openat(dirfd, name, openFlags|flags, 0)
	}
	if errors.Is(err, syscall.ENOENT) {
		return -1, errAbsent
	}
	return fd, err
}

func readAudit(dataDir, ref string, tail int) (auditJSON, error) {
	out := auditJSON{Records: []auditRecord{}}
	notDir := conflict("the dashboard's data directory of project %s is not a directory (it may be a link), so it was not read; "+
		"Studio writes it: look into it on the node", ref)
	dfd, err := openAt(-1, dataDir, syscall.O_DIRECTORY)
	if errors.Is(err, errAbsent) {
		return out, nil
	}
	if err != nil {
		return out, err // root's path: a failure is the daemon's
	}
	defer syscall.Close(dfd)
	rfd, err := openAt(dfd, ref, syscall.O_DIRECTORY)
	switch {
	case errors.Is(err, errAbsent):
		return out, nil
	case errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR):
		return out, notDir
	case err != nil:
		return out, err
	}
	defer syscall.Close(rfd)
	// The newest file has the first claim on the budget.
	budget := int64(auditMaxBytes)
	var chunks [2][]byte
	for i, name := range []string{"audit.log", "audit.log.1"} {
		b, cut, err := readTail(rfd, ref, name, budget)
		if err != nil {
			return out, err
		}
		chunks[1-i], budget = b, budget-int64(len(b))
		out.Truncated = out.Truncated || cut
	}
	// Lines are walked in place, and at most 2 × tail records are held: a file
	// of empty or short lines costs no memory beyond the bytes read.
	var recs []auditRecord
	for _, c := range chunks { // older first
		for len(c) > 0 {
			line := c
			if i := bytes.IndexByte(c, '\n'); i >= 0 {
				line, c = c[:i], c[i+1:]
			} else {
				c = nil
			}
			if len(line) == 0 {
				continue
			}
			rec, ok := parseAudit(line)
			if !ok || rec.Ref != ref {
				out.Skipped++
				continue
			}
			if recs = append(recs, rec); len(recs) >= 2*tail {
				recs, out.Truncated = append(recs[:0], recs[len(recs)-tail:]...), true
			}
		}
	}
	if len(recs) > tail {
		recs, out.Truncated = recs[len(recs)-tail:], true
	}
	out.Records = append(out.Records, recs...)
	return out, nil
}

// readTail reads at most the last budget bytes of the regular file name in
// dirfd, from the start of a line; cut reports that bytes were left out.
func readTail(dirfd int, ref, name string, budget int64) (b []byte, cut bool, err error) {
	fd, err := openAt(dirfd, name, syscall.O_NONBLOCK)
	if errors.Is(err, errAbsent) {
		return nil, false, nil
	}
	notFile := conflict("%s of project %s is not a regular file with one name (a link, a hard link, a FIFO or a directory), so it was not read; "+
		"Studio writes it: look into the dashboard's data directory on the node, and remove it to read the audit again", name, ref)
	if errors.Is(err, syscall.ELOOP) {
		return nil, false, notFile
	}
	if err != nil {
		return nil, false, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	// A second name (a hard link) makes it another file's too: not read.
	if st, ok := fi.Sys().(*syscall.Stat_t); !fi.Mode().IsRegular() || !ok || st.Nlink != 1 {
		return nil, false, notFile
	}
	off, size := int64(0), fi.Size()
	if size > budget {
		off, cut, size = size-budget, true, budget
	}
	// One buffer of the size read; a file that shrank meanwhile ends early.
	b = make([]byte, size)
	n, err := io.ReadFull(io.NewSectionReader(f, off, size), b)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, false, err
	}
	b = b[:n]
	if cut { // the first line is a part of one
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		} else {
			b = nil
		}
	}
	return b, cut, nil
}

// parseAudit reads one record: a JSON object of exactly the record's
// members, each a string (sql_sha256 optional), none repeated, at most
// auditMaxLine bytes. Every text is cleaned.
func parseAudit(line []byte) (auditRecord, bool) {
	if len(line) > auditMaxLine || !bytes.HasPrefix(line, []byte("{")) {
		return auditRecord{}, false
	}
	var v struct {
		T, Ref, Iss, Sub, Role, Login, Kind *string
		SQLSHA256                           *string `json:"sql_sha256"`
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&v) != nil {
		return auditRecord{}, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return auditRecord{}, false
	}
	if uniqueMembers(json.NewDecoder(bytes.NewReader(line)), true) != nil {
		return auditRecord{}, false
	}
	for _, p := range []*string{v.T, v.Ref, v.Iss, v.Sub, v.Role, v.Login, v.Kind} {
		if p == nil {
			return auditRecord{}, false
		}
	}
	c := func(p *string) string {
		if p == nil {
			return ""
		}
		return pgsock.Sanitize(*p, auditField)
	}
	return auditRecord{c(v.T), c(v.Ref), c(v.Iss), c(v.Sub), c(v.Role), c(v.Login), c(v.Kind), c(v.SQLSHA256)}, true
}
