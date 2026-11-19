package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/jwtx"
)

// maxDashFile is the largest dashboard file the gateway reads; a larger one
// is a bad file.
// ponytail: 64 MiB fits the gateway's memory, not every file dashfile's caps allow; the caps are to shrink to fit it.
const maxDashFile = 64 << 20

// principal is an (issuer, subject) pair.
type principal struct{ iss, sub string }

// dashTable is an immutable snapshot of the dashboard file, indexed.
type dashTable struct {
	file      dashfile.File
	keys      []jwtx.Key                      // the issuer's keys as dashboard keys
	notBefore map[principal]int64             // revocations
	roles     map[string]map[principal]string // ref → principal → role
}

// DashTable holds the dashboard table read from the dashboard file, as Table
// does the route file, with one difference: a missing file unloads the table,
// so removing it closes every dashboard.
type DashTable struct {
	path, domain string
	cur          atomic.Pointer[dashTable]

	mu   sync.Mutex  // serialises Reload
	prev os.FileInfo // the file last read, good or bad; nil while there is none
}

// Reload reads the dashboard file if its inode, mtime or size changed since
// the last read. A missing file unloads the table and returns nil. A file
// that cannot be read, is larger than the bound, fails to parse, names
// another studio domain or holds a key the dashboard-key check refuses
// returns an error and changes nothing; it is not read again until it
// changes.
func (t *DashTable) Reload() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Non-blocking, so a FIFO at the path cannot hold the reload in open; the
	// regular-file check below then refuses it.
	fh, err := os.OpenFile(t.path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		t.prev = nil
		if t.cur.Swap(nil) != nil {
			log.Printf("gateway: dashboard file removed, every dashboard closed")
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer fh.Close()
	fi, err := fh.Stat() // of the file that is read, not of a later one at the path
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() { // a device would be read to the bound, a directory not at all
		return fmt.Errorf("%s: not a regular file", t.path)
	}
	if t.prev != nil && os.SameFile(t.prev, fi) && fi.ModTime().Equal(t.prev.ModTime()) && fi.Size() == t.prev.Size() {
		return nil
	}
	t.prev = fi
	b, err := readBounded(fh, fi.Size(), maxDashFile)
	if err != nil {
		return fmt.Errorf("%s: %w", t.path, err)
	}
	f, err := dashfile.Parse(b)
	if err != nil {
		return err
	}
	dt, err := buildDash(f, t.domain)
	if err != nil {
		return err
	}
	t.cur.Store(dt)
	log.Printf("gateway: dashboard table generation %d, %d projects", f.Generation, len(f.Projects))
	return nil
}

// readBounded reads fh, whose stat gave size, whole into one buffer of that
// size, refusing a file of more than max bytes — by its size, and again by
// what arrives, for a file that grew after its stat.
func readBounded(fh *os.File, size, max int64) ([]byte, error) {
	if size > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	// One allocation: ReadFrom needs MinRead free to see the end. (Buffer.Grow
	// would do, but allocates twice under the race detector.)
	buf := bytes.NewBuffer(make([]byte, 0, size+bytes.MinRead))
	if _, err := buf.ReadFrom(io.LimitReader(fh, max+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return buf.Bytes(), nil
}

// buildDash indexes a parsed file. The file must name domain, and each
// issuer key must be RSA and pass jwtx.DashboardKeyFromJWK, or the whole
// file is refused.
func buildDash(f dashfile.File, domain string) (*dashTable, error) {
	if f.StudioDomain != domain {
		return nil, fmt.Errorf("dashboard file: studio_domain %q is not %q", f.StudioDomain, domain)
	}
	dt := &dashTable{file: f, notBefore: make(map[principal]int64, len(f.Revoked)),
		roles: make(map[string]map[principal]string, len(f.Projects))}
	if f.Issuer != nil {
		for _, k := range f.Issuer.Keys {
			if k.Kty != "RSA" {
				return nil, fmt.Errorf("dashboard file: key %q: kty %q is not RSA", k.Kid, k.Kty)
			}
			key, err := jwtx.DashboardKeyFromJWK(k.Kid, k.N, k.E)
			if err != nil {
				return nil, fmt.Errorf("dashboard file: key %q: %w", k.Kid, err)
			}
			dt.keys = append(dt.keys, key)
		}
	}
	for _, r := range f.Revoked {
		p := principal{r.Iss, r.Sub}
		dt.notBefore[p] = max(dt.notBefore[p], r.NotBefore)
	}
	for ref, p := range f.Projects {
		m := make(map[principal]string, len(p.Members))
		for _, mb := range p.Members {
			m[principal{mb.Iss, mb.Sub}] = mb.Role
		}
		dt.roles[ref] = m
	}
	return dt, nil
}
