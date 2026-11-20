package gateway

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/routes"
)

// project is one route entry, its keys already parsed and bounded.
type project struct {
	draining  bool
	asleep    bool     // served only once woken (wake.go)
	upstream  *url.URL // http://<platform address>:3000
	userRoles []string
	keys      []jwtx.Key
	stopped   bool
	aud       []string     // an issuer token must carry one of these
	rate      *routes.Rate // nil: no bucket
}

// table is an immutable snapshot of the route file.
type table struct {
	generation int64
	domain     string
	projects   map[string]*project
	idleStop   int // seconds; 0: no project is reported idle
}

// Table holds the route table read from the route file. Requests read one
// snapshot each; a reload builds a complete new snapshot and swaps it in, and
// a file that fails to parse or validate leaves the last good one in place.
// Until a first good file is read the table is empty and every project request
// is answered 503.
type Table struct {
	path string
	cur  atomic.Pointer[table]

	mu    sync.Mutex  // serialises Reload
	prev  os.FileInfo // the file last read, good or bad
	reads int         // files read, good or bad
}

func NewTable(path string) *Table { return &Table{path: path} }

// Generation is the generation of the table in use; 0 while none is.
func (t *Table) Generation() int64 {
	if tb := t.cur.Load(); tb != nil {
		return tb.generation
	}
	return 0
}

// Reload reads the route file if its inode, mtime or size changed since the
// last read. A file that cannot be read, parsed or validated returns an error and
// changes nothing; a bad file is not read again until it changes.
func (t *Table) Reload() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	fi, err := os.Stat(t.path)
	if err != nil {
		return err
	}
	if t.prev != nil && os.SameFile(t.prev, fi) && fi.ModTime().Equal(t.prev.ModTime()) && fi.Size() == t.prev.Size() {
		return nil
	}
	b, err := os.ReadFile(t.path)
	if err != nil {
		return err
	}
	t.prev = fi
	t.reads++
	f, err := routes.Parse(b)
	if err != nil {
		return err
	}
	tb, err := build(f)
	if err != nil {
		return err
	}
	t.cur.Store(tb)
	log.Printf("gateway: route table generation %d, %d projects", tb.generation, len(tb.projects))
	return nil
}

// Watch reloads the table every interval until ctx ends, logging each new
// error once.
func (t *Table) Watch(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		msg := ""
		if err := t.Reload(); err != nil {
			msg = err.Error()
		}
		if msg != last && msg != "" {
			log.Printf("gateway: route file ignored, last good table kept: %s", msg)
		}
		last = msg
	}
}

// build turns a parsed route file into a snapshot. Keys go through
// jwtx.KeyFromJWK, so one key outside its bounds refuses the whole file.
func build(f routes.File) (*table, error) {
	tb := &table{generation: f.Generation, domain: f.Domain, idleStop: f.IdleStopS, projects: make(map[string]*project, len(f.Projects))}
	for ref, p := range f.Projects {
		u, err := url.Parse(p.Rest)
		if err != nil {
			return nil, fmt.Errorf("routes: %s: rest: %w", ref, err)
		}
		np := &project{draining: p.State == "draining", asleep: p.State == "asleep", upstream: u, userRoles: p.UserRoles,
			stopped: p.State == "stopped", aud: p.Aud, rate: p.Rate}
		for _, k := range p.Keys {
			key, err := jwtx.KeyFromJWK(k.KID, jwtx.Class(k.Class), k.N, k.E)
			if err != nil {
				return nil, fmt.Errorf("routes: %s: key %q: %w", ref, k.KID, err)
			}
			np.keys = append(np.keys, key)
		}
		tb.projects[ref] = np
	}
	return tb, nil
}
