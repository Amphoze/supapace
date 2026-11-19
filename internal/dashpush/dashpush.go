// Package dashpush writes the gateway's dashboard file: the whole file,
// rendered from one store snapshot, put in place by rename when its content
// differs from the file on disk. It is the file's only writer.
package dashpush

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

// Source is the store's snapshot of the table (*store.Store).
type Source interface {
	DashboardTable(ctx context.Context) (store.DashboardTable, error)
}

type Pusher struct {
	mu     sync.Mutex
	src    Source
	cfg    nodecfg.Config
	path   string
	domain string // the node's studio domain; empty: no dashboard, nothing written
}

// New returns the pusher of the node's dashboard file.
func New(src Source, c nodecfg.Config, p nodecfg.Paths) *Pusher {
	return &Pusher{src: src, cfg: c, path: dashcfg.PathsFor(p).DashboardFile(), domain: c.StudioDomain}
}

// Push renders the file from one snapshot and, when it differs from the file
// on disk but for the generation, writes it with a generation one above the
// larger of the file's and the current time in milliseconds. It returns the
// generation on disk. With no studio domain it writes nothing and returns 0.
// Generation 0 always means that no file is in force.
func (p *Pusher) Push(ctx context.Context) (generation int64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.domain == "" {
		return 0, nil
	}
	f, err := p.render(ctx)
	if err != nil {
		return 0, err
	}
	gen, same, err := p.compare(f)
	if err != nil || same {
		return gen, err
	}
	f.Generation = max(gen, time.Now().UnixMilli()) + 1
	b, err := f.Marshal() // validates, and refuses more than the gateway reads
	if err != nil {
		return 0, fmt.Errorf("dashboard file: %w", err)
	}
	if err := writeFile(p.path, b); err != nil {
		return 0, fmt.Errorf("dashboard file: %w", err)
	}
	return f.Generation, nil
}

// InForce renders as Push does and reports the generation on disk and whether
// the file equals the rendering; it writes nothing. With no studio domain no
// file is in force. Generation 0 always means that no file is in force.
func (p *Pusher) InForce(ctx context.Context) (generation int64, inForce bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.domain == "" {
		return 0, false, nil
	}
	f, err := p.render(ctx)
	if err != nil {
		return 0, false, err
	}
	return p.compare(f)
}

// render builds the file, without a generation, from one store snapshot.
func (p *Pusher) render(ctx context.Context) (dashfile.File, error) {
	a, err := dashcfg.For(p.cfg)
	if err != nil {
		return dashfile.File{}, fmt.Errorf("dashboard file: %w", err)
	}
	t, err := p.src.DashboardTable(ctx)
	if err != nil {
		return dashfile.File{}, fmt.Errorf("dashboard file: %w", err)
	}
	f := dashfile.File{Node: p.cfg.NodeID, StudioDomain: p.domain, Studio: "http://" + a.Studio.String() + ":" + strconv.Itoa(dashcfg.StudioPort),
		Revoked: make([]dashfile.Revocation, 0, len(t.Revoked)), Projects: make(map[string]dashfile.Project, len(t.Projects))}
	if is := t.Issuer; is != nil {
		var set struct {
			Keys []dashfile.IssuerKey `json:"keys"`
		}
		if err := json.Unmarshal(is.JWKS, &set); err != nil {
			return dashfile.File{}, fmt.Errorf("dashboard file: issuer keys: %w", err)
		}
		f.Issuer = &dashfile.Issuer{Iss: is.Issuer, ClientID: is.ClientID, AuthorizeURL: is.AuthorizeURL,
			EndSessionURL: is.EndSessionURL, SessionSeconds: int64(is.SessionSeconds), Keys: set.Keys}
	}
	for _, r := range t.Revoked {
		f.Revoked = append(f.Revoked, dashfile.Revocation{Iss: r.Issuer, Sub: r.Subject, NotBefore: ceilSeconds(r.NotBefore)})
	}
	for _, tp := range t.Projects {
		ms := make([]dashfile.Member, 0, len(tp.Members))
		for _, m := range tp.Members {
			ms = append(ms, dashfile.Member{Iss: m.Issuer, Sub: m.Subject, Role: m.Role})
		}
		f.Projects[tp.Ref] = dashfile.Project{Name: tp.Name, Members: ms}
	}
	return f, nil
}

// ceilSeconds rounds t up to whole seconds: a session issued in the second of
// a revocation is refused, never spared.
func ceilSeconds(t time.Time) int64 {
	s := t.Unix()
	if t.Nanosecond() > 0 {
		s++
	}
	return s
}

// compare reads the file on disk and reports its generation (0 when there is
// no file that parses) and whether f with that generation is that file.
func (p *Pusher) compare(f dashfile.File) (generation int64, same bool, err error) {
	disk, err := readFile(p.path)
	if err != nil {
		return 0, false, err
	}
	cur, err := dashfile.Parse(disk)
	if err != nil {
		return 0, false, nil // nothing there that is in force: replaced
	}
	f.Generation = cur.Generation
	b, err := f.Marshal()
	if err != nil {
		return 0, false, fmt.Errorf("dashboard file: %w", err)
	}
	return cur.Generation, bytes.Equal(b, disk), nil
}

// readFile reads the file at path as the gateway does: without blocking on
// what is there, a regular file of at most dashfile.MaxBytes. Anything else
// at the path, or nothing, reads as nil.
func readFile(path string) ([]byte, error) {
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ELOOP):
		return nil, nil
	case err != nil:
		return nil, err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > dashfile.MaxBytes {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(fh, dashfile.MaxBytes+1))
	if err != nil || len(b) > dashfile.MaxBytes {
		return nil, err
	}
	return b, nil
}

// tempPrefix names the writer's temporary files.
const tempPrefix = ".dashboard.json-"

// removeLeftovers removes the temporary files a writer that stopped between
// creating and renaming one left in dir. Only names of that form go, each
// name itself: a link is removed, never followed.
func removeLeftovers(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			os.Remove(filepath.Join(dir, e.Name())) // best effort: what stays does not stop the push
		}
	}
	return nil
}

// writeFile puts b at path whole: a new file in the same directory, mode 0444
// from its creation whatever the umask, synced, renamed over path.
func writeFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := removeLeftovers(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, tempPrefix)
	if err != nil {
		return err
	}
	err = tmp.Chmod(0o444)
	if err == nil {
		_, err = tmp.Write(b)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
