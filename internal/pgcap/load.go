package pgcap

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"syscall"
	"time"
)

// pollEvery is how often the table's file is looked at.
const pollEvery = time.Second

// maxTable is above any table a node writes: a thousand slices of a few
// classes are under 100 KiB.
const maxTable = 1 << 20

// Run serves the table at path until ctx ends: a listening socket for every
// placed slice and class, admission, and a relay per admitted connection. It
// looks at the file every second and applies a changed table; a file that does
// not parse keeps the table in use, and a change of the table's shape is
// logged and not applied (the container is re-created for one). It returns an
// error only when the first table cannot be read or served.
func Run(ctx context.Context, path string, logw io.Writer) error {
	p, err := open(path, logw)
	if err != nil {
		return err
	}
	p.watch(ctx, path)
	return nil
}

// stamp identifies a version of the file: its inode, size and modification time.
type stamp struct {
	ino, size int64
	mtime     time.Time
}

func stat(path string) (stamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{}, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxTable {
		return stamp{}, fmt.Errorf("%s: not a regular file of at most %d bytes", path, maxTable)
	}
	var ino int64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = int64(st.Ino)
	}
	return stamp{ino, fi.Size(), fi.ModTime()}, nil
}

func read(path string) (Table, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Table{}, err
	}
	return ParseTable(b)
}

// open reads the first table and opens its listening sockets.
func open(path string, logw io.Writer) (*proxy, error) {
	seen, err := stat(path) // before the read: a change in between is read again
	if err != nil {
		return nil, err
	}
	tb, err := read(path)
	if err != nil {
		return nil, err
	}
	p := &proxy{log: newLogger(logw), tb: tb, seen: seen, classes: map[string]*classState{}, slots: map[member]*slot{}}
	for _, c := range tb.Classes {
		p.classes[c.Name] = &classState{c: c, peerConns: map[netip.Addr]int{}, peerCancels: map[netip.Addr]int{}}
	}
	if err := p.apply(tb, true); err != nil {
		p.shutdown()
		return nil, err
	}
	return p, nil
}

// watch applies each changed version of the file until ctx ends, then closes
// every listening socket and connection and returns once all have ended.
func (p *proxy) watch(ctx context.Context, path string) {
	defer p.shutdown()
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	var lookErr string // the last failed look at the file
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := stat(path)
		if err != nil {
			if err.Error() != lookErr { // logged once per change of state
				p.log.table("cannot look at the table: " + err.Error())
			}
			lookErr = err.Error()
			continue
		}
		lookErr = ""
		if st == p.seen {
			continue
		}
		p.seen = st
		tb, err := read(path)
		if err != nil {
			p.log.table("kept the table in use: " + err.Error())
			continue
		}
		p.mu.Lock()
		cur := p.tb
		p.mu.Unlock()
		tb, changed, err := keepShape(cur, tb)
		if err != nil {
			p.log.table("kept the table in use: " + err.Error())
			continue
		}
		if changed {
			p.log.table("the table's shape changed and is not reloaded; the rest is applied")
		}
		if p.apply(tb, false) != nil {
			p.seen = stamp{} // a slice whose socket did not open: apply the file again at the next look
		}
	}
}

// keepShape returns next with the shape of cur: listen, the block, the slice
// prefix, the ceiling, the set of classes and each one's name, port base,
// peers, pool and buffer sizes. changed tells whether next differed there.
// When the block's layout differs, a slice index of next would name other
// addresses, and next is refused whole.
func keepShape(cur, next Table) (Table, bool, error) {
	if next.Listen != cur.Listen || next.ProjectBlock != cur.ProjectBlock || next.SlicePrefix != cur.SlicePrefix {
		return Table{}, true, fmt.Errorf("its listening address or slice layout changed")
	}
	changed := next.MaxConns != cur.MaxConns || len(next.Classes) != len(cur.Classes)
	out := next
	out.MaxConns, out.Classes, out.Slices = cur.MaxConns, nil, map[string]map[string]int{}
	for _, c := range cur.Classes {
		i := slices.IndexFunc(next.Classes, func(n Class) bool { return n.Name == c.Name })
		n := c
		if i < 0 {
			changed = true
		} else {
			n = next.Classes[i]
		}
		if n.PortBase != c.PortBase || !slices.Equal(n.Peers, c.Peers) || n.RefusalsMax != c.RefusalsMax ||
			n.CopyBufBytes != c.CopyBufBytes || n.SockBufBytes != c.SockBufBytes {
			changed = true
		}
		n.PortBase, n.Peers, n.RefusalsMax, n.CopyBufBytes, n.SockBufBytes = c.PortBase, c.Peers, c.RefusalsMax, c.CopyBufBytes, c.SockBufBytes
		out.Classes = append(out.Classes, n)
		for k, m := range next.Slices {
			if a, ok := m[c.Name]; ok {
				if out.Slices[k] == nil {
					out.Slices[k] = map[string]int{}
				}
				out.Slices[k][c.Name] = a
			}
		}
	}
	if !changed {
		return next, false, nil
	}
	if err := out.check(); err != nil {
		return Table{}, true, err
	}
	return out, true, nil
}

// apply makes the table in use tb, whose shape is the current one. A member
// that left has its listening socket closed and every socket of it closed —
// relayed connections, cancels and refusals alike — and its counters released
// before anything is opened; a member that entered gets its listening socket;
// a member that stays keeps its counters, its rate and its stream places, and
// takes the new allowance. Caps apply to sockets accepted from now on. At the
// first apply a socket that cannot be opened is an error; later it is logged,
// the rest applied, and the error returned: the watcher applies the file again
// at its next look.
func (p *proxy) apply(tb Table, first bool) error {
	want := map[member]int{}
	for k, m := range tb.Slices {
		i, _ := strconv.Atoi(k)
		for name, a := range m {
			want[member{i, name}] = a
		}
	}
	p.mu.Lock()
	var gone []*slot
	for m, s := range p.slots {
		if _, ok := want[m]; !ok {
			s.cancel()
			s.ln.Close()
			delete(p.slots, m)
			gone = append(gone, s)
		}
	}
	p.mu.Unlock()
	for _, s := range gone {
		s.wg.Wait()
	}

	p.mu.Lock()
	p.tb = tb
	for _, c := range tb.Classes {
		p.classes[c.Name].c = c
	}
	var enter []member
	for m, a := range want {
		if s := p.slots[m]; s != nil {
			s.allowance = a
		} else {
			enter = append(enter, m)
		}
	}
	p.mu.Unlock()
	var failed error
	for _, m := range enter {
		p.mu.Lock()
		c := p.classes[m.class].c
		p.mu.Unlock()
		s, err := p.listen(m, c)
		if err != nil {
			if first {
				return err
			}
			// Tried again at the next look at the file.
			p.log.conn(m, "listen: "+err.Error())
			failed = err
			continue
		}
		p.mu.Lock()
		s.allowance = want[m]
		p.slots[m] = s
		s.wg.Add(1)
		p.mu.Unlock()
		go p.serve(s)
	}
	return failed
}

// shutdown closes every listening socket and connection and waits for all.
func (p *proxy) shutdown() {
	p.mu.Lock()
	all := p.slots
	p.slots = map[member]*slot{}
	for _, s := range all {
		s.cancel()
		s.ln.Close()
	}
	p.mu.Unlock()
	for _, s := range all {
		s.wg.Wait()
	}
}
