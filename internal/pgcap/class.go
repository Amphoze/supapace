// Package pgcap is the platform's wire proxy between shared services and every
// project's database server: per connection it refuses what the protocol rules
// out and bounds what a server may send, by the rules of the client's class.
// A class is a row of the table; nothing in the package names one.
package pgcap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
)

// Table is the proxy's whole configuration: the node-wide part, the class
// table and the slice table.
type Table struct {
	Listen       netip.Addr                `json:"listen"`
	ProjectBlock netip.Prefix              `json:"project_block"`
	SlicePrefix  int                       `json:"slice_prefix"`
	MaxConns     int                       `json:"max_conns"`
	PreambleMS   int                       `json:"preamble_ms"`
	Classes      []Class                   `json:"classes"`
	Slices       map[string]map[string]int `json:"slices"` // slice index → class name → that project's allowance
}

// Class is one kind of client: its ports, its peers and every cap and bound
// the proxy applies to its connections. 0 means "none" for MessageBytes,
// ConnsPerPeer, CancelsPerPeer, WallMS and NoticesMax.
type Class struct {
	Name              string       `json:"name"`
	PortBase          int          `json:"port_base"`
	Peers             []netip.Addr `json:"peers"`
	ConnsPerPeer      int          `json:"conns_per_peer"`
	CancelsPerProject int          `json:"cancels_per_project"`
	CancelsPerPeer    int          `json:"cancels_per_peer"`
	CancelMS          int          `json:"cancel_ms"`
	ConnsPerSecond    int          `json:"conns_per_second"`
	ConnsBurst        int          `json:"conns_burst"`
	RefusalsMax       int          `json:"refusals_max"`
	CopyBufBytes      int          `json:"copy_buf_bytes"`
	SockBufBytes      int          `json:"sock_buf_bytes"`
	MessageBytes      int64        `json:"message_bytes"`
	Window            string       `json:"window"`
	WindowBytes       int64        `json:"window_bytes"`
	Stream            *Stream      `json:"stream"`
	DialMS            int          `json:"dial_ms"`
	AuthMS            int          `json:"auth_ms"`
	WallMS            int          `json:"wall_ms"`
	ScramIterMin      int          `json:"scram_iter_min"`
	ScramIterMax      int          `json:"scram_iter_max"`
	ParamStatusMax    int          `json:"param_status_max"`
	RowFieldsMax      int          `json:"row_fields_max"`
	NoticesMax        int          `json:"notices_max"`
	DropNotices       bool         `json:"drop_notices"`
}

// Stream is a class's stream window: how many of a project's connections may
// be in it at once, and the rate that paces them there.
type Stream struct {
	ConnsPerProject  int   `json:"conns_per_project"`
	BytesPerInterval int64 `json:"bytes_per_interval"`
	IntervalMS       int   `json:"interval_ms"`
}

// The three window kinds.
const (
	WindowConnection = "connection"
	WindowResponse   = "response"
	WindowNone       = "none"
)

const (
	minBuf = 4 << 10
	maxBuf = 1 << 20
	// maxCount is above any count or duration a node has; it keeps every sum
	// and product of Terms and every deadline inside an int.
	maxCount = 1 << 30
)

// ParseTable reads a table strictly: only Marshal's own bytes, and every
// rule of the table's shape.
func ParseTable(b []byte) (Table, error) {
	var t Table
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return Table{}, fmt.Errorf("pgcap: table: %w", err)
	}
	if err := t.check(); err != nil {
		return Table{}, fmt.Errorf("pgcap: table: %w", err)
	}
	// One spelling only: a repeated member, a member in another case, a null,
	// white space or anything after the document would give the bytes a second
	// reading.
	if m, err := t.Marshal(); err != nil || !bytes.Equal(m, b) {
		return Table{}, errors.New("pgcap: table: not in the canonical form")
	}
	return t, nil
}

// sliceCount is how many slices of SlicePrefix the project block holds.
func (t Table) sliceCount() int { return 1 << (t.SlicePrefix - t.ProjectBlock.Bits()) }

func (t Table) check() error {
	switch {
	case !t.Listen.Is4() || t.Listen.IsUnspecified():
		return errors.New("listen is not one IPv4 address")
	case !t.ProjectBlock.IsValid() || !t.ProjectBlock.Addr().Is4() || t.ProjectBlock != t.ProjectBlock.Masked():
		return errors.New("project_block is not an IPv4 network")
	// A slice holds at least the cluster's and the proxy's addresses (.2, .4).
	case t.SlicePrefix <= t.ProjectBlock.Bits() || t.SlicePrefix > 29:
		return errors.New("slice_prefix does not cut the block into slices")
	case t.PreambleMS <= 0:
		return errors.New("preamble_ms must be positive")
	case t.MaxConns > maxCount:
		return errors.New("max_conns above any node's")
	}
	n := t.sliceCount()
	names := map[string]bool{}
	for i, c := range t.Classes {
		if err := c.check(); err != nil {
			return fmt.Errorf("class %q: %w", c.Name, err)
		}
		if names[c.Name] {
			return fmt.Errorf("two classes named %q", c.Name)
		}
		names[c.Name] = true
		if c.PortBase+n-1 > 65535 {
			return fmt.Errorf("class %q: ports past 65535", c.Name)
		}
		for _, o := range t.Classes[:i] {
			if c.PortBase < o.PortBase+n && o.PortBase < c.PortBase+n {
				return fmt.Errorf("classes %q and %q share ports", o.Name, c.Name)
			}
		}
	}
	for k, m := range t.Slices {
		i, err := strconv.Atoi(k)
		if err != nil || strconv.Itoa(i) != k || i < 0 || i >= n {
			return fmt.Errorf("slice %q is not an index of the block", k)
		}
		for name, a := range m {
			if !names[name] {
				return fmt.Errorf("slice %s: no class %q", k, name)
			}
			if a < 0 || a > maxCount {
				return fmt.Errorf("slice %s: allowance outside 0 to %d", k, maxCount)
			}
		}
	}
	if a, b, r := t.Terms(); t.MaxConns < a+b+r {
		return fmt.Errorf("max_conns %d below the terms' sum %d", t.MaxConns, a+b+r)
	}
	return nil
}

func (c Class) check() error {
	for _, p := range c.Peers {
		if !p.Is4() {
			return fmt.Errorf("peer %v is not an IPv4 address", p)
		}
	}
	nonNeg := []int{c.ConnsPerPeer, c.CancelsPerProject, c.CancelsPerPeer, c.WallMS, c.ParamStatusMax, c.RowFieldsMax, c.NoticesMax}
	positive := []int{c.CancelMS, c.ConnsPerSecond, c.ConnsBurst, c.RefusalsMax, c.DialMS, c.AuthMS, c.ScramIterMin}
	switch {
	case c.Name == "":
		return errors.New("empty name")
	case c.PortBase < 1:
		return errors.New("port_base below 1")
	case slices.ContainsFunc(nonNeg, func(v int) bool { return v < 0 || v > maxCount }) || c.MessageBytes < 0:
		return errors.New("a cap that is negative or above any node's")
	case slices.ContainsFunc(positive, func(v int) bool { return v <= 0 || v > maxCount }):
		return errors.New("a deadline, rate, burst, pool or iteration floor that is not positive")
	case c.ScramIterMin > c.ScramIterMax:
		return errors.New("iteration floor above the cap")
	case c.CopyBufBytes < minBuf || c.CopyBufBytes > maxBuf || c.SockBufBytes < minBuf || c.SockBufBytes > maxBuf:
		return errors.New("a buffer size outside 4 KiB to 1 MiB")
	case c.Window != WindowConnection && c.Window != WindowResponse && c.Window != WindowNone:
		return fmt.Errorf("window %q", c.Window)
	case c.Window != WindowNone && c.WindowBytes <= 0, c.WindowBytes < 0:
		return errors.New("window_bytes")
	}
	if s := c.Stream; s != nil && (s.BytesPerInterval <= 0 || s.IntervalMS < 10 || s.IntervalMS > 1000 || s.ConnsPerProject < 1) {
		return errors.New("stream: a rate of 0, an interval outside 10 to 1,000 ms, or no connections")
	}
	return nil
}

// Terms returns the three terms the node-wide ceiling must cover: over the
// classes, the lesser of the allowances summed over the placed projects and the
// per-peer cap summed over the peers (the allowances alone without a per-peer
// cap); the cancel allowances taken the same way; and the classes' pools of
// refusals in flight, summed.
func (t Table) Terms() (conns, cancels, refusals int) {
	for _, c := range t.Classes {
		sum, projects := 0, 0
		for _, m := range t.Slices {
			if a, ok := m[c.Name]; ok {
				sum += a
				projects++
			}
		}
		conns += capped(sum, c.ConnsPerPeer*len(c.Peers), c.ConnsPerPeer)
		cancels += capped(c.CancelsPerProject*projects, c.CancelsPerPeer*len(c.Peers), c.CancelsPerPeer)
		refusals += c.RefusalsMax
	}
	return conns, cancels, refusals
}

func capped(sum, peerSum, perPeer int) int {
	if perPeer == 0 {
		return sum
	}
	return min(sum, peerSum)
}

// ConnBytes is what one relayed connection of the class costs at worst: its two
// copy buffers and four kernel socket buffers, each accounted at twice the
// size set.
func (c Class) ConnBytes() int64 {
	return 2*int64(c.CopyBufBytes) + 4*2*int64(c.SockBufBytes)
}

// Marshal writes the table's one canonical form: members in declaration order,
// no white space, classes by name, slices in ascending numeric order of their
// index and each slice's classes by name.
func (t Table) Marshal() ([]byte, error) {
	keys := make([]string, 0, len(t.Slices))
	for k := range t.Slices {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		x, _ := strconv.Atoi(a)
		y, _ := strconv.Atoi(b)
		if x != y {
			return x - y
		}
		return bytes.Compare([]byte(a), []byte(b))
	})
	sl := []byte{'{'}
	for i, k := range keys {
		kb, _ := json.Marshal(k)
		mb, err := json.Marshal(t.Slices[k]) // the encoder sorts map keys
		if err != nil {
			return nil, err
		}
		if i > 0 {
			sl = append(sl, ',')
		}
		sl = append(append(append(sl, kb...), ':'), mb...)
	}
	sl = append(sl, '}')
	classes := slices.Clone(t.Classes)
	slices.SortStableFunc(classes, func(a, b Class) int { return bytes.Compare([]byte(a.Name), []byte(b.Name)) })
	return json.Marshal(struct {
		Listen       netip.Addr      `json:"listen"`
		ProjectBlock netip.Prefix    `json:"project_block"`
		SlicePrefix  int             `json:"slice_prefix"`
		MaxConns     int             `json:"max_conns"`
		PreambleMS   int             `json:"preamble_ms"`
		Classes      []Class         `json:"classes"`
		Slices       json.RawMessage `json:"slices"`
	}{t.Listen, t.ProjectBlock, t.SlicePrefix, t.MaxConns, t.PreambleMS, classes, sl})
}
