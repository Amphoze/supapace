package agent

// The wire proxy on the node: the container sp-pgcap, its table, and its
// attachment to project networks. One proxy serves every project's dashboard
// SQL path, so its table decides which slice a connection reaches and its
// interfaces sit on networks of projects that are hostile to each other.
// Hence the two orders kept everywhere below: a slice enters the table only
// after the proxy holds its address on that slice's network, and leaves the
// table before the proxy leaves the network. On a node without a studio
// domain nothing here acts.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/pgcap"
)

const (
	// The node check's rows: the proxy as a service, which does not block, and
	// where it sits and what it serves, which does.
	rowProxy         = "proxy"
	rowProxyNetworks = "proxy-networks"

	proxyTableName = "pgcap.json"
	proxyConfMount = "/etc/pgcap"
	proxyClass     = "meta" // the one class this table has: postgres-meta's connections

	// proxyOverhead is the fixed part of the memory rule: the runtime and the
	// idle listening sockets.
	proxyOverhead = 16 << 20
	// proxyTableMax is the largest file the proxy reads as its table.
	proxyTableMax = 1 << 20
	// proxyLogWindow is how far back the node check reads the proxy's log.
	proxyLogWindow = 5 * time.Second
)

// proxyMu is the table's one lock: EnsureProxy, AttachProxy and DetachProxy
// each hold it from reading the file to their last Docker call, so the file
// has one writer, the container one maker, and the node check one view of
// both.
var proxyMu sync.Mutex

// EnsureProxy makes the table hold this daemon's classes and exactly the
// slices of the live projects it is attached to, sp-pgcap run with this
// daemon's configuration, and the proxy sit at host 4 of every project of
// live whose network exists and on no other network but platform. A container
// that must be made again starts from a table without slices; each slice is
// attached before the table names it, and a slice that leaves the table has
// left it before its network is detached. A table whose terms pass the
// ceiling or the memory rule is refused before anything changes. Without a
// studio domain, or on a configuration dashcfg.For refuses, it does nothing.
//
// list returns the live projects. It is called once, with the table's lock
// held, so that no create's attach falls between the reading of the list and
// the work: a project whose attach has finished is in the list, and a create
// at its step waits. Its error is returned and nothing is changed. It must
// not wait for anything an AttachProxy or a DetachProxy in flight holds — a
// project's own lock above all: those calls wait for this one. It must return
// promptly (give it a deadline): every attach, detach, removal and node check
// waits behind it.
func (a *Agent) EnsureProxy(ctx context.Context, list func(context.Context) ([]Spec, error)) error {
	ad, ok, _ := a.dashAddrs()
	if !ok {
		return nil
	}
	if list == nil {
		return errors.New("agent: EnsureProxy without a list of the live projects")
	}
	proxyMu.Lock()
	defer proxyMu.Unlock()
	live, err := list(ctx)
	if err != nil {
		return err
	}
	for _, s := range live {
		if err := s.valid(a.cfg); err != nil {
			return err
		}
	}
	t, err := a.renderProxyTable(ad)
	if err != nil {
		return err
	}
	// The most this call may write: refused here, nothing has been touched.
	full := t
	full.Slices = map[string]map[string]int{}
	for _, s := range live {
		full.Slices[strconv.Itoa(s.SubnetIndex)] = proxyAllowance()
	}
	if _, err := proxyTableBytes(full); err != nil {
		return err
	}
	opts, cmd, conf, err := a.proxyConfig(ctx, ad, t)
	if err != nil {
		return err
	}
	c, err := a.proxyContainer(ctx)
	if err != nil {
		return err
	}
	if c != nil {
		if at, on := c.addr(platformNet); c.Labels[labelConfig] != conf || !on || at != ad.Pgcap.String() {
			c = nil
		}
	}
	switch {
	case c == nil:
		if err := a.writeProxyTable(t); err != nil {
			return err
		}
		if c, err = a.createProxy(ctx, ad, opts, cmd, conf); err != nil {
			return err
		}
	case !c.Running:
		if _, err := dockerRun(ctx, "start", "--", dashcfg.PgcapName); err != nil {
			return err
		}
	}
	// Every project is tried: one whose attach fails is reported and does not
	// take the others' slices or attachments with it.
	var errs []error
	keep := map[string]bool{platformNet: true}
	for _, s := range live {
		name := networkName(s.Ref)
		attached, err := a.attachProxy(ctx, c, s)
		if err != nil {
			errs = append(errs, err)
			// A network that is not the slice's own is never kept. After any
			// other failure the project keeps its slice and its attachment
			// where the proxy held the slice's address on its network.
			if errors.Is(err, ErrContainment) {
				continue
			}
			at, on := c.addr(name)
			attached = on && at == dashcfg.ProxyAddr(a.cfg, s.SubnetIndex).String()
		}
		if attached {
			t.Slices[strconv.Itoa(s.SubnetIndex)] = proxyAllowance()
			keep[name] = true
		}
	}
	if err := a.writeProxyTable(t); err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, n := range slices.Sorted(maps.Keys(c.Networks)) {
		if !keep[n] {
			errs = append(errs, proxyNetwork(ctx, "network", "disconnect", "--", n, dashcfg.PgcapName))
		}
	}
	return errors.Join(errs...)
}

// AttachProxy attaches the proxy to s's project network at host 4 and then
// adds the slice to the table with the bounds table's allowance: a create's
// step. It makes sp-pgcap first when the node has none, from the table on
// disk (one without slices when there is no file). A slice the ceiling or
// the memory rule has no room for is refused before the attach. Calling it
// again changes nothing. Without a studio domain, or on a configuration
// dashcfg.For refuses, it does nothing.
func (a *Agent) AttachProxy(ctx context.Context, s Spec) error {
	ad, ok, _ := a.dashAddrs()
	if !ok {
		return nil
	}
	if err := s.valid(a.cfg); err != nil {
		return err
	}
	proxyMu.Lock()
	defer proxyMu.Unlock()
	t, have, err := a.readProxyTable()
	if err != nil {
		return err
	}
	if !have {
		if t, err = a.renderProxyTable(ad); err != nil {
			return err
		}
	}
	with := t
	with.Slices = cloneSlices(t.Slices)
	with.Slices[strconv.Itoa(s.SubnetIndex)] = proxyAllowance()
	if _, err := proxyTableBytes(with); err != nil {
		return err
	}
	c, err := a.proxyContainer(ctx)
	if err != nil {
		return err
	}
	switch {
	case c == nil:
		// The proxy exits when it cannot read its first table. Its label
		// covers the shape of the table it starts from.
		if err := a.writeProxyTable(t); err != nil {
			return err
		}
		opts, cmd, conf, err := a.proxyConfig(ctx, ad, t)
		if err != nil {
			return err
		}
		if c, err = a.createProxy(ctx, ad, opts, cmd, conf); err != nil {
			return err
		}
	case !c.Running:
		if _, err := dockerRun(ctx, "start", "--", dashcfg.PgcapName); err != nil {
			return err
		}
	}
	attached, err := a.attachProxy(ctx, c, s)
	if err != nil {
		return err
	}
	if !attached {
		return fmt.Errorf("agent: %s absent: the wire proxy is not attached", networkName(s.Ref))
	}
	return a.writeProxyTable(with)
}

// DetachProxy removes ref's slice from the table and then detaches the proxy
// from proj-<ref>: the compensation of AttachProxy, run by RemoveNetwork
// before it removes the network. The slice is the one the network is, read
// from the network itself; a network of that name that is not a project
// network of this node names no slice, and the proxy still leaves it. Nil
// when the network is absent, and when nothing is left to do. Without a
// studio domain, or on a configuration dashcfg.For refuses, it does nothing.
func (a *Agent) DetachProxy(ctx context.Context, ref string) error {
	if _, ok, _ := a.dashAddrs(); !ok {
		return nil
	}
	if err := checkRef(ref); err != nil {
		return err
	}
	proxyMu.Lock()
	defer proxyMu.Unlock()
	n, err := dockerInspectNetwork(ctx, networkName(ref))
	if err != nil || n == nil {
		return err
	}
	if i, ok := a.sliceOf(n); ok {
		t, have, err := a.readProxyTable()
		if err != nil {
			return err
		}
		if _, in := t.Slices[strconv.Itoa(i)]; have && in {
			t.Slices = cloneSlices(t.Slices)
			delete(t.Slices, strconv.Itoa(i))
			if err := a.writeProxyTable(t); err != nil {
				return err
			}
		}
	}
	c, err := a.proxyContainer(ctx)
	if err != nil || c == nil {
		return err
	}
	if _, on := c.Networks[networkName(ref)]; on {
		err = proxyNetwork(ctx, "network", "disconnect", "--", networkName(ref), dashcfg.PgcapName)
	}
	return err
}

// RemoveProxy removes the proxy container, on any node, with its attachments
// to project networks: only under its exact name with its own role label,
// and by the id that was inspected. Nil when there is none. A container of
// that name that is not the platform's is left and is an error. The table
// stays (EnsureProxy makes the proxy again from this daemon's table and
// attaches the live projects); with no proxy the row proxy-networks passes
// and the row proxy reports its absence.
func (a *Agent) RemoveProxy(ctx context.Context) error {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	return removeProxy(ctx)
}

// removeProxy is RemoveProxy with the table's lock held.
func removeProxy(ctx context.Context) error {
	name := dashcfg.PgcapName
	c, err := dockerInspectContainer(ctx, name)
	if err != nil || c == nil {
		return err
	}
	if c.Labels[labelRole] != "pgcap" {
		return fmt.Errorf("agent: a container named %s is not the platform's (no role label pgcap): left as it is", name)
	}
	slog.Info("removing " + name)
	_, err = dockerRun(ctx, "rm", "-f", "--", c.ID) // the container inspected, whatever holds the name now
	return err
}

// sliceOf is the slice a project network is, when it has this node's shape
// for that slice.
func (a *Agent) sliceOf(n *dockerx.Network) (int, bool) {
	s, _ := strings.CutPrefix(n.BridgeName, "spp")
	i, err := strconv.Atoi(s)
	return i, err == nil && a.projectNetMismatch(n, i) == "" // which compares the bridge's name
}

// attachProxy puts the proxy c at host 4 of s's project network, where it is
// not there already; an attachment at another address is made again. It
// never attaches without that explicit address, nor to a network that is not
// the slice's own (ErrContainment). attached is false when the network does
// not exist.
func (a *Agent) attachProxy(ctx context.Context, c *ctrConf, s Spec) (attached bool, err error) {
	name := networkName(s.Ref)
	want := dashcfg.ProxyAddr(a.cfg, s.SubnetIndex)
	if !want.IsValid() {
		return false, fmt.Errorf("agent: slice %d has no address for the wire proxy", s.SubnetIndex)
	}
	n, err := dockerInspectNetwork(ctx, name)
	if err != nil || n == nil {
		return false, err
	}
	if why := a.projectNetMismatch(n, s.SubnetIndex); why != "" {
		return false, refuse(nil, "%s: %s: the wire proxy is not attached", name, why)
	}
	if at, on := c.addr(name); on {
		if at == want.String() {
			return true, nil
		}
		if err := proxyNetwork(ctx, "network", "disconnect", "--", name, dashcfg.PgcapName); err != nil {
			return false, err
		}
	}
	err = proxyNetwork(ctx, "network", "connect", "--ip", want.String(), "--", name, dashcfg.PgcapName)
	return err == nil, err
}

// proxyNetwork runs one `docker network connect` or `disconnect` of the
// proxy (args whole). While the runtime holds a container between two
// restarts — where a crashing one spends nearly all its time — it refuses
// both, and a proxy that is down must not hold a project's create, delete or
// abort: when the call fails and the runtime reports the proxy restarting,
// the proxy is stopped, the call made once more on the stopped container,
// and the proxy started again. A proxy that runs is never stopped for a
// failing call. The caller holds the table's lock.
func proxyNetwork(ctx context.Context, args ...string) error {
	_, err := dockerRun(ctx, args...)
	if err == nil {
		return nil
	}
	name := dashcfg.PgcapName
	out, ierr := dockerRun(ctx, "container", "inspect", "--format", restartFormat, "--", name)
	if f := strings.Fields(out); ierr != nil || len(f) != 4 || f[1] != "true" {
		return err
	}
	if _, serr := dockerRun(ctx, "stop", "--", name); serr != nil {
		return errors.Join(err, serr)
	}
	_, err = dockerRun(ctx, args...)
	_, serr := dockerRun(ctx, "start", "--", name)
	return errors.Join(err, serr)
}

// ───────── the table ─────────

func proxyAllowance() map[string]int {
	return map[string]int{proxyClass: dashcfg.Limits.Proxy.ConnsPerProject}
}

func cloneSlices(m map[string]map[string]int) map[string]map[string]int {
	out := make(map[string]map[string]int, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// renderProxyTable is this daemon's table without slices: the node's
// addresses and the class meta from the bounds table, which must pass its
// own check.
func (a *Agent) renderProxyTable(ad dashcfg.Addrs) (pgcap.Table, error) {
	l := dashcfg.Limits
	if err := l.Check(); err != nil {
		return pgcap.Table{}, err
	}
	block, err := netip.ParsePrefix(a.cfg.ProjectBlock)
	if err != nil {
		return pgcap.Table{}, fmt.Errorf("agent: project_block: %w", err)
	}
	p := l.Proxy
	return pgcap.Table{
		Listen: ad.Pgcap, ProjectBlock: block.Masked(), SlicePrefix: a.cfg.SlicePrefix,
		MaxConns: p.MaxConns, PreambleMS: p.PreambleMS,
		Classes: []pgcap.Class{{
			Name: proxyClass, PortBase: ad.MetaPortLo, Peers: []netip.Addr{ad.PgMeta0, ad.PgMeta1},
			ConnsPerPeer: p.ConnsPerPeer, CancelsPerProject: p.CancelsPerProject, CancelsPerPeer: p.CancelsPerPeer, CancelMS: p.CancelMS,
			ConnsPerSecond: p.ConnsPerSecond, ConnsBurst: p.ConnsBurst, RefusalsMax: p.RefusalsMax,
			CopyBufBytes: p.CopyBufBytes, SockBufBytes: p.SockBufBytes,
			Window: pgcap.WindowConnection, WindowBytes: l.ProxyWindowBytes,
			DialMS: l.ProxyDialMS, AuthMS: l.ProxyAuthMS, WallMS: l.ProxyWallMS,
			ScramIterMin: p.ScramIter, ScramIterMax: p.ScramIter,
			ParamStatusMax: p.ParamStatusMax, RowFieldsMax: p.RowFieldsMax, DropNotices: true,
		}},
		Slices: map[string]map[string]int{},
	}, nil
}

// proxyMemory is what the memory rule charges a table: each class's
// connection and cancel terms at that class's cost of a connection, every
// place of a pool of refusals at half the largest such cost, and the fixed
// overhead.
func proxyMemory(t pgcap.Table) int64 {
	var sum, largest int64
	places := 0
	for _, c := range t.Classes {
		conns, cancels, refusals := pgcap.Table{Classes: []pgcap.Class{c}, Slices: t.Slices}.Terms()
		sum += int64(conns+cancels) * c.ConnBytes()
		places += refusals
		largest = max(largest, c.ConnBytes())
	}
	return sum + int64(places)*largest/2 + proxyOverhead
}

// proxyTableBytes is t in the one form the proxy reads, or the reason it is
// not written: a rule of the table — the ceiling below the sum of its terms
// among them, since an allowance is a placement resource —, a file above
// what the proxy reads, or the memory rule (proxyMemory within 80 % of the
// container's memory limit).
func proxyTableBytes(t pgcap.Table) ([]byte, error) {
	b, err := t.Marshal()
	if err != nil {
		return nil, err
	}
	if _, err := pgcap.ParseTable(b); err != nil {
		return nil, fmt.Errorf("agent: the wire proxy's table is refused: %w", err)
	}
	if len(b) > proxyTableMax {
		return nil, fmt.Errorf("agent: the wire proxy's table is %d bytes, above the 1 MiB the proxy reads", len(b))
	}
	if need, limit := proxyMemory(t), int64(dashcfg.Limits.PgcapMemMB)<<20*8/10; need > limit {
		return nil, fmt.Errorf("agent: the wire proxy's table is refused: its terms and the fixed overhead need %d MiB of memory, above 80 %% of the container's %d MiB",
			(need+1<<20-1)>>20, dashcfg.Limits.PgcapMemMB)
	}
	return b, nil
}

func (a *Agent) proxyTablePath() string {
	return filepath.Join(dashcfg.PathsFor(a.p).ProxyConf(), proxyTableName)
}

// readProxyTable reads the table on disk, never through a link; have is
// false when there is no file. A file that is not a table is an error:
// nothing is derived from it.
func (a *Agent) readProxyTable() (t pgcap.Table, have bool, err error) {
	b, err := readRegularFile(a.proxyTablePath())
	if errors.Is(err, fs.ErrNotExist) {
		return pgcap.Table{}, false, nil
	}
	if err == nil {
		t, err = pgcap.ParseTable(b)
	}
	if err != nil {
		return pgcap.Table{}, false, fmt.Errorf("agent: %s: %w", a.proxyTablePath(), err)
	}
	return t, true, nil
}

// writeProxyTable writes t whole, by rename, root 0444, after every check of
// proxyTableBytes; a file already holding those bytes is left alone (the
// proxy reloads on a change of the file).
func (a *Agent) writeProxyTable(t pgcap.Table) error {
	b, err := proxyTableBytes(t)
	if err != nil {
		return err
	}
	d := dashcfg.PathsFor(a.p)
	f := dashFile{d.ProxyConf(), proxyTableName, b, 0o444, os.Geteuid(), os.Getegid()}
	if f.inPlace() == nil {
		return nil
	}
	if err := a.ensurePlatformDir(); err != nil {
		return err
	}
	for _, dir := range []string{d.DashDir(), d.ProxyConf()} {
		if err := ensureDir(dir, 0o755, -1, -1); err != nil {
			return err
		}
	}
	return writeFile(a.p, f.dir, f.name, f.data, f.mode, f.uid, f.gid)
}

// ───────── the container ─────────

// proxyShape is the part of a table a reload does not apply: a container
// started from another shape has to be made again.
func proxyShape(t pgcap.Table) string {
	classes := slices.Clone(t.Classes)
	slices.SortFunc(classes, func(x, y pgcap.Class) int { return strings.Compare(x.Name, y.Name) })
	s := fmt.Sprintf("listen=%s block=%s slice_prefix=%d max_conns=%d", t.Listen, t.ProjectBlock, t.SlicePrefix, t.MaxConns)
	for _, c := range classes {
		s += fmt.Sprintf(" class=%q port_base=%d peers=%v refusals_max=%d copy_buf=%d sock_buf=%d",
			c.Name, c.PortBase, c.Peers, c.RefusalsMax, c.CopyBufBytes, c.SockBufBytes)
	}
	return s
}

// proxyNofile is the container's open-files limit for t: two descriptors for
// every connection and cancel its classes' peers may hold at once (the
// ceiling, for a class without per-peer caps), one for every place of a pool
// of refusals, one listening socket for every slice of the block and class,
// and 64 to spare.
func proxyNofile(t pgcap.Table) int {
	n := len(t.Classes)<<(t.SlicePrefix-t.ProjectBlock.Bits()) + 64
	units := 0
	for _, c := range t.Classes {
		for _, perPeer := range []int{c.ConnsPerPeer, c.CancelsPerPeer} {
			if perPeer == 0 {
				units += t.MaxConns
			} else {
				units += perPeer * len(c.Peers)
			}
		}
		n += c.RefusalsMax
	}
	return n + 2*min(units, t.MaxConns)
}

// proxyConfig is sp-pgcap's create options, its command (image first) and its
// configuration label for a proxy that starts from table t: options, command,
// image id, the seccomp profile and t's shape. The label covers nothing a
// reload applies, so a changed cap, rate or allowance leaves the container.
func (a *Agent) proxyConfig(ctx context.Context, ad dashcfg.Addrs, t pgcap.Table) (opts, cmd []string, conf string, err error) {
	id, err := imageID(ctx, dashcfg.PgcapImage)
	if err != nil {
		return nil, nil, "", err
	}
	hard := a.dashHardening()
	// The settings that keep a container on several networks from forwarding
	// between them; the one the platform's own already hold is not repeated.
	var noForward []string
	for i, args := 0, dashcfg.NoForwardArgs(); i+1 < len(args); i += 2 {
		if !slices.Contains(hard, args[i+1]) {
			noForward = append(noForward, args[i], args[i+1])
		}
	}
	mb := dashcfg.Limits.PgcapMemMB
	mem, nofile := strconv.Itoa(mb)+"m", strconv.Itoa(proxyNofile(t))
	opts = slices.Concat([]string{"create", "--name", dashcfg.PgcapName, "--user", fmt.Sprintf("%d:%d", dashcfg.PgcapUID, dashcfg.PgcapUID)},
		hard, noForward, []string{"--memory", mem, "--memory-swap", mem, "--pids-limit", "64", "--ulimit", "nofile=" + nofile + ":" + nofile,
			"--network", platformNet, "--ip", ad.Pgcap.String(),
			"-v", dashcfg.PathsFor(a.p).ProxyConf() + ":" + proxyConfMount + ":ro",
			// The image's own heap limit fits one memory limit only.
			"-e", "GOMEMLIMIT=" + strconv.Itoa(mb/2) + "MiB",
			"--label", labelRole + "=pgcap"})
	// The image carries a command, not an entry point: the whole command or none.
	cmd = []string{dashcfg.PgcapImage, "/pgcap", proxyConfMount + "/" + proxyTableName}
	extra, err := fileDigests(a.seccompFile())
	if err != nil {
		return nil, nil, "", err
	}
	return opts, cmd, configHash(opts, cmd, append(extra, "image id="+id, "table "+proxyShape(t))...), nil
}

// proxyContainer is sp-pgcap's configuration, nil when it does not exist.
func (a *Agent) proxyContainer(ctx context.Context) (*ctrConf, error) {
	confs, err := a.existing(ctx, dashcfg.PgcapName)
	if err != nil || len(confs) != 1 {
		return nil, err
	}
	return &confs[0], nil
}

// createProxy makes and starts sp-pgcap on platform alone, removing a
// container of that name first, and returns it as created.
func (a *Agent) createProxy(ctx context.Context, ad dashcfg.Addrs, opts, cmd []string, conf string) (*ctrConf, error) {
	if err := a.ensureDashContainer(ctx, dashcfg.PgcapName, ad.Pgcap.String(), opts, cmd, conf); err != nil {
		return nil, err
	}
	c, err := a.proxyContainer(ctx)
	if err == nil && c == nil {
		err = fmt.Errorf("agent: %s is gone right after its creation", dashcfg.PgcapName)
	}
	return c, err
}

// ───────── the node check's rows ─────────

// checkProxy is the node check's two rows of the wire proxy, read under the
// table's lock so that both see one state of file and container.
//
// live, the row proxy, is the service: sp-pgcap exists, runs with this
// daemon's configuration at its platform address, is not in a restart loop
// and has not restarted since the last check (dashRestarting); its table is
// on disk; it sits at host 4 of the network of every slice of the table; no
// attachment lacks its slice; and its log of the last five seconds names no
// port of the table as not opened. A proxy that is down, or made again by an
// ensure, is an outage: this row does not block.
//
// networks, the row proxy-networks, is containment and blocks (proxyNetworks).
func (a *Agent) checkProxy(ctx context.Context, ad dashcfg.Addrs) (live, networks error) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	c, err := a.proxyContainer(ctx)
	if err != nil {
		return err, err
	}
	t, have, terr := a.readProxyTable()
	networks = a.proxyNetworks(ctx, c, t, terr)

	name := dashcfg.PgcapName
	if err := dashRestarting(ctx, name); err != nil {
		return err, networks
	}
	if err := a.checkPlatformContainer(ctx, name, map[string]string{platformNet: ad.Pgcap.String()}, func() (string, error) {
		t, err := a.renderProxyTable(ad)
		if err != nil {
			return "", err
		}
		_, _, conf, err := a.proxyConfig(ctx, ad, t)
		return conf, err
	}); err != nil {
		return err, networks
	}
	switch {
	case terr != nil:
		return terr, networks
	case !have:
		return fmt.Errorf("%s absent", a.proxyTablePath()), networks
	case c == nil:
		return fmt.Errorf("%s absent", name), networks
	}
	held := map[string]string{} // the proxy's address → the network it is on
	for net := range c.Networks {
		if at, _ := c.addr(net); net != platformNet {
			held[at] = net
		}
	}
	var errs []error
	for _, k := range slices.Sorted(maps.Keys(t.Slices)) {
		i, _ := strconv.Atoi(k)
		want := dashcfg.ProxyAddr(a.cfg, i).String()
		if _, on := held[want]; !on {
			errs = append(errs, fmt.Errorf("%s is not attached at %s, host %d of slice %d, which its table names", name, want, dashcfg.ProxyHost, i))
		}
		delete(held, want)
	}
	for _, at := range slices.Sorted(maps.Keys(held)) {
		errs = append(errs, fmt.Errorf("%s is attached to %s at %q, which no slice of its table accounts for", name, held[at], at))
	}
	return errors.Join(append(errs, proxyUnopened(ctx, t))...), networks
}

// proxyNetworks is the row proxy-networks for the proxy c (nil: there is
// none, and nothing to judge) and its table t. The proxy has an interface on
// every project's network, so it fails when the proxy, running or not, is
// attached to a network that is neither platform nor a project network of
// this node — there it could have a way between tenants or off the node —
// and when the table holds a slice no project network of this node accounts
// for. A table that cannot be read or is no table (terr) is the row proxy's
// to report: here the attachments are then judged alone, so that a file
// stops no project at a daemon start. What is only missing — an attachment,
// a slice — is the row proxy's too. EnsureProxy repairs what this row reports.
func (a *Agent) proxyNetworks(ctx context.Context, c *ctrConf, t pgcap.Table, terr error) error {
	if c == nil {
		return nil
	}
	if terr != nil {
		t.Slices = nil // the attachments are judged alone
	}
	name := dashcfg.PgcapName
	var errs []error
	on := map[int]bool{} // the slices whose project network the proxy is on
	for _, net := range slices.Sorted(maps.Keys(c.Networks)) {
		if net == platformNet {
			continue
		}
		i, ok, err := a.projectSlice(ctx, net)
		if err != nil {
			return err
		}
		if !ok {
			errs = append(errs, fmt.Errorf("%s is attached to %s, which is neither %s nor a project network of this node", name, net, platformNet))
		}
		on[i] = on[i] || ok
	}
	var unattached []int
	for k := range t.Slices {
		if i, _ := strconv.Atoi(k); !on[i] {
			unattached = append(unattached, i)
		}
	}
	if len(unattached) > 0 {
		// A slice the proxy is not attached to is an outage while its project's
		// network exists; without one the table names a slice nobody has.
		nets, err := dockerNetworks(ctx)
		if err != nil {
			return err
		}
		exists := map[int]bool{}
		for _, n := range nets {
			i, ok, err := a.projectSlice(ctx, n.name)
			if err != nil {
				return err
			}
			exists[i] = exists[i] || ok
		}
		slices.Sort(unattached)
		for _, i := range unattached {
			if !exists[i] {
				errs = append(errs, fmt.Errorf("the table of %s holds slice %d, which no project network of this node accounts for", name, i))
			}
		}
	}
	return errors.Join(errs...)
}

// projectSlice is the slice the network name is, when it is named like a
// project's and has this node's shape for a slice (sliceOf).
func (a *Agent) projectSlice(ctx context.Context, name string) (i int, ok bool, err error) {
	ref, named := strings.CutPrefix(name, "proj-")
	if !named || !refRE.MatchString(ref) {
		return 0, false, nil
	}
	n, err := dockerInspectNetwork(ctx, name)
	if err != nil || n == nil {
		return 0, false, err
	}
	i, ok = a.sliceOf(n)
	return i, ok, nil
}

// proxyUnopened fails while the proxy's log of the last proxyLogWindow, by
// the runtime's timestamps, holds a "listen: …" line for a slice and class
// of t: the proxy logs one at every look at its table, once a second, for a
// port it could not open, and nothing when the port opens. Each slice and
// class logs at most one line a second, so the last 5 × (slices × classes +
// 2) lines hold the window whatever the other slices log. The runtime is
// asked for that window only (--since), and the lines' own timestamps
// decide; of a read larger than one call returns, what came back is judged.
func proxyUnopened(ctx context.Context, t pgcap.Table) error {
	name := dashcfg.PgcapName
	tail := 5 * (len(t.Slices)*len(t.Classes) + 2)
	since := strconv.Itoa(int(proxyLogWindow/time.Second)) + "s"
	so, se, err := dockerRunOutput(ctx, "logs", "--timestamps", "--since", since, "--tail", strconv.Itoa(tail), "--", name)
	if err != nil {
		return fmt.Errorf("%s: its log cannot be read: %w", name, err)
	}
	now := time.Now()
	for _, line := range strings.Split(se+so, "\n") {
		stamp, rest, _ := strings.Cut(line, " ")
		at, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil || now.Sub(at) > proxyLogWindow {
			continue
		}
		var e struct {
			Class  string `json:"class"`
			Index  int    `json:"index"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal([]byte(rest), &e) != nil || !strings.HasPrefix(e.Reason, "listen: ") {
			continue
		}
		if _, in := t.Slices[strconv.Itoa(e.Index)][e.Class]; in {
			if len(e.Reason) > 256 {
				e.Reason = strings.ToValidUTF8(e.Reason[:256], "") + "…"
			}
			return fmt.Errorf("%s has not opened the port of slice %d, class %s: %q", name, e.Index, e.Class, e.Reason)
		}
	}
	return nil
}
