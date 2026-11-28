package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgcap"
)

// ───────── fixture ─────────

// proxyFix is a dashboard test node with the wire proxy's image in its store.
// Every write of the table is kept, in order, and recorded in the fake's log
// as "table <its slices>"; the proxy's log is what `docker logs` returns of it
// (the last --tail lines, on standard error).
type proxyFix struct {
	*dashFix
	path string // the table's file

	pmu       sync.Mutex
	tables    []string // every table written, in order
	failWrite error    // returned instead of writing the table
	failLog   error    // returned by a read of the proxy's log
	log       []string // the proxy's log lines, oldest first, each with its timestamp
	tails     []string // the --tail of every log read
	since     bool     // a log read was bounded by time
}

func newProxyFix(t *testing.T, domain string) *proxyFix {
	t.Helper()
	x := &proxyFix{dashFix: newDashFix(t, domain)}
	x.path = filepath.Join(x.d.ProxyConf(), proxyTableName)
	saved := dashcfg.Limits
	t.Cleanup(func() { dashcfg.Limits = saved })
	x.f.mu.Lock()
	x.f.images[dashcfg.PgcapImage] = "sha256:" + strings.Repeat("4", 64)
	x.f.mu.Unlock()
	write := writeFile
	t.Cleanup(swap(&writeFile, func(p nodecfg.Paths, dir, name string, data []byte, mode os.FileMode, uid, gid int) error {
		if filepath.Join(dir, name) == x.path {
			x.pmu.Lock()
			err := x.failWrite
			if err == nil {
				x.tables = append(x.tables, string(data))
			}
			x.pmu.Unlock()
			if err != nil {
				return err
			}
			x.f.record("table " + slicesOf(string(data)))
		}
		return write(p, dir, name, data, mode, uid, gid)
	}))
	logs := dockerRunOutput
	t.Cleanup(swap(&dockerRunOutput, func(ctx context.Context, args ...string) (string, string, error) {
		// The read of the row: by the runtime's timestamps, bounded by time and
		// by lines. (This fake does not apply --since: the agent's own window does.)
		if len(args) != 8 || !slices.Equal(args[:4], []string{"logs", "--timestamps", "--since", "5s"}) || args[4] != "--tail" ||
			args[6] != "--" || args[7] != dashcfg.PgcapName {
			return logs(ctx, args...)
		}
		args = slices.Delete(slices.Clone(args), 2, 4)
		x.pmu.Lock()
		x.since = true
		x.pmu.Unlock()
		x.pmu.Lock()
		failLog := x.failLog
		x.pmu.Unlock()
		if failLog != nil {
			return "", "", failLog
		}
		n, err := strconv.Atoi(args[3])
		if err != nil {
			t.Errorf("log read with --tail %q", args[3])
		}
		x.pmu.Lock()
		defer x.pmu.Unlock()
		x.tails = append(x.tails, args[3])
		lines := x.log
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		var b strings.Builder
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
		return "", b.String(), nil
	}))
	// While the runtime holds the proxy between two restarts it refuses to
	// connect or disconnect it; stopped, it is no longer held.
	onRun := x.f.onRun
	x.f.onRun = func(args []string, stdin []byte) (string, error, bool) {
		x.mu.Lock()
		held := x.restarting[dashcfg.PgcapName]
		if held && len(args) == 3 && args[0] == "stop" && args[2] == dashcfg.PgcapName {
			x.restarting[dashcfg.PgcapName] = false
		}
		x.mu.Unlock()
		if held && len(args) > 2 && args[0] == "network" && (args[1] == "connect" || args[1] == "disconnect") && args[len(args)-1] == dashcfg.PgcapName {
			return "", errors.New("docker: the container is restarting: no network sandbox"), true
		}
		return onRun(args, stdin)
	}
	return x
}

// slicesOf is the slice table of a marshalled table.
func slicesOf(table string) string {
	i := strings.LastIndex(table, `"slices":`)
	return table[i+len(`"slices":`) : len(table)-1]
}

// project is a spec at slice i whose network exists as the agent creates it.
func (x *proxyFix) project(i int) Spec {
	s := x.spec(i)
	c := x.a.cfg
	x.f.net(fakeNet{Network: dockerx.Network{Name: "proj-" + s.Ref, Internal: true, Subnet: c.Slice(i).String(),
		BridgeName: nodecfg.BridgeName(i), Options: map[string]string{
			optBridgeName: nodecfg.BridgeName(i), optGatewayMode: "isolated"}}})
	return s
}

func (x *proxyFix) spec(i int) Spec {
	return Spec{Ref: fmt.Sprintf("proxy%015d", i), Epoch: 1, Generation: 1, UID: 700000 + i, GID: 700000 + i, SubnetIndex: i}
}

func (x *proxyFix) projects(idx ...int) []Spec {
	var out []Spec
	for _, i := range idx {
		out = append(out, x.project(i))
	}
	return out
}

func (x *proxyFix) addr(i int) string { return dashcfg.ProxyAddr(x.a.cfg, i).String() }

// events is what changed, in order: "table <slices>" for a write of the table,
// and the Docker calls that change the proxy or a network, shortened.
func (x *proxyFix) events() []string {
	var out []string
	for _, c := range x.f.calls() {
		if strings.HasPrefix(c, "table ") {
			out = append(out, c)
			continue
		}
		a, ok := strings.CutPrefix(c, "docker ")
		if !ok {
			continue
		}
		f := strings.Fields(a)
		switch {
		case f[0] == "create" || f[0] == "start" || f[0] == "stop" || f[0] == "rm":
			out = append(out, f[0])
		case f[0] == "network" && f[1] == "connect": // network connect --ip A -- NET NAME
			out = append(out, "connect "+f[5]+" "+f[3])
		case f[0] == "network" && f[1] == "disconnect": // network disconnect -- NET NAME
			out = append(out, "disconnect "+f[3])
		case f[0] == "network" && f[1] == "rm":
			out = append(out, "netrm "+f[3])
		}
	}
	return out
}

// table is the file as on disk, parsed.
func (x *proxyFix) table(t *testing.T) pgcap.Table {
	t.Helper()
	b, err := os.ReadFile(x.path)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := pgcap.ParseTable(b)
	if err != nil {
		t.Fatalf("the table on disk: %v", err)
	}
	return tb
}

func (x *proxyFix) slices(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(x.path)
	if err != nil {
		t.Fatal(err)
	}
	return slicesOf(string(b))
}

func (x *proxyFix) ctr() *fakeCtr {
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	return x.f.ctrs[dashcfg.PgcapName]
}

// listed is a list of live projects as EnsureProxy asks for it.
func listed(live []Spec) func(context.Context) ([]Spec, error) {
	return func(context.Context) ([]Spec, error) { return live, nil }
}

func (x *proxyFix) ensure(t *testing.T, live ...Spec) {
	t.Helper()
	if err := x.a.EnsureProxy(context.Background(), listed(live)); err != nil {
		t.Fatal(err)
	}
}

func wantEvents(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n got %q\nwant %q", what, got, want)
	}
}

// ───────── the container ─────────

func TestProxyArgs_Recorded(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	x.ensure(t)
	args := x.create(t, dashcfg.PgcapName)
	hardening(t, x.a, args)
	for flag, want := range map[string]string{"--user": fmt.Sprintf("%d:%d", dashcfg.PgcapUID, dashcfg.PgcapUID),
		"--ip": x.ad.Pgcap.String(), "--memory": "64m", "--memory-swap": "64m", "--pids-limit": "64"} {
		if got := flagValues(args, flag); len(got) != 1 || got[0] != want {
			t.Errorf("%s %q, want %s", flag, got, want)
		}
	}
	// 2 × (32 connections + 16 cancels) + 32 refusals + 1,024 slices + 64.
	if got := flagValues(args, "--ulimit"); !slices.Equal(got, []string{"core=0", "nofile=1216:1216"}) {
		t.Errorf("limits %q", got)
	}
	sysctls := flagValues(args, "--sysctl")
	for i := 1; i < len(dashcfg.NoForwardArgs()); i += 2 {
		if v := dashcfg.NoForwardArgs()[i]; len(slices.DeleteFunc(slices.Clone(sysctls), func(s string) bool { return s != v })) != 1 {
			t.Errorf("forwarding setting %s is set %q, want once", v, sysctls)
		}
	}
	if len(sysctls) != 7 {
		t.Errorf("settings %q, want the platform's two and the six against forwarding, one shared", sysctls)
	}
	if got := flagValues(args, "-e"); !slices.Equal(got, []string{"GOMEMLIMIT=32MiB"}) {
		t.Errorf("environment %q, want the heap limit at half the memory limit", got)
	}
	if got, want := mounts(args), map[string]string{"/etc/pgcap": x.d.ProxyConf() + " ro"}; len(got) != 1 || got["/etc/pgcap"] != want["/etc/pgcap"] {
		t.Errorf("mounts %v, want %v", got, want)
	}
	if got := positional(args); !slices.Equal(got, []string{dashcfg.PgcapImage, "/pgcap", "/etc/pgcap/pgcap.json"}) {
		t.Errorf("image and command %q, want the command whole", got)
	}
	if slices.Contains(args, "--tmpfs") || slices.Contains(args, "--env-file") {
		t.Errorf("a writable path or a second environment: %q", args)
	}
	c := x.ctr()
	if c.Labels[labelRole] != "pgcap" || len(c.Labels) != 2 || !c.Running {
		t.Errorf("labels %v, running %v", c.Labels, c.Running)
	}

	// Another node size, another memory limit, another per-peer cap: each
	// changes its argument, and with it the label.
	label := func(edit func()) (string, []string) {
		t.Helper()
		edit()
		opts, _, conf, err := x.a.proxyConfig(context.Background(), x.ad, mustTable(t, x))
		if err != nil {
			t.Fatal(err)
		}
		return conf, opts
	}
	base, _ := label(func() {})
	if base != c.Labels[labelConfig] {
		t.Errorf("the container's label is not the one its configuration gives")
	}
	conf, opts := label(func() { x.a.cfg.SlicePrefix = 24 }) // 256 slices
	if !slices.Contains(flagValues(opts, "--ulimit"), "nofile=448:448") || conf == base {
		t.Errorf("256 slices: limits %q, label changed %v", flagValues(opts, "--ulimit"), conf != base)
	}
	x.a.cfg.SlicePrefix = 26
	conf, opts = label(func() { dashcfg.Limits.PgcapMemMB = 96 })
	if flagValue(opts, "--memory") != "96m" || flagValue(opts, "-e") != "GOMEMLIMIT=48MiB" || conf == base {
		t.Errorf("96 MiB: memory %q, environment %q, label changed %v", flagValue(opts, "--memory"), flagValue(opts, "-e"), conf != base)
	}
	dashcfg.Limits.PgcapMemMB = 64
	conf, opts = label(func() { dashcfg.Limits.Proxy.ConnsPerPeer = 8 }) // 2 × (16 + 16) + 32 + 1,024 + 64
	if !slices.Contains(flagValues(opts, "--ulimit"), "nofile=1184:1184") || conf == base {
		t.Errorf("a per-peer cap of 8: limits %q, label changed %v", flagValues(opts, "--ulimit"), conf != base)
	}
	// A class without per-peer caps is bounded by the ceiling alone: 2 x 80.
	conf, opts = label(func() { dashcfg.Limits.Proxy.ConnsPerPeer = 0 })
	if !slices.Contains(flagValues(opts, "--ulimit"), "nofile=1280:1280") || conf == base {
		t.Errorf("no per-peer cap: limits %q, label changed %v", flagValues(opts, "--ulimit"), conf != base)
	}
	dashcfg.Limits.Proxy.ConnsPerPeer = 16
	if conf, _ = label(func() {}); conf != base {
		t.Error("the label is not stable")
	}
}

// mustTable renders the table of the node as it is configured now, no slice.
func mustTable(t *testing.T, x *proxyFix) pgcap.Table {
	t.Helper()
	ad, err := dashcfg.For(x.a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := x.a.renderProxyTable(ad)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

// TestProxyLabel_CoversTheShape: every member a reload does not apply changes
// the label; a member a reload applies does not.
func TestProxyLabel_CoversTheShape(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	label := func(edit func(*pgcap.Table)) string {
		t.Helper()
		tb := mustTable(t, x)
		edit(&tb)
		_, _, conf, err := x.a.proxyConfig(ctx, x.ad, tb)
		if err != nil {
			t.Fatal(err)
		}
		return conf
	}
	base := label(func(*pgcap.Table) {})
	for name, edit := range map[string]func(*pgcap.Table){
		"listen":        func(tb *pgcap.Table) { tb.Listen = x.ad.PgMeta0 },
		"block":         func(tb *pgcap.Table) { tb.ProjectBlock = netip.MustParsePrefix("10.214.0.0/16") },
		"slice prefix":  func(tb *pgcap.Table) { tb.SlicePrefix = 27 },
		"ceiling":       func(tb *pgcap.Table) { tb.MaxConns++ },
		"class name":    func(tb *pgcap.Table) { tb.Classes[0].Name = "other" },
		"port base":     func(tb *pgcap.Table) { tb.Classes[0].PortBase++ },
		"peers":         func(tb *pgcap.Table) { tb.Classes[0].Peers = []netip.Addr{x.ad.PgMeta1, x.ad.Pgcap} },
		"pool":          func(tb *pgcap.Table) { tb.Classes[0].RefusalsMax++ },
		"copy buffer":   func(tb *pgcap.Table) { tb.Classes[0].CopyBufBytes *= 2 },
		"socket buffer": func(tb *pgcap.Table) { tb.Classes[0].SockBufBytes *= 2 },
		"a second class": func(tb *pgcap.Table) {
			c := tb.Classes[0]
			c.Name, c.PortBase = "second", 30000
			tb.Classes = append(tb.Classes, c)
		},
	} {
		if label(edit) == base {
			t.Errorf("%s: the label does not cover it", name)
		}
		// By the shape itself, not by an option that follows from it.
		tb := mustTable(t, x)
		edit(&tb)
		if proxyShape(tb) == proxyShape(mustTable(t, x)) {
			t.Errorf("%s: the shape does not name it", name)
		}
	}
	for name, edit := range map[string]func(*pgcap.Table){
		"window":       func(tb *pgcap.Table) { tb.Classes[0].WindowBytes++ },
		"rate":         func(tb *pgcap.Table) { tb.Classes[0].ConnsPerSecond++ },
		"wall clock":   func(tb *pgcap.Table) { tb.Classes[0].WallMS++ },
		"preamble":     func(tb *pgcap.Table) { tb.PreambleMS++ },
		"cancel/slice": func(tb *pgcap.Table) { tb.Classes[0].CancelsPerProject++ },
		"a slice":      func(tb *pgcap.Table) { tb.Slices["3"] = map[string]int{proxyClass: 5} },
	} {
		if label(edit) != base {
			t.Errorf("%s: the label covers what a reload applies", name)
		}
	}
}

// TestEnsureProxy_TableWrittenBeforeTheContainer: the proxy exits when its
// first table cannot be read, so no container is created while the file is
// absent, and its first table has no slice whatever is live.
func TestEnsureProxy_TableWrittenBeforeTheContainer(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	live := x.projects(3, 7)
	boom := errors.New("no space left on device")
	x.failWrite = boom
	if err := x.a.EnsureProxy(context.Background(), listed(live)); !errors.Is(err, boom) {
		t.Fatalf("with a table that cannot be written: %v", err)
	}
	if _, err := os.Lstat(x.path); !errors.Is(err, os.ErrNotExist) || len(x.f.mutations()) != 0 {
		t.Fatalf("file %v, Docker calls %q: want neither", err, x.f.mutations())
	}
	x.failWrite = nil
	x.ensure(t, live...)
	wantEvents(t, "the first creation", x.events(), "table {}", "create", "start",
		"connect proj-"+live[0].Ref+" "+x.addr(3), "connect proj-"+live[1].Ref+" "+x.addr(7), `table {"3":{"meta":5},"7":{"meta":5}}`)
}

// ───────── the table ─────────

func TestProxyTable_ClassesFromLimits_SlicesFromLive(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	x.ensure(t, x.projects(7, 3)...)
	const want = `{"listen":"10.212.0.6","project_block":"10.213.0.0/16","slice_prefix":26,"max_conns":80,"preamble_ms":2000,` +
		`"classes":[{"name":"meta","port_base":20000,"peers":["10.212.0.4","10.212.0.5"],` +
		`"conns_per_peer":16,"cancels_per_project":2,"cancels_per_peer":8,"cancel_ms":2000,` +
		`"conns_per_second":30,"conns_burst":60,"refusals_max":32,"copy_buf_bytes":65536,"sock_buf_bytes":32768,` +
		`"message_bytes":0,"window":"connection","window_bytes":12582912,"stream":null,` +
		`"dial_ms":3000,"auth_ms":10000,"wall_ms":55000,"scram_iter_min":4096,"scram_iter_max":4096,` +
		`"param_status_max":64,"row_fields_max":1664,"notices_max":0,"drop_notices":true}],` +
		`"slices":{"3":{"meta":5},"7":{"meta":5}}}`
	b, err := os.ReadFile(x.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Errorf("the table:\n got %s\nwant %s", b, want)
	}
	if got := ownerMode(t, x.dashFix, x.path); got != dashRoot+" 0444" {
		t.Errorf("the file is %s, want %s 0444", got, dashRoot)
	}
	if got := ownerMode(t, x.dashFix, x.d.ProxyConf()); got != dashRoot+" 0755" {
		t.Errorf("its directory is %s", got)
	}
	// A bounds table that fails its nesting renders nothing.
	dashcfg.Limits.ProxyDialMS = dashcfg.Limits.MetaConnSecs * 1000 // row 10 < row 9 fails
	x.f.resetLog()
	if err := x.a.EnsureProxy(context.Background(), listed(nil)); err == nil || len(x.events()) != 0 {
		t.Errorf("a failing bounds table: %v, events %q", err, x.events())
	}
}

// TestProxyTable_OneWriterWholeFile: attaches, detaches and whole ensures at
// the same time leave a file that parses at every moment and holds exactly
// what was attached and not detached.
func TestProxyTable_OneWriterWholeFile(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	going := x.projects(20, 21, 22, 23)
	x.ensure(t, going...)
	coming := x.projects(1, 2, 3, 4, 5, 6, 7, 8)
	live := append(slices.Clone(coming), x.project(30))
	// Every change of an attachment takes a moment: calls that did not exclude
	// each other would read the table before another had written it.
	x.f.before = func(args []string) {
		if len(args) > 1 && args[0] == "network" && (args[1] == "connect" || args[1] == "disconnect") {
			time.Sleep(2 * time.Millisecond)
		}
	}

	done := make(chan struct{})
	var readers, writers sync.WaitGroup
	var reads int
	readers.Add(1)
	go func() { // the proxy's view: whatever it reads is a whole table
		defer readers.Done()
		for {
			b, err := os.ReadFile(x.path)
			if err != nil {
				t.Errorf("the file while it is written: %v", err)
				return
			}
			if _, err := pgcap.ParseTable(b); err != nil {
				t.Errorf("a read while it is written: %v (%d bytes)", err, len(b))
				return
			}
			reads++
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	run := func(what string, fn func() error) {
		writers.Add(1)
		go func() {
			defer writers.Done()
			if err := fn(); err != nil {
				t.Errorf("%s: %v", what, err)
			}
		}()
	}
	for _, s := range coming {
		run("attach", func() error { return x.a.AttachProxy(ctx, s) })
	}
	for _, s := range going {
		run("detach", func() error { return x.a.DetachProxy(ctx, s.Ref) })
	}
	for range 3 {
		run("ensure", func() error { return x.a.EnsureProxy(ctx, listed(live)) })
	}
	writers.Wait()
	// Nothing mends the table after the race: whatever order the calls took,
	// each attach added its slice, each detach or ensure took a leaving one
	// away, and an ensure added slice 30.
	close(done)
	readers.Wait()
	if reads == 0 {
		t.Fatal("the reader never read")
	}
	want := `{"1":{"meta":5},"2":{"meta":5},"3":{"meta":5},"4":{"meta":5},"5":{"meta":5},"6":{"meta":5},"7":{"meta":5},"8":{"meta":5},"30":{"meta":5}}`
	if got := x.slices(t); got != want {
		t.Errorf("slices %s, want %s", got, want)
	}
	c := x.ctr()
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	if len(c.Nets) != 10 {
		t.Errorf("attached to %v, want the platform and the nine", c.Nets)
	}
	for _, s := range going {
		if _, on := c.Nets["proj-"+s.Ref]; on {
			t.Errorf("still attached to proj-%s", s.Ref)
		}
	}
	// Nothing of a write is left beside the file.
	ents, err := os.ReadDir(x.d.ProxyConf())
	if err != nil || len(ents) != 1 || ents[0].Name() != proxyTableName {
		t.Errorf("the directory holds %v (%v), want the table alone", ents, err)
	}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// TestProxyTable_WrittenByRename_CapChangeDoesNotRecreate: a changed cap, rate
// or allowance is a new file under the same name and the same container; a
// changed buffer size, pool or ceiling is a new container.
func TestProxyTable_WrittenByRename_CapChangeDoesNotRecreate(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	live := x.projects(3)
	x.ensure(t, live...)
	id := x.ctr().ID
	for _, c := range []struct {
		name, has string
		edit      func()
	}{
		{"a cap", `"window_bytes":13631488`, func() { dashcfg.Limits.ProxyWindowBytes = 13 << 20 }},
		{"a rate", `"conns_per_second":20`, func() { dashcfg.Limits.Proxy.ConnsPerSecond = 20 }},
		{"an allowance", `"slices":{"3":{"meta":4}}`, func() { dashcfg.Limits.Proxy.ConnsPerProject = 4 }},
	} {
		ino := inode(t, x.path)
		c.edit()
		x.f.resetLog()
		x.ensure(t, live...)
		b, _ := os.ReadFile(x.path)
		if !strings.Contains(string(b), c.has) {
			t.Errorf("%s: the file lacks %s", c.name, c.has)
		}
		if inode(t, x.path) == ino {
			t.Errorf("%s: the file was written in place, not renamed", c.name)
		}
		if m := x.f.mutations(); len(m) != 0 || x.ctr().ID != id {
			t.Errorf("%s: Docker calls %q, the container re-created %v", c.name, m, x.ctr().ID != id)
		}
	}
	// The same table again is not written again.
	ino := inode(t, x.path)
	x.f.resetLog()
	x.ensure(t, live...)
	if inode(t, x.path) != ino || len(x.events()) != 0 {
		t.Errorf("an unchanged table: events %q, rewritten %v", x.events(), inode(t, x.path) != ino)
	}
	for _, c := range []struct {
		name string
		edit func()
	}{
		{"a buffer size", func() { dashcfg.Limits.Proxy.CopyBufBytes = 32 << 10 }},
		{"the pool", func() { dashcfg.Limits.Proxy.RefusalsMax = 40; dashcfg.Limits.Proxy.MaxConns = 88 }},
		{"the ceiling", func() { dashcfg.Limits.Proxy.MaxConns = 96 }},
	} {
		c.edit()
		x.f.resetLog()
		x.ensure(t, live...)
		wantEvents(t, c.name, x.events(), "table {}", "rm", "create", "start", "connect proj-"+live[0].Ref+" "+x.addr(3), `table {"3":{"meta":4}}`)
		if x.ctr().ID == id {
			t.Errorf("%s: the container was kept", c.name)
		}
		id = x.ctr().ID
	}
}

// TestProxyTable_RefusesTermsAboveTheCeiling: an allowance is a placement
// resource. A class without a per-peer cap sums its projects' allowances;
// against a ceiling of 80 the write that passes it is refused with the
// reason and the file stays the last good one.
func TestProxyTable_RefusesTermsAboveTheCeiling(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	dashcfg.Limits.Proxy.ConnsPerPeer = 0
	if dashcfg.Limits.Proxy.MaxConns != 80 || dashcfg.Limits.Proxy.ConnsPerProject != 5 {
		t.Fatalf("the figures of this test changed: %+v", dashcfg.Limits.Proxy)
	}
	var all []Spec
	for i := range 28 {
		all = append(all, x.project(i))
	}
	x.ensure(t, all[:3]...)
	good, _ := os.ReadFile(x.path)
	x.f.resetLog()
	err := x.a.EnsureProxy(ctx, listed(all)) // 140 connections, 16 cancels, 32 refusals
	if err == nil || !strings.Contains(err.Error(), "max_conns 80 below the terms' sum 188") {
		t.Fatalf("28 slices of allowance 5: %v, want the refusal with its reason", err)
	}
	if ev := x.events(); len(ev) != 0 {
		t.Errorf("the refused ensure attached or wrote: %q", ev)
	}
	if b, _ := os.ReadFile(x.path); string(b) != string(good) {
		t.Errorf("the file after the refusal:\n%s\nwant the last good one:\n%s", b, good)
	}
	// One slice at a time: the sixth is the last the ceiling holds (30 + 12 + 32),
	// the seventh (35 + 14 + 32) is refused and leaves the six.
	x.ensure(t, all[:3]...)
	for i := 3; i < 6; i++ {
		if err := x.a.AttachProxy(ctx, all[i]); err != nil {
			t.Fatalf("slice %d: %v", i, err)
		}
	}
	good, _ = os.ReadFile(x.path)
	x.f.resetLog()
	if err := x.a.AttachProxy(ctx, all[6]); err == nil || !strings.Contains(err.Error(), "below the terms' sum 81") {
		t.Fatalf("the seventh slice: %v", err)
	}
	if ev := x.events(); len(ev) != 0 {
		t.Errorf("the refused attach left %q behind", ev)
	}
	if b, _ := os.ReadFile(x.path); string(b) != string(good) || len(x.table(t).Slices) != 6 {
		t.Errorf("the file after the refused attach holds %s", slicesOf(string(b)))
	}
	// Control: with the per-peer cap the same 28 are within the ceiling.
	dashcfg.Limits.Proxy.ConnsPerPeer = 16
	x.ensure(t, all...)
	if n := len(x.table(t).Slices); n != 28 {
		t.Errorf("control: %d slices", n)
	}
}

// TestProxyMemoryRule: the terms at their class's figures and the fixed
// overhead stay within 80 % of the container's memory limit, or the table is
// refused until the limit is raised.
func TestProxyMemoryRule(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	var all []Spec
	for i := range 28 {
		all = append(all, x.project(i))
	}
	x.ensure(t, all...)
	tb := x.table(t)
	// 32 connections and 16 cancels at 384 KiB, 32 refusals at 192 KiB: 24 MiB,
	// plus 16 MiB.
	if c := tb.Classes[0]; c.ConnBytes() != 384<<10 {
		t.Fatalf("a connection of the class costs %d bytes", c.ConnBytes())
	}
	if got, want := proxyMemory(tb), int64(32*384+16*384+32*192)<<10+16<<20; got != want || want != 40<<20 {
		t.Errorf("this table needs %d bytes, want %d (40 MiB)", got, want)
	}
	if limit := int64(dashcfg.Limits.PgcapMemMB) << 20 * 8 / 10; proxyMemory(tb) > limit || dashcfg.Limits.PgcapMemMB != 64 {
		t.Errorf("40 MiB is not within 80 %% of %d MiB", dashcfg.Limits.PgcapMemMB)
	}
	// Fewer placed projects, smaller terms: two slices hold 10 connections and 4 cancels.
	two := tb
	two.Slices = map[string]map[string]int{"0": {proxyClass: 5}, "1": {proxyClass: 5}}
	if got, want := proxyMemory(two), int64(14*384+32*192)<<10+16<<20; got != want {
		t.Errorf("two slices need %d bytes, want %d", got, want)
	}
	good, _ := os.ReadFile(x.path)
	for _, c := range []struct {
		name string
		edit func()
	}{
		// 640 KiB a connection: 48 × 640 + 32 × 320 KiB = 40 MiB, plus 16.
		{"larger buffers", func() { dashcfg.Limits.Proxy.SockBufBytes = 64 << 10 }},
		// 64 connections, 16 cancels, 64 refusals: 42 MiB, plus 16.
		{"a larger ceiling", func() {
			dashcfg.Limits.Proxy.ConnsPerPeer, dashcfg.Limits.Proxy.RefusalsMax, dashcfg.Limits.Proxy.MaxConns = 32, 64, 144
		}},
	} {
		saved := dashcfg.Limits
		c.edit()
		err := x.a.EnsureProxy(ctx, listed(all))
		if err == nil || !strings.Contains(err.Error(), "memory") {
			t.Errorf("%s: %v, want the refusal by the memory rule", c.name, err)
		}
		if b, _ := os.ReadFile(x.path); string(b) != string(good) {
			t.Errorf("%s: the file changed at the refusal", c.name)
		}
		dashcfg.Limits.PgcapMemMB = 96 // 76.8 MiB allowed
		if err := x.a.EnsureProxy(ctx, listed(all)); err != nil {
			t.Errorf("%s, the limit raised: %v", c.name, err)
		}
		dashcfg.Limits = saved
		x.ensure(t, all...)
	}
}

func TestProxyTable_RefusesAFileAboveOneMiB(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	tb := mustTable(t, x)
	if _, err := proxyTableBytes(tb); err != nil {
		t.Fatalf("control: %v", err)
	}
	tb.Classes[0].Name = strings.Repeat("m", 1<<20)
	if _, err := proxyTableBytes(tb); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Errorf("a table above 1 MiB: %v", err)
	}
}

// TestProxyTable_AFileThatIsNoTable: an attach or a detach changes one slice
// of the table it reads; a file that is no table stops both, changed by
// neither, and the ensure — which knows every live project — replaces it.
func TestProxyTable_AFileThatIsNoTable(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(3, 7)
	x.ensure(t, live...)
	other := x.project(9)
	for name, bad := range map[string][]byte{"not a table": []byte(`{"listen":"10.212.0.6"}`), "white space": append(mustBytes(t, x), '\n')} {
		rewrite(t, x.path, bad)
		x.f.resetLog()
		if err := x.a.AttachProxy(ctx, other); err == nil {
			t.Errorf("%s: an attach went on", name)
		}
		if err := x.a.DetachProxy(ctx, live[0].Ref); err == nil {
			t.Errorf("%s: a detach went on", name)
		}
		if b, _ := os.ReadFile(x.path); string(b) != string(bad) || len(x.f.mutations()) != 0 {
			t.Errorf("%s: the file or Docker was changed: %q", name, x.f.mutations())
		}
		x.ensure(t, live...)
		if got := x.slices(t); got != `{"3":{"meta":5},"7":{"meta":5}}` {
			t.Errorf("%s: the ensure left %s", name, got)
		}
	}
	// A link in the file's place is not followed.
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, mustBytes(t, x), 0o444); err != nil {
		t.Fatal(err)
	}
	os.Remove(x.path)
	if err := os.Symlink(target, x.path); err != nil {
		t.Fatal(err)
	}
	if err := x.a.AttachProxy(ctx, other); err == nil {
		t.Error("an attach read the table through a link")
	}
	if _, _, err := x.a.readProxyTable(); err == nil {
		t.Error("the table was read through a link")
	}
}

func mustBytes(t *testing.T, x *proxyFix) []byte {
	t.Helper()
	b, err := os.ReadFile(x.path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ───────── ensure ─────────

func TestEnsureProxy_AttachesEveryLiveProject_Idempotent(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	live := x.projects(3, 7, 1023)
	unplaced := x.spec(40) // live, its network not made yet
	live = append(live, unplaced)
	x.ensure(t, live...)
	c := x.ctr()
	want := map[string]string{platformNet: x.ad.Pgcap.String(), "proj-" + live[0].Ref: x.addr(3), "proj-" + live[1].Ref: x.addr(7),
		"proj-" + live[2].Ref: x.addr(1023)}
	x.f.mu.Lock()
	if len(c.Nets) != len(want) {
		t.Errorf("attached to %v, want %v", c.Nets, want)
	}
	for n, a := range want {
		if c.Nets[n] != a {
			t.Errorf("on %s at %q, want %s", n, c.Nets[n], a)
		}
	}
	x.f.mu.Unlock()
	// A slice is in the table once its address is on the container: the
	// project without a network waits for its own attach.
	if got := x.slices(t); got != `{"3":{"meta":5},"7":{"meta":5},"1023":{"meta":5}}` {
		t.Errorf("slices %s", got)
	}
	x.f.resetLog()
	x.ensure(t, live...)
	if ev := x.events(); len(ev) != 0 {
		t.Errorf("a second ensure: %q, want nothing", ev)
	}
	// A stopped proxy is started, not made again.
	c.Running = false
	x.f.resetLog()
	x.ensure(t, live...)
	wantEvents(t, "stopped", x.events(), "start")
	// An attachment at another address is made again at the right one.
	x.f.mu.Lock()
	c.Nets["proj-"+live[1].Ref] = x.a.cfg.PostgRESTAddr(7).String()
	x.f.mu.Unlock()
	x.f.resetLog()
	x.ensure(t, live...)
	wantEvents(t, "misplaced", x.events(), "disconnect proj-"+live[1].Ref, "connect proj-"+live[1].Ref+" "+x.addr(7))
	// A spec that names no slice of the node stops the ensure before anything.
	x.f.resetLog()
	if err := x.a.EnsureProxy(context.Background(), listed([]Spec{x.spec(1024)})); err == nil || len(x.f.calls()) != 0 {
		t.Errorf("a slice outside the block: %v, calls %q", err, x.f.calls())
	}
	bad := x.spec(5)
	bad.Ref = "../x"
	if err := x.a.EnsureProxy(context.Background(), listed(append(slices.Clone(live), bad))); err == nil || len(x.f.calls()) != 0 {
		t.Errorf("a ref that is none: %v, calls %q", err, x.f.calls())
	}
}

// TestEnsureProxy_LeavesNoAttachmentWithoutALiveProject: what the proxy is
// attached to beyond the platform and the live projects' networks is
// detached — after its slice has left the table.
func TestEnsureProxy_LeavesNoAttachmentWithoutALiveProject(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	live := x.projects(3, 7)
	x.ensure(t, live...)
	x.f.mu.Lock()
	x.f.ctrs[dashcfg.PgcapName].Nets["bridge"] = "10.214.0.9"
	x.f.mu.Unlock()
	x.f.resetLog()
	x.ensure(t, live[:1]...)
	ev := x.events()
	slices.Sort(ev[1:]) // the two detaches come in no fixed order
	wantEvents(t, "one project left, and a foreign network", ev, `table {"3":{"meta":5}}`, "disconnect bridge", "disconnect proj-"+live[1].Ref)
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	if n := x.f.ctrs[dashcfg.PgcapName].Nets; len(n) != 2 {
		t.Errorf("attached to %v", n)
	}
}

// TestEnsureProxy_RecreatedThenReattached: a new container has no interface
// on any project network, so it starts from a table without slices and every
// live slice is attached again before the table names it.
func TestEnsureProxy_RecreatedThenReattached(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	live := x.projects(3, 7)
	x.ensure(t, live...)
	old := x.ctr().ID
	for name, edit := range map[string]func(){
		"another label":           func() { x.ctr().Labels[labelConfig] = "other" },
		"off the platform":        func() { delete(x.ctr().Nets, platformNet) },
		"at another address":      func() { x.ctr().Nets[platformNet] = x.ad.Studio.String() },
		"removed":                 func() { x.f.mu.Lock(); delete(x.f.ctrs, dashcfg.PgcapName); x.f.mu.Unlock() },
		"another seccomp profile": func() { rewrite(t, x.a.seccompFile(), []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`)) },
		"the image built again": func() {
			x.f.mu.Lock()
			x.f.images[dashcfg.PgcapImage] = "sha256:" + strings.Repeat("5", 64)
			x.f.mu.Unlock()
		},
	} {
		edit()
		x.f.resetLog()
		x.ensure(t, live...)
		want := []string{"table {}", "rm", "create", "start", "connect proj-" + live[0].Ref + " " + x.addr(3),
			"connect proj-" + live[1].Ref + " " + x.addr(7), `table {"3":{"meta":5},"7":{"meta":5}}`}
		if name == "removed" {
			want = slices.Delete(want, 1, 2)
		}
		wantEvents(t, name, x.events(), want...)
		if x.ctr().ID == old {
			t.Errorf("%s: the container was kept", name)
		}
		old = x.ctr().ID
	}
}

// ───────── attach, detach ─────────

func TestAttachProxy_AttachThenAddSlice(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(3)
	x.ensure(t, live...)
	s := x.project(5)
	x.f.resetLog()
	if err := x.a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "attach", x.events(), "connect proj-"+s.Ref+" "+x.addr(5), `table {"3":{"meta":5},"5":{"meta":5}}`)
	x.f.resetLog()
	if err := x.a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ev := x.events(); len(ev) != 0 {
		t.Errorf("a second attach: %q, want nothing", ev)
	}
	// Half done — attached, the slice not yet added — the next attach adds it.
	if err := x.a.DetachProxy(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	x.failWrite = errors.New("no space left on device")
	if err := x.a.AttachProxy(ctx, s); err == nil {
		t.Fatal("an attach whose table could not be written reported success")
	}
	x.failWrite = nil
	x.f.resetLog()
	if err := x.a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "resumed", x.events(), `table {"3":{"meta":5},"5":{"meta":5}}`)
	// The allowance is the bounds table's.
	dashcfg.Limits.Proxy.ConnsPerProject = 3
	if err := x.a.AttachProxy(ctx, x.project(6)); err != nil {
		t.Fatal(err)
	}
	if got := x.slices(t); got != `{"3":{"meta":5},"5":{"meta":5},"6":{"meta":3}}` {
		t.Errorf("slices %s", got)
	}
}

func TestDetachProxy_RemoveSliceThenDetach(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(3, 5, 7)
	x.ensure(t, live...)
	x.f.resetLog()
	if err := x.a.DetachProxy(ctx, live[1].Ref); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "detach", x.events(), `table {"3":{"meta":5},"7":{"meta":5}}`, "disconnect proj-"+live[1].Ref)
	x.f.resetLog()
	if err := x.a.DetachProxy(ctx, live[1].Ref); err != nil {
		t.Fatal(err)
	}
	if ev := x.events(); len(ev) != 0 {
		t.Errorf("a second detach: %q, want nothing", ev)
	}
	// Half done — the slice removed, the detach failed — the next one detaches.
	boom := errors.New("docker: daemon busy")
	x.f.failVerb["network disconnect"] = boom
	if err := x.a.DetachProxy(ctx, live[0].Ref); !errors.Is(err, boom) {
		t.Fatalf("a failing detach: %v", err)
	}
	if got := x.slices(t); got != `{"7":{"meta":5}}` {
		t.Errorf("slices after the failed detach %s: the slice leaves the table first", got)
	}
	delete(x.f.failVerb, "network disconnect")
	x.f.resetLog()
	if err := x.a.DetachProxy(ctx, live[0].Ref); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "resumed", x.events(), "disconnect proj-"+live[0].Ref)
	// A table that cannot be written: nothing is detached.
	x.failWrite = errors.New("no space left on device")
	x.f.resetLog()
	if err := x.a.DetachProxy(ctx, live[2].Ref); err == nil || len(x.events()) != 0 {
		t.Errorf("the slice could not be removed: %v, events %q", err, x.events())
	}
	x.failWrite = nil
	// A project that never had a network, an invalid ref.
	x.f.resetLog()
	if err := x.a.DetachProxy(ctx, x.spec(50).Ref); err != nil || len(x.events()) != 0 {
		t.Errorf("no network: %v, events %q", err, x.events())
	}
	if err := x.a.DetachProxy(ctx, "../x"); err == nil {
		t.Error("an invalid ref accepted")
	}
	// A network of that name that is not the slice's own: the table is left
	// alone (it names no slice of it), the proxy still leaves the network.
	odd := x.spec(60)
	x.f.net(fakeNet{Network: dockerx.Network{Name: "proj-" + odd.Ref, Subnet: x.a.cfg.Slice(7).String(), BridgeName: nodecfg.BridgeName(7)}})
	x.f.mu.Lock()
	x.f.ctrs[dashcfg.PgcapName].Nets["proj-"+odd.Ref] = x.addr(7)
	x.f.mu.Unlock()
	x.f.resetLog()
	if err := x.a.DetachProxy(ctx, odd.Ref); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "a foreign network", x.events(), "disconnect proj-"+odd.Ref)
}

func TestAttachProxy_OnlyWithAnExplicitAddress(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(0, 3, 1023)
	x.ensure(t, live[:2]...)
	if err := x.a.AttachProxy(ctx, live[2]); err != nil {
		t.Fatal(err)
	}
	connects := x.f.argv("network", "connect")
	if len(connects) != 3 {
		t.Fatalf("connects %q", connects)
	}
	for k, i := range []int{0, 3, 1023} {
		want := []string{"network", "connect", "--ip", x.addr(i), "--", "proj-" + live[k].Ref, dashcfg.PgcapName}
		if !slices.Equal(connects[k], want) {
			t.Errorf("connect %q, want %q", connects[k], want)
		}
	}
	if x.addr(3) != "10.213.0.196" {
		t.Errorf("slice 3's proxy address is %s", x.addr(3))
	}
	x.f.resetLog()
	// A slice outside the block has no address: refused before any call.
	if err := x.a.AttachProxy(ctx, x.spec(1024)); err == nil || len(x.f.calls()) != 0 {
		t.Errorf("a slice outside the block: %v, calls %q", err, x.f.calls())
	}
	c, err := x.a.proxyContainer(ctx)
	if err != nil || c == nil {
		t.Fatal(err)
	}
	x.f.resetLog()
	if on, err := x.a.attachProxy(ctx, c, x.spec(1024)); err == nil || on || len(x.f.calls()) != 0 {
		t.Errorf("the attach itself, a slice outside the block: %v, %v, calls %q", on, err, x.f.calls())
	}
	bad := x.spec(5)
	bad.Ref = "../x"
	if err := x.a.AttachProxy(ctx, bad); err == nil || len(x.f.calls()) != 0 {
		t.Errorf("a ref that is none: %v, calls %q", err, x.f.calls())
	}
	// A network that is not the slice's own is never joined.
	for name, edit := range map[string]func(*fakeNet){
		"not internal":     func(n *fakeNet) { n.Internal = false },
		"another subnet":   func(n *fakeNet) { n.Subnet = x.a.cfg.Slice(9).String() },
		"another bridge":   func(n *fakeNet) { n.BridgeName = "br-0123456789ab" },
		"with a gateway":   func(n *fakeNet) { delete(n.Options, optGatewayMode) },
		"its network gone": nil,
	} {
		s := x.project(8)
		x.f.mu.Lock()
		if edit == nil {
			delete(x.f.nets, "proj-"+s.Ref)
		} else {
			edit(x.f.nets["proj-"+s.Ref])
		}
		x.f.mu.Unlock()
		x.f.resetLog()
		err := x.a.AttachProxy(ctx, s)
		if err == nil || len(x.events()) != 0 {
			t.Errorf("%s: %v, events %q", name, err, x.events())
		}
		if edit != nil && !errors.Is(err, ErrContainment) {
			t.Errorf("%s: %v, want a containment refusal", name, err)
		}
		if err := x.a.EnsureProxy(ctx, listed(append(slices.Clone(live), s))); (err == nil) != (edit == nil) || len(x.events()) != 0 {
			t.Errorf("%s, by the ensure: %v, events %q", name, err, x.events())
		}
	}
}

// TestAttachProxy_CreatesTheContainerWhenAbsent: a create never depends on a
// round having run.
func TestAttachProxy_CreatesTheContainerWhenAbsent(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	s := x.project(5)
	if err := x.a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "the first attach of a node", x.events(), "table {}", "create", "start", "connect proj-"+s.Ref+" "+x.addr(5), `table {"5":{"meta":5}}`)
	made := x.create(t, dashcfg.PgcapName)
	// Exactly as the ensure makes it: the ensure finds nothing to change.
	x.f.resetLog()
	x.ensure(t, s)
	if ev := x.events(); len(ev) != 0 {
		t.Errorf("the ensure after it: %q, want nothing", ev)
	}
	x.f.mu.Lock()
	delete(x.f.ctrs, dashcfg.PgcapName)
	x.f.mu.Unlock()
	x.ensure(t, s)
	if got := x.create(t, dashcfg.PgcapName); !slices.Equal(got, made) {
		t.Errorf("the ensure creates it with %q, the attach with %q", got, made)
	}
	// A stopped proxy is started.
	x.ctr().Running = false
	x.f.resetLog()
	if err := x.a.AttachProxy(ctx, x.project(6)); err != nil {
		t.Fatal(err)
	}
	if ev := x.events(); len(ev) != 3 || ev[0] != "start" {
		t.Errorf("stopped: %q", ev)
	}
	// Absent with a table of another shape on disk (another daemon's): the
	// container is labelled with the shape it starts from, so the ensure,
	// which writes this daemon's table, makes it again.
	x.f.mu.Lock()
	delete(x.f.ctrs, dashcfg.PgcapName)
	x.f.mu.Unlock()
	old := x.table(t)
	old.MaxConns = 96
	b, err := old.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rewrite(t, x.path, b)
	if err := x.a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	if n := x.table(t).MaxConns; n != 96 {
		t.Errorf("an attach changed the table's shape: ceiling %d", n)
	}
	x.f.resetLog()
	x.ensure(t, s)
	if ev := x.events(); len(ev) < 4 || !slices.Equal(ev[:4], []string{"table {}", "rm", "create", "start"}) || x.table(t).MaxConns != 80 {
		t.Errorf("the ensure after a table of another shape: %q, ceiling %d", ev, x.table(t).MaxConns)
	}
}

func TestProxy_NoStudioDomain_AllThreeDoNothing(t *testing.T) {
	x := newProxyFix(t, "")
	ctx := context.Background()
	s := x.project(5)
	x.f.resetLog()
	if err := errors.Join(x.a.EnsureProxy(ctx, listed([]Spec{s})), x.a.AttachProxy(ctx, s), x.a.DetachProxy(ctx, s.Ref)); err != nil {
		t.Fatal(err)
	}
	if c := x.f.calls(); len(c) != 0 {
		t.Errorf("calls %q, want none", c)
	}
	if _, err := os.Lstat(x.d.DashDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dashboard's directory exists (%v)", err)
	}
	// Removing a network there asks nothing of the proxy.
	if err := x.a.RemoveNetwork(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "RemoveNetwork", x.events(), "netrm proj-"+s.Ref)
	// Control: the same calls on the same node with the domain act.
	x.a.cfg.StudioDomain = "studio.test"
	s = x.project(5)
	if err := x.a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	if x.ctr() == nil || x.slices(t) != `{"5":{"meta":5}}` {
		t.Error("control: no proxy with the domain")
	}
}

func TestProxy_ConfigRefused_AllThreeDoNothing(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	s := x.project(5)
	x.a.cfg.GatewayIP = x.ad.Pgcap.String() // a node file dashcfg.For refuses
	if _, err := dashcfg.For(x.a.cfg); err == nil {
		t.Fatal("the configuration of this test is accepted")
	}
	x.f.resetLog()
	if err := errors.Join(x.a.EnsureProxy(ctx, listed([]Spec{s})), x.a.AttachProxy(ctx, s), x.a.DetachProxy(ctx, s.Ref)); err != nil {
		t.Fatal(err)
	}
	if c := x.f.calls(); len(c) != 0 {
		t.Errorf("calls %q, want none", c)
	}
	if _, err := os.Lstat(x.d.ProxyConf()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the table's directory exists (%v)", err)
	}
	// Control: the same node with a configuration that is accepted.
	x.a.cfg.GatewayIP = nodecfg.Default("sp.test").GatewayIP
	if err := x.a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	if x.ctr() == nil || x.slices(t) != `{"5":{"meta":5}}` {
		t.Error("control: no proxy on the accepted configuration")
	}
}

// TestRemoveNetwork_DetachesFirst: the slice leaves the table, the proxy the
// network, and then the network goes; a step that fails stops the ones after
// it and the call can be made again.
func TestRemoveNetwork_DetachesFirst(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(3, 7)
	x.ensure(t, live...)
	x.f.resetLog()
	if err := x.a.RemoveNetwork(ctx, live[0].Ref); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "RemoveNetwork", x.events(), `table {"7":{"meta":5}}`, "disconnect proj-"+live[0].Ref, "netrm proj-"+live[0].Ref)
	x.f.resetLog()
	if err := x.a.RemoveNetwork(ctx, live[0].Ref); err != nil || len(x.events()) != 0 {
		t.Errorf("again: %v, events %q", err, x.events())
	}
	boom := errors.New("docker: daemon busy")
	x.f.failVerb["network disconnect"] = boom
	x.f.resetLog()
	if err := x.a.RemoveNetwork(ctx, live[1].Ref); !errors.Is(err, boom) {
		t.Fatalf("a failing detach: %v", err)
	}
	wantEvents(t, "the detach fails: the network stays", x.events(), "table {}", "disconnect proj-"+live[1].Ref) // the call that failed
	delete(x.f.failVerb, "network disconnect")
	x.f.resetLog()
	if err := x.a.RemoveNetwork(ctx, live[1].Ref); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, "made again", x.events(), "disconnect proj-"+live[1].Ref, "netrm proj-"+live[1].Ref)
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	if n := x.f.ctrs[dashcfg.PgcapName].Nets; len(n) != 1 {
		t.Errorf("the proxy is still on %v", n)
	}
}

// ───────── the connection string ─────────

// TestProxyDSN_NoTLSRequest: the proxy answers a request for encryption with
// a refusal, and the client behind it then fails; so for every slice of the
// table the agent writes, the platform's connection string names the table's
// address and that slice's port and asks for no TLS.
func TestProxyDSN_NoTLSRequest(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	x.ensure(t, x.projects(0, 3, 7, 1023)...)
	tb := x.table(t)
	if len(tb.Slices) != 4 || len(tb.Classes) != 1 {
		t.Fatalf("table %+v", tb)
	}
	for k := range tb.Slices {
		i, _ := strconv.Atoi(k)
		for _, login := range []string{dashcfg.LoginRW, dashcfg.LoginRO} {
			dsn := dashcfg.DSN(x.ad, login, "p w/1", i)
			want := "postgresql://" + login + ":p%20w%2F1@" + tb.Listen.String() + ":" + strconv.Itoa(tb.Classes[0].PortBase+i) + "/postgres?sslmode=disable"
			if dsn != want {
				t.Errorf("slice %d: %s, want %s", i, dsn, want)
			}
			if _, q, _ := strings.Cut(dsn, "?"); q != "sslmode=disable" {
				t.Errorf("slice %d: parameters %q, want sslmode=disable alone", i, q)
			}
			if l, got, err := dashcfg.ParseDSN(x.ad, dsn); err != nil || l != login || got != i {
				t.Errorf("slice %d: parsed as %s, %d, %v", i, l, got, err)
			}
		}
	}
}

// ───────── the node check's row ─────────

// check is the row proxy, networks the row proxy-networks.
func (x *proxyFix) check() error {
	live, _ := x.a.checkProxy(context.Background(), x.ad)
	return live
}

func (x *proxyFix) networks() error {
	_, nets := x.a.checkProxy(context.Background(), x.ad)
	return nets
}

func stamp(age time.Duration) string {
	return time.Now().Add(-age).UTC().Format(time.RFC3339Nano)
}

func TestNodeCheck_Proxy_NotRunningRestartedOrNotAttached(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	live := x.projects(3, 7)
	want := func(what, sub string) {
		t.Helper()
		if err := x.check(); err == nil || !strings.Contains(err.Error(), sub) {
			t.Errorf("%s: %v, want a failure naming %q", what, err, sub)
		}
	}
	ok := func(what string) {
		t.Helper()
		if err := x.check(); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	want("before it is made", "absent")
	x.ensure(t, live...)
	// This daemon's first check has no count to compare with: restarts of
	// before it are not news.
	x.mu.Lock()
	x.restarts[dashcfg.PgcapName] = 4
	x.mu.Unlock()
	ok("as made, restarted before this daemon's first check")

	x.ctr().Running = false
	want("stopped", "not running")
	x.ctr().Running = true

	// The restart count since the last check: Docker's back-off spaces a
	// crashing proxy's restarts up to a minute apart, and it runs in between.
	x.mu.Lock()
	x.restarts[dashcfg.PgcapName] = 6
	x.mu.Unlock()
	want("restarted twice since the last check", "restarted 2 times since the last check")
	ok("no restart since")
	x.mu.Lock()
	x.restarts[dashcfg.PgcapName] = 7
	x.mu.Unlock()
	want("once more", "restarted 1 times since the last check")
	x.mu.Lock()
	x.restarts[dashcfg.PgcapName] = 2
	x.mu.Unlock()
	x.ctr().Labels[labelConfig] = "other"
	x.ensure(t, live...) // made again since the last check: it counts from nought, not from seven
	want("made again and restarted twice since", "restarted 2 times since the last check")
	ok("no restart since")
	x.mu.Lock()
	x.restarts[dashcfg.PgcapName] = 0
	x.mu.Unlock()
	x.ctr().Labels[labelConfig] = "other"
	x.ensure(t, live...)
	ok("made again, never restarted")
	x.mu.Lock()
	x.restarting[dashcfg.PgcapName] = true
	x.logs[dashcfg.PgcapName] = "pgcap: the table cannot be read\n"
	x.mu.Unlock()
	want("in Docker's restart loop", "the table cannot be read")
	x.mu.Lock()
	x.restarting[dashcfg.PgcapName] = false
	x.mu.Unlock()
	ok("running again")

	// A live project whose network lacks the proxy at .4: the start gate does
	// not refuse a missing member.
	net7 := "proj-" + live[1].Ref
	x.f.mu.Lock()
	delete(x.f.ctrs[dashcfg.PgcapName].Nets, net7)
	x.f.mu.Unlock()
	want("not attached to a slice of its table", "slice 7")
	x.f.mu.Lock()
	x.f.ctrs[dashcfg.PgcapName].Nets[net7] = x.a.cfg.PostgRESTAddr(7).String()
	x.f.mu.Unlock()
	want("attached at another address", "slice 7")
	x.f.mu.Lock()
	x.f.ctrs[dashcfg.PgcapName].Nets[net7] = x.addr(7)
	x.f.ctrs[dashcfg.PgcapName].Nets["bridge"] = "10.214.0.9"
	x.f.mu.Unlock()
	want("on a network no slice of its table accounts for", "bridge")
	x.f.mu.Lock()
	delete(x.f.ctrs[dashcfg.PgcapName].Nets, "bridge")
	x.f.ctrs[dashcfg.PgcapName].Nets[platformNet] = x.ad.Studio.String()
	x.f.mu.Unlock()
	want("at another platform address", x.ad.Pgcap.String())
	x.f.mu.Lock()
	x.f.ctrs[dashcfg.PgcapName].Nets[platformNet] = x.ad.Pgcap.String()
	x.f.mu.Unlock()
	ok("attached as the table says")

	x.ctr().Labels[labelConfig] = "other"
	want("another configuration", "another configuration")
	x.ensure(t, live...)

	// A placed slice whose port the proxy logs as not opened.
	x.pmu.Lock()
	x.log = []string{stamp(time.Second) + ` {"class":"meta","index":7,"reason":"listen: listen tcp4 10.212.0.6:20007: bind: address already in use"}`}
	x.pmu.Unlock()
	want("a port not opened", "slice 7")
	x.pmu.Lock()
	x.log = nil
	x.pmu.Unlock()

	good := mustBytes(t, x)
	rewrite(t, x.path, []byte("{}"))
	want("a file that is no table", proxyTableName)
	os.Remove(x.path)
	want("no table", proxyTableName)
	if err := os.WriteFile(x.path, good, 0o444); err != nil {
		t.Fatal(err)
	}
	ok("the table back")
}

// TestNodeCheck_Proxy_PortNotOpened: the proxy has no status to ask. It logs
// "listen: …" for a slice and class whose port it could not open, at every
// look at its table, and nothing when the port opens: the row fails while
// the log's last five seconds, by the runtime's timestamps, hold such a line
// for a slice and class of the table.
func TestNodeCheck_Proxy_PortNotOpened(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	live := x.projects(3, 7)
	x.ensure(t, live...)
	line := func(age time.Duration, class string, index int, reason string) string {
		return fmt.Sprintf(`%s {"class":%q,"index":%d,"reason":%q}`, stamp(age), class, index, reason)
	}
	const unopened = "listen: listen tcp4 10.212.0.6:20003: bind: address already in use"
	for _, c := range []struct {
		name string
		log  []string
		fail bool
	}{
		{"an empty log", nil, false},
		{"a line of the last five seconds", []string{line(2*time.Second, "meta", 3, unopened)}, true},
		{"the same line, older than five seconds", []string{line(6*time.Second, "meta", 3, unopened)}, false},
		{"a slice that has left the table", []string{line(time.Second, "meta", 9, unopened)}, false},
		{"a class the table does not have", []string{line(time.Second, "other", 3, unopened)}, false},
		{"another reason of that slice", []string{line(time.Second, "meta", 3, "too many connections: the project's allowance")}, false},
		{"a table event and a line without a timestamp", []string{stamp(time.Second) + ` {"table":"kept the table in use: listen: x"}`,
			`{"class":"meta","index":3,"reason":"` + unopened + `"}`, "listen: not a log line"}, false},
		{"among other lines", []string{line(4*time.Second, "meta", 7, "dial: connection refused"), line(3*time.Second, "meta", 3, unopened),
			line(time.Second, "meta", 7, "dial: connection refused")}, true},
	} {
		x.pmu.Lock()
		x.log = c.log
		x.pmu.Unlock()
		err := x.check()
		if (err != nil) != c.fail {
			t.Errorf("%s: %v, want a failure %v", c.name, err, c.fail)
		}
		if c.fail && !strings.Contains(err.Error(), "slice 3") {
			t.Errorf("%s: %v does not name the slice", c.name, err)
		}
	}
	// What is read: timestamps, and the last 5 × (slices × classes + 2) lines.
	x.pmu.Lock()
	if n := len(x.tails); n == 0 || x.tails[n-1] != "20" {
		t.Errorf("the log read asked for the last %q lines, want 20 for two slices of one class", x.tails)
	}
	x.pmu.Unlock()

	// A flood: every other slice of a full node logs a refusal every second.
	// The unopened port's line is the oldest of what the bound still holds.
	var all []Spec
	for i := range 28 {
		all = append(all, x.project(i))
	}
	x.ensure(t, all...)
	const tail = 5 * (28 + 2)
	flood := []string{line(4900*time.Millisecond, "meta", 3, unopened)}
	for len(flood) < tail {
		age := 4800*time.Millisecond - time.Duration(len(flood))*30*time.Millisecond
		flood = append(flood, line(age, "meta", 4+len(flood)%24, "too many connections: the rate"))
	}
	x.pmu.Lock()
	x.log = flood
	x.pmu.Unlock()
	if err := x.check(); err == nil || !strings.Contains(err.Error(), "slice 3") {
		t.Errorf("a flood of refusals on the other slices hid the line: %v", err)
	}
	x.pmu.Lock()
	if n := len(x.tails); x.tails[n-1] != strconv.Itoa(tail) {
		t.Errorf("the log read asked for the last %s lines, want %d", x.tails[n-1], tail)
	}
	// One line more of the flood and the line is past what is read: by then
	// it is older than the lines of five seconds (each slice logs at most one
	// a second).
	x.log = append(x.log, line(time.Millisecond, "meta", 5, "too many connections: the rate"))
	x.pmu.Unlock()
	if err := x.check(); err != nil {
		t.Errorf("control: the bound is on what is read: %v", err)
	}
	// A log that cannot be read proves nothing either.
	x.pmu.Lock()
	x.failLog = errors.New("docker: daemon busy")
	x.pmu.Unlock()
	if err := x.check(); err == nil || !strings.Contains(err.Error(), "daemon busy") {
		t.Errorf("a failing log read: %v", err)
	}
	x.pmu.Lock()
	x.failLog = nil
	x.pmu.Unlock()
	// A full log — more than one read returns — is no failure by itself: old
	// lines of any number say nothing of a port, and what was read is judged.
	big := make([]string, tail)
	for i := range big {
		big[i] = line(time.Hour, "meta", 4, strings.Repeat("r", 600))
	}
	x.pmu.Lock()
	x.log = big
	x.pmu.Unlock()
	if err := x.check(); err != nil {
		t.Errorf("a full log of old lines: %v", err)
	}
	x.pmu.Lock()
	x.log[0] = line(time.Second, "meta", 3, unopened)
	x.pmu.Unlock()
	if err := x.check(); err == nil || !strings.Contains(err.Error(), "slice 3") {
		t.Errorf("a full log whose read holds the line: %v", err)
	}
	// The read is bounded by time as well as by lines.
	x.pmu.Lock()
	if !x.since {
		t.Error("the log read is not bounded by time")
	}
	x.pmu.Unlock()
}

// TestNodeCheck_ProxyNetworks: the blocking row. The proxy has an interface
// on every project network, so where it sits and which slices it serves is
// containment: it fails when the proxy is on a network that is neither
// platform nor a project network of this node, and when its table holds a
// slice no project network accounts for. What is merely missing — an
// attachment, a slice, the proxy itself — is the row proxy's.
func TestNodeCheck_ProxyNetworks(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	live := x.projects(3, 7)
	fails := func(what, sub string) {
		t.Helper()
		if err := x.networks(); err == nil || !strings.Contains(err.Error(), sub) {
			t.Errorf("%s: %v, want a failure naming %q", what, err, sub)
		}
	}
	passes := func(what string, liveness bool) {
		t.Helper()
		if err := x.networks(); err != nil {
			t.Errorf("%s: %v", what, err)
		}
		if err := x.check(); (err == nil) != liveness {
			t.Errorf("%s: the row proxy: %v, want it passing %v", what, err, liveness)
		}
	}
	nets := func(edit func(map[string]string)) {
		x.f.mu.Lock()
		defer x.f.mu.Unlock()
		edit(x.f.ctrs[dashcfg.PgcapName].Nets)
	}
	passes("no proxy: nothing is attached, no table is served", false)
	x.ensure(t, live...)
	passes("as made", true)
	x.ctr().Running = false
	passes("stopped: its networks are still judged, and are in order", false)
	nets(func(n map[string]string) { n["bridge"] = "10.214.0.9" })
	fails("stopped, on Docker's bridge", "bridge")
	x.ctr().Running = true
	fails("on Docker's bridge", "bridge")
	nets(func(n map[string]string) { delete(n, "bridge"); n[ingressNet] = "10.212.8.9" })
	fails("on the ingress network", ingressNet)
	nets(func(n map[string]string) { delete(n, ingressNet) })

	// A network named like a project's that is not a project network of this
	// node: the proxy on it could have a way off the node.
	odd := x.spec(9)
	x.f.net(fakeNet{Network: dockerx.Network{Name: "proj-" + odd.Ref, Subnet: x.a.cfg.Slice(9).String(), BridgeName: nodecfg.BridgeName(9),
		Options: map[string]string{optBridgeName: nodecfg.BridgeName(9)}}}) // not internal, no isolated gateway
	nets(func(n map[string]string) { n["proj-"+odd.Ref] = x.addr(9) })
	fails("on a network that is not internal", "proj-"+odd.Ref)
	nets(func(n map[string]string) { delete(n, "proj-"+odd.Ref) })
	x.f.mu.Lock()
	delete(x.f.nets, "proj-"+odd.Ref)
	x.f.mu.Unlock()
	// A network with a slice's exact shape under a name that is no project's.
	x.f.net(fakeNet{Network: dockerx.Network{Name: "scratch", Internal: true, Subnet: x.a.cfg.Slice(9).String(), BridgeName: nodecfg.BridgeName(9),
		Options: map[string]string{optBridgeName: nodecfg.BridgeName(9), optGatewayMode: "isolated"}}})
	nets(func(n map[string]string) { n["scratch"] = x.addr(9) })
	fails("on a network shaped like a slice under another name", "scratch")
	nets(func(n map[string]string) { delete(n, "scratch") })
	x.f.mu.Lock()
	delete(x.f.nets, "scratch")
	x.f.mu.Unlock()

	// Attached to a project network whose slice is not in the table (an
	// attach that stopped half-way): no listener serves it. Not containment.
	half := x.project(11)
	nets(func(n map[string]string) { n["proj-"+half.Ref] = x.addr(11) })
	passes("attached, the slice not added", false)
	nets(func(n map[string]string) { delete(n, "proj-"+half.Ref) })

	// A slice of the table whose network exists but lacks the proxy: an
	// outage of that project's dashboard. Not containment.
	nets(func(n map[string]string) { delete(n, "proj-"+live[1].Ref) })
	passes("a slice whose network lacks the proxy", false)
	// The same slice with its network gone: the table names a slice no
	// project of this node has.
	x.f.mu.Lock()
	gone := x.f.nets["proj-"+live[1].Ref]
	delete(x.f.nets, "proj-"+live[1].Ref)
	x.f.mu.Unlock()
	fails("a slice without a project network", "slice 7")
	x.f.net(*gone)
	nets(func(n map[string]string) { n["proj-"+live[1].Ref] = x.addr(7) })
	passes("back as made", true)

	// A table the agent cannot parse is the row proxy's to report: this row
	// still judges every attachment, and blocks for those alone — the next
	// daemon start must not stop every project over a file.
	good := mustBytes(t, x)
	for name, bad := range map[string][]byte{"not a table": []byte("{}"), "a line end appended": append(slices.Clone(good), 0x0a)} {
		rewrite(t, x.path, bad)
		passes(name+", with a proxy running", false)
		if err := x.check(); err == nil || !strings.Contains(err.Error(), proxyTableName) {
			t.Errorf("%s: the row proxy: %v, want it naming the file", name, err)
		}
		nets(func(n map[string]string) { n["bridge"] = "10.214.0.9" })
		fails(name+", the proxy on Docker's bridge", "bridge")
		nets(func(n map[string]string) { delete(n, "bridge") })
	}
	os.Remove(x.path)
	passes("no table: no slice is served", false)
	if err := os.WriteFile(x.path, good, 0o444); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("docker: daemon busy")
	x.f.failInspect["proj-"+live[0].Ref] = boom
	fails("a network that cannot be inspected", "daemon busy")
	delete(x.f.failInspect, "proj-"+live[0].Ref)
	x.f.failInspect[dashcfg.PgcapName] = boom
	fails("a proxy that cannot be inspected", "daemon busy")
	delete(x.f.failInspect, dashcfg.PgcapName)
	passes("readable again", true)
}

// TestNodeCheck_ProxyRows_OnlyWhereTheDashboardIsConfigured: the node check
// has the two rows on a node whose dashboard is configured and nowhere else;
// proxy fails without blocking, proxy-networks blocks.
func TestNodeCheck_ProxyRows_OnlyWhereTheDashboardIsConfigured(t *testing.T) {
	a, f := goodNode(t)
	all := rows(t, a)
	for _, name := range []string{rowProxy, rowProxyNetworks} {
		if _, ok := all[name]; ok {
			t.Errorf("a node without a studio domain has the row %s", name)
		}
	}
	a.cfg.StudioDomain = "studio.test"
	all = rows(t, a)
	if r, ok := all[rowProxy]; !ok || r.OK || Blocking(r) || !strings.Contains(r.Detail, "absent") {
		t.Errorf("no proxy yet: row %+v (present %v, blocking %v), want it failing and not blocking", r, ok, Blocking(r))
	}
	if r, ok := all[rowProxyNetworks]; !ok || !r.OK {
		t.Errorf("no proxy yet: row %+v (present %v), want it passing", r, ok)
	}
	// A proxy on a network it must not be on: the second row fails and blocks.
	ad, err := dashcfg.For(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.ctr(fakeCtr{Name: dashcfg.PgcapName, Running: true, CapDrop: []string{"ALL"}, Labels: map[string]string{labelRole: "pgcap"},
		Nets: map[string]string{platformNet: ad.Pgcap.String(), "bridge": "10.214.0.9"}})
	if r := rows(t, a)[rowProxyNetworks]; r.OK || !Blocking(r) || !strings.Contains(r.Detail, "bridge") {
		t.Errorf("a proxy on Docker's bridge: row %+v (blocking %v)", r, Blocking(r))
	}
	// Neither row is a property of its name alone.
	if Blocking(nodecfg.CheckResult{Name: rowProxy}) || !Blocking(nodecfg.CheckResult{Name: rowProxyNetworks}) ||
		!Blocking(nodecfg.CheckResult{Name: "forwarding"}) || !Blocking(nodecfg.CheckResult{Name: "project-addresses"}) {
		t.Error("Blocking: proxy must be exempt; proxy-networks, forwarding and project-addresses must block")
	}
	// A configuration that cannot host a dashboard has neither row.
	a.cfg.GatewayIP = ad.Pgcap.String()
	all = rows(t, a)
	if _, ok := all[rowProxy]; ok {
		t.Error("a refused configuration has the row proxy")
	}
	if _, ok := all[rowProxyNetworks]; ok {
		t.Error("a refused configuration has the row proxy-networks")
	}
}

// TestProxy_HeldBetweenRestarts_StoppedForTheCallThenStarted: while the
// runtime holds a crashing proxy between two restarts it refuses to connect
// or disconnect it. The proxy's outage must not hold a project's create,
// delete or abort: the agent stops it, repeats the one call on the stopped
// container, and starts it again — once, and only when the runtime reports
// it restarting.
func TestProxy_HeldBetweenRestarts_StoppedForTheCallThenStarted(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(3, 7)
	x.ensure(t, live...)
	hold := func() {
		x.mu.Lock()
		x.restarting[dashcfg.PgcapName] = true
		x.mu.Unlock()
		x.f.resetLog()
	}
	// A delete or an abort: the network goes although the proxy is held.
	hold()
	if err := x.a.RemoveNetwork(ctx, live[0].Ref); err != nil {
		t.Fatalf("removing a network while the proxy is held: %v", err)
	}
	wantEvents(t, "RemoveNetwork", x.events(), `table {"7":{"meta":5}}`, "disconnect proj-"+live[0].Ref, "stop",
		"disconnect proj-"+live[0].Ref, "start", "netrm proj-"+live[0].Ref)
	// A create's step.
	s := x.project(9)
	hold()
	if err := x.a.AttachProxy(ctx, s); err != nil {
		t.Fatalf("attaching while the proxy is held: %v", err)
	}
	wantEvents(t, "AttachProxy", x.events(), "connect proj-"+s.Ref+" "+x.addr(9), "stop", "connect proj-"+s.Ref+" "+x.addr(9), "start",
		`table {"7":{"meta":5},"9":{"meta":5}}`)
	// The ensure: a project that left, one that came.
	s2 := x.project(11)
	hold()
	if err := x.a.EnsureProxy(ctx, listed([]Spec{live[1], s2})); err != nil {
		t.Fatalf("the ensure while the proxy is held: %v", err)
	}
	wantEvents(t, "EnsureProxy", x.events(), "connect proj-"+s2.Ref+" "+x.addr(11), "stop", "connect proj-"+s2.Ref+" "+x.addr(11), "start",
		`table {"7":{"meta":5},"11":{"meta":5}}`, "disconnect proj-"+s.Ref)
	if !x.ctr().Running {
		t.Error("the proxy was left stopped")
	}
	// Bounded: a call that fails again on the stopped container is not made a
	// third time, the proxy is still started, and the failure is returned.
	hold()
	boom := errors.New("docker: daemon busy")
	x.f.failVerb["network disconnect"] = boom
	if err := x.a.DetachProxy(ctx, s2.Ref); !errors.Is(err, boom) {
		t.Errorf("a disconnect that fails stopped as well: %v", err)
	}
	wantEvents(t, "one retry", x.events(), `table {"7":{"meta":5}}`, "disconnect proj-"+s2.Ref, "stop", "disconnect proj-"+s2.Ref, "start")
	delete(x.f.failVerb, "network disconnect")
	// A proxy that runs is never stopped over a failing call: every dashboard
	// connection of the node would be cut for nothing.
	x.f.failVerb["network connect"] = boom
	x.f.resetLog()
	s3 := x.project(13)
	if err := x.a.AttachProxy(ctx, s3); !errors.Is(err, boom) {
		t.Errorf("a failing connect of a running proxy: %v", err)
	}
	wantEvents(t, "a running proxy", x.events(), "connect proj-"+s3.Ref+" "+x.addr(13))
	delete(x.f.failVerb, "network connect")
	// A start that fails after the repeated call is reported.
	hold()
	x.f.failVerb["start"] = boom
	if err := x.a.AttachProxy(ctx, s3); !errors.Is(err, boom) {
		t.Errorf("a proxy that could not be started again: %v", err)
	}
	delete(x.f.failVerb, "start")
	x.ensure(t, live[1], s3)
	// The ensure that only detaches, and an attachment at another address made
	// again: the same helper at both.
	hold()
	if err := x.a.EnsureProxy(ctx, listed([]Spec{live[1]})); err != nil {
		t.Fatalf("the ensure that detaches while the proxy is held: %v", err)
	}
	wantEvents(t, "EnsureProxy, a project gone", x.events(), `table {"7":{"meta":5}}`, "disconnect proj-"+s3.Ref, "stop", "disconnect proj-"+s3.Ref, "start")
	x.f.mu.Lock()
	x.f.ctrs[dashcfg.PgcapName].Nets["proj-"+live[1].Ref] = x.a.cfg.PostgRESTAddr(7).String()
	x.f.mu.Unlock()
	hold()
	if err := x.a.AttachProxy(ctx, live[1]); err != nil {
		t.Fatalf("a misplaced attachment made again while the proxy is held: %v", err)
	}
	wantEvents(t, "misplaced", x.events(), "disconnect proj-"+live[1].Ref, "stop", "disconnect proj-"+live[1].Ref, "start",
		"connect proj-"+live[1].Ref+" "+x.addr(7))
	// A proxy that cannot be stopped: the call is not repeated.
	hold()
	x.f.failVerb["stop"] = boom
	if err := x.a.DetachProxy(ctx, live[1].Ref); !errors.Is(err, boom) {
		t.Errorf("a proxy that cannot be stopped: %v", err)
	}
	wantEvents(t, "not stopped, not repeated", x.events(), "table {}", "disconnect proj-"+live[1].Ref, "stop")
}

// TestEnsureProxy_OneFailingProjectDoesNotTakeTheOthers: a project whose
// attach fails is reported, and every other project of the list is still
// attached and named by the table — one network of the wrong shape, or one
// failing call, does not take the SQL path from the rest of the node.
func TestEnsureProxy_OneFailingProjectDoesNotTakeTheOthers(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(3, 5, 7, 9)
	x.f.mu.Lock()
	x.f.nets["proj-"+live[1].Ref].Internal = false // not this node's shape for the slice
	x.f.mu.Unlock()
	boom := errors.New("docker: daemon busy")
	onRun := x.f.onRun
	x.f.onRun = func(args []string, stdin []byte) (string, error, bool) {
		if len(args) > 2 && args[0] == "network" && args[1] == "connect" && slices.Contains(args, "proj-"+live[2].Ref) {
			x.f.record("docker " + strings.Join(args, " ") + " (failed)")
			return "", boom, true
		}
		return onRun(args, stdin)
	}
	err := x.a.EnsureProxy(ctx, listed(live))
	if !errors.Is(err, ErrContainment) || !errors.Is(err, boom) || !strings.Contains(err.Error(), "proj-"+live[1].Ref) {
		t.Fatalf("the ensure: %v, want both failures joined", err)
	}
	if got := x.slices(t); got != `{"3":{"meta":5},"9":{"meta":5}}` {
		t.Errorf("slices %s, want the two that attached", got)
	}
	c := x.ctr()
	x.f.mu.Lock()
	if len(c.Nets) != 3 || c.Nets["proj-"+live[0].Ref] != x.addr(3) || c.Nets["proj-"+live[3].Ref] != x.addr(9) {
		t.Errorf("attached to %v", c.Nets)
	}
	x.f.mu.Unlock()
	// A failing call on a project that is attached and served: its slice and
	// its attachment stay; the others' changes are still made.
	x.f.onRun = onRun
	x.f.mu.Lock()
	x.f.nets["proj-"+live[1].Ref].Internal = true
	x.f.mu.Unlock()
	x.ensure(t, live...)
	x.f.failInspect["proj-"+live[0].Ref] = boom
	x.f.resetLog()
	if err := x.a.EnsureProxy(ctx, listed(live[:3])); !errors.Is(err, boom) {
		t.Fatalf("an inspection that fails: %v", err)
	}
	wantEvents(t, "the project that left is still detached", x.events(), `table {"3":{"meta":5},"5":{"meta":5},"7":{"meta":5}}`, "disconnect proj-"+live[3].Ref)
	delete(x.f.failInspect, "proj-"+live[0].Ref)
	// A network of the wrong shape the proxy is somehow on is not kept.
	x.f.mu.Lock()
	x.f.nets["proj-"+live[1].Ref].Internal = false
	x.f.mu.Unlock()
	x.f.resetLog()
	if err := x.a.EnsureProxy(ctx, listed(live[:3])); !errors.Is(err, ErrContainment) {
		t.Fatalf("a network that lost its shape: %v", err)
	}
	wantEvents(t, "detached from the network that is no slice", x.events(), `table {"3":{"meta":5},"7":{"meta":5}}`, "disconnect proj-"+live[1].Ref)
	// A detach that fails is reported, and the other one is still made.
	x.f.mu.Lock()
	x.f.nets["proj-"+live[1].Ref].Internal = true
	x.f.mu.Unlock()
	x.ensure(t, live...)
	x.f.failVerb["network disconnect"] = boom
	x.f.resetLog()
	if err := x.a.EnsureProxy(ctx, listed(live[:2])); !errors.Is(err, boom) {
		t.Errorf("a detach that fails: %v", err)
	}
	wantEvents(t, "both detaches tried", x.events(), `table {"3":{"meta":5},"5":{"meta":5}}`, "disconnect proj-"+live[2].Ref, "disconnect proj-"+live[3].Ref)
	// A project whose proxy sits at another address than the slice's, and
	// cannot be moved: its slice is not written — no listener without its
	// address — while the other project keeps its own.
	x.f.mu.Lock()
	x.f.ctrs[dashcfg.PgcapName].Nets["proj-"+live[0].Ref] = x.a.cfg.PostgRESTAddr(3).String()
	x.f.mu.Unlock()
	x.f.resetLog()
	if err := x.a.EnsureProxy(ctx, listed(live[:2])); !errors.Is(err, boom) {
		t.Errorf("a misplaced attachment that cannot be moved: %v", err)
	}
	if got := x.slices(t); got != `{"5":{"meta":5}}` {
		t.Errorf("slices %s, want the well-placed project alone", got)
	}
	delete(x.f.failVerb, "network disconnect")
}

// TestEnsureProxy_ListReadUnderTheLock: the ensure takes the table's lock and
// only then asks for the live projects. A list read before the lock could be
// older than a create's step: that project's attach, finished in between,
// would lose its slice and its attachment to the ensure. Read under the lock,
// an attach that starts while the list is read waits, completes after the
// ensure, and its slice survives.
func TestEnsureProxy_ListReadUnderTheLock(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	old := x.projects(3)
	x.ensure(t, old...)
	s := x.project(9) // a create that reaches its step while the list is read
	attached := make(chan error, 1)
	var calls int
	var early bool
	live := func(context.Context) ([]Spec, error) {
		calls++
		go func() { attached <- x.a.AttachProxy(ctx, s) }()
		// The list was read before that create placed its project. With the
		// lock held the attach cannot finish here, however long this takes.
		select {
		case err := <-attached:
			early = true
			attached <- err
		case <-time.After(100 * time.Millisecond):
		}
		return old, nil
	}
	if err := x.a.EnsureProxy(ctx, live); err != nil {
		t.Fatal(err)
	}
	if err := <-attached; err != nil {
		t.Fatalf("the attach: %v", err)
	}
	if calls != 1 || early {
		t.Errorf("the list was read %d times; the attach finished while it was read: %v", calls, early)
	}
	if got := x.slices(t); got != `{"3":{"meta":5},"9":{"meta":5}}` {
		t.Errorf("slices %s: the attach's slice did not survive the ensure", got)
	}
	x.f.mu.Lock()
	if x.f.ctrs[dashcfg.PgcapName].Nets["proj-"+s.Ref] != x.addr(9) {
		t.Errorf("the proxy is on %v", x.f.ctrs[dashcfg.PgcapName].Nets)
	}
	x.f.mu.Unlock()
	// A list that cannot be read: its error, and nothing changed.
	boom := errors.New("store: not reachable")
	x.f.resetLog()
	err := x.a.EnsureProxy(ctx, func(context.Context) ([]Spec, error) { return nil, boom })
	if !errors.Is(err, boom) || len(x.f.calls()) != 0 {
		t.Errorf("a failing list: %v, calls %q", err, x.f.calls())
	}
	if err := x.a.EnsureProxy(ctx, nil); err == nil || len(x.f.calls()) != 0 {
		t.Errorf("no list at all: %v, calls %q", err, x.f.calls())
	}
	// Where the agent does nothing the list is not asked for.
	x.a.cfg.StudioDomain = ""
	if err := x.a.EnsureProxy(ctx, func(context.Context) ([]Spec, error) { t.Error("the list was read"); return nil, boom }); err != nil {
		t.Error(err)
	}
}

// TestRemoveProxy: the proxy alone is removed, on any node, only under its
// exact name with its own role label and by the id that was inspected; its
// table stays. A container of that name that is not the platform's is left
// and named.
func TestRemoveProxy(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(3, 7)
	if err := x.a.RemoveProxy(ctx); err != nil || len(x.f.mutations()) != 0 {
		t.Fatalf("with no proxy: %v, %q", err, x.f.mutations())
	}
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	x.ensure(t, live...)
	x.f.ctr(fakeCtr{Name: dashcfg.PgcapName + "2", Running: true, CapDrop: []string{"ALL"}, Labels: map[string]string{labelRole: "pgcap"}})
	id := x.ctr().ID
	table := mustBytes(t, x)
	x.f.resetLog()
	if err := x.a.RemoveProxy(ctx); err != nil {
		t.Fatal(err)
	}
	if got := x.f.argv("rm"); len(got) != 1 || !slices.Equal(got[0], []string{"rm", "-f", "--", id}) || len(x.f.mutations()) != 1 {
		t.Errorf("removals %q (changes %q), want the proxy alone, by its id", got, x.f.mutations())
	}
	x.f.mu.Lock()
	var left []string
	for n := range x.f.ctrs {
		left = append(left, n)
	}
	x.f.mu.Unlock()
	slices.Sort(left)
	if want := []string{dashcfg.PgcapName + "2", dashcfg.PgMeta0Name, dashcfg.PgMeta1Name, dashcfg.StudioName}; !slices.Equal(left, want) {
		t.Errorf("containers left %q, want %q", left, want)
	}
	if string(mustBytes(t, x)) != string(table) {
		t.Error("the table changed")
	}
	// With no proxy the blocking row passes and the liveness row says so;
	// the ensure brings it back, attached, from the table's own slices.
	if live, nets := x.a.checkProxy(ctx, x.ad); nets != nil || live == nil {
		t.Errorf("after the removal: proxy %v, proxy-networks %v", live, nets)
	}
	x.ensure(t, live...)
	if x.ctr() == nil || x.slices(t) != `{"3":{"meta":5},"7":{"meta":5}}` {
		t.Error("the ensure did not bring the proxy back")
	}
	// Not the platform's: no role label, another role's label.
	for _, labels := range []map[string]string{{}, {labelRole: "studio"}} {
		x.f.mu.Lock()
		x.f.ctrs[dashcfg.PgcapName].Labels = labels
		x.f.mu.Unlock()
		x.f.resetLog()
		if err := x.a.RemoveProxy(ctx); err == nil || !strings.Contains(err.Error(), dashcfg.PgcapName) || len(x.f.mutations()) != 0 {
			t.Fatalf("labels %v: %v, changes %q; want it left and named", labels, err, x.f.mutations())
		}
	}
	x.f.mu.Lock()
	x.f.ctrs[dashcfg.PgcapName].Labels = map[string]string{labelRole: "pgcap"}
	x.f.mu.Unlock()
	// What cannot be read or removed is reported.
	boom := errors.New("docker: daemon busy")
	x.f.failInspect[dashcfg.PgcapName] = boom
	if err := x.a.RemoveProxy(ctx); !errors.Is(err, boom) {
		t.Errorf("a proxy that cannot be inspected: %v", err)
	}
	delete(x.f.failInspect, dashcfg.PgcapName)
	x.f.failVerb["rm"] = boom
	if err := x.a.RemoveProxy(ctx); !errors.Is(err, boom) {
		t.Errorf("a removal that fails: %v", err)
	}
	delete(x.f.failVerb, "rm")
	// On a node without a dashboard it acts all the same.
	x.a.cfg.StudioDomain = ""
	if err := x.a.RemoveProxy(ctx); err != nil || x.ctr() != nil {
		t.Errorf("on a node without a studio domain: %v, the proxy still there %v", err, x.ctr() != nil)
	}
}
