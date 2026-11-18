package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/adminapi"
	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/routes"
	"github.com/Amphoze/supapace/internal/saga"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

func init() { commands["serve"] = serveCmd }

// nodeAgent is what serve needs from *agent.Agent; the tests use a fake.
type nodeAgent interface {
	SetContainmentFailed(bool)
	ContainmentFailed() bool
	EnsurePlatformNetworks(context.Context) error
	EnsureImageFiles(context.Context) error
	EnsureControlPlaneDB(context.Context) error
	EnsureGateway(context.Context) error
	NodeCheck(context.Context) []nodecfg.CheckResult
	DrainAllRoutes(context.Context) (int64, error)
	StopAllTenants(context.Context) error
	EnsureCluster(context.Context, agent.Spec) error
	EnsurePostgREST(context.Context, agent.Spec) error
	CheckCluster(context.Context, agent.Spec) ([]nodecfg.CheckResult, error)
	CheckHost(context.Context, agent.Spec) []nodecfg.CheckResult
	RouteFor(agent.Spec, string) routes.Project
	SetRoute(context.Context, string, *routes.Project) (int64, error)
}

// refStore is what boot reads from the control-plane store.
type refStore interface {
	ListProjects(context.Context) ([]store.Project, error)
	GetProject(context.Context, string) (store.Project, error)
	ListOperations(context.Context, string) ([]store.Operation, error)
	TryLockRefChecked(context.Context, string) (unlock func(), held func(context.Context) error, ok bool, err error)
}

// runner is what serve needs from *saga.Runner.
type runner interface {
	ResumeAll(context.Context) error
	Run(context.Context)
	SpecFor(context.Context, string) (agent.Spec, error)
	Submit(ctx context.Context, kind, ref string, params json.RawMessage) (int64, error)
	Abort(ctx context.Context, ref string) (int64, error)
}

// backend is the store and what is built on it.
type backend struct {
	st    refStore
	rn    runner
	api   func(adminapi.Ops) http.Handler
	close func()
}

// daemon is one run of `supapaced serve`. Its function values and timings
// are the tests' seams.
type daemon struct {
	p  nodecfg.Paths
	ag nodeAgent

	nftRender   func() ([]byte, error)
	nftLoad     func(context.Context) error
	nftCheck    func(context.Context) error
	bridgeNF    func() error
	listTenants func(context.Context) ([]string, error) // names of the running tenant containers
	containers  func(ctx context.Context, label string) ([]dockerx.Container, error)
	connect     func(context.Context) (*backend, error)
	now         func() time.Time

	slots      int           // concurrent host-side adoptions
	budget     time.Duration // one project's host-side adoption
	retryEvery time.Duration // background retry of the pending-adoption set
	healthWait time.Duration // advisory check: wait for a started cluster to answer
	checkEvery time.Duration // advisory check: interval while not ready
	verifyMax  time.Duration // `project check`
	driftEvery time.Duration
	grace      time.Duration    // for in-flight admin requests at shutdown
	holdMax    time.Duration    // a drift hold older than this is ignored
	ticks      <-chan time.Time // drift ticks; nil: a ticker of driftEvery

	be *backend // set by boot
	st refStore
	rn runner

	mu        sync.Mutex
	pending   map[string]bool // active projects not yet adopted since boot or the last containment failure
	drained   map[string]bool // adopted projects whose route a failed repair drained
	refillDue bool            // the set must be filled again; until then every project counts as pending
	gen       uint64          // refills and due marks, so an adoption never undoes a later refill
	wake      chan struct{}   // one slot: the drift timer cleared the flag
	strikes   int             // consecutive unverifiable firewall checks (drift goroutine only)
	bg        sync.WaitGroup  // advisory checks
}

func newDaemon(p nodecfg.Paths, ag nodeAgent) *daemon {
	return &daemon{p: p, ag: ag,
		nftLoad:     func(ctx context.Context) error { return nft.Load(ctx, p) },
		nftCheck:    func(ctx context.Context) error { return nft.Check(ctx, p) },
		bridgeNF:    nft.EnsureBridgeNF,
		listTenants: runningTenants,
		containers:  dockerx.ListContainers,
		now:         time.Now,
		slots:       4, budget: 180 * time.Second, retryEvery: 60 * time.Second,
		healthWait: 90 * time.Second, checkEvery: 2 * time.Second, verifyMax: 75 * time.Second,
		driftEvery: 10 * time.Second, holdMax: agent.DriftHoldMax, grace: 10 * time.Second,
		pending: map[string]bool{}, drained: map[string]bool{}, wake: make(chan struct{}, 1)}
}

// serveCmd runs the daemon until SIGTERM or SIGINT. Exit 0 after a signal,
// 1 when start-up fails (the supervisor starts it again), 2 on usage.
func serveCmd(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: supapaced serve")
		return 2
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, nil)))
	fatal := func(what string, err error) int {
		slog.Error("serve: "+what, "err", clean(err))
		return 1
	}
	if err := pgsock.CheckEnv(); err != nil {
		return fatal("environment", err)
	}
	cfg, err := nodecfg.Load(paths.NodeJSON())
	if err != nil {
		return fatal("node configuration", err)
	}
	kek, err := secrets.LoadKEK(paths.KEK())
	if err != nil {
		return fatal("key-encryption key", err)
	}
	ag := agent.New(cfg, paths)
	d := newDaemon(paths, ag)
	d.nftRender = func() ([]byte, error) { return nft.Render(cfg) }
	d.connect = func(ctx context.Context) (*backend, error) {
		st, err := openStore(ctx, paths, cfg)
		if err != nil {
			return nil, err
		}
		rn := saga.New(st, ag, kek, cfg, paths)
		return &backend{st: st, rn: rn, close: st.Close,
			api: func(o adminapi.Ops) http.Handler { return adminapi.New(st, kek, o, cfg.Domain, paths) }}, nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		stop() // a second signal ends the process during the bounded shutdown
	}()
	return d.serve(ctx)
}

// openStore opens, migrates and registers the node in the control-plane
// database, retrying while the server that EnsureControlPlaneDB started
// comes up (its first start initialises the data directory).
func openStore(ctx context.Context, p nodecfg.Paths, c nodecfg.Config) (*store.Store, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		st, err := func() (*store.Store, error) {
			octx, ocancel := context.WithTimeout(ctx, 10*time.Second)
			defer ocancel()
			st, err := store.Open(octx, filepath.Join(p.CPDir(), "sock"))
			if err != nil {
				return nil, err
			}
			if err = st.Migrate(octx); err == nil {
				err = st.EnsureNode(octx, c)
			}
			if err != nil {
				st.Close()
				return nil, err
			}
			return st, nil
		}()
		if err == nil {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("control-plane store: %w", err)
		case <-time.After(time.Second):
		}
	}
}

// serve is the start-up order, then the daemon's life until ctx ends.
func (d *daemon) serve(ctx context.Context) int {
	lock, err := claimRunDir(d.p.AdminSock())
	if err != nil {
		slog.Error("serve: refusing to start", "err", clean(err))
		return 1
	}
	defer lock.Close()
	nftOK, ok := d.boot(ctx)
	if !ok {
		if ctx.Err() != nil {
			return 0
		}
		return 1
	}
	defer d.close()

	if err := d.ag.EnsureGateway(ctx); err != nil {
		slog.Error("gateway", "err", clean(err))
	}
	if err := d.rn.ResumeAll(ctx); err != nil {
		slog.Error("serve: resuming operations", "err", clean(err))
		return 1
	}
	ln, err := listenAdmin(d.p.AdminSock())
	if err != nil {
		slog.Error("serve: admin socket", "err", clean(err))
		return 1
	}
	srv := &http.Server{Handler: d.api(ops{d}),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: d.verifyMax + 15*time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn)}
	var wg sync.WaitGroup
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	run(func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("admin socket", "err", clean(err))
		}
	})
	run(func() { d.driftLoop(wctx) })
	run(func() { d.rn.Run(wctx) })
	run(func() { d.ensureLoop(wctx) })
	slog.Info("serving", "socket", d.p.AdminSock(), "nft_ok", nftOK, "containment_failed", d.ag.ContainmentFailed())

	<-ctx.Done()
	slog.Info("stopping: tenant containers are left running")
	sctx, scancel := context.WithTimeout(context.Background(), d.grace)
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close() // handlers still running past the grace: cut them
	}
	scancel()
	cancel()
	wg.Wait()
	d.bg.Wait()
	return 0
}

// api is the admin handler; a backend without one (tests) answers 404.
func (d *daemon) api(o adminapi.Ops) http.Handler {
	if d.be.api == nil {
		return http.NotFoundHandler()
	}
	return d.be.api(o)
}

func (d *daemon) close() {
	if d.be.close != nil {
		d.be.close()
	}
}

// claimRunDir runs before anything else touches the node. It makes sure the
// directory of the admin socket is a real directory owned by this uid with
// mode 0700, takes an exclusive lock there held until the process ends
// (a second daemon refuses here, before any drain or stop), and refuses a
// socket path that holds anything but a socket.
func claimRunDir(sock string) (*os.File, error) {
	dir := filepath.Dir(sock)
	if err := checkRunDir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "serve.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another supapaced serve is running (%s is locked)", f.Name())
		}
		return nil, err
	}
	if err := checkSocketPath(sock); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// checkRunDir creates dir 0700 when absent and refuses anything but a real
// directory owned by this uid that no one else can enter.
func checkRunDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 || int(fi.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return fmt.Errorf("%s must be a directory owned by uid %d with mode 0700 (is %v)", dir, os.Geteuid(), fi.Mode())
	}
	return nil
}

// checkSocketPath refuses a path that exists and is not a socket.
func checkSocketPath(path string) error {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case fi.Mode().Type() != fs.ModeSocket:
		return fmt.Errorf("%s exists and is not a socket (%v): refusing to replace it", path, fi.Mode().Type())
	}
	return nil
}

// listenAdmin listens on the admin socket, mode 0600 in a directory only
// its owner can enter. It refuses a path that exists and is not a socket,
// and a socket another daemon still answers on; a stale socket is removed.
func listenAdmin(path string) (net.Listener, error) {
	if err := checkRunDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := checkSocketPath(path); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s: another daemon is serving on it", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// runningTenants lists the running cluster and PostgREST containers.
func runningTenants(ctx context.Context) ([]string, error) {
	var names []string
	for _, role := range []string{"cluster", "postgrest"} {
		cs, err := dockerx.ListContainers(ctx, "supapace.role="+role)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if c.Running {
				names = append(names, c.Name)
			}
		}
	}
	return names, nil
}

// clean is an error's text as it may be logged: control characters removed,
// at most 1 KiB (it can carry Docker's or a cluster's words).
func clean(err error) string { return pgsock.Sanitize(err.Error(), 1024) }
