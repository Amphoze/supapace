// Package agent is the part of the node daemon that owns Docker objects and
// host-side state for projects: the project network and directories, the
// platform's own containers and networks, the start gate that every tenant
// container start passes, and the node check.
//
// Containment is decided from host-side facts only: container configuration
// as Docker recorded it, network membership, interfaces and the firewall
// state. Nothing a project's database server says reaches the gate or the
// containment flag; the database server of a project is untrusted.
package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
)

// Seams: every call this package makes to Docker, ip, nft and the root-side
// filesystem helpers goes through one of these, so tests replace them.
var (
	dockerRun              = dockerx.Run
	dockerRunInput         = dockerx.RunInput
	dockerInspectContainer = dockerx.InspectContainer
	dockerInspectNetwork   = dockerx.InspectNetwork
	dockerListContainers   = dockerx.ListContainers
	dockerServerVersion    = dockerx.ServerVersion

	nftCheck       = nft.Check
	ensureBridgeNF = nft.EnsureBridgeNF
	runIP          = ipCommand

	createProjectDir = nodefs.CreateProjectDir
	setQuota         = nodefs.SetQuota
	writeFile        = nodefs.WriteFile
	chown            = os.Lchown
)

var (
	// ErrStaleGeneration: the desired generation is older than the one applied in the same epoch.
	ErrStaleGeneration = errors.New("agent: generation older than the one applied")
	// ErrEpochDivergence: state.json records another epoch than the desired one.
	ErrEpochDivergence = errors.New("agent: applied state belongs to another epoch")
	// ErrContainment: the start gate (or an object's options) could not show containment.
	ErrContainment = errors.New("agent: containment not verified")
)

// Spec is a project's desired state as the agent applies it.
type Spec struct {
	Ref                      string
	Epoch, Generation        int64
	UID, GID, SubnetIndex    int
	DiskQuotaMB, MemMB, Pids int
	GUC                      map[string]string
	UserRoles                []string
	Secrets                  bootstrap.Secrets
	Keys                     []jwtx.Key
	// HealthWait bounds the wait for a SCRAM login after a networked start or
	// an adoption: zero means 120 s, negative means no wait — except the first
	// networked start, which always waits (120 s when zero or negative).
	HealthWait time.Duration
	// FirstBoot is set only by a create. Without it a project that has no
	// state file is refused instead of being given a first boot, which
	// empties its data directory.
	FirstBoot bool
}

// String and GoString keep the secrets out of every fmt verb and log line.
func (s Spec) String() string {
	return fmt.Sprintf("agent.Spec{Ref:%s Epoch:%d Generation:%d SubnetIndex:%d}", s.Ref, s.Epoch, s.Generation, s.SubnetIndex)
}

func (s Spec) GoString() string { return s.String() }

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

func checkRef(ref string) error {
	if !refRE.MatchString(ref) {
		return fmt.Errorf("agent: invalid ref %q", ref)
	}
	return nil
}

// valid checks the parts of s that name host objects.
func (s Spec) valid(c nodecfg.Config) error {
	if err := checkRef(s.Ref); err != nil {
		return err
	}
	if s.SubnetIndex < 0 || s.SubnetIndex >= c.Slices() {
		return fmt.Errorf("agent: subnet index %d out of range", s.SubnetIndex)
	}
	return nil
}

// Agent applies desired state on one node.
type Agent struct {
	cfg    nodecfg.Config
	p      nodecfg.Paths
	failed atomic.Bool
}

func New(c nodecfg.Config, p nodecfg.Paths) *Agent { return &Agent{cfg: c, p: p} }

// SetContainmentFailed is called by boot and the drift timer, from host-side
// facts only (nft.Check, NodeCheck). While set, the gate refuses.
func (a *Agent) SetContainmentFailed(failed bool) { a.failed.Store(failed) }

func (a *Agent) ContainmentFailed() bool { return a.failed.Load() }

// Object names and labels.
const (
	platformNet = "platform"
	ingressNet  = "ingress"
	gatewayName = "sp-gateway"
	cpName      = "sp-cp-db"

	labelRole = "supapace.role"

	optBridgeName  = "com.docker.network.bridge.name"
	optGatewayMode = "com.docker.network.bridge.gateway_mode_ipv4"
)

func networkName(ref string) string   { return "proj-" + ref }
func clusterName(ref string) string   { return "pg-" + ref }
func postgrestName(ref string) string { return "postgrest-" + ref }

// host is a host path below the test root ("" in production).
func (a *Agent) host(path string) string { return filepath.Join(a.p.Root, path) }

// seccompFile is the profile every container the daemon starts is given.
func (a *Agent) seccompFile() string { return filepath.Join(a.p.PlatformDir(), "seccomp.json") }

// Output bounds of one ip call. A detailed link listing of a full node (about
// four interfaces per project) stays far below the stdout bound; stderr keeps
// its start.
const (
	ipMaxStdout = 16 << 20
	ipMaxStderr = 64 << 10
)

// capped keeps the first max bytes written to it and calls over, once, when
// more arrive; it never fails a write, so the child is not blocked.
type capped struct {
	buf  bytes.Buffer
	max  int
	full bool
	over func()
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.buf.Write(p[:room])
		if !c.full && c.over != nil {
			c.over()
		}
		c.full = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

// ipCommand runs `ip args…` (no shell) with a 10 s bound and returns stdout.
// A call that prints more than ipMaxStdout is killed and refused.
func ipCommand(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", args...)
	cmd.WaitDelay = time.Second
	stdout := &capped{max: ipMaxStdout, over: cancel}
	stderr := &capped{max: ipMaxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if stdout.full {
		return nil, fmt.Errorf("ip %s: output larger than %d bytes", strings.Join(args, " "), ipMaxStdout)
	}
	if err != nil {
		return nil, fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.buf.String()))
	}
	return stdout.buf.Bytes(), nil
}

// StopAllTenants' bounds: the clusters' grace period (as in StopCluster),
// each kill, and the whole call.
const (
	clusterStopGrace = 45
	killMax          = 10 * time.Second
	stopAllMax       = 60 * time.Second
)

// StopAllTenants first disconnects every running cluster and PostgREST
// container from all its networks, every call in parallel and none waiting on
// a tenant. Only when every disconnect has returned are the containers
// stopped, in parallel: a cluster with its grace period (Docker kills it at
// the end of it), so it shuts down cleanly and needs no crash recovery at its
// next start; a PostgREST container is killed (it holds no state and, as pid
// 1, ignores the stop signal); a container whose disconnect failed is killed
// too. Each kill has its own short bound, so a kill still runs when the
// disconnect failed on the call's bound. The whole call takes at most
// stopAllMax plus killMax. The stopped containers are left for the next
// ensure. Used on containment failure only.
func (a *Agent) StopAllTenants(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, stopAllMax)
	defer cancel()
	var running []dockerx.Container
	for _, role := range []string{"cluster", "postgrest"} {
		cs, err := dockerListContainers(ctx, labelRole+"="+role)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if c.Running {
				running = append(running, c)
			}
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	failed := map[string]bool{} // containers whose disconnect failed
	call := func(c string, args ...string) {
		defer wg.Done()
		cctx := ctx
		if args[0] == "kill" {
			var kcancel context.CancelFunc
			cctx, kcancel = context.WithTimeout(context.WithoutCancel(ctx), killMax)
			defer kcancel()
		}
		if _, err := dockerRun(cctx, args...); err != nil {
			mu.Lock()
			errs = append(errs, err)
			if args[0] == "network" {
				failed[c] = true
			}
			mu.Unlock()
		}
	}
	for _, c := range running {
		for n := range c.IPs {
			wg.Add(1)
			go call(c.Name, "network", "disconnect", "-f", "--", n, c.Name)
		}
	}
	wg.Wait()
	for _, c := range running {
		args := []string{"kill", "--", c.Name}
		if c.Labels[labelRole] == "cluster" && !failed[c.Name] { // no goroutine writes failed any more
			args = []string{"stop", "-t", strconv.Itoa(clusterStopGrace), "--", c.Name}
		}
		wg.Add(1)
		go call(c.Name, args...)
	}
	wg.Wait()
	return errors.Join(errs...)
}
