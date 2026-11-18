// Package dockerx drives the docker CLI by argv, never through a shell.
package dockerx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var defaultTimeout = 60 * time.Second

// Container is the subset of `docker container inspect` the daemon needs.
type Container struct {
	ID, Name, Image string
	Pid             int
	Running         bool
	RestartPolicy   string
	Labels          map[string]string
	IPs             map[string]string // network name -> address
}

// Network is the subset of `docker network inspect` the daemon needs.
type Network struct {
	Name, BridgeName, Subnet string
	Internal                 bool
	Options                  map[string]string
	Containers               []string // container names, sorted
}

// Run executes `docker args...` and returns stdout. The default timeout is
// 60 s; an earlier deadline on ctx wins. On timeout the child and its
// process group are killed. Stdout is capped at 4 MiB: a call that writes
// more is killed the same way and fails with ErrOutputTooLarge. Stderr keeps
// its first 64 KiB.
func Run(ctx context.Context, args ...string) (string, error) {
	return RunInput(ctx, nil, args...)
}

// RunInput is Run with stdin supplied to the child.
func RunInput(ctx context.Context, stdin []byte, args ...string) (string, error) {
	out, _, err := run(ctx, stdin, args)
	return out, err
}

// RunOutput is Run that also returns the start of stderr (at most 64 KiB),
// whether or not the call succeeds: `docker logs` writes a container's
// stderr there.
func RunOutput(ctx context.Context, args ...string) (stdout, stderr string, err error) {
	return run(ctx, nil, args)
}

// ErrOutputTooLarge is the cause of a call whose stdout exceeded maxStdout.
var ErrOutputTooLarge = errors.New("output too large")

// Output bounds. Stdout beyond maxStdout kills the call; stderr keeps its
// start (all that classification reads) and discards the rest.
const (
	maxStdout = 4 << 20
	maxStderr = 64 << 10
)

// capBuf is an io.Writer that never holds more than max bytes: excess is
// discarded and, once, reported through over (if set). Data is kept in chunks
// of at most 32 KiB so that growing never copies what is already held.
type capBuf struct {
	mu     sync.Mutex
	max, n int
	chunks [][]byte
	hit    bool
	over   func()
}

func (c *capBuf) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := len(p)
	if total > c.max-c.n {
		p = p[:c.max-c.n]
		if !c.hit && c.over != nil {
			c.over()
		}
		c.hit = true
	}
	for len(p) > 0 {
		last := len(c.chunks) - 1
		if last < 0 || len(c.chunks[last]) == cap(c.chunks[last]) {
			c.chunks = append(c.chunks, make([]byte, 0, min(32<<10, c.max-c.n)))
			last++
		}
		k := min(len(p), cap(c.chunks[last])-len(c.chunks[last]))
		c.chunks[last] = append(c.chunks[last], p[:k]...)
		p = p[k:]
		c.n += k
	}
	return total, nil
}

func (c *capBuf) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var sb strings.Builder
	sb.Grow(c.n)
	for _, ch := range c.chunks {
		sb.Write(ch)
	}
	return sb.String()
}

var (
	absentContainer = regexp.MustCompile(`\A(Error response from daemon: |Error: )?No such (container|object): `)
	absentNetwork   = regexp.MustCompile(`\A(Error response from daemon: |Error: )?network \S+ not found`)
)

// runError is a failed docker call. Arguments may carry secrets (-e K=V), so
// only the verb is named in the message.
type runError struct {
	verb   string
	cause  error
	stderr string // start of stderr (at most maxStderr), used for classification
}

func (e *runError) Error() string {
	s := strings.ToValidUTF8(strings.TrimSpace(e.stderr), "") // drop a rune cut at the cap
	return fmt.Sprintf("docker %s: %v: %s", e.verb, e.cause, s)
}

func (e *runError) Unwrap() error { return e.cause }

// isAbsent reports whether err is docker itself (exit status non-zero, not a
// missing binary or a cancelled context) saying the object does not exist.
func isAbsent(err error, re *regexp.Regexp) bool {
	var re2 *runError
	if !errors.As(err, &re2) {
		return false
	}
	var ee *exec.ExitError
	return errors.As(re2.cause, &ee) && re.MatchString(strings.TrimSpace(re2.stderr))
}

func run(ctx context.Context, stdin []byte, args []string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	ctx, kill := context.WithCancel(ctx) // cancelled when stdout hits its cap
	defer kill()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out := &capBuf{max: maxStdout, over: kill}
	errb := &capBuf{max: maxStderr}
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()
	if err == nil && !out.hit {
		return out.String(), errb.String(), nil
	}
	verb := ""
	if len(args) > 0 {
		verb = args[0]
	}
	switch {
	case out.hit:
		return "", errb.String(), &runError{verb: verb, cause: ErrOutputTooLarge, stderr: errb.String()}
	case ctx.Err() != nil:
		err = ctx.Err()
	}
	return out.String(), errb.String(), &runError{verb: verb, cause: err, stderr: errb.String()}
}

type rawContainer struct {
	ID    string
	Name  string
	State struct {
		Running bool
		Pid     int
	}
	Config struct {
		Image  string
		Labels map[string]string
	}
	HostConfig      struct{ RestartPolicy struct{ Name string } }
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress string }
	}
}

func (r rawContainer) typed() Container {
	c := Container{
		ID: r.ID, Name: strings.TrimPrefix(r.Name, "/"), Image: r.Config.Image,
		Pid: r.State.Pid, Running: r.State.Running, RestartPolicy: r.HostConfig.RestartPolicy.Name,
		Labels: r.Config.Labels, IPs: map[string]string{},
	}
	if c.Labels == nil {
		c.Labels = map[string]string{}
	}
	for n, v := range r.NetworkSettings.Networks {
		if v.IPAddress != "" {
			c.IPs[n] = v.IPAddress
		}
	}
	return c
}

func inspectContainers(ctx context.Context, names ...string) ([]Container, error) {
	out, err := Run(ctx, append([]string{"container", "inspect", "--"}, names...)...)
	if err != nil {
		return nil, err
	}
	var raw []rawContainer
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("docker container inspect: parse: %w", err)
	}
	cs := make([]Container, len(raw))
	for i, r := range raw {
		cs[i] = r.typed()
	}
	return cs, nil
}

// InspectContainer returns nil, nil when the container does not exist.
func InspectContainer(ctx context.Context, name string) (*Container, error) {
	cs, err := inspectContainers(ctx, name)
	if err != nil {
		if isAbsent(err, absentContainer) {
			return nil, nil
		}
		return nil, err
	}
	if len(cs) == 0 {
		return nil, nil
	}
	return &cs[0], nil
}

// InspectNetwork returns nil, nil when the network does not exist.
func InspectNetwork(ctx context.Context, name string) (*Network, error) {
	out, err := Run(ctx, "network", "inspect", "--", name)
	if err != nil {
		if isAbsent(err, absentNetwork) {
			return nil, nil
		}
		return nil, err
	}
	var raw []struct {
		Name, Driver string
		Id           string
		Internal     bool
		Options      map[string]string
		IPAM         struct{ Config []struct{ Subnet string } }
		Containers   map[string]struct{ Name string }
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("docker network inspect: parse: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	r := raw[0]
	n := &Network{Name: r.Name, Internal: r.Internal, Options: r.Options}
	if n.Options == nil {
		n.Options = map[string]string{}
	}
	if len(r.IPAM.Config) > 0 {
		n.Subnet = r.IPAM.Config[0].Subnet
	}
	n.BridgeName = n.Options["com.docker.network.bridge.name"]
	// Docker names an unconfigured bridge br-<first 12 id characters>.
	if n.BridgeName == "" && len(r.Id) >= 12 {
		n.BridgeName = "br-" + r.Id[:12]
	}
	for _, c := range r.Containers {
		n.Containers = append(n.Containers, c.Name)
	}
	sort.Strings(n.Containers)
	return n, nil
}

// ListContainers returns all containers (running or not) carrying the label
// filter, e.g. "supapace.ref=abc" or "supapace.ref".
func ListContainers(ctx context.Context, labelFilter string) ([]Container, error) {
	var err error
	// One retry: a container may vanish between ps and inspect.
	for try := 0; try < 2; try++ {
		var out string
		out, err = Run(ctx, "ps", "-a", "-q", "--no-trunc", "--filter", "label="+labelFilter)
		if err != nil {
			return nil, err
		}
		ids := strings.Fields(out)
		if len(ids) == 0 {
			return nil, nil
		}
		var cs []Container
		cs, err = inspectContainers(ctx, ids...)
		if err == nil {
			return cs, nil
		}
		if !isAbsent(err, absentContainer) {
			return nil, err
		}
	}
	return nil, err
}

// ServerVersion returns the daemon's version string.
func ServerVersion(ctx context.Context) (string, error) {
	out, err := Run(ctx, "version", "--format", "{{.Server.Version}}")
	return strings.TrimSpace(out), err
}
