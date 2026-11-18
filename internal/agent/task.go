package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// The task containers — the phase-A data wipe, the restart's configuration
// check and the purge of a project's tree — run the cluster image at the
// project's uid with the hardening of every container, no network and no
// restart policy, detached and named task-<ref>-<kind>. They attach to
// nothing, so they are not gated. Each is polled, and removed by name when
// it ends or when its deadline passes (stopping the CLI client would not
// stop the container).
var (
	daemonExe             = os.Executable // the tree-removal helper (`supapaced rmtree`), mounted read-only
	removeEmptyProjectDir = nodefs.RemoveEmptyProjectDir
	dockerRunOutput       = dockerx.RunOutput // docker logs: the task's stdout and stderr

	taskPoll    = time.Second
	taskTimeout = 300 * time.Second // upper bound of one task; a caller's earlier deadline wins
)

// taskOutputMax caps a task's captured output before it enters an error.
const taskOutputMax = 64 << 10

// taskOutput is what a task wrote: stdout and stderr, each sanitised and
// capped.
type taskOutput struct{ stdout, stderr string }

func (o taskOutput) String() string { return "stdout: " + o.stdout + "; stderr: " + o.stderr }

// runTask runs one task container to its end and returns its exit code and
// its output. flags are added to the common ones; cmd follows the image.
func (a *Agent) runTask(ctx context.Context, s Spec, kind string, flags []string, entrypoint string, cmd ...string) (int, taskOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()
	name := "task-" + s.Ref + "-" + kind
	kill := func() error {
		_, err := dockerRun(context.WithoutCancel(ctx), "rm", "-f", "-v", "--", name)
		return err
	}
	if _, err := dockerRun(ctx, "rm", "-f", "-v", "--", name); err != nil { // left by an earlier attempt
		return 0, taskOutput{}, err
	}
	args := []string{"run", "-d", "--name", name, "--network", "none", "--user", fmt.Sprintf("%d:%d", s.UID, s.GID),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--memory", "128m", "--memory-swap", "128m", "--pids-limit", "64", "--ulimit", "core=0", "--ulimit", "nofile=65536:65536",
		"--no-healthcheck", "--label", labelRole + "=task", "--label", "supapace.ref=" + s.Ref,
		"--label", "supapace.generation=" + strconv.FormatInt(s.Generation, 10), "--label", "supapace.epoch=" + strconv.FormatInt(s.Epoch, 10)}
	args = append(append(args, flags...), "--entrypoint", entrypoint, "--", a.cfg.Images.Postgres)
	if _, err := dockerRun(ctx, append(args, cmd...)...); err != nil {
		return 0, taskOutput{}, errors.Join(err, kill())
	}
	code, err := waitTask(ctx, name)
	if err != nil {
		return 0, taskOutput{}, errors.Join(fmt.Errorf("agent: %s: %w", name, err), kill())
	}
	out, errOut, err := dockerRunOutput(ctx, "logs", "--tail", "1000", "--", name)
	switch {
	case errors.Is(err, dockerx.ErrOutputTooLarge):
		out = "(output too large to capture)"
	case err != nil:
		out, errOut = "(output unavailable)", ""
	}
	return code, taskOutput{pgsock.Sanitize(out, taskOutputMax), pgsock.Sanitize(errOut, taskOutputMax)}, kill()
}

// waitTask polls the container until it has exited and returns its code.
func waitTask(ctx context.Context, name string) (int, error) {
	for {
		out, err := dockerRun(ctx, "inspect", "--type", "container", "--format", "{{.State.Status}} {{.State.ExitCode}}", "--", name)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			return 0, err
		}
		f := strings.Fields(out)
		if len(f) != 2 {
			return 0, fmt.Errorf("unexpected state %q", pgsock.Sanitize(out, 64))
		}
		if f[0] == "exited" || f[0] == "dead" {
			code, err := strconv.Atoi(f[1])
			if err != nil {
				return 0, fmt.Errorf("unexpected exit code %q", pgsock.Sanitize(f[1], 64))
			}
			return code, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(taskPoll):
		}
	}
}

func taskFailed(kind string, s Spec, code int, out taskOutput) error {
	return fmt.Errorf("agent: %s: %s task failed (exit %d): %s", s.Ref, kind, code, out)
}

// helperMount mounts the daemon's own executable, which carries the
// tree-removal helper, read-only into a task.
func helperMount() ([]string, error) {
	exe, err := daemonExe()
	if err != nil {
		return nil, fmt.Errorf("agent: own executable: %w", err)
	}
	return []string{"-v", exe + ":/supapaced:ro"}, nil
}

// wipeData empties the project's data directory at the project's uid (the
// directory itself, its owner and attributes stay), so that a
// half-initialised directory left by an interrupted first boot is never
// taken over. The project directory is mounted, so that data/ lies on the
// same file system as its parent (the helper refuses a mount point); without
// it nothing is launched (a mount of a missing path would create it as root).
func (a *Agent) wipeData(ctx context.Context, s Spec) error {
	if fi, err := os.Lstat(a.p.ProjectDir(s.Ref)); err != nil || !fi.IsDir() {
		return fmt.Errorf("agent: %s: project directory missing or not a directory", s.Ref)
	}
	flags, err := helperMount()
	if err != nil {
		return err
	}
	flags = append(flags, "-v", a.p.ProjectDir(s.Ref)+":/p")
	code, out, err := a.runTask(ctx, s, "wipe", flags, "/supapaced", "rmtree", "--keep-root", "/p/data")
	if err != nil {
		return err
	}
	if code != 0 {
		return taskFailed("wipe", s, code, out)
	}
	return nil
}

// Prevalidate renders the candidate include directory of s into
// <render>/candidate/conf.d (the live directory is never touched) and checks
// it with `postgres -C max_connections` in a task container: the platform's
// rendered files and the candidate mounted read-only, an empty tmpfs at the
// data path (nothing of the project's data), no pgsodium key. One -C per
// run; a non-zero exit or empty output refuses the candidate.
func (a *Agent) Prevalidate(ctx context.Context, s Spec) error {
	if err := a.clusterSpec(s); err != nil {
		return err
	}
	r := a.p.RenderDir(s.Ref)
	for _, n := range []string{"passwd", "group", "supautils.conf"} {
		if fi, err := os.Lstat(filepath.Join(r, n)); err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("agent: %s: rendered %s missing", s.Ref, n)
		}
	}
	cand := filepath.Join(r, "candidate")
	if err := ensureDir(cand, 0o755, -1, -1); err != nil {
		return err
	}
	if err := a.renderConfD(filepath.Join(cand, "conf.d"), s); err != nil {
		return err
	}
	bl, err := clusterBaseline()
	if err != nil {
		return err
	}
	cmdline, err := a.imageCommandLine()
	if err != nil {
		return err
	}
	flags := []string{"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--tmpfs", fmt.Sprintf("/var/lib/postgresql/data:rw,noexec,nosuid,size=1m,mode=0700,uid=%d,gid=%d", s.UID, s.GID),
		"-v", r + "/passwd:/etc/passwd:ro", "-v", r + "/group:/etc/group:ro",
		"-v", r + "/supautils.conf:" + bl.Files.SupautilsConf + ":ro",
		"-v", filepath.Join(cand, "conf.d") + ":" + bl.Files.IncludeDir + ":ro"}
	cmd := append(append([]string{"-D", "/etc/postgresql"}, cmdline...), "-C", "max_connections")
	code, out, err := a.runTask(ctx, s, "prevalidate", flags, "postgres", cmd...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("agent: %s: candidate configuration refused (exit %d): %s", s.Ref, code, out.stderr)
	}
	// The value is printed on stdout; a warning on stderr is not a value.
	if strings.TrimSpace(out.stdout) == "" {
		return fmt.Errorf("agent: %s: candidate configuration check printed no value: %s", s.Ref, out.stderr)
	}
	return nil
}

// PromoteCandidate replaces the live include directory with the validated
// candidate (rename; the old directory removed). The cluster is stopped
// first by the caller. Without a candidate it is a no-op, so a resumed step
// does nothing twice.
func (a *Agent) PromoteCandidate(ctx context.Context, ref string) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	r := a.p.RenderDir(ref)
	cand := filepath.Join(r, "candidate", "conf.d")
	fi, err := os.Lstat(cand)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("agent: %s is not a directory", cand)
	}
	if err := os.RemoveAll(filepath.Join(r, "conf.d")); err != nil {
		return err
	}
	if err := os.Rename(cand, filepath.Join(r, "conf.d")); err != nil {
		return err
	}
	return os.Remove(filepath.Join(r, "candidate"))
}

// PurgeDir removes the project's tree: data/ and sock/ at the project's uid
// by the tree-removal helper in a task container, then root's one call, a
// non-recursive removal of the emptied project directory. The uid's quota
// limits are cleared first: at a full block quota the helper could not move
// entries and would fail on every retry. It refuses while pg-<ref> or
// postgrest-<ref> exists in any state, so nothing can use the lifted limit.
// An absent directory launches nothing (a mount of a missing path would
// create it as root).
func (a *Agent) PurgeDir(ctx context.Context, s Spec) error {
	if err := checkRef(s.Ref); err != nil {
		return err
	}
	// The quota is lifted on the promise that the project's containers are
	// gone: check it.
	for _, name := range []string{clusterName(s.Ref), postgrestName(s.Ref)} {
		c, err := dockerInspectContainer(ctx, name)
		if err != nil {
			return err
		}
		if c != nil {
			return fmt.Errorf("agent: %s: %s still exists; refusing to purge", s.Ref, name)
		}
	}
	pd := a.p.ProjectDir(s.Ref)
	fi, err := os.Lstat(pd)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return setQuota(a.p, s.UID, 0)
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("agent: %s is not a directory", pd)
	case s.UID <= 0 || s.GID <= 0:
		return fmt.Errorf("agent: %s: spec lacks the project's ids", s.Ref)
	}
	flags, err := helperMount()
	if err != nil {
		return err
	}
	if err := setQuota(a.p, s.UID, 0); err != nil {
		return err
	}
	flags = append(flags, "-v", pd+":/p")
	code, out, err := a.runTask(ctx, s, "purge", flags, "/supapaced", "rmtree", "/p/data", "/p/sock")
	if err != nil {
		return err
	}
	if code != 0 {
		return taskFailed("purge", s, code, out)
	}
	return removeEmptyProjectDir(a.p, s.Ref)
}
