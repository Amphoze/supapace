package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/adminapi"
	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/poolcfg"
	"github.com/Amphoze/supapace/internal/store"
)

// The log reads behind the admin API's two log routes (projectLogs for
// Logs, nodeLogs for NodeLogs). A project's containers are found by their
// labels — the project's ref and the role cluster or postgrest — and read
// by id; a name a caller gives is never used. The node's containers come
// from nodeLogNames, a closed list. Each line is attributed to the container
// it was read from; the admin API strips control characters and bounds the
// answer.
//
// Bounds: a container is asked for tail+1 lines (so that a cut is known);
// dockerx keeps 4 MiB of standard output and the first 64 KiB of standard
// error, so a read over either is asked again for half the lines, down to
// one. At most two reads run at once; a read waits at most logsMax for a
// slot, and all its calls end at logsMax from the slot: a container that
// floods its log or a Docker call that hangs holds a slot for logsMax at most.

var (
	logsList    = dockerx.ListContainers
	logsInspect = dockerx.InspectContainer
	logsRun     = dockerx.RunOutput
	logsMax     = 15 * time.Second
	logSlots    = make(chan struct{}, 2)
)

// logsStderrCap is what dockerx keeps of a call's standard error.
const logsStderrCap = 64 << 10

// nodeLogNames maps the admin API's closed list to the containers' names.
var nodeLogNames = map[string]string{
	"gateway":     gatewayContainer,
	"pooler":      poolcfg.PoolerName,
	"proxy":       dashcfg.PgcapName,
	"platform-db": poolcfg.PlatformDBName,
}

// projectLogRoles maps a project's containers, as the API names them, to
// their supapace.role label.
var projectLogRoles = [][2]string{{"cluster", "cluster"}, {"rest", "postgrest"}}

var logRefRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

func projectLogs(ctx context.Context, ref, container string, tail int) (adminapi.Logs, error) {
	out := adminapi.Logs{Lines: []adminapi.LogLine{}, Notes: []string{}}
	if !logRefRE.MatchString(ref) || container != "" && container != "cluster" && container != "rest" ||
		tail < 1 || tail > adminapi.LogsMaxTail {
		return out, fmt.Errorf("project logs: ref %.32q, container %.32q, tail %d refused", ref, container, tail)
	}
	ctx, release, err := logSlot(ctx)
	if err != nil {
		return out, err
	}
	defer release()
	cs, err := logsList(ctx, "supapace.ref="+ref)
	if err != nil {
		return out, logErr(ctx, err)
	}
	for _, r := range projectLogRoles {
		if container != "" && container != r[0] {
			continue
		}
		found := false
		for _, c := range cs {
			if c.Labels["supapace.ref"] != ref || c.Labels["supapace.role"] != r[1] {
				continue
			}
			found = true
			if err := readLog(ctx, &out, c.ID, r[0], tail); err != nil {
				return out, err
			}
		}
		if !found {
			out.Notes = append(out.Notes, r[0]+": the project has no such container on this node")
		}
	}
	return out, nil
}

func nodeLogs(ctx context.Context, container string, tail int) (adminapi.Logs, error) {
	out := adminapi.Logs{Lines: []adminapi.LogLine{}, Notes: []string{}}
	name, ok := nodeLogNames[container]
	if !ok || tail < 1 || tail > adminapi.LogsMaxTail {
		return out, fmt.Errorf("node logs: container %.32q, tail %d refused", container, tail)
	}
	ctx, release, err := logSlot(ctx)
	if err != nil {
		return out, err
	}
	defer release()
	c, err := logsInspect(ctx, name)
	if err != nil {
		return out, logErr(ctx, err)
	}
	if c == nil {
		return out, fmt.Errorf("%w: the %s does not run on this node (no container %s)", store.ErrConflict, container, name)
	}
	return out, readLog(ctx, &out, c.ID, container, tail)
}

// logSlot waits at most logsMax for one of the slots, then bounds the read
// itself at logsMax from there: a timed-out read is the read's, not the queue's.
func logSlot(ctx context.Context) (context.Context, func(), error) {
	wait, stop := context.WithTimeout(ctx, logsMax)
	defer stop()
	select {
	case logSlots <- struct{}{}:
		ctx, cancel := context.WithTimeout(ctx, logsMax)
		return ctx, func() { <-logSlots; cancel() }, nil
	case <-wait.Done():
		return nil, nil, fmt.Errorf("%w: two log reads are running; try again when one has ended", store.ErrConflict)
	}
}

// logErr is a failed call: past the read's deadline, a conflict that says so.
func logErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: the log could not be read within %v; try again, or with a smaller --tail", store.ErrConflict, logsMax)
	}
	return err
}

// readLog appends the last lines of container id, attributed to container.
func readLog(ctx context.Context, out *adminapi.Logs, id, container string, tail int) error {
	n := tail + 1
	for {
		stdout, stderr, err := logsRun(ctx, "logs", "--timestamps", "--tail", strconv.Itoa(n), "--", id)
		over := errors.Is(err, dockerx.ErrOutputTooLarge) || err == nil && len(stderr) >= logsStderrCap
		if over && n > 1 {
			n /= 2
			continue
		}
		if errors.Is(err, dockerx.ErrOutputTooLarge) {
			return fmt.Errorf("%w: the newest line of the %s is too large to read", store.ErrConflict, container)
		}
		if err != nil && ctx.Err() == nil {
			// Docker's stderr here can hold the container's own text: none of it is kept.
			code := -1
			if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
				code = ee.ExitCode()
			}
			slog.Warn("logs: a container's log could not be read", "container", container, "exit_status", code)
			return fmt.Errorf("%w: the log of the %s could not be read; try again", store.ErrConflict, container)
		}
		if err != nil {
			return logErr(ctx, err)
		}
		if n < tail {
			out.Notes = append(out.Notes, fmt.Sprintf("older lines of %s not shown: one read of a container's log holds at most "+
				"4 MiB of its standard output and 64 KiB of its standard error, so only the newest %d line%s could be read of the %d asked", container, n,
				map[bool]string{true: "s"}[n > 1], tail))
		}
		skipped := 0
		for _, s := range []string{stdout, stderr} {
			for l := range strings.Lines(s) {
				// Docker writes "<RFC 3339 time> <text>"; the time is its own.
				ts, text, _ := strings.Cut(strings.TrimSuffix(l, "\n"), " ")
				t, err := time.Parse(time.RFC3339Nano, ts)
				if err != nil {
					skipped++
					continue
				}
				out.Lines = append(out.Lines, adminapi.LogLine{Container: container, At: t.UTC().Format(adminapi.LogAtLayout), Text: text})
			}
		}
		if skipped > 0 {
			out.Notes = append(out.Notes, fmt.Sprintf("%s: %d line%s without a time left out", container, skipped,
				map[bool]string{true: "s"}[skipped > 1]))
		}
		return nil
	}
}
