package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/pgsock"
)

// Logs by container. A project's answer holds lines of that project's own
// containers only (cluster, rest), which the daemon selects by their labels;
// the node's names one shared container from a closed list. A shared
// container's lines are never under a project, whatever they say. Each line
// carries the container it came from, set by the daemon from where it read
// it, never from the text; the text loses every control character (a TAB
// becomes a space), so no text can start a line of its own or move the
// cursor. The answer is
// bounded here, whatever the daemon read: the newest tail lines, at most
// LogsMaxBytes of text, no line over LogLineMax; every cut is a note.

const (
	logsDefaultTail = 100
	LogsMaxTail     = 1000
	LogsMaxBytes    = 1 << 20  // the text of one answer
	LogLineMax      = 16 << 10 // one line's text (Docker's own split of a long line)
	logsMaxNotes    = 16
	// LogAtLayout is the time of a line: UTC, nanoseconds, fixed width, so
	// that the order of the strings is the order of the times.
	LogAtLayout = "2006-01-02T15:04:05.000000000Z"
)

var (
	// ProjectLogContainers are a project's containers as the route names them.
	ProjectLogContainers = []string{"cluster", "rest"}
	// NodeLogContainers is the closed list of the node's shared containers.
	NodeLogContainers = []string{"gateway", "pooler", "proxy", "platform-db"}
)

// LogLine is one line of a container's log.
type LogLine struct {
	Container string `json:"container"`
	At        string `json:"at"`
	Text      string `json:"text"`
}

// Logs is the answer of both routes, and what the daemon's capabilities
// return: lines, and notes saying what is not shown and why.
type Logs struct {
	Lines []LogLine `json:"lines"`
	Notes []string  `json:"notes"`
}

// The daemon's capabilities, asserted at use. Logs reads the project's
// containers by label (container "" for both); NodeLogs one container of
// NodeLogContainers. Each returns at most tail+1 lines a container, so that
// a cut is known.
type (
	projectLogger interface {
		Logs(ctx context.Context, ref, container string, tail int) (Logs, error)
	}
	nodeLogger interface {
		NodeLogs(ctx context.Context, container string, tail int) (Logs, error)
	}
)

const logsNotHere = "logs are not available on this node: this daemon cannot read containers' logs yet"

func (a *api) projectLogs(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	container, tail, err := logsQuery(r, ProjectLogContainers, false)
	if err != nil {
		return nil, err
	}
	if _, err := a.st.GetProject(r.Context(), ref); err != nil {
		return nil, err
	}
	l, ok := a.ops.(projectLogger)
	if !ok {
		return nil, conflict(logsNotHere)
	}
	got, err := l.Logs(r.Context(), ref, container, tail)
	if err != nil {
		return nil, err
	}
	served := ProjectLogContainers
	if container != "" {
		served = []string{container}
	}
	return boundLogs(got, served, tail)
}

func (a *api) nodeLogs(r *http.Request) (any, error) {
	container, tail, err := logsQuery(r, NodeLogContainers, true)
	if err != nil {
		return nil, err
	}
	l, ok := a.ops.(nodeLogger)
	if !ok {
		return nil, conflict(logsNotHere)
	}
	got, err := l.NodeLogs(r.Context(), container, tail)
	if err != nil {
		return nil, err
	}
	return boundLogs(got, []string{container}, tail)
}

// logsQuery reads ?container= (one of names; required when need) and
// ?tail= (1 to LogsMaxTail, default logsDefaultTail), and nothing else.
func logsQuery(r *http.Request, names []string, need bool) (string, int, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", 0, badRequest("query: %v", err)
	}
	container, tail := "", logsDefaultTail
	for k, v := range q {
		if len(v) != 1 || k != "container" && k != "tail" {
			return "", 0, badRequest("the query parameters are one container and one tail")
		}
		if k == "tail" {
			if tail, err = strconv.Atoi(v[0]); err != nil || tail < 1 || tail > LogsMaxTail {
				return "", 0, badRequest("tail must be 1 to %d", LogsMaxTail)
			}
		} else if container = v[0]; !slices.Contains(names, container) {
			return "", 0, badRequest("container must be one of %s", strings.Join(names, ", "))
		}
	}
	if need && container == "" {
		return "", 0, badRequest("container is required: one of %s", strings.Join(names, ", "))
	}
	return container, tail, nil
}

// boundLogs checks and bounds what the daemon read. A line of a container
// the route does not serve, or with a time not in LogAtLayout, fails the
// answer (the daemon's fault; its text is neither shown nor logged).
func boundLogs(got Logs, served []string, tail int) (Logs, error) {
	lines := slices.Clone(got.Lines)
	for _, l := range lines {
		if !slices.Contains(served, l.Container) {
			return Logs{}, fmt.Errorf("a log line of container %.32q in an answer for %s", l.Container, strings.Join(served, ", "))
		}
		if _, err := time.Parse(LogAtLayout, l.At); err != nil {
			return Logs{}, fmt.Errorf("a log line of %s without a time in the answer's layout", l.Container)
		}
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].At < lines[j].At })
	out := Logs{Lines: []LogLine{}, Notes: []string{}}
	for _, n := range got.Notes[:min(len(got.Notes), logsMaxNotes)] {
		out.Notes = append(out.Notes, clean(n, maxMessage, "a note without text"))
	}
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
		out.Notes = append(out.Notes, fmt.Sprintf("older lines not shown: the answer holds the newest %d lines "+
			"(--tail, at most %d)", tail, LogsMaxTail))
	}
	// Newest first, so that the byte bound keeps the newest.
	start, total, long := len(lines), 0, 0
	for i := len(lines) - 1; i >= 0; i-- {
		t := strings.ReplaceAll(lines[i].Text, "\t", " ") // a TAB keeps words apart
		t, cut := pgsock.Sanitize(t, len(t)), false
		if len(t) > LogLineMax {
			t, cut = pgsock.Sanitize(t, LogLineMax), true
		}
		if total+len(t) > LogsMaxBytes {
			out.Notes = append(out.Notes, fmt.Sprintf("older lines not shown: the answer holds at most %d MiB of text", LogsMaxBytes>>20))
			break
		}
		if cut {
			long++
		}
		total += len(t)
		lines[i].Text, start = t, i
	}
	if long > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("%d line%s longer than %d bytes shortened to that length",
			long, map[bool]string{true: "s"}[long > 1], LogLineMax))
	}
	out.Lines = append(out.Lines, lines[start:]...)
	return out, nil
}
