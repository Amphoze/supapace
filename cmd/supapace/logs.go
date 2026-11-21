package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/poolcfg"
)

// project logs and node logs. stdout is the answer, as for every command;
// stderr lists its lines, oldest first, one terminal line each: the
// container the daemon read it from, its time, " | " and its text, cleaned
// of control characters again here, so that no text starts a line of its
// own. Then what was not shown and why.

// nodeContainer names the node's containers for the hint of a daemon that
// cannot serve logs yet.
// logsRefRE is a ref's form.
var logsRefRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

var nodeContainer = map[string]string{"gateway": "sp-gateway", "pooler": poolcfg.PoolerName, "proxy": dashcfg.PgcapName,
	"platform-db": poolcfg.PlatformDBName}

// logsCall registers the flags of a log command on fs and returns the
// function that builds its call; nil for any other command.
func logsCall(verb string, fs *flag.FlagSet) func(pos []string, project string) (call, error) {
	if verb != "project logs" && verb != "node logs" {
		return nil
	}
	var container string
	var tail *int
	fs.Func("container", "", func(s string) error {
		if s == "" {
			return errors.New("empty container")
		}
		container = s
		return nil
	})
	fs.Func("tail", "", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil {
			return errors.New("want an integer")
		}
		tail = &n
		return nil
	})
	return func(pos []string, project string) (call, error) {
		q := url.Values{}
		if container != "" {
			q.Set("container", container)
		}
		shown := 100
		if tail != nil {
			q.Set("tail", strconv.Itoa(*tail))
			shown = *tail
		}
		path := project + "/logs"
		var targets []string
		if verb == "node logs" {
			if container == "" {
				return call{}, usagef("node logs: --container is required")
			}
			path, targets = "/v1/node/logs", []string{nodeContainer[container]}
		} else {
			ref := "REF" // the hint names a ref only in its valid form
			if logsRefRE.MatchString(pos[0]) {
				ref = pos[0]
			}
			targets = map[string][]string{"": {"pg-" + ref, "postgrest-" + ref}, "cluster": {"pg-" + ref},
				"rest": {"postgrest-" + ref}}[container]
		}
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		return call{method: "GET", path: path, notes: logsNotes(targets, shown)}, nil
	}
}

// logsNotes lists the answer on stderr. targets are the containers to read
// on the node while the daemon cannot serve logs.
func logsNotes(targets []string, tail int) func(io.Writer, int, []byte) int {
	return func(w io.Writer, status int, body []byte) int {
		if status != http.StatusOK {
			var e struct{ Message string }
			json.Unmarshal(body, &e)
			if e.Message != "" {
				say(w, "%s", e.Message)
			}
			if status == http.StatusConflict && strings.HasPrefix(e.Message, "logs are not available on this node") {
				var cmds []string
				for _, n := range targets {
					cmds = append(cmds, fmt.Sprintf("'docker logs --timestamps --tail %d %s 2>&1 | cat -v'", tail, n))
				}
				say(w, "this node's daemon does not serve logs yet (a later supapaced does); meanwhile, on the node: %s "+
					"(2>&1 | cat -v shows the control characters a container wrote, on either stream, "+
					"instead of passing them to the terminal)", strings.Join(cmds, " and "))
			}
			return 1
		}
		var l struct {
			Lines []struct{ Container, At, Text string }
			Notes []string
		}
		if err := json.Unmarshal(body, &l); err != nil {
			say(w, "the answer could not be read: %v", err)
			return 1
		}
		width := 0
		for _, x := range l.Lines {
			width = max(width, len(pgsock.Sanitize(x.Container, 32)))
		}
		for _, x := range l.Lines {
			fmt.Fprintf(w, "%-*s %s | %s\n", width, pgsock.Sanitize(x.Container, 32), pgsock.Sanitize(x.At, 40),
				pgsock.Sanitize(x.Text, len(x.Text)))
		}
		if len(l.Lines) == 0 {
			say(w, "no lines")
		}
		for _, n := range l.Notes {
			say(w, "%s", n)
		}
		return 0
	}
}
