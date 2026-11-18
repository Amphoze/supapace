// Command supapace is the operator's client for the node's admin API, which
// the daemon serves on its root-only Unix socket. It parses arguments, makes
// the HTTP call and, for a mutation, polls the operation every 500 ms until it
// ends (unless --no-wait). Nothing else.
//
// stdout holds exactly one JSON document: the body of the last API response
// received, byte for byte (an explicit help request prints the usage there
// instead). Progress and errors go to stderr. Exit status: 0 success; 1 an
// API error, an operation that ended failed or aborted (for `project abort`,
// aborted is the success), a check with "ok": false, or an unreachable
// daemon; 2 usage; 130 interrupted while waiting.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
)

func usageText() string {
	return `usage: supapace <command> [arguments]

Talks to the node daemon's admin API on ` + nodecfg.Paths{}.AdminSock() + ` (run as root).
stdout holds exactly one JSON document, the body of the last API response;
progress and errors go to stderr. Flags may come before or after REF or ID.

Projects:
  project create --name NAME --issuer-jwks FILE [--ref REF]
                 [--user-role ROLE]... [--disk-quota SIZE] [--no-wait]
      --name NAME          1 to 64 letters, digits, spaces, '.', '_' or '-',
                           starting with a letter or digit
      --issuer-jwks FILE   the issuer's public JSON Web Key Set: 1 to 16 RSA
                           signing keys (RS256, 2048 to 4096 bits), each
                           with a kid
      --ref REF            20 characters of a-z and 0-9; generated when omitted;
                           a ref is never reused
      --user-role ROLE     a role the issuer's tokens may claim (repeatable;
                           default authenticated)
      --disk-quota SIZE    MiB, or a number with suffix m, g or t
                           (default 8g, at least 1g, at most 16t)
  project list
  project show REF
  project keys REF         its anon key, service_role key and postgres password
  project check REF        check the project's database server and report
  project restart REF [--set KEY=VALUE]... [--no-wait]
      --set KEY=VALUE      disk_quota_mb=MIB or one of these (repeatable):
` + wrap(strings.Join(pgconf.GUCAllowList, ", "), 27, 80) + `
  project delete REF [--no-wait]
  project purge REF [--no-wait]    purge a deleted project now
  project abort REF [--no-wait]    abort a create that has not completed

Operations:
  op list [REF]
  op show ID
  op retry ID [--no-wait]          put a failed operation back in the queue

Node:
  node check

  --no-wait          print the mutation's answer at once instead of waiting
                     for its operation to end
  help, -h, --help   print this text

Exit status:
  0    success
  1    an API error; an operation that ended failed or aborted (for project
       abort, aborted is the success); a check with "ok": false; the daemon
       could not be reached
  2    usage, or an argument that cannot be read
  130  interrupted while waiting (the operation continues on the node)
`
}

// wrap breaks s at spaces into lines of at most width bytes, each indented.
func wrap(s string, indent, width int) string {
	pad := strings.Repeat(" ", indent)
	var lines []string
	line := pad
	for _, w := range strings.Fields(s) {
		if len(line) > indent && len(line)+1+len(w) > width {
			lines, line = append(lines, line), pad
		}
		if len(line) > indent {
			line += " "
		}
		line += w
	}
	return strings.Join(append(lines, line), "\n")
}

const (
	maxFile        = 1 << 20  // an issuer key set file
	maxResponse    = 16 << 20 // a response body
	requestTimeout = 5 * time.Minute
)

type client struct {
	sock   string
	poll   time.Duration // between operation polls
	outage time.Duration // how long polling tolerates an unreachable daemon (it restarts by itself)
	polled func()        // tests only: runs after each poll answer, before it is looked at
}

func defaultClient() client {
	return client{sock: nodecfg.Paths{}.AdminSock(), poll: 500 * time.Millisecond, outage: 2 * time.Minute}
}

func main() {
	os.Exit(run(os.Args[1:], defaultClient(), os.Stdout, os.Stderr))
}

// call is one parsed command.
type call struct {
	method, path string
	body         any    // nil: no body
	wait         string // final operation state that is success; "" = do not poll
	check        bool   // the body's "ok" decides the exit status
	ref          string // the project the command is about, when known
}

// usageError is a malformed command line: printed with the usage text.
type usageError struct{ error }

func usagef(format string, args ...any) error { return usageError{fmt.Errorf(format, args...)} }

var errHelp = errors.New("help requested")

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

var quotaRE = regexp.MustCompile(`^([0-9]{1,9})([mMgGtT]?)$`)

// parseQuota reads a size with an optional m, g or t suffix as MiB.
func parseQuota(s string) (int, error) {
	m := quotaRE.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("want a number with an optional m, g or t suffix")
	}
	n, _ := strconv.Atoi(m[1])
	shift := map[string]int{"": 0, "m": 0, "g": 10, "t": 20}[strings.ToLower(m[2])]
	return n << shift, nil
}

func readJWKS(path string) (json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	switch {
	case err != nil:
		return nil, err
	case len(b) > maxFile:
		return nil, fmt.Errorf("%s: over %d bytes", path, maxFile)
	case !json.Valid(b):
		return nil, fmt.Errorf("%s: not a JSON document", path)
	}
	return b, nil
}

// arity is the number of positional arguments of each command: min, max.
var arity = map[string][2]int{
	"project create": {0, 0}, "project list": {0, 0}, "project show": {1, 1}, "project keys": {1, 1},
	"project check": {1, 1}, "project restart": {1, 1}, "project delete": {1, 1}, "project purge": {1, 1},
	"project abort": {1, 1}, "op list": {0, 1}, "op show": {1, 1}, "op retry": {1, 1}, "node check": {0, 0},
}

func isHelp(s string) bool { return s == "help" || s == "-h" || s == "-help" || s == "--help" }

func parse(args []string) (c call, err error) {
	if len(args) > 0 && isHelp(args[0]) {
		return call{}, errHelp
	}
	if len(args) > 1 && isHelp(args[1]) && (args[0] == "project" || args[0] == "op" || args[0] == "node") {
		return call{}, errHelp
	}
	if len(args) < 2 {
		return call{}, usagef("missing command")
	}
	verb, rest := args[0]+" "+args[1], args[2:]
	ar, known := arity[verb]
	if !known {
		return call{}, usagef("unknown command %q", verb)
	}
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var noWait bool
	switch verb {
	case "project create", "project restart", "project delete", "project purge", "project abort", "op retry":
		fs.BoolVar(&noWait, "no-wait", false, "")
	}
	var name, jwks, ref string
	var quota *int
	var roles, sets list
	switch verb {
	case "project create":
		fs.StringVar(&name, "name", "", "")
		fs.StringVar(&jwks, "issuer-jwks", "", "")
		fs.Func("ref", "", func(s string) error {
			if s == "" {
				return errors.New("empty ref")
			}
			ref = s
			return nil
		})
		fs.Var(&roles, "user-role", "")
		fs.Func("disk-quota", "", func(s string) error {
			mb, err := parseQuota(s)
			quota = &mb
			return err
		})
	case "project restart":
		fs.Var(&sets, "set", "")
	}
	// Flags may come before, between and after positional arguments; "--"
	// ends them.
	var pos []string
	for {
		if err := fs.Parse(rest); errors.Is(err, flag.ErrHelp) {
			return call{}, errHelp
		} else if err != nil {
			return call{}, usagef("%s: %v", verb, err)
		}
		if fs.NArg() == 0 {
			break
		}
		if used := len(rest) - fs.NArg(); used > 0 && rest[used-1] == "--" {
			pos = append(pos, fs.Args()...)
			break
		}
		pos, rest = append(pos, fs.Arg(0)), fs.Args()[1:]
	}
	for _, p := range pos {
		if p == "" {
			return call{}, usagef("%s: empty argument", verb)
		}
	}
	if len(pos) < ar[0] || len(pos) > ar[1] {
		return call{}, usagef("%s: wrong number of arguments", verb)
	}
	defer func() {
		switch {
		case verb == "project create":
			c.ref = ref
		case strings.HasPrefix(verb, "project ") && len(pos) > 0:
			c.ref = pos[0]
		}
	}()
	wait := func(state string) string {
		if noWait {
			return ""
		}
		return state
	}
	var arg string
	if len(pos) > 0 {
		arg = url.PathEscape(pos[0])
	}
	project := "/v1/projects/" + arg

	switch verb {
	case "project create":
		if name == "" || jwks == "" {
			return call{}, usagef("project create: --name and --issuer-jwks are required")
		}
		set, err := readJWKS(jwks)
		if err != nil {
			return call{}, err
		}
		body := struct {
			Name        string          `json:"name"`
			Ref         string          `json:"ref,omitempty"`
			IssuerJWKS  json.RawMessage `json:"issuer_jwks"`
			UserRoles   []string        `json:"user_roles,omitempty"`
			DiskQuotaMB *int            `json:"disk_quota_mb,omitempty"`
		}{Name: name, Ref: ref, IssuerJWKS: set, UserRoles: roles, DiskQuotaMB: quota}
		return call{method: "POST", path: "/v1/projects", body: body, wait: wait("done")}, nil
	case "project list":
		return call{method: "GET", path: "/v1/projects"}, nil
	case "project show":
		return call{method: "GET", path: project}, nil
	case "project keys":
		return call{method: "GET", path: project + "/keys"}, nil
	case "project check":
		return call{method: "POST", path: project + "/check", check: true}, nil
	case "project restart":
		body := struct {
			Set         map[string]string `json:"set,omitempty"`
			DiskQuotaMB *int              `json:"disk_quota_mb,omitempty"`
		}{}
		for _, s := range sets {
			k, v, ok := strings.Cut(s, "=")
			if !ok || k == "" {
				return call{}, usagef("--set %q: want key=value", s)
			}
			if _, dup := body.Set[k]; dup || k == "disk_quota_mb" && body.DiskQuotaMB != nil {
				return call{}, usagef("--set %s given twice", k)
			}
			if k == "disk_quota_mb" {
				n, err := strconv.Atoi(v)
				if err != nil {
					return call{}, usagef("--set disk_quota_mb=%q: want an integer (MiB)", v)
				}
				body.DiskQuotaMB = &n
				continue
			}
			if body.Set == nil {
				body.Set = map[string]string{}
			}
			body.Set[k] = v
		}
		return call{method: "POST", path: project + "/restart", body: body, wait: wait("done")}, nil
	case "project delete":
		return call{method: "DELETE", path: project, wait: wait("done")}, nil
	case "project purge":
		return call{method: "POST", path: project + "/purge", wait: wait("done")}, nil
	case "project abort":
		return call{method: "POST", path: project + "/abort", wait: wait("aborted")}, nil
	case "op list":
		if len(pos) == 0 {
			return call{method: "GET", path: "/v1/operations"}, nil
		}
		return call{method: "GET", path: "/v1/operations?" + url.Values{"ref": {pos[0]}}.Encode()}, nil
	case "op show":
		return call{method: "GET", path: "/v1/operations/" + arg}, nil
	case "op retry":
		return call{method: "POST", path: "/v1/operations/" + arg + "/retry", wait: wait("done")}, nil
	}
	return call{method: "GET", path: "/v1/node/check", check: true}, nil // node check
}

// operation is what the CLI reads from an operation object.
type operation struct {
	ID        int64  `json:"id"`
	Ref       string `json:"ref"`
	Kind      string `json:"kind"`
	State     string `json:"state"`
	Step      string `json:"step"`
	LastError string `json:"last_error"`
}

// after names the last completed step.
func after(step string) string {
	if step == "" {
		return "starting"
	}
	return "after step " + step
}

func run(args []string, c client, stdout, stderr io.Writer) int {
	cl, err := parse(args)
	var ue usageError
	switch {
	case errors.Is(err, errHelp):
		io.WriteString(stdout, usageText())
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "supapace: %v\n\n%s", err, usageText())
		return 2
	case err != nil:
		fmt.Fprintf(stderr, "supapace: %v\n", err)
		return 2
	}
	hc := &http.Client{Timeout: requestTimeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.sock)
		},
	}}
	// A mutation catches SIGINT and SIGTERM from its first request on: the
	// operator must learn what may already have happened.
	ctx := context.Background()
	if cl.method != "GET" && !cl.check {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	status, body, err := do(ctx, hc, cl.method, cl.path, cl.body)
	if err != nil && ctx.Err() != nil {
		look := "supapace op list"
		if cl.ref != "" {
			look += " " + cl.ref
		}
		fmt.Fprintf(stderr, "supapace: interrupted before the answer; the request may already have been accepted; look with '%s'\n", look)
		return 130
	}
	if err != nil {
		fmt.Fprintf(stderr, "supapace: %v\n", reach(c.sock, err))
		return 1
	}
	if status != http.StatusAccepted || cl.wait == "" {
		stdout.Write(body)
		if status/100 != 2 {
			return 1
		}
		if cl.check {
			var r struct{ OK bool }
			if json.Unmarshal(body, &r) != nil || !r.OK {
				return 1
			}
		}
		return 0
	}

	var m struct {
		OperationID int64 `json:"operation_id"`
	}
	if json.Unmarshal(body, &m) != nil || m.OperationID <= 0 {
		stdout.Write(body)
		fmt.Fprintln(stderr, "supapace: the response names no operation")
		return 1
	}
	id := m.OperationID
	follow := fmt.Sprintf("operation %d continues on the node; follow it with 'supapace op show %d'", id, id)
	path := "/v1/operations/" + strconv.FormatInt(id, 10)
	var seen, lastErr string
	var down time.Time // start of the current outage
	for {
		select {
		case <-ctx.Done():
			return interrupted(stdout, stderr, body, follow)
		case <-time.After(c.poll):
		}
		status, b, err := do(ctx, hc, "GET", path, nil)
		if c.polled != nil {
			c.polled()
		}
		if err != nil {
			if ctx.Err() != nil {
				return interrupted(stdout, stderr, body, follow)
			}
			if down.IsZero() {
				down = time.Now()
				fmt.Fprintf(stderr, "supapace: %v; still waiting\n", reach(c.sock, err))
			}
			if time.Since(down) > c.outage {
				stdout.Write(body)
				fmt.Fprintf(stderr, "supapace: daemon unreachable for %v; %s\n", c.outage, follow)
				return 1
			}
			continue
		}
		// The newest body first: an interrupt from here on prints it, and a
		// final one ends by its own rules.
		down, body = time.Time{}, b
		var op operation
		if status != http.StatusOK || json.Unmarshal(b, &op) != nil {
			stdout.Write(b)
			return 1
		}
		switch op.State {
		case "done", "failed", "aborted":
			stdout.Write(b)
			if op.State == cl.wait {
				return 0
			}
			summary(stderr, op)
			return 1
		}
		if s := op.State + " " + op.Step; s != seen {
			seen = s
			fmt.Fprintf(stderr, "operation %d: %s, %s\n", id, op.State, after(op.Step))
		}
		if op.LastError != lastErr {
			lastErr = op.LastError
			if lastErr != "" {
				fmt.Fprintf(stderr, "operation %d: last error: %s\n", id, lastErr)
			}
		}
	}
}

// interrupted ends a wait on a signal: the last body received on stdout, and
// how to follow the operation.
func interrupted(stdout, stderr io.Writer, body []byte, follow string) int {
	stdout.Write(body)
	fmt.Fprintf(stderr, "supapace: interrupted; %s\n", follow)
	return 130
}

// summary tells the operator how an operation ended and the ways on.
func summary(w io.Writer, op operation) {
	why := op.LastError
	if why == "" {
		why = "no error recorded"
	}
	fmt.Fprintf(w, "supapace: operation %d %s %s: %s\n", op.ID, op.State, after(op.Step), why)
	if op.State != "failed" {
		return
	}
	fmt.Fprintf(w, "supapace: retry it with 'supapace op retry %d'\n", op.ID)
	if op.Kind == "create" {
		fmt.Fprintf(w, "supapace: or give the project up with 'supapace project abort %s'\n", op.Ref)
	}
}

// reach explains a failure to connect to the admin socket.
func reach(sock string, err error) error {
	var op *net.OpError
	var errno syscall.Errno
	if !errors.As(err, &op) || op.Op != "dial" || !errors.As(err, &errno) {
		return err
	}
	switch errno {
	case syscall.EACCES, syscall.EPERM:
		return fmt.Errorf("cannot reach %s: %v (run as root)", sock, errno)
	case syscall.ENOENT, syscall.ECONNREFUSED:
		return fmt.Errorf("cannot reach %s: %v (is supapaced running?)", sock, errno)
	}
	return fmt.Errorf("cannot reach %s: %v", sock, errno)
}

// do makes one call and returns the status and the raw body.
func do(ctx context.Context, hc *http.Client, method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://supapace"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err == nil && len(b) > maxResponse {
		err = fmt.Errorf("response over %d bytes", maxResponse)
	}
	return resp.StatusCode, b, err
}
