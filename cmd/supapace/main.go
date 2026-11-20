// Command supapace is the operator's client for the node's admin API, which
// the daemon serves on its root-only Unix socket. It parses arguments, makes
// the HTTP call and, for a mutation, polls the operation every 500 ms until it
// ends (unless --no-wait). Nothing else.
//
// stdout holds exactly one JSON document: the body of the last API response
// received, byte for byte (an explicit help request prints the usage there
// instead). Progress and errors go to stderr. Exit status: 0 success; 1 an
// API error, an operation that ended failed, aborted or superseded (for `project abort`,
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
	"slices"
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
'supapace <command> --help' prints the usage of that command alone.

Projects:
  project create --name NAME --issuer-jwks FILE [--ref REF]
                 [--user-role ROLE]... [--disk-quota SIZE] [--no-wait]
                 [--upload-per-day SIZE] [--upload-objects-per-day N]
                 [--layout N]
      --name NAME          1 to 64 letters, digits, spaces, '.', '_' or '-',
                           starting with a letter or digit
      --issuer-jwks FILE   the issuer's public JSON Web Key Set: 1 to 16 RSA
                           signing keys (RS256, 2048 to 4096 bits), each
                           with a kid
      --ref REF            20 characters of a-z and 0-9; generated when omitted;
                           a ref is never reused
      --user-role ROLE     a role the issuer's tokens may claim (repeatable).
                           The roles given replace the default,
                           authenticated: add --user-role authenticated
                           to keep it. The platform does not create a
                           role: create it in the project's database and
                           grant it to authenticator, as PostgREST
                           requires (create role editor nologin;
                           grant editor to authenticator;)
      --disk-quota SIZE    MiB, or a number with suffix m, g or t
                           (default 8g, at least 1g, at most 16t)
      --upload-per-day SIZE
                           what the project's backups may copy to the
                           off-site store per day: whole MiB, or a number
                           with suffix m, g or t (default: twice the disk
                           quota; 0 is the default)
      --upload-objects-per-day N
                           the files they may copy per day (default: one per
                           512 KiB of the daily size, at least 7500)
      --layout N           1: a project without backups. Accepted on a
                           development node only, for tests
      User tokens: there is no shared secret. The issuer signs each token
      with RS256 and a private key of the set; the header carries
      "alg":"RS256" and that key's "kid"; the claims carry "role"
      (authenticated, or one of the --user-role roles when any were given),
      "exp" (integer seconds, in the future) and optionally "sub" and
      "nbf"; at most 8 KiB. A client sends
      it as "Authorization: Bearer TOKEN" with the anon key as apikey.
  project list [--state STATE]...
      --state STATE        only projects in STATE (repeatable): provisioning,
                           active, restarting, restoring, deleting, deleted,
                           purged or aborted
  project show REF         the project's record, url and disk_used_bytes
                           (what its disk quota charges); its state is the
                           lifecycle state, not health (see project check)
  project keys REF         the project's url and credentials:
      url                  https://REF.DOMAIN, the gateway's address for it
      ca_cert              the CA that signed the gateway's certificate, or
                           null when the certificate is the operator's own
      anon_key             for client applications: the apikey header (or
                           query parameter) of every request; RLS applies
      service_role_key     for trusted servers only; it bypasses RLS
      postgres_password    the database role postgres, for schema changes;
                           no port is published; psql asks
                           for it: docker exec -it pg-REF
                           psql -h 127.0.0.1 -U postgres
  project check REF        check the project's database server and report
  project restart REF [--set KEY=VALUE]... [--no-wait]
      --set KEY=VALUE      disk_quota_mb=MIB or one of these (repeatable):
` + wrap(strings.Join(pgconf.GUCAllowList, ", "), 27, 80) + `
      A disk_quota_mb below the project's disk usage plus 256 MiB (what a
      clean cluster start needs) is refused (quota_below_usage; project
      show has disk_used_bytes). A cluster that stopped at its quota needs
      its usage plus 1280 MiB (crash recovery replays up to 1 GiB of WAL).
      A restart whose stop/start step or health check fails is
      rolled back to the previous configuration (aborted, rolled_back).
      upload_per_day=SIZE and upload_objects_per_day=N set the daily
      off-site budget of --upload-per-day and --upload-objects-per-day of
      project create (0: the default).
      A project left restarting by a failed restart accepts a new restart
      with other settings, or a delete.
  project backups REF      the project's backups: full backup sets, the
                           window a restore may target, the last push of
                           WAL and the last copy to the off-site store,
                           quota use, gaps, notices and restores. Figures
                           under push are as the project's last push job
                           reported them. Times are UTC. A project without
                           backups (layout 1) answers with empty lists
  project restore REF --to TARGET [--timeline N] [--from local|offsite]
                  [--no-wait]
      --to TARGET          latest (the end of the archive), a time in RFC
                           3339 with its offset (2026-11-18T10:43:32Z), or a
                           WAL position (0/16B3748); it must lie in the
                           window that project backups shows
      --timeline N         the timeline to follow (default: the newest
                           recorded one)
      --from local|offsite read the backup from the node's repository
                           (default) or from the off-site store; a backup
                           older than the project's seeding from the
                           off-site store is read from there only
      The project's data is replaced; the project is unavailable while it
      is restoring. Changes made after the target are no longer in the
      project. To return to the state before the restore: project restore
      REF --to latest --timeline N, N being previous_timeline in the
      operation's result. A restore that fails after the project stopped
      serving leaves it restoring: retry it (op retry), restore again, or
      delete the project; one that fails earlier leaves the project as it
      was (see project show REF).
  project delete REF [--no-wait]
  project purge REF [--no-wait]    purge a deleted project now
  project abort REF [--no-wait]    abort a create that has not completed
  project rotate-key REF --service
                           replace the project's service_role key; it
                           cannot be undone. Once the command answers
                           without an error the gateway refuses the old
                           key; an answer not_in_force (exit 1) means the
                           daemon finishes the rotation in its next rounds.
                           The project's own server-side clients must take
                           the new key (project keys REF)
  project audit REF [--tail N]
                           the newest N records (1 to 1000, default 100) of
                           the SQL the dashboard ran for the project: when,
                           who (issuer and subject), with which role and
                           login, the kind and the SHA-256 of the text

Dashboard members (a node with a studio domain):
  member add REF --subject SUB --role ROLE [--issuer ISS]
      --subject SUB        the principal's sub claim at its issuer: 1 to
                           255 characters of printable ASCII
      --role ROLE          owner, developer or read_only
      --issuer ISS         the principal's issuer (default: the dashboard
                           issuer of 'dashboard issuer set')
      A removal does not end a session: if the principal was removed in
      the last eight hours and kept its session cookie, the cookie is
      valid again once it is added back. 'supapace dashboard revoke
      ISSUER SUBJECT' ends every session of a principal.
      While the node's containment is not verified (see 'supapace node
      check'), member add and a role change that raises a role are
      refused (containment_failed); removals, lowered roles, revocations,
      the dashboard issuer and rotations are served.
  member set-role REF --subject SUB --role ROLE [--issuer ISS]
                  [--keep-service-key | --rotate-service-key]
      What a role change that ends an owner's or a read_only membership
      does is what a removal does: see 'supapace member remove --help'.
      Raising a role is refused while the node's containment is not
      verified; lowering one is served (see 'supapace member add --help').
  member remove REF --subject SUB [--issuer ISS]
                [--keep-service-key | --rotate-service-key]
      The gateway refuses the member's requests from its next reading of
      the dashboard file, which the command writes before it answers.
      An answer not_in_force (exit 1) means the change is stored but the
      gateway still admits the member until the daemon writes the file;
      'supapace dashboard show' exits 0 once it does.
      An owner who stops being one (removed, or given another role):
      the project's service_role key is rotated, which cannot be undone;
      the project's own server-side clients must take the new key
      (project keys REF). --keep-service-key leaves the key valid, so
      that member add undoes the change; the answer's still_valid says
      what the former owner may still use. --rotate-service-key rotates
      it whatever the role; an owner who stays an owner keeps it.
      A read_only member who stops being one: the read-only role's
      database sessions are ended and its scheduled jobs deleted, the
      other read-only members' included (their sessions reconnect; their
      jobs must be scheduled again). The daemon runs this clean-up before
      the command answers (while the node's containment is not verified,
      only once it is) and once more shortly after; a session can outlive
      the first run. Nothing skips it.
      A developer's removal rotates nothing by default
      (--rotate-service-key does). A removal ends dashboard access only: a
      statement the member already started runs to its end, and what an
      owner or developer did in the database as postgres stays.
  member list REF          the project's members: issuer, subject, role and
                           when each was added (also listed on stderr)
  member clean-jobs REF    run the read-only role's clean-up now: its
                           sessions are ended and its scheduled jobs
                           deleted; no member changes. Refused while the
                           dashboard file is not in force

Dashboard (a node with a studio domain):
  dashboard issuer set --issuer ISS --client-id ID --authorize-url URL
                       --jwks FILE [--end-session-url URL]
                       [--session-hours N]
      --issuer ISS         the iss claim of the issuer's ID tokens, exactly
      --client-id ID       the dashboard's client id at the issuer
      --authorize-url URL  the issuer's authorization endpoint: https, no
                           fragment
      --jwks FILE          the issuer's public JSON Web Key Set. Its RSA
                           signing keys (RS256, 2048 to 4096 bits) are
                           used, at most 16; keys of other types or for
                           encryption are left out. A key of a project is
                           refused
      --end-session-url URL
                           where signing out sends the browser (https)
      --session-hours N    how long a session lasts: 1 to 8 (default 8)
  dashboard issuer show
  dashboard revoke ISSUER SUBJECT
                           end every session of the principal on every
                           project of this node; it can sign in again
                           where it is still a member
  dashboard show           the studio domain, the number of members and
                           revocations, and in_force: whether the gateway
                           applies the latest member, issuer and
                           revocation changes. It exits 0 only when
                           the gateway reads the file the store renders

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
  1    an API error; an operation that ended failed, aborted or superseded
       (for project abort, aborted is the success); a check with "ok":
       false; the daemon could not be reached; a dashboard change that is
       committed but not yet in force (not_in_force: the daemon retries,
       and 'supapace dashboard show' tells when it is)
  2    usage, or an argument that cannot be read
  130  interrupted while waiting (the operation continues on the node)
`
}

// commandUsage returns the lines of the usage text that describe verb, or ""
// for no such command.
func commandUsage(verb string) string {
	var b strings.Builder
	for _, l := range strings.SplitAfter(usageText(), "\n") {
		switch {
		case strings.HasPrefix(l, "  "+verb+" ") || l == "  "+verb+"\n":
			b.WriteString(l)
		case b.Len() > 0 && strings.HasPrefix(l, "   "):
			b.WriteString(l)
		case b.Len() > 0:
			return b.String()
		}
	}
	return b.String()
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
	body         any      // nil: no body
	wait         string   // final operation state that is success; "" = do not poll
	check        bool     // the body's "ok" decides the exit status
	ref          string   // the project the command is about, when known
	roles        []string // project create: the user roles asked for
	look         string   // where to look (quoted commands) after a request whose answer was lost; "": the operations
	before       string   // printed to stderr before the request
	// notes prints what the operator must know about the answer to stderr
	// and returns the exit status; nil: the status alone decides.
	notes func(stderr io.Writer, status int, body []byte) int
}

// usageError is a malformed command line: printed with the usage text.
type usageError struct{ error }

func usagef(format string, args ...any) error { return usageError{fmt.Errorf(format, args...)} }

var errHelp = errors.New("help requested")

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

var quotaRE = regexp.MustCompile(`^([0-9]{1,9})([mMgGtT]?)$`)

// wholeMiB is the refusal of a size that is not a whole number of MiB.
const wholeMiB = "want whole MiB: a number with an optional m, g or t suffix (512m, 16g; 0 for the default)"

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
	"project abort": {1, 1}, "project backups": {1, 1}, "project restore": {1, 1}, "op list": {0, 1},
	"op show": {1, 1}, "op retry": {1, 1}, "node check": {0, 0},
	"member add": {1, 1}, "member set-role": {1, 1}, "member remove": {1, 1}, "member list": {1, 1}, "member clean-jobs": {1, 1},
	"dashboard issuer set": {0, 0}, "dashboard issuer show": {0, 0}, "dashboard revoke": {2, 2}, "dashboard show": {0, 0},
	"project rotate-key": {1, 1}, "project audit": {1, 1},
}

func isHelp(s string) bool { return s == "help" || s == "-h" || s == "-help" || s == "--help" }

// verbOf splits the command words from the arguments: two words, or three
// for "dashboard issuer".
func verbOf(args []string) (verb string, rest []string) {
	if len(args) < 2 {
		return "", nil
	}
	verb, rest = args[0]+" "+args[1], args[2:]
	if verb == "dashboard issuer" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") && !isHelp(rest[0]) {
		verb, rest = verb+" "+rest[0], rest[1:]
	}
	return verb, rest
}

func parse(args []string) (c call, err error) {
	if len(args) > 0 && isHelp(args[0]) {
		return call{}, errHelp
	}
	if len(args) > 1 && isHelp(args[1]) && slices.Contains([]string{"project", "op", "node", "member", "dashboard"}, args[0]) {
		return call{}, errHelp
	}
	if len(args) < 2 {
		return call{}, usagef("missing command")
	}
	verb, rest := verbOf(args)
	ar, known := arity[verb]
	if !known {
		if len(rest) > 0 && isHelp(rest[0]) && commandUsage(verb) != "" {
			return call{}, errHelp // a group of commands: "dashboard issuer --help"
		}
		return call{}, usagef("unknown command %q", verb)
	}
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var noWait bool
	switch verb {
	case "project create", "project restart", "project delete", "project purge", "project abort", "project restore",
		"op retry":
		fs.BoolVar(&noWait, "no-wait", false, "")
	}
	var name, jwks, ref string
	var quota, uploadMB, uploadObj, layout, timeline *int
	var to, from string
	// intFlag reads an integer flag into *p.
	intFlag := func(name string, p **int) {
		fs.Func(name, "", func(s string) error {
			n, err := strconv.Atoi(s)
			if err != nil {
				return errors.New("want an integer")
			}
			*p = &n
			return nil
		})
	}
	var roles, sets, states list
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
		fs.Func("upload-per-day", "", func(s string) error {
			mb, err := parseQuota(s)
			if err != nil {
				return errors.New(wholeMiB)
			}
			uploadMB = &mb
			return nil
		})
		intFlag("upload-objects-per-day", &uploadObj)
		intFlag("layout", &layout)
	case "project restart":
		fs.Var(&sets, "set", "")
	case "project restore":
		fs.Func("to", "", func(s string) error {
			if s == "" {
				return errors.New("empty target")
			}
			to = s
			return nil
		})
		intFlag("timeline", &timeline)
		fs.StringVar(&from, "from", "", "")
	case "project list":
		fs.Var(&states, "state", "")
	}
	build := dashCall(verb, fs)
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
	if build != nil {
		return build(pos, project)
	}

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
			UploadMB    *int            `json:"upload_mb_per_day,omitempty"`
			UploadObj   *int            `json:"upload_objects_per_day,omitempty"`
			Layout      *int            `json:"layout,omitempty"`
		}{Name: name, Ref: ref, IssuerJWKS: set, UserRoles: roles, DiskQuotaMB: quota, UploadMB: uploadMB,
			UploadObj: uploadObj, Layout: layout}
		return call{method: "POST", path: "/v1/projects", body: body, wait: wait("done"), roles: roles}, nil
	case "project list":
		if len(states) == 0 {
			return call{method: "GET", path: "/v1/projects"}, nil
		}
		return call{method: "GET", path: "/v1/projects?" + url.Values{"state": states}.Encode()}, nil
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
			UploadMB    *int              `json:"upload_mb_per_day,omitempty"`
			UploadObj   *int              `json:"upload_objects_per_day,omitempty"`
		}{}
		// The settings that are members of their own, not database settings.
		ints := map[string]**int{"disk_quota_mb": &body.DiskQuotaMB, "upload_per_day": &body.UploadMB,
			"upload_objects_per_day": &body.UploadObj}
		for _, s := range sets {
			k, v, ok := strings.Cut(s, "=")
			if !ok || k == "" {
				return call{}, usagef("--set %q: want key=value", s)
			}
			if p, isInt := ints[k]; isInt {
				if *p != nil {
					return call{}, usagef("--set %s given twice", k)
				}
				if k == "upload_per_day" {
					n, err := parseQuota(v)
					if err != nil {
						return call{}, usagef("--set upload_per_day=%q: %s", v, wholeMiB)
					}
					*p = &n
					continue
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					return call{}, usagef("--set %s=%q: want an integer", k, v)
				}
				*p = &n
				continue
			}
			if _, dup := body.Set[k]; dup {
				return call{}, usagef("--set %s given twice", k)
			}
			if body.Set == nil {
				body.Set = map[string]string{}
			}
			body.Set[k] = v
		}
		return call{method: "POST", path: project + "/restart", body: body, wait: wait("done")}, nil
	case "project backups":
		return call{method: "GET", path: project + "/backups"}, nil
	case "project restore":
		if to == "" {
			return call{}, usagef("project restore: --to is required")
		}
		body := struct {
			To       string `json:"to"`
			Timeline *int   `json:"timeline,omitempty"`
			From     string `json:"from,omitempty"`
		}{to, timeline, from}
		return call{method: "POST", path: project + "/restore", body: body, wait: wait("done")}, nil
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
		return "before its first step"
	}
	return "after step " + step
}

func run(args []string, c client, stdout, stderr io.Writer) int {
	cl, err := parse(args)
	// The command named, when it is one: its usage stands for the whole text.
	var cmd string
	if v, _ := verbOf(args); v != "" {
		cmd = commandUsage(v)
	}
	var ue usageError
	switch {
	case errors.Is(err, errHelp) && cmd != "":
		io.WriteString(stdout, "usage:\n"+cmd)
		return 0
	case errors.Is(err, errHelp):
		io.WriteString(stdout, usageText())
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "supapace: %v\n", err)
		if cmd != "" {
			fmt.Fprint(stderr, "usage:\n"+cmd)
		}
		fmt.Fprintln(stderr, "see 'supapace --help' for the usage of every command")
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
	if cl.before != "" {
		say(stderr, "%s", cl.before)
	}
	ctx := context.Background()
	if cl.method != "GET" && !cl.check {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	status, body, err := do(ctx, hc, cl.method, cl.path, cl.body)
	if err != nil && ctx.Err() != nil {
		look := "'supapace op list'"
		if cl.ref != "" {
			look = "'supapace op list " + cl.ref + "'"
		}
		if cl.look != "" {
			look = cl.look
		}
		fmt.Fprintf(stderr, "supapace: interrupted before the answer; the request may already have been accepted; look with %s\n", look)
		return 130
	}
	if err != nil {
		fmt.Fprintf(stderr, "supapace: %v\n", reach(c.sock, err))
		var op *net.OpError
		if cl.look != "" && !(errors.As(err, &op) && op.Op == "dial") {
			fmt.Fprintf(stderr, "supapace: the request may already have been accepted; look with %s\n", cl.look)
		}
		return 1
	}
	if status != http.StatusAccepted || cl.wait == "" {
		stdout.Write(body)
		if cl.notes != nil {
			return cl.notes(stderr, status, body)
		}
		if status/100 != 2 {
			return 1
		}
		if cl.check {
			var r struct{ OK bool }
			if json.Unmarshal(body, &r) != nil || !r.OK {
				return 1
			}
		}
		cl.created(stderr, body)
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
		case "done", "failed", "aborted", "superseded":
			stdout.Write(b)
			if op.State == cl.wait {
				cl.created(stderr, b)
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

// created tells the operator of a create that succeeded where to look next,
// and what user roles still need. body is the create's last answer.
func (cl call) created(w io.Writer, body []byte) {
	if cl.method != "POST" || cl.path != "/v1/projects" {
		return
	}
	var r struct {
		Ref         string
		OperationID int64 `json:"operation_id"`
	}
	if json.Unmarshal(body, &r) != nil || r.Ref == "" {
		return
	}
	if r.OperationID > 0 { // --no-wait: the create is queued, nothing is issued yet
		fmt.Fprintf(w, "supapace: project %s is being created; follow it with 'supapace op show %d'; once it is done, "+
			"its url, keys and CA: 'supapace project keys %s'\n", r.Ref, r.OperationID, r.Ref)
	} else {
		fmt.Fprintf(w, "supapace: project %s: its url, keys and CA: 'supapace project keys %s'\n", r.Ref, r.Ref)
	}
	if roles := slices.DeleteFunc(slices.Clone(cl.roles), func(s string) bool { return s == "authenticated" }); len(roles) > 0 {
		fmt.Fprintf(w, "supapace: tokens can use the role(s) %s once each exists in the project's database "+
			"and is granted to authenticator (see 'supapace project create --help')\n", strings.Join(roles, ", "))
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
	if op.State == "superseded" {
		fmt.Fprintf(w, "supapace: a later operation of the project replaced it, and it is not retried; "+
			"see 'supapace op list %s'\n", op.Ref)
		return
	}
	if op.State != "failed" {
		return
	}
	if op.Kind == "restart" && strings.HasPrefix(op.LastError, "quota_below_usage: ") {
		fmt.Fprintf(w, "supapace: nothing was changed; restart with at least the smallest accepted value: "+
			"'supapace project restart %s --set disk_quota_mb=MIB'\n", op.Ref)
		return
	}
	fmt.Fprintf(w, "supapace: retry it with 'supapace op retry %d'\n", op.ID)
	// A restart that left its project restarting says so in last_error (the
	// worker's note); one that failed before the bump left the project active.
	switch {
	case op.Kind == "create":
		fmt.Fprintf(w, "supapace: or give the project up with 'supapace project abort %s'\n", op.Ref)
	case op.Kind == "restore":
		fmt.Fprintf(w, "supapace: or restore again with other options: 'supapace project restore %s --to TARGET'; "+
			"a project left restoring (see 'supapace project show %s') can also be removed: 'supapace project delete %s'\n",
			op.Ref, op.Ref, op.Ref)
	case op.Kind == "restart" && strings.Contains(op.LastError, "; the project stays restarting at generation "):
		fmt.Fprintf(w, "supapace: or replace it with other settings: 'supapace project restart %s --set KEY=VALUE', "+
			"or remove the project: 'supapace project delete %s'\n", op.Ref, op.Ref)
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
