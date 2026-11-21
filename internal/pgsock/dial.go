// Package pgsock is the only way the daemon talks to a project's database
// server: over the cluster container's Unix socket, reached by descriptor
// without following links, after checking that the process that created the
// listening socket is the container's init process the platform recorded.
//
// The database server is untrusted. Nothing secret is sent unless the server
// takes the one authentication path the platform accepts (SCRAM-SHA-256 with
// the salt and iteration count the platform fixed), every session carries a
// fixed set of startup parameters, and every session is bounded in time and
// bytes below the client library, so no answer can stall or exhaust the
// daemon. Nothing in the environment can redirect, weaken, stall or break a
// dial, because a dial with any PG* variable set does not start (CheckEnv).
//
// Errors name the project and the step, never the dialled path, and carry
// server-supplied text only sanitized; no error from Dial unwraps to raw
// server text.
//
// Callers:
//   - wrap each statement's context in Stmt and test errors with IsBudget;
//   - pass every error from a statement, a rows iteration or a scan through
//     Clean before logging or returning it;
//   - never log conn.Config() (it holds the password). Target prints, logs
//     and marshals redacted, but fmt and slog's text handler read an
//     unexported struct field by reflection: never keep a Target in an
//     unexported field of a value that is formatted or logged;
//   - Close the connection when the step ends, and after any error.
package pgsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/pgproto3"
)

// Target identifies one cluster and how to log in to it.
type Target struct {
	ProjectsDir, Ref string
	UID              int    // owner of the socket and of the listening process
	PostmasterPid    int    // the container's init, as seen from the node
	PostmasterStart  uint64 // its start time (ProcStart) recorded when the container started
	// ListenerPid and ListenerStart are zero unless the listener is a recorded
	// child of PostmasterPid; then the peer must be exactly that (pid, start).
	ListenerPid   int
	ListenerStart uint64
	User          string
	Password      string
	ScramSalt     []byte // the role's ScramSalt; required unless AllowTrust
	AllowTrust    bool   // accept a login without authentication; SASL is then refused
	Superuser     bool   // also send the superuser parameters (superuserParams)
	Budget        Budget // zero value: DefaultBudget
}

var (
	ErrNotSocket          = errors.New("pgsock: not a socket owned by the project")
	ErrPeer               = errors.New("pgsock: socket peer is not the recorded cluster process")
	ErrCleartextRequested = errors.New("pgsock: server requested a cleartext or MD5 password")
	ErrNotScram           = errors.New("pgsock: server did not authenticate with SCRAM-SHA-256")
	ErrScramParams        = errors.New("pgsock: SCRAM parameters differ from the platform's")
	ErrBudget             = errors.New("pgsock: session budget exceeded")
	ErrEnvironment        = errors.New("pgsock: connection settings in the environment")
	// ErrConnect: connecting to the checked socket failed (nothing listens
	// on it, for one); its text is the word "connect" alone, so the error
	// reads as before it was wrapped.
	ErrConnect = errors.New("connect")
)

// String prints t with Password and ScramSalt redacted; Format, GoString and
// LogValue do the same, so no fmt verb or slog call prints them.
func (t Target) String() string {
	return fmt.Sprintf("pgsock.Target{ProjectsDir:%q Ref:%q UID:%d PostmasterPid:%d PostmasterStart:%d "+
		"ListenerPid:%d ListenerStart:%d User:%q Password:[redacted] ScramSalt:[redacted] AllowTrust:%t "+
		"Superuser:%t Budget:%+v}", t.ProjectsDir, t.Ref, t.UID, t.PostmasterPid, t.PostmasterStart,
		t.ListenerPid, t.ListenerStart, t.User, t.AllowTrust, t.Superuser, t.Budget)
}

func (t Target) GoString() string { return t.String() }

// MarshalJSON writes every field but Password and ScramSalt, which are
// redacted.
func (t Target) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ProjectsDir, Ref          string
		UID, PostmasterPid        int
		PostmasterStart           uint64
		ListenerPid               int
		ListenerStart             uint64
		User, Password, ScramSalt string
		AllowTrust, Superuser     bool
		Budget                    Budget
	}{t.ProjectsDir, t.Ref, t.UID, t.PostmasterPid, t.PostmasterStart, t.ListenerPid, t.ListenerStart,
		t.User, "[redacted]", "[redacted]", t.AllowTrust, t.Superuser, t.Budget})
}

func (t Target) Format(f fmt.State, _ rune) { io.WriteString(f, t.String()) }

func (t Target) LogValue() slog.Value {
	return slog.GroupValue(slog.String("ref", t.Ref), slog.String("projects_dir", t.ProjectsDir),
		slog.Int("uid", t.UID), slog.Int("postmaster_pid", t.PostmasterPid), slog.String("user", t.User),
		slog.Bool("superuser", t.Superuser), slog.Bool("allow_trust", t.AllowTrust))
}

// CheckEnv refuses an environment holding any variable whose name starts with
// PG: the client library would read it. The error names the variables, never
// their values. Dial calls it first; the daemon may call it at start.
func CheckEnv() error {
	var names []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "PG") {
			names = append(names, Sanitize(k, 64))
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("%w: %s set", ErrEnvironment, strings.Join(names, ", "))
}

// ServerError is what remains of an error the server sent: its SQLSTATE when
// it is five characters [0-9A-Z] (else empty) and its sanitized message.
type ServerError struct{ Code, Message string }

func (e *ServerError) Error() string {
	if e.Code == "" {
		return "pgsock: server error: " + e.Message
	}
	return "pgsock: server error " + e.Code + ": " + e.Message
}

var sqlstateRE = regexp.MustCompile(`^[0-9A-Z]{5}$`)

// cleanError carries sanitized text and unwraps only to a ServerError and the
// sentinel errors the original matched.
type cleanError struct {
	text   string
	causes []error
}

func (e *cleanError) Error() string    { return e.text }
func (e *cleanError) Unwrap() []error  { return e.causes }
func (e *cleanError) GoString() string { return e.text }

// Clean returns err with its text sanitized and no path — Unwrap, errors.As
// or a formatting verb — back to the original error or its text. The result
// still matches, with errors.Is, every error of this package,
// context.DeadlineExceeded and context.Canceled that err matched, and exposes
// a *ServerError through errors.As when err held a server error. nil stays
// nil, and an error Clean returned is returned as is. Callers apply it to
// every error from a statement, a rows iteration or a scan before it is
// logged or returned: the library's scan and decode errors quote column names
// and values the server sent.
func Clean(err error) error {
	if err == nil {
		return nil
	}
	if ce, ok := err.(*cleanError); ok {
		return ce
	}
	var causes []error
	var pe *pgconn.PgError
	var se *ServerError
	switch {
	case errors.As(err, &pe):
		se = &ServerError{Message: Sanitize(pe.Message, 512)}
		if sqlstateRE.MatchString(pe.Code) {
			se.Code = pe.Code
		}
	case errors.As(err, &se):
		se = &ServerError{Code: se.Code, Message: Sanitize(se.Message, 512)}
		if !sqlstateRE.MatchString(se.Code) {
			se.Code = ""
		}
	}
	if se != nil {
		causes = append(causes, se)
	}
	for _, s := range []error{ErrNotSocket, ErrPeer, ErrConnect, ErrCleartextRequested, ErrNotScram, ErrScramParams,
		ErrBudget, ErrEnvironment, context.DeadlineExceeded, context.Canceled} {
		if errors.Is(err, s) {
			causes = append(causes, s)
		}
	}
	return &cleanError{text: Sanitize(err.Error(), 512), causes: causes}
}

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// afterCheck, when set, runs after the socket inode is checked and before it
// is connected to. Only this package's tests set it.
var afterCheck func()

// StartupParams returns the parameters every platform session sends in its
// startup packet, so they are in force before anything in the database runs.
// This is their only definition.
func StartupParams(superuser bool) map[string]string {
	m := map[string]string{
		"search_path":                         "pg_catalog,pg_temp",
		"role":                                "none",
		"default_transaction_read_only":       "off",
		"statement_timeout":                   "0",
		"lock_timeout":                        "0",
		"idle_in_transaction_session_timeout": "0",
		"idle_session_timeout":                "0",
		"transaction_timeout":                 "0",
		"local_preload_libraries":             "",
		"exit_on_error":                       "off",
		"default_transaction_isolation":       "read committed",
		"default_transaction_deferrable":      "off",
		"standard_conforming_strings":         "on",
		"backslash_quote":                     "safe_encoding",
		// A platform write is made durable on this server alone: a synchronous
		// standby named in the system file would hold every commit until the
		// statement budget, and the cluster has no standby of the platform's.
		"synchronous_commit": "local",
		// A delay after authentication in the system file would hold every
		// session past its connect budget.
		"post_auth_delay":       "0",
		"client_encoding":       "UTF8",
		"DateStyle":             "ISO, MDY",
		"TimeZone":              "UTC",
		"IntervalStyle":         "postgres",
		"bytea_output":          "hex",
		"extra_float_digits":    "1",
		"quote_all_identifiers": "off",
		"transform_null_equals": "off",
		"row_security":          "on",
		"check_function_bodies": "on",
		"default_tablespace":    "",
		"temp_tablespaces":      "",
		"client_min_messages":   "notice",
		"application_name":      "supapace-agent",
	}
	if superuser {
		// A non-superuser session is refused with any of the sixteen the
		// server reserves to superusers; the three debug_print_* are settable
		// by any role. A setting of
		// the login role, of the database or of the system file reaches the
		// session unless overridden here; each line names what it keeps out.
		for k, v := range superuserParams {
			m[k] = v
		}
	}
	return m
}

// superuserParams are the startup parameters only a superuser session sends.
// The image decides which of them exist: an image bump re-runs the session
// experiments before the bootstrap baseline is regenerated.
var superuserParams = map[string]string{
	"event_triggers":                   "off",     // a login trigger held the session until its connect deadline
	"session_preload_libraries":        "",        // a role or database setting loads a library into the session
	"log_statement":                    "none",    // the session's statement texts in the server log
	"log_min_duration_statement":       "-1",      // the same, logged by duration
	"log_min_duration_sample":          "-1",      // the same, sampled
	"log_transaction_sample_rate":      "0",       // every statement of a sampled transaction, password statements among them
	"log_duration":                     "off",     // a duration line for each statement
	"log_min_messages":                 "warning", // debug-level messages that carry statement texts
	"log_min_error_statement":          "panic",   // the STATEMENT line after a logged message: a failed password statement logged its text
	"debug_print_parse":                "off",     // the parse tree, with the statement's literal in it
	"debug_print_rewritten":            "off",     // the same after rewriting
	"debug_print_plan":                 "off",     // the plans of the session's reads
	"track_activities":                 "off",     // the running statement shown to other sessions in pg_stat_activity, and the postmaster's "failed process was running" line for a killed session
	"pgaudit.log":                      "none",    // session audit lines
	"pgaudit.role":                     "",        // object audit lines for the session's reads
	"auto_explain.log_min_duration":    "-1",      // plans with their statement text; the image preloads the library
	"pg_stat_statements.track":         "none",    // the session's statements kept in the statement statistics
	"pg_stat_statements.track_utility": "off",     // utility statements kept there (the image's default is on)
	"plan_filter.statement_cost_limit": "0",       // a role setting refused every statement that has a plan
}

// dialError names the project and the step; its text carries the cause only
// sanitized, and it unwraps to the cause.
type dialError struct {
	ref, step string
	err       error
}

func (e *dialError) Error() string {
	return "pgsock: project " + e.ref + ": " + e.step + ": " + Sanitize(e.err.Error(), 512)
}

func (e *dialError) Unwrap() error { return e.err }

// Dial connects to the cluster of t and logs in. The returned connection is
// bounded by t's budget for its whole life; the caller closes it when its
// step ends.
func Dial(ctx context.Context, t Target) (*pgx.Conn, error) {
	start := time.Now()
	b := t.Budget.withDefaults()
	ref := t.Ref
	if !refRE.MatchString(ref) {
		return nil, fmt.Errorf("pgsock: invalid project ref %q", Sanitize(ref, 64))
	}
	fail := func(step string, err error) (*pgx.Conn, error) {
		return nil, Clean(&dialError{ref: ref, step: step, err: err})
	}
	if err := CheckEnv(); err != nil {
		return fail("environment", err)
	}
	switch {
	case t.PostmasterPid <= 1:
		return fail("target", fmt.Errorf("%w: recorded pid %d", ErrPeer, t.PostmasterPid))
	case len(t.ScramSalt) == 0 && !t.AllowTrust:
		return fail("target", fmt.Errorf("%w: no salt", ErrScramParams))
	}
	cfg, err := config(t, b)
	if err != nil {
		return fail("config", err)
	}
	dctx, cancel := context.WithDeadlineCause(ctx, start.Add(b.Connect), ErrBudget)
	defer cancel()
	uc, err := dialChecked(dctx, t)
	if err != nil {
		return fail("socket", err)
	}
	g := newGuard(uc, b, t.ScramSalt, t.AllowTrust, start)
	var used atomic.Bool
	cfg.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		if used.Swap(true) {
			return nil, errors.New("pgsock: one connection per dial")
		}
		return g, nil
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		g.Close()
		return fail("login", err)
	}
	return conn, nil
}

// dialChecked opens the socket inode, connects through it and checks the
// peer before a byte is written.
func dialChecked(ctx context.Context, t Target) (*net.UnixConn, error) {
	fd, err := openSocket(t.ProjectsDir, t.Ref, t.UID)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	if afterCheck != nil {
		afterCheck()
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", "/proc/self/fd/"+strconv.Itoa(fd))
	if err != nil {
		var oe *net.OpError
		if errors.As(err, &oe) {
			err = oe.Err // drop the dialled path
		}
		if c := context.Cause(ctx); errors.Is(c, ErrBudget) {
			return nil, fmt.Errorf("%w: connect: %v", ErrBudget, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrConnect, err)
	}
	uc := c.(*net.UnixConn)
	if err := checkPeer(uc, t); err != nil {
		uc.Close()
		return nil, err
	}
	return uc, nil
}

// checkPeer requires the process that created the listening socket to be the
// recorded postmaster (or the recorded listener child of it), by pid and start
// time, running as the project's uid.
func checkPeer(c *net.UnixConn, t Target) error {
	pid, uid, err := peerCred(c)
	if err != nil {
		return fmt.Errorf("%w: credentials: %v", ErrPeer, err)
	}
	if pid <= 1 {
		return fmt.Errorf("%w: peer pid %d", ErrPeer, pid)
	}
	if uid != t.UID {
		return fmt.Errorf("%w: peer uid %d", ErrPeer, uid)
	}
	wantPid, wantStart := t.PostmasterPid, t.PostmasterStart
	if t.ListenerPid != 0 {
		wantPid, wantStart = t.ListenerPid, t.ListenerStart
	}
	if pid != wantPid {
		return fmt.Errorf("%w: peer pid %d", ErrPeer, pid)
	}
	ppid, start, err := procStat(pid)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPeer, err)
	}
	if start != wantStart {
		return fmt.Errorf("%w: peer start time differs", ErrPeer)
	}
	if t.ListenerPid != 0 {
		if ppid != t.PostmasterPid {
			return fmt.Errorf("%w: listener parent %d", ErrPeer, ppid)
		}
		if s, err := ProcStart(t.PostmasterPid); err != nil || s != t.PostmasterStart {
			return fmt.Errorf("%w: postmaster start time differs", ErrPeer)
		}
	}
	return nil
}

// config builds a client configuration nothing outside t can change: one
// host, no fallbacks, no TLS, no environment- or service-file-derived value
// left in place (Dial has already refused any PG* variable; the placeholder
// password keeps the password file from being read), the fixed startup parameters, and only the authentication
// methods the guard admits.
func config(t Target, b Budget) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig("host=/pgsock port=5432 dbname=postgres sslmode=disable sslcertmode=disable password=unused")
	if err != nil {
		var pe *pgconn.ParseConfigError
		if errors.As(err, &pe) {
			err = errors.New("environment holds an unusable connection setting")
		}
		return nil, err
	}
	c := &cfg.Config
	c.Host, c.Port, c.Database = "/pgsock", 5432, "postgres"
	c.User, c.Password = t.User, t.Password
	c.TLSConfig, c.Fallbacks = nil, nil
	c.ConnectTimeout = 0
	c.LookupFunc = func(context.Context, string) ([]string, error) { return nil, errors.New("pgsock: no lookups") }
	c.BuildFrontend = pgproto3.NewFrontend
	c.MaxProtocolMessageBodyLen = b.MessageBytes
	c.BuildContextWatcherHandler = func(pc *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.DeadlineContextWatcherHandler{Conn: pc.Conn()}
	}
	c.RuntimeParams = StartupParams(t.Superuser)
	c.KerberosSrvName, c.KerberosSpn = "", ""
	c.SSLNegotiation = "postgres"
	c.SSLCertMode = "disable"
	c.AfterNetConnect, c.ValidateConnect, c.AfterConnect = nil, nil, nil
	c.OnNotice, c.OnNotification = nil, nil
	c.OAuthTokenProvider = nil
	c.MinProtocolVersion, c.MaxProtocolVersion = "3.0", "3.0"
	c.ChannelBinding = "disable"
	c.RequireAuth = "scram-sha-256"
	if t.AllowTrust {
		c.RequireAuth = "none"
	}
	cfg.Tracer = nil
	return cfg, nil
}
