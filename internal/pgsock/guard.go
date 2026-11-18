package pgsock

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Budget bounds one session. A zero field takes its value from DefaultBudget.
type Budget struct {
	Connect, Statement, Session time.Duration
	Bytes                       int64 // everything read from the server
	MessageBytes                int   // body of one backend message
	ParamStatus                 int   // ParameterStatus messages per session
	Notices                     int   // NoticeResponse + NotificationResponse messages per session
}

// DefaultBudget is the budget of a Target whose Budget is the zero value.
var DefaultBudget = Budget{
	Connect: 5 * time.Second, Statement: 10 * time.Second, Session: 60 * time.Second,
	Bytes: 4 << 20, MessageBytes: 1 << 20, ParamStatus: 64, Notices: 256,
}

func (b Budget) withDefaults() Budget {
	d := DefaultBudget
	if b.Connect <= 0 {
		b.Connect = d.Connect
	}
	if b.Statement <= 0 {
		b.Statement = d.Statement
	}
	if b.Session <= 0 {
		b.Session = d.Session
	}
	if b.Bytes <= 0 {
		b.Bytes = d.Bytes
	}
	if b.MessageBytes <= 0 {
		b.MessageBytes = d.MessageBytes
	}
	if b.ParamStatus <= 0 {
		b.ParamStatus = d.ParamStatus
	}
	if b.Notices <= 0 {
		b.Notices = d.Notices
	}
	return b
}

// Stmt returns a context for one statement. The session's guard bounds every
// statement by b.Statement itself — from the first request written while
// idle, and again from each ReadyForQuery that leaves requests outstanding, so
// pipelined statements are bounded one by one — and ends it with ErrBudget.
// The context is a backstop that expires slightly later (its cause is
// ErrBudget too), so the guard's ErrBudget is the normal result.
func Stmt(ctx context.Context, b Budget) (context.Context, context.CancelFunc) {
	d := b.withDefaults().Statement
	return context.WithTimeoutCause(ctx, d+max(50*time.Millisecond, d/20), ErrBudget)
}

// IsBudget reports whether err means a session or statement bound was
// exceeded: ErrBudget, or a context deadline (a Stmt backstop or a caller's
// own). It is the one test callers use; the session is then dead and the step
// can be retried with a new Dial.
func IsBudget(err error) bool {
	return errors.Is(err, ErrBudget) || errors.Is(err, context.DeadlineExceeded)
}

// Sanitize removes C0 and C1 control characters, DEL, invalid UTF-8 and every
// character of the Unicode categories Cf, Zl and Zp (bidirectional controls,
// zero-width characters, U+FEFF, line and paragraph separators) from s, and
// caps the result at max bytes without splitting a character. Every
// server-supplied text passes through it before it reaches an error or a log.
func Sanitize(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		if r == utf8.RuneError && n <= 1 || r < 0x20 || r >= 0x7f && r <= 0x9f ||
			unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			continue
		}
		if b.Len()+n > max {
			break
		}
		b.WriteString(s[i-n : i])
	}
	return b.String()
}

// guard sits between the client library and the socket. It reads whole
// backend messages, checks each one, and only then hands its bytes to the
// library: a message over the size cap or past the byte budget is refused on
// its header, the authentication exchange must be SCRAM-SHA-256 with the
// platform's salt and iteration count, and every read and write is clamped to
// the connect, statement and session deadlines whatever the library asks for.
// Any refusal closes the connection and sticks.
type guard struct {
	net.Conn
	b          Budget
	salt       []byte
	allowTrust bool

	mu      sync.Mutex
	err     error
	rdl     time.Time // deadlines the library set
	wdl     time.Time
	connect time.Time // in force until the first ReadyForQuery
	session time.Time
	stmt    time.Time // deadline of the statement in flight; zero when idle
	ready   bool

	// writer state: frontend messages are framed to count the requests
	// (Query, Sync) that each owe a ReadyForQuery
	outstanding int
	wStarted    bool // the untyped startup packet has been framed
	whdr        [5]byte
	whn         int
	wskip       int64

	// reader state, under rmu: the library may read from two goroutines at
	// once (its background reader and the drain of an asynchronous close)
	rmu     sync.Mutex
	pending []byte
	buf     []byte
	total   int64
	params  int
	notices int
	auth    int // authStart … authDone
}

const (
	authStart    = iota // expecting an authentication request
	authSASL            // SASL offered, expecting the server-first message
	authContinue        // server-first checked, expecting the server-final message
	authFinal           // server-final seen, expecting AuthenticationOk
	authDone
)

func newGuard(c net.Conn, b Budget, salt []byte, allowTrust bool, start time.Time) *guard {
	return &guard{Conn: c, b: b, salt: salt, allowTrust: allowTrust,
		connect: start.Add(b.Connect), session: start.Add(b.Session)}
}

// budgetError is ErrBudget with a reason. It reports itself as a timeout:
// the client library then keeps it instead of replacing it with a generic
// "conn closed" when it surfaces while a result is being read.
type budgetError struct{ reason string }

func (e *budgetError) Error() string        { return ErrBudget.Error() + ": " + e.reason }
func (e *budgetError) Is(target error) bool { return target == ErrBudget }
func (e *budgetError) Timeout() bool        { return true }
func (e *budgetError) Temporary() bool      { return false }

func budgetErr(format string, a ...any) error {
	return &budgetError{reason: fmt.Sprintf(format, a...)}
}

// fail records err as the connection's error and closes it.
func (g *guard) fail(err error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err == nil {
		g.err = err
		g.Conn.Close()
	}
	return g.err
}

// limit returns the deadline in force for an operation the library bounded by
// lib, and the platform's own bound within it.
func (g *guard) limit(lib time.Time) (eff, own time.Time) {
	own = g.session
	if !g.ready && g.connect.Before(own) {
		own = g.connect
	}
	if !g.stmt.IsZero() && g.stmt.Before(own) {
		own = g.stmt
	}
	eff = own
	if !lib.IsZero() && lib.Before(eff) {
		eff = lib
	}
	return eff, own
}

func (g *guard) SetDeadline(t time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rdl, g.wdl = t, t
	eff, _ := g.limit(t)
	return g.Conn.SetDeadline(eff)
}

func (g *guard) SetReadDeadline(t time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rdl = t
	eff, _ := g.limit(t)
	return g.Conn.SetReadDeadline(eff)
}

func (g *guard) SetWriteDeadline(t time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.wdl = t
	eff, _ := g.limit(t)
	return g.Conn.SetWriteDeadline(eff)
}

// timeout turns an I/O error into ErrBudget when the platform's own deadline
// is what elapsed.
func (g *guard) timeout(err error, own time.Time) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() && !time.Now().Before(own) {
		return g.fail(budgetErr("deadline exceeded"))
	}
	return g.fail(err)
}

func (g *guard) Write(p []byte) (int, error) {
	g.mu.Lock()
	if g.err != nil {
		defer g.mu.Unlock()
		return 0, g.err
	}
	g.countRequests(p)
	if g.ready && g.stmt.IsZero() {
		g.stmt = time.Now().Add(g.b.Statement)
	}
	eff, own := g.limit(g.wdl)
	g.Conn.SetWriteDeadline(eff)
	g.mu.Unlock()
	n, err := g.Conn.Write(p)
	if err != nil {
		return n, g.timeout(err, own)
	}
	return n, nil
}

// countRequests frames the frontend bytes in p and counts each Query and Sync
// as a request owing a ReadyForQuery. Called with g.mu held.
func (g *guard) countRequests(p []byte) {
	for len(p) > 0 {
		if g.wskip > 0 {
			n := min(int64(len(p)), g.wskip)
			p, g.wskip = p[n:], g.wskip-n
			continue
		}
		hl := 5
		if !g.wStarted {
			hl = 4
		}
		k := copy(g.whdr[g.whn:hl], p)
		g.whn, p = g.whn+k, p[k:]
		if g.whn < hl {
			return
		}
		var l uint32
		if hl == 4 {
			l, g.wStarted = binary.BigEndian.Uint32(g.whdr[:4]), true
		} else {
			l = binary.BigEndian.Uint32(g.whdr[1:5])
			if g.whdr[0] == 'Q' || g.whdr[0] == 'S' {
				g.outstanding++
			}
		}
		g.wskip, g.whn = max(int64(l)-4, 0), 0
	}
}

func (g *guard) Read(p []byte) (int, error) {
	g.rmu.Lock()
	defer g.rmu.Unlock()
	if len(g.pending) == 0 {
		if err := g.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, g.pending)
	g.pending = g.pending[n:]
	return n, nil
}

// fill reads until g.buf holds n bytes.
func (g *guard) fill(n int) error {
	if cap(g.buf) < n {
		nb := make([]byte, len(g.buf), n)
		copy(nb, g.buf)
		g.buf = nb
	}
	for len(g.buf) < n {
		g.mu.Lock()
		if g.err != nil {
			defer g.mu.Unlock()
			return g.err
		}
		eff, own := g.limit(g.rdl)
		g.Conn.SetReadDeadline(eff)
		g.mu.Unlock()
		m, err := g.Conn.Read(g.buf[len(g.buf):n])
		g.buf = g.buf[:len(g.buf)+m]
		g.total += int64(m)
		if err != nil {
			return g.timeout(err, own)
		}
	}
	return nil
}

// next reads and checks one backend message and queues it for the library.
func (g *guard) next() error {
	g.buf = g.buf[:0]
	if err := g.fill(5); err != nil {
		return err
	}
	typ := g.buf[0]
	n := int64(binary.BigEndian.Uint32(g.buf[1:5])) - 4
	if err := g.header(typ, n); err != nil {
		return g.fail(err)
	}
	if err := g.fill(5 + int(n)); err != nil {
		return err
	}
	if err := g.body(typ, g.buf[5:]); err != nil {
		return g.fail(err)
	}
	g.pending = g.buf
	return nil
}

// header refuses a message on its type and announced length, before its body
// is read.
func (g *guard) header(typ byte, n int64) error {
	switch {
	case n < 0:
		return budgetErr("malformed message length")
	case n > int64(g.b.MessageBytes):
		return budgetErr("message of %d bytes over the cap of %d", n, g.b.MessageBytes)
	case g.total+n > g.b.Bytes:
		return budgetErr("session read budget of %d bytes exceeded", g.b.Bytes)
	}
	if g.auth != authDone {
		switch typ {
		case 'R', 'E', 'N', 'v':
		default:
			return fmt.Errorf("%w: message %d before authentication completed", ErrNotScram, typ)
		}
	} else {
		switch typ {
		case 'S', 'K', 'Z', 'E', 'N', 'A', 'T', 'D', 'C', 'I', '1', '2', '3', 'n', 't', 's':
		default:
			return budgetErr("message type %d refused", typ)
		}
	}
	switch typ {
	case 'S':
		if g.params++; g.params > g.b.ParamStatus {
			return budgetErr("more than %d parameter-status messages", g.b.ParamStatus)
		}
	case 'N', 'A':
		if g.notices++; g.notices > g.b.Notices {
			return budgetErr("more than %d notice messages", g.b.Notices)
		}
	case 'Z':
		g.mu.Lock()
		g.ready, g.stmt = true, time.Time{}
		if g.outstanding > 0 {
			g.outstanding--
		}
		if g.outstanding > 0 { // pipelined requests remain: the next statement's bound starts now
			g.stmt = time.Now().Add(g.b.Statement)
		}
		g.mu.Unlock()
	}
	return nil
}

// body checks the content of authentication messages.
func (g *guard) body(typ byte, b []byte) error {
	if typ != 'R' {
		return nil
	}
	if len(b) < 4 {
		return fmt.Errorf("%w: malformed authentication message", ErrNotScram)
	}
	code, data := binary.BigEndian.Uint32(b), b[4:]
	switch {
	case code == 3 || code == 5:
		return ErrCleartextRequested
	case code == 0 && (g.auth == authFinal || g.auth == authStart && g.allowTrust):
		g.auth = authDone
	case code == 10 && g.auth == authStart:
		if g.allowTrust {
			return fmt.Errorf("%w: SASL requested from a target without a salt", ErrScramParams)
		}
		mechs := strings.Split(string(data), "\x00")
		found := false
		for _, m := range mechs {
			found = found || m == "SCRAM-SHA-256"
		}
		if !found {
			return fmt.Errorf("%w: SCRAM-SHA-256 not offered", ErrNotScram)
		}
		g.auth = authSASL
	case code == 11 && g.auth == authSASL:
		if err := g.checkServerFirst(data); err != nil {
			return err
		}
		g.auth = authContinue
	case code == 12 && g.auth == authContinue:
		g.auth = authFinal
	default:
		return fmt.Errorf("%w: authentication request %d refused", ErrNotScram, code)
	}
	return nil
}

// checkServerFirst requires the server-first message "r=…,s=…,i=…" to carry
// exactly the platform's salt and iteration count, so the client derives keys
// only for the verifier the platform set.
func (g *guard) checkServerFirst(data []byte) error {
	f := bytes.Split(data, []byte(","))
	if len(f) != 3 || !bytes.HasPrefix(f[0], []byte("r=")) || !bytes.HasPrefix(f[1], []byte("s=")) || !bytes.HasPrefix(f[2], []byte("i=")) {
		return fmt.Errorf("%w: malformed server-first message", ErrScramParams)
	}
	salt, err := base64.StdEncoding.DecodeString(string(f[1][2:]))
	if err != nil || subtle.ConstantTimeCompare(salt, g.salt) != 1 {
		return fmt.Errorf("%w: salt differs from the platform's", ErrScramParams)
	}
	if string(f[2][2:]) != strconv.Itoa(scramIterations) {
		return fmt.Errorf("%w: iteration count differs from %d", ErrScramParams, scramIterations)
	}
	return nil
}
