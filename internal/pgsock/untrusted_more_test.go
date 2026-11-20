package pgsock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ───────── pipelined statements ─────────

// segment is the reply to one SendQueryParams followed by a Sync.
func segment(withZ bool) []byte {
	b := bytes.Join([][]byte{msg('1', nil), msg('2', nil), msg('n', nil), msg('C', []byte("SELECT 0\x00"))}, nil)
	if withZ {
		b = append(b, msg('Z', []byte{'I'})...)
	}
	return b
}

// readSyncs reads frontend messages until n Sync (or Flush, when flush) messages arrived.
func readSyncs(c *fconn, n int, flush bool) error {
	for n > 0 {
		t, _, err := c.read()
		if err != nil {
			return err
		}
		if t == 'S' || flush && t == 'H' {
			n--
		}
	}
	return nil
}

// runPipeline sends n statements, each followed by a Sync unless noSync, and
// reads every result. Server errors are results, not the end.
func runPipeline(c *pgx.Conn, n int, noSync bool) error {
	p := c.PgConn().StartPipeline(context.Background())
	defer p.Close()
	for i := 0; i < n; i++ {
		p.SendQueryParams("select 1", nil, nil, nil, nil)
		if noSync {
			p.SendFlushRequest()
		} else {
			p.SendPipelineSync()
		}
	}
	if err := p.Flush(); err != nil {
		return err
	}
	want := n
	for want > 0 {
		r, err := p.GetResults()
		if err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) {
				continue
			}
			return err
		}
		switch r := r.(type) {
		case *pgconn.ResultReader:
			if _, err := r.Close(); err != nil {
				var pe *pgconn.PgError
				if !errors.As(err, &pe) {
					return err
				}
			}
			if noSync {
				want--
			}
		case *pgconn.PipelineSync:
			want--
		case nil:
			return errors.New("pipeline ended early")
		}
	}
	return nil
}

func TestUntrusted_PipelineEachStatementBounded(t *testing.T) {
	const stmt = time.Second
	cases := []struct {
		name    string
		n       int
		noSync  bool
		reply   func(c *fconn) error
		wantOK  bool
		maxTime time.Duration
	}{
		{"three syncs, each answered within the bound, together beyond it", 3, false, func(c *fconn) error {
			readSyncs(c, 3, false)
			for i := 0; i < 3; i++ {
				time.Sleep(400 * time.Millisecond)
				c.Write(segment(true))
			}
			return nil
		}, true, 5 * time.Second},
		{"three syncs, two answered, then silent", 3, false, func(c *fconn) error {
			readSyncs(c, 3, false)
			c.Write(append(segment(true), segment(true)...))
			return nil
		}, false, 5 * time.Second},
		{"error mid-pipeline, then silent", 2, false, func(c *fconn) error {
			readSyncs(c, 2, false)
			c.Write(append(msg('E', []byte("SERROR\x00C42601\x00Mx\x00\x00")), msg('Z', []byte{'I'})...))
			return nil
		}, false, 5 * time.Second},
		{"extended protocol without a Sync, silent", 1, true, func(c *fconn) error {
			readSyncs(c, 1, true)
			return nil
		}, false, 5 * time.Second},
		{"fewer ReadyForQuery than Syncs", 2, false, func(c *fconn) error {
			readSyncs(c, 2, false)
			c.Write(append(segment(true), segment(false)...))
			return nil
		}, false, 5 * time.Second},
		{"more ReadyForQuery than Syncs, then a silent pipeline", 1, false, func(c *fconn) error {
			readSyncs(c, 1, false)
			c.Write(bytes.Join([][]byte{segment(true), msg('Z', []byte{'I'}), msg('Z', []byte{'I'})}, nil))
			return nil
		}, true, 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, func(c *fconn) error {
				if err := c.login(); err != nil {
					return err
				}
				return tc.reply(c)
			})
			tg := f.target(t)
			tg.Budget = Budget{Connect: 2 * time.Second, Statement: stmt, Session: 10 * time.Second}
			c, err := dial(t, tg)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err = runPipeline(c.c, tc.n, tc.noSync)
			el := time.Since(start)
			row("| pipeline: %s | %s | %v |", tc.name, errClass(err), el.Round(time.Millisecond))
			if tc.wantOK != (err == nil) || el > tc.maxTime {
				t.Fatalf("err %v after %v", err, el)
			}
			if !tc.wantOK && !IsBudget(err) {
				t.Fatalf("err %v is not a budget error", err)
			}
			if tc.name == "more ReadyForQuery than Syncs, then a silent pipeline" {
				// the surplus ReadyForQuery messages are still queued: the next
				// pipelines end promptly, by the library's refusal or the bound
				start = time.Now()
				for i := 0; i < 4 && err == nil; i++ {
					err = runPipeline(c.c, 1, false)
				}
				el = time.Since(start)
				row("| pipeline: after surplus ReadyForQuery, silent | %s | %v |", errClass(err), el.Round(time.Millisecond))
				if err == nil || el > 5*time.Second {
					t.Fatalf("after surplus ReadyForQuery: err %v after %v", err, el)
				}
			}
		})
	}
}

// Honest pipelines separated by idle gaps longer than the statement bound:
// no deadline is left armed across the gaps.
func TestUntrusted_PipelineIdleGapsNotCharged(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		if err := c.login(); err != nil {
			return err
		}
		for i := 0; i < 4; i++ {
			if err := readSyncs(c, 2, false); err != nil {
				return err
			}
			c.Write(append(segment(true), segment(true)...))
		}
		return nil
	})
	tg := f.target(t)
	tg.Budget.Statement = 300 * time.Millisecond
	c, err := dial(t, tg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := runPipeline(c.c, 2, false); err != nil {
			t.Fatalf("pipeline %d: %v", i, err)
		}
		time.Sleep(400 * time.Millisecond)
	}
}

// ───────── serialized reads ─────────

func pipeGuard(t *testing.T, b Budget) (*guard, net.Conn) {
	t.Helper()
	cl, sv := net.Pipe()
	t.Cleanup(func() { cl.Close(); sv.Close() })
	return newGuard(cl, b.withDefaults(), testSalt(), false, time.Now()), sv
}

// twoReaders starts two concurrent reads and returns a channel of their
// results and elapsed times.
func twoReaders(g *guard) chan error {
	ch := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := g.Read(make([]byte, 64))
			ch <- err
		}()
	}
	return ch
}

func waitBoth(t *testing.T, ch chan error, within time.Duration) []error {
	t.Helper()
	var errs []error
	deadline := time.After(within)
	for len(errs) < 2 {
		select {
		case err := <-ch:
			errs = append(errs, err)
		case <-deadline:
			t.Fatalf("readers still blocked after %v (%d returned)", within, len(errs))
		}
	}
	return errs
}

func TestUntrusted_ConcurrentReads(t *testing.T) {
	long := Budget{Connect: 20 * time.Second, Statement: 20 * time.Second, Session: 20 * time.Second}
	t.Run("deadline moved while one read blocks and one waits", func(t *testing.T) {
		g, _ := pipeGuard(t, long)
		ch := twoReaders(g)
		time.Sleep(100 * time.Millisecond)
		g.SetReadDeadline(time.Now())
		for _, err := range waitBoth(t, ch, 5*time.Second) {
			if err == nil {
				t.Fatal("read succeeded")
			}
		}
	})
	t.Run("Close while one read blocks and one waits", func(t *testing.T) {
		g, _ := pipeGuard(t, long)
		ch := twoReaders(g)
		time.Sleep(100 * time.Millisecond)
		g.Close()
		waitBoth(t, ch, 5*time.Second)
	})
	t.Run("connect bound with two readers", func(t *testing.T) {
		g, _ := pipeGuard(t, Budget{Connect: 300 * time.Millisecond, Statement: 20 * time.Second, Session: 20 * time.Second})
		start := time.Now()
		ch := twoReaders(g)
		for _, err := range waitBoth(t, ch, 5*time.Second) {
			if !errors.Is(err, ErrBudget) {
				t.Fatalf("err %v", err)
			}
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("both returned after %v", el)
		}
	})
	t.Run("budget refusal while another reader waits", func(t *testing.T) {
		g, sv := pipeGuard(t, long)
		ch := twoReaders(g)
		time.Sleep(50 * time.Millisecond)
		go sv.Write([]byte{'R', 0x40, 0, 0, 0})
		for _, err := range waitBoth(t, ch, 5*time.Second) {
			if !errors.Is(err, ErrBudget) {
				t.Fatalf("err %v", err)
			}
		}
	})
	t.Run("library deadline in the future does not extend the bound", func(t *testing.T) {
		g, _ := pipeGuard(t, Budget{Connect: 300 * time.Millisecond, Statement: 20 * time.Second, Session: 20 * time.Second})
		ch := twoReaders(g)
		time.Sleep(50 * time.Millisecond)
		g.SetReadDeadline(time.Now().Add(time.Hour))
		for _, err := range waitBoth(t, ch, 5*time.Second) {
			if !errors.Is(err, ErrBudget) {
				t.Fatalf("err %v", err)
			}
		}
	})
}

// ───────── cleaned errors ─────────

// A statement error that is not a server error but quotes server-supplied
// column names and values must leave Clean sanitized.
func TestUntrusted_CleanNonServerErrors(t *testing.T) {
	name := "col\x1b[31m\u202eevil"
	value := "\x1b]0;title\x07abc\u2066"
	f := newFake(t, afterQuery(func(c *fconn) error {
		fd := append([]byte{0, 1}, []byte(name+"\x00")...)
		fd = append(fd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 0xff, 0xff, 0xff, 0xff, 0, 0)
		row := append([]byte{0, 1, 0, 0, 0, byte(len(value))}, value...)
		c.Write(bytes.Join([][]byte{msg('T', fd), msg('D', row), msg('C', []byte("SELECT 1\x00")), msg('Z', []byte{'I'})}, nil))
		return nil
	}))
	c, err := dial(t, f.target(t))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = c.c.QueryRow(context.Background(), "select", pgx.QueryExecModeSimpleProtocol).Scan(&n)
	cl := Clean(err)
	row("clean: scan error %q → Clean %q", err, cl)
	if err == nil {
		t.Fatal("scan succeeded")
	}
	for _, s := range []string{cl.Error(), fmt.Sprintf("%+v", cl), fmt.Sprintf("%#v", cl)} {
		assertClean(t, s)
		if strings.ContainsAny(s, "\u202e\u2066") {
			t.Fatalf("Clean kept format characters: %q", s)
		}
	}
}

func TestUntrusted_CleanEdges(t *testing.T) {
	pe := &pgconn.PgError{Code: "4\x1b[0", Message: "m\x1b[2J\u202e", Detail: "DETAIL-RAW", Hint: "HINT-RAW"}
	for name, err := range map[string]error{
		"joined with raw text": errors.Join(errors.New("raw\x1b[31m"), pe),
		"wrapped twice":        fmt.Errorf("a: %w", fmt.Errorf("b: %w", pe)),
	} {
		cl := Clean(err)
		var got *pgconn.PgError
		if errors.As(cl, &got) {
			t.Fatalf("%s: raw server error reachable", name)
		}
		for _, s := range []string{cl.Error(), fmt.Sprintf("%+v", cl), fmt.Sprintf("%#v", cl), fmt.Sprintf("%v", []error{cl})} {
			if strings.Contains(s, "RAW") || strings.ContainsAny(s, "\x1b\u202e") {
				t.Fatalf("%s: %q", name, s)
			}
		}
		var se *ServerError
		if !errors.As(cl, &se) || se.Code != "" {
			t.Fatalf("%s: server error %+v", name, se)
		}
	}
}

// Every error Dial returns, whatever the server sent, has no path to raw text.
func TestUntrusted_DialErrorsHaveNoRawPath(t *testing.T) {
	for _, tc := range authCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, tc.script)
			tg := f.target(t)
			tg.Budget.Connect = 2 * time.Second
			c, err := dial(t, tg)
			if c != nil {
				c.close()
			}
			f.result(t)
			if err == nil {
				return
			}
			var pe *pgconn.PgError
			if errors.As(err, &pe) {
				t.Fatal("Dial error unwraps to *pgconn.PgError")
			}
			for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
				assertClean(t, s)
				if strings.ContainsAny(s, "\u202e") {
					t.Fatalf("format character kept: %q", s)
				}
			}
		})
	}
}

// ───────── redaction ─────────

type withExported struct{ T Target }
type withUnexported struct{ t Target }
type withPointer struct{ T *Target }

func TestUntrusted_TargetRedactedEverywhere(t *testing.T) {
	tg := Target{Ref: testRef, User: testUser, Password: testPassword, ScramSalt: testSalt()}
	salt64 := base64.StdEncoding.EncodeToString(testSalt())
	check := func(name, s string) {
		leaked := strings.Contains(s, testPassword) || strings.Contains(s, salt64) || strings.Contains(s, fmt.Sprint(testSalt()))
		row("redaction: %s leaks: %v", name, leaked)
		// fmt and slog's text handler print an unexported field by reflection,
		// without calling any method of Target: no method can redact it there
		if leaked && !strings.HasPrefix(name, "unexported field") {
			t.Errorf("%s prints a secret", name)
		}
	}
	for _, v := range []struct {
		name string
		v    any
	}{
		{"value", tg}, {"pointer", &tg}, {"slice", []Target{tg}}, {"map", map[string]Target{"a": tg}},
		{"exported field", withExported{tg}}, {"unexported field", withUnexported{tg}}, {"pointer field", withPointer{&tg}},
	} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			check(v.name+" "+verb, fmt.Sprintf(verb, v.v))
		}
		b, _ := json.Marshal(v.v)
		check(v.name+" json.Marshal", string(b))
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v.v)
		check(v.name+" slog JSON", buf.String())
		buf.Reset()
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "v", v.v)
		check(v.name+" slog text", buf.String())
	}
}

// ───────── environment and placeholder password ─────────

// Files the library would open from the home directory are FIFOs: opening
// one blocks, so a dial that returns proves none was opened.
func TestUntrusted_HomeFilesNeverOpened(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".postgresql"), 0o700)
	for _, p := range []string{".pgpass", ".pg_service.conf", ".postgresql/postgresql.crt", ".postgresql/postgresql.key",
		".postgresql/root.crt", ".postgresql/root.crl"} {
		if err := syscall.Mkfifo(filepath.Join(home, p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	f := newFake(t, func(c *fconn) error { return c.login() })
	done := make(chan error, 1)
	go func() {
		c, err := Dial(context.Background(), f.target(t))
		if err == nil {
			c.Close(context.Background())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial blocked: a file under HOME was opened")
	}
	f.result(t)
}

// The placeholder password of the connection string is never used: a target
// with an empty password proves with the empty password.
func TestUntrusted_PlaceholderPasswordNeverUsed(t *testing.T) {
	var proofFor []string
	var mu sync.Mutex
	f := newFake(t, func(c *fconn) error {
		n, err := saslStart(c)
		if err != nil {
			return err
		}
		sfirst := "r=" + n + "srv,s=" + b64salt() + ",i=4096"
		c.auth(11, []byte(sfirst))
		_, body, err := c.read()
		if err != nil {
			return err
		}
		fin := string(body)
		j := strings.LastIndex(fin, ",p=")
		proof, _ := base64.StdEncoding.DecodeString(fin[j+3:])
		authMsg := "n=,r=" + n + "," + sfirst + "," + fin[:j]
		for _, pw := range []string{"", "unused", testPassword} {
			ck := hm(pbkdf2Key(pw, testSalt()), "Client Key")
			st := sha256Sum(ck)
			sig := hm(st, authMsg)
			ok := len(proof) == len(sig)
			for k := range sig {
				ok = ok && proof[k]^sig[k] == ck[k]
			}
			if ok {
				mu.Lock()
				proofFor = append(proofFor, pw)
				mu.Unlock()
			}
		}
		return nil
	})
	tg := f.target(t)
	tg.Password = ""
	tg.Budget.Connect = time.Second
	dial(t, tg)
	f.result(t)
	mu.Lock()
	defer mu.Unlock()
	row("placeholder: proof computed for %q", proofFor)
	if len(proofFor) != 1 || proofFor[0] != "" {
		t.Fatalf("proof was for %q, want the empty password", proofFor)
	}
}

// Under strace (when available): no open of a password or service file.
func TestUntrusted_NoConfigFilesOpenedStrace(t *testing.T) {
	if os.Getenv("SOCK_TEST_STRACE") == "1" {
		f := newFake(t, func(c *fconn) error { return c.login() })
		c, err := dial(t, f.target(t))
		if err != nil {
			t.Fatal(err)
		}
		c.close()
		f.result(t)
		return
	}
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace not installed")
	}
	out := filepath.Join(t.TempDir(), "trace")
	cmd := exec.Command("strace", "-f", "-qq", "-e", "trace=open,openat,openat2,stat,newfstatat,statx,access,faccessat2", "-o", out,
		os.Args[0], "-test.run", "^TestUntrusted_NoConfigFilesOpenedStrace$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SOCK_TEST_STRACE=1")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("strace unusable here: %v %s", err, b)
	}
	b, _ := os.ReadFile(out)
	var hits []string
	for _, l := range strings.Split(string(b), "\n") {
		// the library stats default certificate paths; opening any of these files is the failure
		if (strings.Contains(l, "open") || strings.Contains(l, "access")) && (strings.Contains(l, "pgpass") ||
			strings.Contains(l, "pg_service") || strings.Contains(l, ".postgresql") || strings.Contains(l, "pgsysconf")) ||
			strings.Contains(l, "pgpass") || strings.Contains(l, "pg_service") {
			hits = append(hits, l)
		}
	}
	row("strace: %d opens of password, service or certificate files, or any access to the first two: %q", len(hits), hits)
	if len(hits) != 0 {
		t.Fatalf("files touched:\n%s", strings.Join(hits, "\n"))
	}
}

// ───────── after a timeout the connection fails fast ─────────

func TestUntrusted_DeadConnFailsFast(t *testing.T) {
	f := newFake(t, func(c *fconn) error { return c.login() })
	tg := f.target(t)
	tg.Budget = Budget{Connect: 2 * time.Second, Statement: 300 * time.Millisecond, Session: 600 * time.Millisecond}
	c, err := dial(t, tg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.c.WaitForNotification(context.Background())
	closed := c.c.IsClosed()
	start := time.Now()
	_, err2 := c.c.Exec(context.Background(), "select 1")
	el := time.Since(start)
	row("dead conn: WaitForNotification %s, IsClosed %v, next Exec %s after %v", errClass(err), closed, errClass(err2), el.Round(time.Millisecond))
	if !IsBudget(err) || err2 == nil || el > 250*time.Millisecond {
		t.Fatalf("wait %v, exec %v after %v", err, err2, el)
	}
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// row appends a line to $SOCK_TEST_TABLE when set (a PG* name would be
// cleared by TestMain).
func row(format string, a ...any) {
	p := os.Getenv("SOCK_TEST_TABLE")
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", a...)
}
