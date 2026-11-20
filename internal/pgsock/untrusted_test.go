package pgsock

import (
	"bufio"
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// ───────── authentication sequences ─────────

// saslStart reads the startup packet, offers SCRAM-SHA-256 and returns the
// client nonce from the initial response.
func saslStart(c *fconn) (string, error) {
	c.startup()
	if err := c.auth(10, []byte("SCRAM-SHA-256\x00\x00")); err != nil {
		return "", err
	}
	t, body, err := c.read()
	if err != nil || t != 'p' {
		return "", fmt.Errorf("want SASLInitialResponse, got %q %v", t, err)
	}
	i := bytes.Index(body, []byte("r="))
	if i < 0 {
		return "", errors.New("no nonce")
	}
	return string(body[i+2:]), nil
}

func b64salt() string { return base64.StdEncoding.EncodeToString(testSalt()) }

// serverFirst sends a server-first message built from the client nonce.
func serverFirst(build func(nonce string) string) func(c *fconn) error {
	return func(c *fconn) error {
		n, err := saslStart(c)
		if err != nil {
			return err
		}
		return c.auth(11, []byte(build(n)))
	}
}

func rawAfterStartup(raw ...[]byte) func(c *fconn) error {
	return func(c *fconn) error {
		c.startup()
		_, err := c.Write(bytes.Join(raw, nil))
		return err
	}
}

func nonCanonicalSalt() string {
	s := []byte(b64salt()) // 16 bytes: 22 significant characters + "=="
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, s[21])
	s[21] = alphabet[i|0x0f] // the low four bits of the last character are padding bits
	return string(s)
}

type authCase struct {
	name      string
	script    func(c *fconn) error
	conforms  bool // the server-first message, if any, carries the platform's salt and count
	wantLogin bool
	want      error // the guard's own refusal, when it is the guard that refuses
}

func authCases() []authCase {
	sf := func(format string) func(c *fconn) error {
		return serverFirst(func(n string) string { return strings.ReplaceAll(format, "NONCE", n) })
	}
	honest := func(c *fconn) error { return c.login() }
	var cases []authCase
	for _, code := range []uint32{2, 3, 5, 6, 7, 8, 9, 13, 0xffffffff} {
		code := code
		want := ErrNotScram
		if code == 3 || code == 5 {
			want = ErrCleartextRequested
		}
		cases = append(cases, authCase{name: fmt.Sprintf("R/%d at start", code), want: want,
			script: func(c *fconn) error { c.startup(); return c.auth(code, []byte{1, 2, 3, 4}) }})
	}
	cases = append(cases,
		authCase{name: "R/0 at start (no trust)", want: ErrNotScram, script: func(c *fconn) error { c.startup(); return c.ready() }},
		authCase{name: "R/11 at start", want: ErrNotScram, script: func(c *fconn) error { c.startup(); return c.auth(11, []byte("r=x,s="+b64salt()+",i=4096")) }},
		authCase{name: "R/12 at start", want: ErrNotScram, script: func(c *fconn) error { c.startup(); return c.auth(12, []byte("v=AAAA")) }},
		authCase{name: "SASL list: only -PLUS", want: ErrNotScram, script: func(c *fconn) error { c.startup(); return c.auth(10, []byte("SCRAM-SHA-256-PLUS\x00\x00")) }},
		authCase{name: "SASL list: OAUTHBEARER only", want: ErrNotScram, script: func(c *fconn) error { c.startup(); return c.auth(10, []byte("OAUTHBEARER\x00\x00")) }},
		authCase{name: "SASL list: unterminated SCRAM-SHA-256", script: func(c *fconn) error { c.startup(); return c.auth(10, []byte("SCRAM-SHA-256")) }},
		authCase{name: "SASL list: -PLUS, OAUTHBEARER, SCRAM-SHA-256 then honest", conforms: true, wantLogin: true, script: func(c *fconn) error {
			c.startup()
			c.auth(10, []byte("SCRAM-SHA-256-PLUS\x00OAUTHBEARER\x00SCRAM-SHA-256\x00\x00"))
			t, body, err := c.read()
			if err != nil || t != 'p' || !bytes.HasPrefix(body, []byte("SCRAM-SHA-256\x00")) {
				return fmt.Errorf("initial response %q %q %v", t, body, err)
			}
			cn := string(body[bytes.Index(body, []byte("r="))+2:])
			return finishScram(c, cn, "n=,r="+cn)
		}},
		authCase{name: "SASL requested twice", want: ErrNotScram, script: func(c *fconn) error {
			if _, err := saslStart(c); err != nil {
				return err
			}
			return c.auth(10, []byte("SCRAM-SHA-256\x00\x00"))
		}},
		authCase{name: "R/0 after SASL list", want: ErrNotScram, script: func(c *fconn) error {
			if _, err := saslStart(c); err != nil {
				return err
			}
			return c.ready()
		}},
		authCase{name: "R/12 instead of server-first", want: ErrNotScram, script: func(c *fconn) error {
			if _, err := saslStart(c); err != nil {
				return err
			}
			return c.auth(12, []byte("v=AAAA"))
		}},
		authCase{name: "ErrorResponse after client-first", script: func(c *fconn) error {
			if _, err := saslStart(c); err != nil {
				return err
			}
			return c.send('E', []byte("SFATAL\x00C28P01\x00Mbad \x1b[2Jpassword\x00\x00"))
		}},
		authCase{name: "notices interleaved, honest", conforms: true, script: func(c *fconn) error {
			c.startup()
			n := msg('N', []byte("SNOTICE\x00Mhi\x00\x00"))
			c.Write(n)
			c.auth(10, []byte("SCRAM-SHA-256\x00\x00"))
			c.Write(n)
			t, body, err := c.read()
			if err != nil || t != 'p' {
				return err
			}
			cn := string(body[bytes.Index(body, []byte("r="))+2:])
			return finishScram(c, cn, "n=,r="+cn)
		}},
		authCase{name: "NegotiateProtocolVersion first, honest", conforms: true, wantLogin: true, script: func(c *fconn) error {
			c.startup()
			c.send('v', []byte{0, 0, 0, 0, 0, 0, 0, 0})
			c.auth(10, []byte("SCRAM-SHA-256\x00\x00"))
			t, body, err := c.read()
			if err != nil || t != 'p' {
				return err
			}
			cn := string(body[bytes.Index(body, []byte("r="))+2:])
			return finishScram(c, cn, "n=,r="+cn)
		}},
		authCase{name: "ParameterStatus before auth", want: ErrNotScram, script: rawAfterStartup(msg('S', []byte("a\x00b\x00")))},
		authCase{name: "BackendKeyData before auth", want: ErrNotScram, script: rawAfterStartup(msg('K', make([]byte, 8)))},
		authCase{name: "ReadyForQuery before auth", want: ErrNotScram, script: rawAfterStartup(msg('Z', []byte{'I'}))},
		authCase{name: "RowDescription before auth", want: ErrNotScram, script: rawAfterStartup(msg('T', []byte{0, 0}))},
		authCase{name: "SSL 'S' byte then SASL", script: rawAfterStartup([]byte{'S'}, msg('R', authBody(10, []byte("SCRAM-SHA-256\x00\x00"))))},
		authCase{name: "SSL 'N' byte then SASL", script: rawAfterStartup([]byte{'N'}, msg('R', authBody(10, []byte("SCRAM-SHA-256\x00\x00"))))},
		authCase{name: "zero-length body R", want: ErrNotScram, script: rawAfterStartup([]byte{'R', 0, 0, 0, 4})},
		authCase{name: "length field 0", want: ErrBudget, script: rawAfterStartup([]byte{'R', 0, 0, 0, 0})},
		authCase{name: "length field 3", want: ErrBudget, script: rawAfterStartup([]byte{'R', 0, 0, 0, 3})},
		authCase{name: "length field 0xFFFFFFFF", want: ErrBudget, script: rawAfterStartup([]byte{'R', 0xff, 0xff, 0xff, 0xff})},
		authCase{name: "length field 0x80000000", want: ErrBudget, script: rawAfterStartup([]byte{'R', 0x80, 0, 0, 0})},
		authCase{name: "truncated R/10 then close", script: func(c *fconn) error {
			c.startup()
			c.Write([]byte{'R', 0, 0, 0, 100, 0, 0, 0, 10, 'S'})
			return c.Conn.(*net.UnixConn).CloseWrite()
		}},
		authCase{name: "server-first reordered s,r,i", want: ErrScramParams, script: sf("s=" + b64salt() + ",r=NONCEsrv,i=4096")},
		authCase{name: "server-first duplicated r", want: ErrScramParams, script: sf("r=NONCEsrv,r=NONCEsrv,s=" + b64salt() + ",i=4096")},
		authCase{name: "server-first duplicated s", want: ErrScramParams, script: sf("r=NONCEsrv,s=" + b64salt() + ",s=" + b64salt() + ",i=4096")},
		authCase{name: "server-first extension m= first", want: ErrScramParams, script: sf("m=x,r=NONCEsrv,s=" + b64salt() + ",i=4096")},
		authCase{name: "server-first extra attribute", want: ErrScramParams, script: sf("r=NONCEsrv,s=" + b64salt() + ",i=4096,x=y")},
		authCase{name: "server-first trailing comma", want: ErrScramParams, script: sf("r=NONCEsrv,s=" + b64salt() + ",i=4096,")},
		authCase{name: "server-first foreign salt", want: ErrScramParams, script: sf("r=NONCEsrv,s=" + base64.StdEncoding.EncodeToString(make([]byte, 16)) + ",i=4096")},
		authCase{name: "server-first salt unpadded", want: ErrScramParams, script: sf("r=NONCEsrv,s=" + base64.RawStdEncoding.EncodeToString(testSalt()) + ",i=4096")},
		authCase{name: "server-first salt URL alphabet", conforms: base64.URLEncoding.EncodeToString(testSalt()) == b64salt(), script: sf("r=NONCEsrv,s=" + base64.URLEncoding.EncodeToString(testSalt()) + ",i=4096")},
		authCase{name: "server-first empty salt", want: ErrScramParams, script: sf("r=NONCEsrv,s=,i=4096")},
		authCase{name: "server-first nonce does not extend the client's", conforms: true, script: sf("r=AAAAAAAAAAAAAAAAAAAAAAAA,s=" + b64salt() + ",i=4096")},
		authCase{name: "server-first nonce equals the client's", conforms: true, script: sf("r=NONCE,s=" + b64salt() + ",i=4096")},
	)
	for _, it := range []string{"04096", "4096 ", " 4096", "+4096", "4096\x00", "4096\n", "0x1000", "99999999999999999999", "10000000", "0", "-1", "4095", "4097", ""} {
		cases = append(cases, authCase{name: fmt.Sprintf("iterations %q", it), want: ErrScramParams, script: sf("r=NONCEsrv,s=" + b64salt() + ",i=" + it)})
	}
	cases = append(cases,
		authCase{name: "salt non-canonical trailing bits, honest", conforms: true, wantLogin: true, script: func(c *fconn) error {
			n, err := saslStart(c)
			if err != nil {
				return err
			}
			return finishScramWith(c, n, "n=,r="+n, "r="+n+"srv,s="+nonCanonicalSalt()+",i=4096", false, "")
		}},
		authCase{name: "salt with embedded newline, honest", conforms: true, wantLogin: true, script: func(c *fconn) error {
			n, err := saslStart(c)
			if err != nil {
				return err
			}
			s := b64salt()
			return finishScramWith(c, n, "n=,r="+n, "r="+n+"srv,s="+s[:8]+"\n"+s[8:]+",i=4096", false, "")
		}},
		authCase{name: "server-final with e= attribute", conforms: true, script: func(c *fconn) error {
			n, err := saslStart(c)
			if err != nil {
				return err
			}
			return finishScramWith(c, n, "n=,r="+n, "", false, "e=invalid-proof")
		}},
		authCase{name: "server-final with wrong signature", conforms: true, script: func(c *fconn) error {
			n, err := saslStart(c)
			if err != nil {
				return err
			}
			return finishScramWith(c, n, "n=,r="+n, "", true, "")
		}},
		authCase{name: "server-final repeated", want: ErrNotScram, conforms: true, script: func(c *fconn) error {
			n, err := saslStart(c)
			if err != nil {
				return err
			}
			return finishScramWith(c, n, "n=,r="+n, "", false, "twice")
		}},
		authCase{name: "R/0 after server-first (no server-final)", want: ErrNotScram, conforms: true, script: func(c *fconn) error {
			n, err := saslStart(c)
			if err != nil {
				return err
			}
			c.auth(11, []byte("r="+n+"srv,s="+b64salt()+",i=4096"))
			c.read()
			return c.ready()
		}},
		authCase{name: "server-first repeated after client-final", want: ErrNotScram, conforms: true, script: func(c *fconn) error {
			n, err := saslStart(c)
			if err != nil {
				return err
			}
			c.auth(11, []byte("r="+n+"srv,s="+b64salt()+",i=4096"))
			c.read()
			return c.auth(11, []byte("r="+n+"srv,s="+b64salt()+",i=4096"))
		}},
		authCase{name: "honest then R/12 after AuthenticationOk", want: ErrBudget, conforms: true, script: func(c *fconn) error {
			c.startup()
			c.scram(scramOpts{})
			c.auth(0, nil)
			return c.auth(12, []byte("v=AAAA"))
		}},
		authCase{name: "honest then FATAL with escapes", conforms: true, script: func(c *fconn) error {
			c.startup()
			c.scram(scramOpts{})
			c.auth(0, nil)
			return c.send('E', []byte("SFATAL\x00C57P01\x00M\x1b]0;title\x07gone\u202eevil\x00\x00"))
		}},
		authCase{name: "honest", conforms: true, wantLogin: true, script: honest},
	)
	return cases
}

// finishScram completes an honest exchange after the initial response.
func finishScram(c *fconn, cnonce, bare string) error {
	return finishScramWith(c, cnonce, bare, "", false, "")
}

func finishScramWith(c *fconn, cnonce, bare, sfirst string, badSig bool, final string) error {
	if sfirst == "" {
		sfirst = "r=" + cnonce + "srv,s=" + b64salt() + ",i=4096"
	}
	if err := c.auth(11, []byte(sfirst)); err != nil {
		return err
	}
	t, body, err := c.read()
	if err != nil || t != 'p' {
		return fmt.Errorf("want SASLResponse, got %q %v", t, err)
	}
	fin := string(body)
	j := strings.LastIndex(fin, ",p=")
	salt := testSalt()
	sp := pbkdf2Key(testPassword, salt)
	authMsg := bare + "," + sfirst + "," + fin[:j]
	serverSig := hm(hm(sp, "Server Key"), authMsg)
	if badSig {
		serverSig[0] ^= 1
	}
	switch final {
	case "":
	case "twice":
		c.auth(12, []byte("v="+base64.StdEncoding.EncodeToString(serverSig)))
	default:
		return c.auth(12, []byte(final))
	}
	if err := c.auth(12, []byte("v="+base64.StdEncoding.EncodeToString(serverSig))); err != nil {
		return err
	}
	return c.ready()
}

func errClass(err error) string {
	if err == nil {
		return "nil"
	}
	var cls []string
	for _, e := range []struct {
		n string
		e error
	}{{"ErrNotSocket", ErrNotSocket}, {"ErrPeer", ErrPeer}, {"ErrCleartextRequested", ErrCleartextRequested},
		{"ErrNotScram", ErrNotScram}, {"ErrScramParams", ErrScramParams}, {"ErrBudget", ErrBudget},
		{"DeadlineExceeded", context.DeadlineExceeded}} {
		if errors.Is(err, e.e) {
			cls = append(cls, e.n)
		}
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		cls = append(cls, "PgError")
	}
	if len(cls) == 0 {
		return "library: " + err.Error()
	}
	return strings.Join(cls, "+")
}

// tableRow appends a line to $SOCK_TEST_TABLE when set.
func tableRow(format string, a ...any) {
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

// Every authentication sequence: nothing derived from the password is written
// unless the server-first message carried the platform's salt and count.
func TestUntrusted_AuthSequences(t *testing.T) {
	for _, tc := range authCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, tc.script)
			tg := f.target(t)
			tg.Budget.Connect = 2 * time.Second
			start := time.Now()
			c, err := dial(t, tg)
			el := time.Since(start)
			if c != nil {
				c.close()
			}
			r := f.result(t)
			types := r.types()
			ps := bytes.Count(types, []byte{'p'})
			tableRow("| %s | %q (%d bytes) | %s | %v |", tc.name, types, len(r.raw), errClass(err), el.Round(time.Millisecond))
			if bytes.Contains(r.raw, []byte(testPassword)) {
				t.Fatal("cleartext password written")
			}
			if !tc.conforms && ps > 1 {
				t.Fatalf("client-final written after a non-conforming exchange: %q", types)
			}
			if tc.wantLogin != (err == nil) {
				t.Fatalf("login %v, want %v (err %v)", err == nil, tc.wantLogin, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			if err != nil {
				assertClean(t, err.Error())
			}
			if el > 2500*time.Millisecond {
				t.Fatalf("decision took %v", el)
			}
		})
	}
}

// ───────── environment ─────────

func TestUntrusted_Environment(t *testing.T) {
	dir := t.TempDir()
	svc := filepath.Join(dir, "svc.conf")
	os.WriteFile(svc, []byte("[s]\nhost="+dir+"\nport=1\nsslmode=require\nuser=x\ndbname=x\noptions=-c role=x\n"), 0o600)
	pass := filepath.Join(dir, "pgpass")
	os.WriteFile(pass, []byte("*:*:*:*:other\n"), 0o600)
	hostile := map[string]string{
		"PGHOST": dir + ",/tmp", "PGPORT": "1", "PGDATABASE": "x", "PGUSER": "x", "PGPASSWORD": "other",
		"PGPASSFILE": pass, "PGAPPNAME": "x", "PGCONNECT_TIMEOUT": "1", "PGSSLMODE": "verify-full",
		"PGSSLNEGOTIATION": "direct", "PGTARGETSESSIONATTRS": "standby", "PGSERVICEFILE": svc, "PGSERVICE": "s",
		"PGTZ": "Asia/Tokyo", "PGOPTIONS": "-c search_path=public", "PGMINPROTOCOLVERSION": "3.2",
		"PGMAXPROTOCOLVERSION": "3.2", "PGCHANNELBINDING": "require", "PGREQUIREAUTH": "password,md5",
		"PGSSLCERTMODE": "require", "PGSSLROOTCERT": filepath.Join(dir, "missing"), "PGSSLKEY": filepath.Join(dir, "missing"),
		"PGSSLCERT": filepath.Join(dir, "missing"), "PGGSSENCMODE": "require",
		"PGSERVICE_BROKEN_VALUE_x": "missing", "PGX": "1",
	}
	// Each variable alone stops the dial before anything is read or connected,
	// and the error names the variable, never its value.
	for k, v := range hostile {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v+"-secret-value")
			f := newFake(t, func(c *fconn) error { return c.login() })
			_, err := dial(t, f.target(t))
			tableRow("env: %s set → %v", k, err)
			wantErr(t, err, ErrEnvironment)
			if !strings.Contains(err.Error(), k) || strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), dir) {
				t.Fatalf("error %q: must name %s and no value", err, k)
			}
			if err := CheckEnv(); !errors.Is(err, ErrEnvironment) {
				t.Fatalf("CheckEnv = %v", err)
			}
			f.noConnection(t)
		})
	}

	// All of them together: the configuration the dial would build is still fixed.
	for k, v := range hostile {
		t.Setenv(k, v)
	}
	tg := Target{User: testUser, Password: testPassword, Superuser: true}
	cfg, err := config(tg, DefaultBudget)
	if err != nil {
		t.Fatalf("config under every hostile value: %v", err)
	}
	if cfg.Host != "/pgsock" || cfg.Port != 5432 || cfg.Database != "postgres" || cfg.User != testUser ||
		cfg.Password != testPassword || len(cfg.Fallbacks) != 0 || cfg.TLSConfig != nil ||
		cfg.ChannelBinding != "disable" || cfg.MinProtocolVersion != "3.0" || cfg.MaxProtocolVersion != "3.0" ||
		cfg.SSLCertMode != "disable" || cfg.RequireAuth != "scram-sha-256" || cfg.ValidateConnect != nil ||
		fmt.Sprint(cfg.RuntimeParams) != fmt.Sprint(StartupParams(true)) {
		t.Fatalf("configuration taken from the environment: %+v", cfg.Config)
	}
}

// ───────── path race ─────────

const sysRenameat2 = 316 // amd64

func exchange(a, b string) error {
	pa, _ := syscall.BytePtrFromString(a)
	pb, _ := syscall.BytePtrFromString(b)
	_, _, e := syscall.Syscall6(sysRenameat2, uintptr(^uint(99)), uintptr(unsafe.Pointer(pa)), uintptr(^uint(99)), uintptr(unsafe.Pointer(pb)), 2, 0)
	if e != 0 {
		return e
	}
	return nil
}

func init() {
	if os.Getenv("PGSOCK_TEST_HELPER") != "swap" {
		return
	}
	// pairs a|b,c|d,...: exchange each pair twice per round until stdin closes
	var pairs [][2]string
	for _, p := range strings.Split(os.Getenv("PGSOCK_SWAP"), ",") {
		a, b, _ := strings.Cut(p, "|")
		pairs = append(pairs, [2]string{a, b})
	}
	var stop atomic.Bool
	go func() { io.Copy(io.Discard, os.Stdin); stop.Store(true) }()
	n := 0
	for !stop.Load() {
		for _, p := range pairs {
			if err := exchange(p[0], p[1]); err != nil {
				fmt.Fprintln(os.Stderr, "swap:", err)
				os.Exit(1)
			}
			exchange(p[0], p[1])
			n++
		}
	}
	fmt.Fprintln(os.Stderr, "swaps:", n)
	os.Exit(0)
}

func startHelper(t *testing.T, env []string, uid int) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if uid >= 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { stdin.Close(); cmd.Wait() }) }
	t.Cleanup(stop)
	return stop
}

// The tenant swaps directory, link, socket and hard link into place while the
// daemon dials thousands of times: the decoy may be connected to (then the
// peer check must refuse it) but never receives a byte.
func TestUntrusted_PathRace(t *testing.T) {
	uid := -1
	owner := os.Getuid()
	if os.Getuid() == 0 {
		uid, owner = 70124, 70124
	}
	root, err := os.MkdirTemp("", "pgr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	os.Chmod(root, 0o755)
	ref := filepath.Join(root, testRef)
	sock := filepath.Join(ref, "sock")
	decoyDir := filepath.Join(ref, "decoy")
	for _, d := range []string{ref, sock, decoyDir} {
		os.MkdirAll(d, 0o700)
		os.Chown(d, owner, owner)
	}
	real := filepath.Join(sock, ".s.PGSQL.5432")
	decoyPath := filepath.Join(decoyDir, ".s.PGSQL.5432")
	rl, rpid, rstart, _ := handoff(t, real, uid)
	dl, _, _, _ := handoff(t, decoyPath, uid)
	// tenant-made objects: a link to the decoy socket, a hard link of it, a link to the decoy directory
	os.Symlink(decoyPath, filepath.Join(sock, "lnk"))
	if err := os.Link(decoyPath, filepath.Join(sock, "hard")); err != nil {
		t.Fatal(err)
	}
	os.Symlink(decoyDir, filepath.Join(ref, "dirlnk"))
	for _, p := range []string{filepath.Join(sock, "lnk"), filepath.Join(ref, "dirlnk")} {
		os.Lchown(p, owner, owner)
	}

	var decoyConns, decoyBytes atomic.Int64
	go func() {
		for {
			c, err := dl.Accept()
			if err != nil {
				return
			}
			decoyConns.Add(1)
			go func() {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := io.Copy(io.Discard, c)
				decoyBytes.Add(n)
			}()
		}
	}()
	var realConns atomic.Int64
	go func() {
		for {
			nc, err := rl.Accept()
			if err != nil {
				return
			}
			realConns.Add(1)
			go func() {
				defer nc.Close()
				nc.SetDeadline(time.Now().Add(5 * time.Second))
				raw, mu := &bytes.Buffer{}, &sync.Mutex{}
				c := &fconn{Conn: nc, raw: raw, mu: mu}
				c.r = bufio.NewReader(teeReader{nc, raw, mu})
				c.login()
				io.Copy(io.Discard, c.r)
			}()
		}
	}()

	pairs := strings.Join([]string{
		sock + "|" + decoyDir,                    // directory exchanged with the decoy directory
		real + "|" + filepath.Join(sock, "lnk"),  // socket name exchanged with a link
		real + "|" + filepath.Join(sock, "hard"), // socket name exchanged with a hard link of the decoy
		sock + "|" + filepath.Join(ref, "dirlnk"),
	}, ",")
	stopSwap := startHelper(t, []string{"PGSOCK_TEST_HELPER=swap", "PGSOCK_SWAP=" + pairs}, uid)

	tg := Target{ProjectsDir: root, Ref: testRef, UID: owner, PostmasterPid: rpid, PostmasterStart: rstart,
		User: testUser, Password: testPassword, ScramSalt: testSalt(), Superuser: true,
		Budget: Budget{Connect: 3 * time.Second}}
	outcomes := map[string]int{}
	n := 3000
	if testing.Short() {
		n = 300
	}
	for i := 0; i < n; i++ {
		c, err := Dial(context.Background(), tg)
		if err == nil {
			c.Close(context.Background())
		}
		outcomes[errClass(err)]++
	}
	stopSwap()
	time.Sleep(200 * time.Millisecond)
	tableRow("race: %d dials as uid %d: outcomes %v; real listener conns %d; decoy conns %d, decoy bytes %d",
		n, uid, outcomes, realConns.Load(), decoyConns.Load(), decoyBytes.Load())
	t.Logf("outcomes %v real %d decoy conns %d bytes %d", outcomes, realConns.Load(), decoyConns.Load(), decoyBytes.Load())
	if decoyBytes.Load() != 0 {
		t.Fatalf("the decoy received %d bytes", decoyBytes.Load())
	}
	if outcomes["nil"] == 0 || outcomes["ErrPeer"] == 0 || outcomes["ErrNotSocket"] == 0 {
		t.Logf("race did not exercise every branch: %v", outcomes)
	}
}

// ───────── leaks ─────────

func fdCount(t *testing.T) int {
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// multiFake serves every connection with script.
func multiFake(t *testing.T, script func(c *fconn) error) *fake {
	t.Helper()
	f := newFake(t, nil)
	os.Remove(f.path)
	l, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			f.accepts.Add(1)
			go func() {
				defer nc.Close()
				nc.SetDeadline(time.Now().Add(5 * time.Second))
				raw, mu := &bytes.Buffer{}, &sync.Mutex{}
				c := &fconn{Conn: nc, raw: raw, mu: mu}
				c.r = bufio.NewReader(teeReader{nc, raw, mu})
				script(c)
				io.Copy(io.Discard, c.r)
			}()
		}
	}()
	return f
}

func TestUntrusted_NoLeaks(t *testing.T) {
	type kind struct {
		name   string
		script func(c *fconn) error
		mutate func(f *fake, tg *Target)
	}
	kinds := []kind{
		{"symlinked socket", nil, func(f *fake, tg *Target) {}},
		{"wrong owner", func(c *fconn) error { return nil }, func(f *fake, tg *Target) { tg.UID++ }},
		{"wrong start", func(c *fconn) error { return nil }, func(f *fake, tg *Target) { tg.PostmasterStart++ }},
		{"cleartext", func(c *fconn) error { c.startup(); return c.auth(3, nil) }, nil},
		{"foreign salt", func(c *fconn) error {
			c.startup()
			_, err := c.scram(scramOpts{salt: make([]byte, 16), noFinal: true})
			return err
		}, nil},
		{"oversized", func(c *fconn) error { c.startup(); _, err := c.Write([]byte{'R', 0x40, 0, 0, 0}); return err }, nil},
		{"flood", func(c *fconn) error {
			c.startup()
			for {
				if err := c.send('N', []byte("SNOTICE\x00Mx\x00\x00")); err != nil {
					return nil
				}
			}
		}, nil},
		{"login and query", func(c *fconn) error {
			if err := c.login(); err != nil {
				return err
			}
			return c.answer()
		}, nil},
	}
	runtime.GC()
	fd0, g0 := fdCount(t), runtime.NumGoroutine()
	for _, k := range kinds {
		f := multiFake(t, func(c *fconn) error {
			if k.script != nil {
				return k.script(c)
			}
			return nil
		})
		tg := f.target(t)
		if k.name == "symlinked socket" {
			os.Rename(f.path, f.path+".x")
			os.Symlink(f.path+".x", f.path)
		}
		if k.mutate != nil {
			k.mutate(f, &tg)
		}
		for i := 0; i < 250; i++ {
			c, err := Dial(context.Background(), tg)
			if err == nil {
				ctx, cancel := Stmt(context.Background(), tg.Budget)
				_, err = c.Exec(ctx, "select 1")
				cancel()
				c.Close(context.Background())
			}
			if (k.name == "login and query") != (err == nil) {
				t.Fatalf("%s: %v", k.name, err)
			}
		}
	}
	// The fakes' handlers end on their own: wait for the counts to settle.
	var fd1, g1 int
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		runtime.GC()
		fd1, g1 = fdCount(t), runtime.NumGoroutine()
		if fd1-fd0 <= 2*len(kinds)+2 && g1-g0 <= 2*len(kinds)+4 || time.Now().After(deadline) {
			break
		}
	}
	tableRow("leaks: 2000 dials (8 kinds x 250): fds %d → %d, goroutines %d → %d (fakes' listeners still open)", fd0, fd1, g0, g1)
	// each multiFake keeps its listener: one fd and one goroutine per kind
	if fd1-fd0 > 2*len(kinds)+2 { // two listeners per multiFake
		t.Fatalf("descriptors %d → %d", fd0, fd1)
	}
	if g1-g0 > 2*len(kinds)+4 {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines %d → %d\n%s", g0, g1, buf[:runtime.Stack(buf, true)])
	}
}

// ───────── allocation ─────────

// peakHeap runs fn while sampling the heap, and returns the peak heap in use
// above the starting point and the bytes allocated.
func peakHeap(fn func()) (peak, total uint64) {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	base, alloc0 := m.HeapAlloc, m.TotalAlloc
	var max atomic.Uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var s runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
			runtime.ReadMemStats(&s)
			if s.HeapAlloc > base && s.HeapAlloc-base > max.Load() {
				max.Store(s.HeapAlloc - base)
			}
		}
	}()
	fn()
	close(done)
	wg.Wait()
	runtime.ReadMemStats(&m)
	return max.Load(), m.TotalAlloc - alloc0
}

func TestUntrusted_HeapBounds(t *testing.T) {
	bigRow := msg('D', append([]byte{0, 1, 0, 0x0f, 0xff, 0xf5}, make([]byte, 0x0ffff5)...)) // a 1 MiB body
	smallRows := bytes.Repeat(msg('D', []byte{0, 1, 0, 0, 0, 1, '1'}), 8192)
	rowDesc := msg('T', []byte{0, 1, 'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0})
	psFlood := func() []byte {
		var b []byte
		for i := 0; i < 1000; i++ {
			b = append(b, msg('S', []byte(fmt.Sprintf("p%d\x00v\x00", i)))...)
		}
		return b
	}()
	cases := []struct {
		name  string
		query bool
		b     Budget
		then  func(c *fconn) error
	}{
		{"announces a 1 GiB message", true, Budget{}, func(c *fconn) error {
			_, err := c.Write([]byte{'D', 0x40, 0, 0, 4})
			c.Write(make([]byte, 1<<16))
			return err
		}},
		{"1 MiB rows at the cap, endless", true, Budget{}, func(c *fconn) error {
			c.Write(rowDesc)
			for {
				if _, err := c.Write(bigRow); err != nil {
					return nil
				}
			}
		}},
		{"endless small rows", true, Budget{}, func(c *fconn) error {
			c.Write(rowDesc)
			for {
				if _, err := c.Write(smallRows); err != nil {
					return nil
				}
			}
		}},
		{"1,000,000 parameter-status", true, Budget{}, func(c *fconn) error {
			for i := 0; i < 1000; i++ {
				if _, err := c.Write(psFlood); err != nil {
					return nil
				}
			}
			return nil
		}},
		{"notice flood", true, Budget{}, func(c *fconn) error {
			n := bytes.Repeat(msg('N', []byte("SNOTICE\x00Mx\x00\x00")), 1000)
			for {
				if _, err := c.Write(n); err != nil {
					return nil
				}
			}
		}},
		{"one byte per 100 ms (statement 1 s)", true, Budget{Statement: time.Second}, func(c *fconn) error {
			for _, x := range bytes.Repeat(msg('N', []byte("SNOTICE\x00Mslow\x00\x00")), 100) {
				if _, err := c.Write([]byte{x}); err != nil {
					return nil
				}
				time.Sleep(100 * time.Millisecond)
			}
			return nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, afterQuery(tc.then))
			tg := f.target(t)
			tg.Budget = tc.b
			var err error
			var el time.Duration
			peak, total := peakHeap(func() {
				start := time.Now()
				c, derr := Dial(context.Background(), tg)
				if derr != nil {
					err = derr
					return
				}
				_, err = c.Exec(context.Background(), "select 1")
				el = time.Since(start)
				c.Close(context.Background())
			})
			tableRow("| %s | %s | %v | peak heap +%.2f MiB | allocated %.2f MiB |", tc.name, errClass(err), el.Round(time.Millisecond),
				float64(peak)/(1<<20), float64(total)/(1<<20))
			if !errors.Is(err, ErrBudget) {
				t.Fatalf("err %v", err)
			}
			if peak > 3*uint64(DefaultBudget.Bytes) {
				t.Fatalf("peak heap %d", peak)
			}
			f.result(t)
		})
	}
}

// ───────── calls on the returned connection ─────────

func TestUntrusted_ConnCalls(t *testing.T) {
	silent := afterQuery(func(c *fconn) error { time.Sleep(4 * time.Second); return nil })
	noRead := func(c *fconn) error { // logs in, then never reads again
		if err := c.login(); err != nil {
			return err
		}
		time.Sleep(4 * time.Second)
		return nil
	}
	// Every call is ended by the budget (statement 500 ms, session 1.5 s from
	// the dial), never by the peer, whose script runs 4 s: the ceiling sits well
	// above the budget and well below the peer's end.
	b := Budget{Connect: 2 * time.Second, Statement: 500 * time.Millisecond, Session: 1500 * time.Millisecond}
	const bound = 3 * time.Second
	big := "select '" + strings.Repeat("x", 16<<20) + "'"
	cases := []struct {
		name   string
		script func(c *fconn) error
		call   func(c *pgx.Conn) error
	}{
		{"Exec of 16 MiB to a peer that never reads", noRead, func(c *pgx.Conn) error {
			_, err := c.Exec(context.Background(), big)
			return err
		}},
		{"Ping to a silent peer", silent, func(c *pgx.Conn) error { return c.Ping(context.Background()) }},
		// The context (150 ms) ends the call, not the guard's statement bound
		// (500 ms): the error is the context's deadline, not ErrBudget.
		{"Stmt context on a silent peer", silent, func(c *pgx.Conn) error {
			ctx, cancel := Stmt(context.Background(), Budget{Statement: 100 * time.Millisecond})
			defer cancel()
			_, err := c.Exec(ctx, "select 1")
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrBudget) {
				return fmt.Errorf("want the Stmt context's deadline, got %v", err)
			}
			return err
		}},
		{"WaitForNotification on a silent peer", noRead, func(c *pgx.Conn) error {
			_, err := c.WaitForNotification(context.Background())
			return err
		}},
		{"CopyFrom", afterQuery(func(c *fconn) error {
			c.send('G', []byte{0, 0, 1, 0, 0})
			time.Sleep(4 * time.Second)
			return nil
		}), func(c *pgx.Conn) error {
			_, err := c.CopyFrom(context.Background(), pgx.Identifier{"t"}, []string{"x"}, pgx.CopyFromRows([][]any{{1}}))
			return err
		}},
		{"SendBatch to a silent peer", silent, func(c *pgx.Conn) error {
			br := c.SendBatch(context.Background(), &pgx.Batch{QueuedQueries: []*pgx.QueuedQuery{{SQL: "select 1"}, {SQL: "select 2"}}})
			_, err := br.Exec()
			br.Close()
			return err
		}},
		{"Prepare to a silent peer", silent, func(c *pgx.Conn) error {
			_, err := c.Prepare(context.Background(), "s", "select 1")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, tc.script)
			tg := f.target(t)
			tg.Budget = b
			c, err := Dial(context.Background(), tg)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err = tc.call(c)
			el := time.Since(start)
			cs := time.Now()
			c.Close(context.Background())
			cl := time.Since(cs)
			tableRow("| %s | %s | %v | Close %v | accepts %d |", tc.name, errClass(err), el.Round(time.Millisecond), cl.Round(time.Millisecond), f.accepts.Load())
			if err == nil || el > bound || cl > 600*time.Millisecond {
				t.Fatalf("err %v after %v, close %v", err, el, cl)
			}
			if n := f.accepts.Load(); n != 1 {
				t.Fatalf("%d connections (a cancel request dialled?)", n)
			}
		})
	}

	t.Run("re-dial and cancel request through the returned connection", func(t *testing.T) {
		f := newFake(t, func(c *fconn) error { return c.login() })
		c, err := dial(t, f.target(t))
		if err != nil {
			t.Fatal(err)
		}
		cerr := c.c.PgConn().CancelRequest(context.Background())
		_, rerr := pgx.ConnectConfig(context.Background(), c.c.Config())
		tableRow("conn: CancelRequest → %v; ConnectConfig(conn.Config()) → %v; Config().Password visible: %v",
			cerr, rerr, c.c.Config().Password == testPassword)
		if cerr == nil || rerr == nil {
			t.Fatal("second connection allowed")
		}
		if _, ok := c.c.PgConn().Conn().(*guard); !ok {
			t.Fatal("PgConn().Conn() is not the guard")
		}
		c.close()
		time.Sleep(50 * time.Millisecond)
		if n := f.accepts.Load(); n != 1 {
			t.Fatalf("%d connections", n)
		}
	})
}

// ───────── Sanitize ─────────

func TestUntrusted_Sanitize(t *testing.T) {
	long := strings.Repeat("é", 1<<20)
	if s := Sanitize(long, 513); len(s) != 512 || !strings.HasSuffix(s, "é") {
		t.Fatalf("len %d", len(s))
	}
	if Sanitize("abc", -1) != "" {
		t.Fatal("negative max")
	}
}

func pbkdf2Key(pw string, salt []byte) []byte {
	k, _ := pbkdf2.Key(sha256.New, pw, salt, 4096, 32)
	return k
}

// A verifier for a password holding every printable ASCII character is
// accepted by the real server and the password logs in through Dial.
func TestUntrusted_VerifierEveryPrintableASCII(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("docker not reachable")
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("docker", "image", "inspect", im.ControlPlane).Run(); err != nil {
		t.Skipf("image %s not present", im.ControlPlane)
	}
	root, err := os.MkdirTemp("", "pgs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		exec.Command("docker", "run", "--rm", "-v", root+":/r", "--network", "none", "--entrypoint", "rm", im.ControlPlane, "-rf", "/r/"+testRef).Run()
		os.RemoveAll(root)
	})
	sock := filepath.Join(root, testRef, "sock")
	os.MkdirAll(sock, 0o755)
	os.Chmod(sock, 0o777)
	name := fmt.Sprintf("sp-test-pgsock-ascii-%d", os.Getpid())
	out, err := exec.Command("docker", "run", "-d", "--name", name, "--label", "supapace.test=1", "--network", "none",
		"-e", "POSTGRES_PASSWORD=initpw", "-e", "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256",
		"-v", sock+":/var/run/postgresql", im.ControlPlane).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	pidOut, _ := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", name).Output()
	var pid int
	fmt.Sscan(string(pidOut), &pid)
	start, err := ProcStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	var pw []byte
	for c := byte(0x20); c <= 0x7e; c++ {
		pw = append(pw, c)
	}
	tg := Target{ProjectsDir: root, Ref: testRef, UID: 70, PostmasterPid: pid, PostmasterStart: start,
		User: "postgres", Password: string(pw), ScramSalt: mustSalt(testDEK, testRef, "postgres"), Superuser: true}
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err = Dial(context.Background(), tg); errors.Is(err, ErrScramParams) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cluster not reachable: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	var prev *pgx.Conn
	defer func() {
		if prev != nil {
			prev.Close(context.Background())
		}
	}()
	for _, p := range []string{string(pw), " ", " leading and trailing ", `\'"`} {
		v, err := ScramVerifier(p, tg.ScramSalt)
		if err != nil {
			t.Fatal(err)
		}
		if prev == nil {
			if out, err := exec.Command("docker", "exec", "-e", "PGPASSWORD=initpw", name, "psql", "-v", "ON_ERROR_STOP=1",
				"-U", "postgres", "-d", "postgres", "-c", "ALTER ROLE postgres PASSWORD '"+v+"'").CombinedOutput(); err != nil {
				t.Fatalf("alter role: %v %s", err, out)
			}
		} else {
			if _, err := prev.Exec(context.Background(), "ALTER ROLE postgres PASSWORD '"+v+"'"); err != nil {
				t.Fatal(err)
			}
			prev.Close(context.Background())
		}
		tg.Password = p
		c, err := Dial(context.Background(), tg)
		if err != nil {
			t.Fatalf("password %q: %v", p, err)
		}
		prev = c
		tableRow("verifier for %q accepted by the server and logs in", p)
	}
}

// In pipeline mode a ReadyForQuery ends the guard's statement deadline while
// the next pipelined statement is still outstanding.
func TestUntrusted_PipelineAfterReadyForQuery(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		if err := c.login(); err != nil {
			return err
		}
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 1<<16)
		c.r.Read(buf)
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		var b []byte
		for _, m := range [][]byte{msg('1', nil), msg('2', nil), msg('n', nil), msg('C', []byte("SELECT 0\x00")), msg('Z', []byte{'I'})} {
			b = append(b, m...)
		}
		c.Write(b)
		time.Sleep(5 * time.Second)
		return nil
	})
	tg := f.target(t)
	tg.Budget = Budget{Connect: 2 * time.Second, Statement: 300 * time.Millisecond, Session: 10 * time.Second}
	c, err := dial(t, tg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	p := c.c.PgConn().StartPipeline(context.Background())
	p.SendQueryParams("select 1", nil, nil, nil, nil)
	p.SendPipelineSync()
	p.SendQueryParams("select 2", nil, nil, nil, nil)
	p.SendPipelineSync()
	err = p.Flush()
	for err == nil {
		var r any
		r, err = p.GetResults()
		if rr, ok := r.(*pgconn.ResultReader); ok {
			_, err = rr.Close()
		}
	}
	el := time.Since(start)
	p.Close()
	tableRow("pipeline: second pipelined statement after a ReadyForQuery ended after %v (statement bound 300ms, session 10s): %s", el.Round(time.Millisecond), errClass(err))
	if el > 3*time.Second {
		t.Errorf("pipelined statement bounded only by the session: %v", el)
	}
}

// The listener's creator runs at another uid than the socket's owner.
func TestUntrusted_PeerUIDDiffersFromSocketOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	const owner, other = 70125, 70126
	f := newFake(t, nil)
	os.Remove(f.path)
	os.Chmod(f.root, 0o755)
	for _, d := range []string{filepath.Join(f.root, testRef), f.sockDir} {
		os.Chown(d, other, other)
	}
	l, pid, start, _ := handoff(t, f.path, other)
	go f.serve(l, nil)
	if err := os.Chown(f.path, owner, owner); err != nil {
		t.Fatal(err)
	}
	tg := f.target(t)
	tg.UID, tg.PostmasterPid, tg.PostmasterStart = owner, pid, start
	_, err := dial(t, tg)
	wantErr(t, err, ErrPeer)
	if r := f.result(t); len(r.raw) != 0 {
		t.Fatalf("fake received %d bytes", len(r.raw))
	}
}

// A socket path longer than sun_path is reached through its descriptor.
func TestUntrusted_PathLongerThanSunPath(t *testing.T) {
	f := newFake(t, func(c *fconn) error { return c.login() })
	deep := filepath.Join(f.root, strings.Repeat("d", 120), strings.Repeat("e", 120))
	os.MkdirAll(deep, 0o755)
	if err := os.Rename(filepath.Join(f.root, testRef), filepath.Join(deep, testRef)); err != nil {
		t.Fatal(err)
	}
	tg := f.target(t)
	tg.ProjectsDir = deep
	c, err := dial(t, tg)
	if err != nil {
		t.Fatalf("path of %d bytes: %v", len(filepath.Join(deep, testRef, "sock", ".s.PGSQL.5432")), err)
	}
	c.close()
	f.result(t)
}

// SendBatch: the server answers up to the first ReadyForQuery, then is silent.
func TestUntrusted_BatchAfterReadyForQuery(t *testing.T) {
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeCacheDescribe, pgx.QueryExecModeDescribeExec, pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol} {
		t.Run(mode.String(), func(t *testing.T) {
			var types atomic.Value
			f := newFake(t, func(c *fconn) error {
				if err := c.login(); err != nil {
					return err
				}
				var seen []byte
				for {
					typ, _, err := c.read()
					if err != nil {
						return nil
					}
					seen = append(seen, typ)
					types.Store(string(seen))
					if typ == 'S' || typ == 'Q' {
						break
					}
				}
				c.Write(msg('Z', []byte{'I'}))
				time.Sleep(5 * time.Second)
				return nil
			})
			tg := f.target(t)
			tg.Budget = Budget{Connect: 2 * time.Second, Statement: 300 * time.Millisecond, Session: 3 * time.Second}
			c, err := dial(t, tg)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			b := &pgx.Batch{}
			b.Queue("select $1::int", 1)
			b.Queue("select $1::int", 2)
			br := c.c.SendBatch(context.Background(), b)
			_, err = br.Exec()
			br.Close()
			el := time.Since(start)
			tableRow("batch %s: client sent %q before the first ReadyForQuery; ended after %v: %s", mode, types.Load(), el.Round(time.Millisecond), errClass(err))
		})
	}
}

// The guard's statement deadline restarts with each statement: a session of
// several short statements outlasting one statement bound is not cut (each
// answer comes after 300 ms of a 1 s bound; together they take over 1.5 s).
func TestUntrusted_StatementDeadlinePerStatement(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		if err := c.login(); err != nil {
			return err
		}
		for i := 0; i < 5; i++ {
			time.Sleep(300 * time.Millisecond)
			if err := c.answer(); err != nil {
				return err
			}
		}
		return nil
	})
	tg := f.target(t)
	tg.Budget.Statement = time.Second
	c, err := dial(t, tg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := c.c.Exec(context.Background(), "select 1"); err != nil {
			t.Fatalf("statement %d: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The pid is compared, not only the start time: another recorded pid with
// the listener's own start time is refused.
func TestUntrusted_PeerPidComparedNotOnlyStart(t *testing.T) {
	f := newFake(t, nil)
	tg := f.target(t)
	tg.PostmasterPid, _ = otherProcess(t)
	_, err := dial(t, tg)
	wantErr(t, err, ErrPeer)
	if r := f.result(t); len(r.raw) != 0 {
		t.Fatalf("fake received %d bytes", len(r.raw))
	}
}

// A recorded listener child whose postmaster's start time differs is refused.
func TestUntrusted_ListenerWithStalePostmaster(t *testing.T) {
	f := newFake(t, nil)
	os.Remove(f.path)
	l, pid, start, _ := handoff(t, f.path, -1)
	go f.serve(l, nil)
	tg := f.target(t)
	tg.ListenerPid, tg.ListenerStart = pid, start
	tg.PostmasterStart++
	_, err := dial(t, tg)
	wantErr(t, err, ErrPeer)
	if r := f.result(t); len(r.raw) != 0 {
		t.Fatalf("fake received %d bytes", len(r.raw))
	}
}
