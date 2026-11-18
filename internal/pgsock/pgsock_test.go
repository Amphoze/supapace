package pgsock

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// ───────── helper re-execution ─────────
//
// PGSOCK_TEST_HELPER=handoff makes the test binary listen on PGSOCK_TEST_PATH,
// pass the listener to its parent over descriptor 3 (SCM_RIGHTS) and wait
// until its stdin closes: the socket's creator is then this other process.

func TestMain(m *testing.M) {
	if os.Getenv("PGSOCK_TEST_HELPER") == "handoff" {
		os.Exit(helperHandoff())
	}
	// Dial refuses to start with any PG* variable set; tests that need one set it.
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "PG") {
			os.Unsetenv(k)
		}
	}
	os.Exit(m.Run())
}

func helperHandoff() int {
	l, err := net.Listen("unix", os.Getenv("PGSOCK_TEST_PATH"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ul := l.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	f, err := ul.File()
	if err != nil {
		return 1
	}
	if err := syscall.Sendmsg(3, []byte{1}, syscall.UnixRights(int(f.Fd())), nil, 0); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	io.Copy(io.Discard, os.Stdin)
	return 0
}

// handoff starts a helper that creates the listener at path (as uid when uid
// >= 0) and returns the listener, the helper's pid and its start time; stop
// ends the helper and waits for it.
func handoff(t *testing.T, path string, uid int) (l net.Listener, pid int, start uint64, stop func()) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "mine"), os.NewFile(uintptr(fds[1]), "theirs")
	defer mine.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "PGSOCK_TEST_HELPER=handoff", "PGSOCK_TEST_PATH="+path)
	cmd.ExtraFiles = []*os.File{theirs}
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
	theirs.Close()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			stdin.Close()
			cmd.Wait()
		})
	}
	t.Cleanup(stop)
	buf, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := syscall.Recvmsg(int(mine.Fd()), buf, oob, 0)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		t.Fatalf("no descriptor from helper: %v", err)
	}
	got, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(got) != 1 {
		t.Fatalf("no descriptor from helper: %v", err)
	}
	lf := os.NewFile(uintptr(got[0]), "listener")
	l, err = net.FileListener(lf)
	lf.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	pid = cmd.Process.Pid
	if start, err = ProcStart(pid); err != nil {
		t.Fatal(err)
	}
	return l, pid, start, stop
}

// ───────── fake backend ─────────

const (
	testPassword = "correct-horse-battery-staple-0123456789"
	testUser     = "supabase_admin"
	testRef      = "abcdefghij0123456789"
)

var testDEK = bytes.Repeat([]byte{7}, 32)

func testSalt() []byte { return mustSalt(testDEK, testRef, testUser) }

func mustSalt(dek []byte, ref, role string) []byte {
	s, err := ScramSalt(dek, ref, role)
	if err != nil {
		panic(err)
	}
	return s
}

// fconn is the fake's side of one connection; everything it receives is kept.
type fconn struct {
	net.Conn
	r   *bufio.Reader
	raw *bytes.Buffer
	mu  *sync.Mutex
}

type teeReader struct {
	c   net.Conn
	raw *bytes.Buffer
	mu  *sync.Mutex
}

func (t teeReader) Read(p []byte) (int, error) {
	n, err := t.c.Read(p)
	t.mu.Lock()
	t.raw.Write(p[:n])
	t.mu.Unlock()
	return n, err
}

func (c *fconn) startup() map[string]string {
	var hdr [8]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:4])-8)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return nil
	}
	m := map[string]string{}
	parts := strings.Split(string(body), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "" {
			break
		}
		m[parts[i]] = parts[i+1]
	}
	return m
}

func (c *fconn) read() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[1:])-4)
	_, err := io.ReadFull(c.r, body)
	return hdr[0], body, err
}

func msg(t byte, body []byte) []byte {
	b := []byte{t, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(body)+4))
	return append(b, body...)
}

func (c *fconn) send(t byte, body []byte) error { _, err := c.Write(msg(t, body)); return err }

func authBody(code uint32, rest []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, code)
	return append(b, rest...)
}

func (c *fconn) auth(code uint32, rest []byte) error { return c.send('R', authBody(code, rest)) }

// scramOpts lets a script deviate from an honest SCRAM exchange.
type scramOpts struct {
	salt    []byte
	iter    int
	badSig  bool
	noFinal bool // stop after the server-first message
}

// scram runs the server side of SCRAM-SHA-256 for testPassword; it reports
// whether the client's proof was valid.
func (c *fconn) scram(o scramOpts) (bool, error) {
	if o.salt == nil {
		o.salt = testSalt()
	}
	if o.iter == 0 {
		o.iter = 4096
	}
	if err := c.auth(10, []byte("SCRAM-SHA-256\x00\x00")); err != nil {
		return false, err
	}
	t, body, err := c.read()
	if err != nil || t != 'p' {
		return false, fmt.Errorf("want SASLInitialResponse, got %q %v", t, err)
	}
	i := bytes.IndexByte(body, 0)
	clientFirst := string(body[i+5:])
	bare := strings.TrimPrefix(clientFirst, "n,,")
	cnonce := bare[strings.Index(bare, "r=")+2:]
	serverFirst := fmt.Sprintf("r=%sSERVERNONCE,s=%s,i=%d", cnonce, base64.StdEncoding.EncodeToString(o.salt), o.iter)
	if err := c.auth(11, []byte(serverFirst)); err != nil {
		return false, err
	}
	if o.noFinal {
		return false, nil
	}
	t, body, err = c.read()
	if err != nil || t != 'p' {
		return false, fmt.Errorf("want SASLResponse, got %q %v", t, err)
	}
	final := string(body)
	j := strings.LastIndex(final, ",p=")
	proof, _ := base64.StdEncoding.DecodeString(final[j+3:])
	sp, _ := pbkdf2.Key(sha256.New, testPassword, o.salt, o.iter, 32)
	clientKey := hm(sp, "Client Key")
	stored := sha256.Sum256(clientKey)
	authMsg := bare + "," + serverFirst + "," + final[:j]
	sig := hm(stored[:], authMsg)
	ok := len(proof) == len(sig)
	for k := range sig {
		if ok && proof[k]^sig[k] != clientKey[k] {
			ok = false
		}
	}
	serverSig := hm(hm(sp, "Server Key"), authMsg)
	if o.badSig {
		serverSig[0] ^= 1
	}
	return ok, c.auth(12, []byte("v="+base64.StdEncoding.EncodeToString(serverSig)))
}

func hm(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

// ready sends AuthenticationOk, a few parameter statuses, BackendKeyData and
// ReadyForQuery.
func (c *fconn) ready() error {
	var b []byte
	b = append(b, msg('R', authBody(0, nil))...)
	for _, kv := range [][2]string{{"server_version", "17.6"}, {"client_encoding", "UTF8"}, {"standard_conforming_strings", "on"}} {
		b = append(b, msg('S', []byte(kv[0]+"\x00"+kv[1]+"\x00"))...)
	}
	b = append(b, msg('K', []byte{0, 0, 0, 42, 1, 2, 3, 4})...)
	b = append(b, msg('Z', []byte{'I'})...)
	_, err := c.Write(b)
	return err
}

// login is an honest startup, SCRAM exchange and ReadyForQuery.
func (c *fconn) login() error {
	c.startup()
	ok, err := c.scram(scramOpts{})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("client proof invalid")
	}
	return c.ready()
}

// answer replies to one simple query with one row.
func (c *fconn) answer() error {
	t, _, err := c.read()
	if err != nil {
		return err
	}
	if t != 'Q' {
		return fmt.Errorf("want Query, got %q", t)
	}
	var b []byte
	b = append(b, msg('T', append([]byte{0, 1}, append([]byte("x\x00"), make([]byte, 18)...)...))...)
	binary.BigEndian.PutUint32(b[len(b)-12:], 25) // type oid text
	binary.BigEndian.PutUint16(b[len(b)-8:], 0xffff)
	binary.BigEndian.PutUint32(b[len(b)-6:], 0xffffffff)
	b = append(b, msg('D', []byte{0, 1, 0, 0, 0, 1, '1'})...)
	b = append(b, msg('C', []byte("SELECT 1\x00"))...)
	b = append(b, msg('Z', []byte{'I'})...)
	_, err = c.Write(b)
	return err
}

type record struct {
	raw     []byte
	params  map[string]string
	accepts int
	err     error
}

// types lists the frontend message types after the startup packet.
func (r record) types() []byte {
	b := r.raw
	if len(b) < 4 {
		return nil
	}
	b = b[binary.BigEndian.Uint32(b):]
	var out []byte
	for len(b) >= 5 {
		out = append(out, b[0])
		n := int(binary.BigEndian.Uint32(b[1:]))
		if n+1 > len(b) {
			break
		}
		b = b[1+n:]
	}
	return out
}

type fake struct {
	root    string
	sockDir string
	path    string
	accepts atomic.Int32
	done    chan record
	params  map[string]string
	pmu     sync.Mutex
}

// newFake creates <root>/<ref>/sock/.s.PGSQL.5432 listening in this process
// and serves the first connection with script.
func newFake(t *testing.T, script func(c *fconn) error) *fake {
	t.Helper()
	root, err := os.MkdirTemp("", "pgs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	f := &fake{root: root, sockDir: filepath.Join(root, testRef, "sock"), done: make(chan record, 1)}
	if err := os.MkdirAll(f.sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f.path = filepath.Join(f.sockDir, ".s.PGSQL.5432")
	l, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go f.serve(l, script)
	return f
}

func (f *fake) serve(l net.Listener, script func(c *fconn) error) {
	first := true
	for {
		nc, err := l.Accept()
		if err != nil {
			return
		}
		f.accepts.Add(1)
		if !first {
			nc.Close()
			continue
		}
		first = false
		go func() {
			defer nc.Close()
			nc.SetDeadline(time.Now().Add(20 * time.Second))
			raw, mu := &bytes.Buffer{}, &sync.Mutex{}
			c := &fconn{Conn: nc, raw: raw, mu: mu}
			c.r = bufio.NewReader(teeReader{nc, raw, mu})
			var serr error
			if script != nil {
				serr = script(c)
			}
			io.Copy(io.Discard, c.r) // until the client closes
			mu.Lock()
			rec := record{raw: append([]byte(nil), raw.Bytes()...), err: serr}
			mu.Unlock()
			if len(rec.raw) > 8 {
				c2 := &fconn{r: bufio.NewReader(bytes.NewReader(rec.raw))}
				rec.params = c2.startup()
			}
			f.done <- rec
		}()
	}
}

// result waits for the served connection to end.
func (f *fake) result(t *testing.T) record {
	t.Helper()
	select {
	case r := <-f.done:
		r.accepts = int(f.accepts.Load())
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("fake: connection did not end")
		return record{}
	}
}

// noConnection asserts the fake was never connected to.
func (f *fake) noConnection(t *testing.T) {
	t.Helper()
	time.Sleep(20 * time.Millisecond)
	if n := f.accepts.Load(); n != 0 {
		t.Fatalf("fake accepted %d connection(s), want none", n)
	}
}

// otherProcess starts a process that lives until the test ends and returns
// its pid and start time.
func otherProcess(t *testing.T) (int, uint64) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	start, err := ProcStart(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid, start
}

func selfStart(t *testing.T) uint64 {
	t.Helper()
	s, err := ProcStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fake) target(t *testing.T) Target {
	return Target{
		ProjectsDir: f.root, Ref: testRef, UID: os.Getuid(),
		PostmasterPid: os.Getpid(), PostmasterStart: selfStart(t),
		User: testUser, Password: testPassword, ScramSalt: testSalt(), Superuser: true,
		Budget: Budget{Connect: 5 * time.Second, Statement: 10 * time.Second, Session: 30 * time.Second},
	}
}

func dial(t *testing.T, tg Target) (*connCloser, error) {
	t.Helper()
	c, err := Dial(context.Background(), tg)
	if err != nil {
		return nil, err
	}
	cc := &connCloser{c: c}
	t.Cleanup(cc.close)
	return cc, nil
}

type connCloser struct {
	c    *pgx.Conn
	once sync.Once
}

func (c *connCloser) close() { c.once.Do(func() { c.c.Close(context.Background()) }) }

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

// ───────── path tests ─────────

func TestDial_RefusesSymlinkedRefDir(t *testing.T) {
	f := newFake(t, nil)
	real := filepath.Join(f.root, "real")
	if err := os.Rename(filepath.Join(f.root, testRef), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(f.root, testRef)); err != nil {
		t.Fatal(err)
	}
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrNotSocket)
	f.noConnection(t)
}

func TestDial_RefusesSymlinkedSockDir(t *testing.T) {
	f := newFake(t, nil)
	real := filepath.Join(f.root, testRef, "real")
	if err := os.Rename(f.sockDir, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, f.sockDir); err != nil {
		t.Fatal(err)
	}
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrNotSocket)
	f.noConnection(t)
}

func TestDial_RefusesSymlinkAtSocketName(t *testing.T) {
	f := newFake(t, nil)
	moved := filepath.Join(f.root, "moved.sock")
	if err := os.Rename(f.path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, f.path); err != nil {
		t.Fatal(err)
	}
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrNotSocket)
	f.noConnection(t)
}

func TestDial_RefusesNonSocket(t *testing.T) {
	f := newFake(t, nil)
	os.Remove(f.path)
	if err := os.WriteFile(f.path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrNotSocket)
}

func TestDial_RefusesWrongOwnerUID(t *testing.T) {
	f := newFake(t, nil)
	tg := f.target(t)
	tg.UID = os.Getuid() + 1
	_, err := dial(t, tg)
	wantErr(t, err, ErrNotSocket)
	f.noConnection(t)
}

func TestDial_RefusesBadRef(t *testing.T) {
	f := newFake(t, nil)
	for _, ref := range []string{"", "..", testRef + "/sock/..", "ABCDEFGHIJ0123456789"} {
		tg := f.target(t)
		tg.Ref = ref
		if _, err := dial(t, tg); err == nil {
			t.Fatalf("ref %q accepted", ref)
		}
	}
	f.noConnection(t)
}

// The name is swapped for a link to another socket after the check: the
// connection still reaches the checked inode, never the other listener.
func TestDial_ConnectsThroughCheckedInode(t *testing.T) {
	f := newFake(t, func(c *fconn) error { return c.login() })
	decoyPath := filepath.Join(f.root, "decoy.sock")
	decoy, err := net.Listen("unix", decoyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer decoy.Close()
	var hits atomic.Int32
	go func() {
		for {
			c, err := decoy.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	afterCheck = func() {
		if err := os.Rename(f.path, f.path+".real"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(decoyPath, f.path); err != nil {
			t.Error(err)
		}
	}
	defer func() { afterCheck = nil }()
	c, err := dial(t, f.target(t))
	if err != nil {
		t.Fatalf("dial through the checked inode: %v", err)
	}
	c.close()
	if r := f.result(t); r.err != nil {
		t.Fatal(r.err)
	}
	time.Sleep(20 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the swapped-in listener received %d connection(s)", n)
	}
}

// ───────── peer tests ─────────

func TestDial_RefusesWrongPeerPid(t *testing.T) {
	f := newFake(t, nil)
	tg := f.target(t)
	tg.PostmasterPid, tg.PostmasterStart = otherProcess(t)
	_, err := dial(t, tg)
	wantErr(t, err, ErrPeer)
	if r := f.result(t); len(r.raw) != 0 {
		t.Fatalf("fake received %d bytes, want 0", len(r.raw))
	}
}

func TestDial_RefusesWrongStartTime(t *testing.T) {
	f := newFake(t, nil)
	tg := f.target(t)
	tg.PostmasterStart++
	_, err := dial(t, tg)
	wantErr(t, err, ErrPeer)
	if r := f.result(t); len(r.raw) != 0 {
		t.Fatalf("fake received %d bytes, want 0", len(r.raw))
	}
}

func TestDial_RefusesPidZeroAndOne(t *testing.T) {
	f := newFake(t, nil)
	for _, pid := range []int{0, 1, -1} {
		tg := f.target(t)
		tg.PostmasterPid = pid
		_, err := dial(t, tg)
		wantErr(t, err, ErrPeer)
	}
	f.noConnection(t)
}

// A listener created by another process (this test serves it): the peer is
// that process, not the target's postmaster.
func TestDial_RefusesListenerOfAnotherProcess(t *testing.T) {
	f := newFake(t, nil)
	os.Remove(f.path)
	l, _, _, _ := handoff(t, f.path, -1)
	go f.serve(l, nil)
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrPeer)
	if r := f.result(t); len(r.raw) != 0 {
		t.Fatalf("fake received %d bytes, want 0", len(r.raw))
	}
}

// The creator of the listener has exited: its pid matches but its stat is gone.
func TestDial_RefusesUnreadableStat(t *testing.T) {
	f := newFake(t, nil)
	os.Remove(f.path)
	l, pid, start, stop := handoff(t, f.path, -1)
	stop()
	go f.serve(l, nil)
	tg := f.target(t)
	tg.PostmasterPid, tg.PostmasterStart = pid, start
	_, err := dial(t, tg)
	wantErr(t, err, ErrPeer)
	if r := f.result(t); len(r.raw) != 0 {
		t.Fatalf("fake received %d bytes, want 0", len(r.raw))
	}
}

// The recorded listener identity: a child of the postmaster that created the
// listener is accepted only as that exact (pid, start) pair.
func TestDial_ListenerIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(tg *Target, pid int, start uint64)
		wantErr error
	}{
		{"recorded", func(tg *Target, pid int, start uint64) { tg.ListenerPid, tg.ListenerStart = pid, start }, nil},
		{"other start", func(tg *Target, pid int, start uint64) { tg.ListenerPid, tg.ListenerStart = pid, start+1 }, ErrPeer},
		{"other parent", func(tg *Target, pid int, start uint64) {
			tg.ListenerPid, tg.ListenerStart = pid, start
			tg.PostmasterPid, tg.PostmasterStart = otherProcess(t)
		}, ErrPeer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var script func(*fconn) error
			if tc.wantErr == nil {
				script = func(c *fconn) error { return c.login() }
			}
			f := newFake(t, nil)
			os.Remove(f.path)
			l, pid, start, _ := handoff(t, f.path, -1)
			go f.serve(l, script)
			tg := f.target(t)
			tc.mutate(&tg, pid, start)
			c, err := dial(t, tg)
			if tc.wantErr != nil {
				wantErr(t, err, tc.wantErr)
				if r := f.result(t); len(r.raw) != 0 {
					t.Fatalf("fake received %d bytes, want 0", len(r.raw))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c.close()
			if r := f.result(t); r.err != nil {
				t.Fatal(r.err)
			}
		})
	}
}

// Root only: the daemon reaches a listener created by another uid in a tree
// that uid owns, and refuses it for any other recorded uid.
func TestDial_RootReachesProjectUIDListener(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	const uid = 70123
	for _, wrongUID := range []bool{false, true} {
		var script func(*fconn) error
		if !wrongUID {
			script = func(c *fconn) error { return c.login() }
		}
		f := newFake(t, nil)
		os.Remove(f.path)
		os.Chmod(f.root, 0o755)
		for _, d := range []string{filepath.Join(f.root, testRef), f.sockDir} {
			if err := os.Chown(d, uid, uid); err != nil {
				t.Fatal(err)
			}
			os.Chmod(d, 0o700)
		}
		l, pid, start, _ := handoff(t, f.path, uid)
		go f.serve(l, script)
		tg := f.target(t)
		tg.UID, tg.PostmasterPid, tg.PostmasterStart = uid, pid, start
		if wrongUID {
			tg.UID = uid + 1
			_, err := dial(t, tg)
			wantErr(t, err, ErrNotSocket)
			f.noConnection(t)
			continue
		}
		c, err := dial(t, tg)
		if err != nil {
			t.Fatal(err)
		}
		c.close()
		if r := f.result(t); r.err != nil {
			t.Fatal(r.err)
		}
	}
}

func TestDial_ErrorsDoNotNameThePath(t *testing.T) {
	cases := map[string]func(f *fake, tg *Target){
		"owner":   func(f *fake, tg *Target) { tg.UID++ },
		"peer":    func(f *fake, tg *Target) { tg.PostmasterStart++ },
		"missing": func(f *fake, tg *Target) { os.Remove(f.path) },
		"guard":   func(f *fake, tg *Target) {},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, func(c *fconn) error { c.startup(); return c.auth(3, nil) })
			tg := f.target(t)
			mutate(f, &tg)
			_, err := dial(t, tg)
			if err == nil {
				t.Fatal("dial succeeded")
			}
			s := err.Error()
			if strings.Contains(s, f.root) || strings.Contains(s, "/proc/") || strings.Contains(s, testPassword) {
				t.Fatalf("error names the path or a secret: %q", s)
			}
			if !strings.Contains(s, testRef) {
				t.Fatalf("error does not name the ref: %q", s)
			}
		})
	}
}

// ───────── guard tests ─────────

func TestDial_RequiresScramSalt(t *testing.T) {
	f := newFake(t, nil)
	tg := f.target(t)
	tg.ScramSalt = nil
	_, err := dial(t, tg)
	wantErr(t, err, ErrScramParams)
	f.noConnection(t)
}

func TestGuard_RefusesCleartextRequest(t *testing.T) {
	f := newFake(t, func(c *fconn) error { c.startup(); return c.auth(3, nil) })
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrCleartextRequested)
	r := f.result(t)
	if bytes.IndexByte(r.types(), 'p') >= 0 || bytes.Contains(r.raw, []byte(testPassword)) {
		t.Fatalf("fake received a password message: types %q", r.types())
	}
}

func TestGuard_RefusesMD5(t *testing.T) {
	f := newFake(t, func(c *fconn) error { c.startup(); return c.auth(5, []byte{1, 2, 3, 4}) })
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrCleartextRequested)
	if r := f.result(t); bytes.IndexByte(r.types(), 'p') >= 0 {
		t.Fatalf("fake received a password message: types %q", r.types())
	}
}

func TestGuard_RefusesOtherMethods(t *testing.T) {
	for _, code := range []uint32{2, 7, 9, 99} {
		f := newFake(t, func(c *fconn) error { c.startup(); return c.auth(code, nil) })
		_, err := dial(t, f.target(t))
		wantErr(t, err, ErrNotScram)
		if r := f.result(t); len(r.types()) != 0 {
			t.Fatalf("code %d: fake received %q", code, r.types())
		}
	}
}

func TestGuard_RefusesTrustUnlessAllowed(t *testing.T) {
	trust := func(c *fconn) error { c.startup(); return c.ready() }
	f := newFake(t, trust)
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrNotScram)
	f.result(t)

	f = newFake(t, trust)
	tg := f.target(t)
	tg.AllowTrust, tg.ScramSalt, tg.Password = true, nil, ""
	c, err := dial(t, tg)
	if err != nil {
		t.Fatalf("trust allowed: %v", err)
	}
	c.close()
	f.result(t)
}

func TestGuard_TrustTargetRefusesSASL(t *testing.T) {
	f := newFake(t, func(c *fconn) error { c.startup(); _, err := c.scram(scramOpts{noFinal: true}); return err })
	tg := f.target(t)
	tg.AllowTrust = true
	_, err := dial(t, tg)
	wantErr(t, err, ErrScramParams)
	if r := f.result(t); bytes.IndexByte(r.types(), 'p') >= 0 {
		t.Fatalf("fake received %q", r.types())
	}
}

func TestGuard_AllowsScram(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		if err := c.login(); err != nil {
			return err
		}
		return c.answer()
	})
	c, err := dial(t, f.target(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.c.Exec(context.Background(), "select 1"); err != nil {
		t.Fatal(err)
	}
	c.close()
	if r := f.result(t); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestGuard_RefusesForeignSalt(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		c.startup()
		_, err := c.scram(scramOpts{salt: mustSalt(testDEK, testRef, "postgres"), noFinal: true})
		return err
	})
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrScramParams)
	if r := f.result(t); bytes.Count(r.types(), []byte{'p'}) != 1 {
		t.Fatalf("fake received %q, want only the initial response", r.types())
	}
}

func TestGuard_RefusesHighIterations(t *testing.T) {
	for _, iter := range []int{10000000, 4095, 4097} {
		f := newFake(t, func(c *fconn) error {
			c.startup()
			_, err := c.scram(scramOpts{iter: iter, noFinal: true})
			return err
		})
		start := time.Now()
		_, err := dial(t, f.target(t))
		el := time.Since(start)
		wantErr(t, err, ErrScramParams)
		if iter == 10000000 && el > 100*time.Millisecond {
			t.Fatalf("refusal took %v", el)
		}
		if r := f.result(t); bytes.Count(r.types(), []byte{'p'}) != 1 {
			t.Fatalf("fake received %q, want no client-final message", r.types())
		}
	}
}

func TestGuard_RefusesServerFirstExtensions(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		c.startup()
		if err := c.auth(10, []byte("SCRAM-SHA-256\x00\x00")); err != nil {
			return err
		}
		c.read()
		sf := fmt.Sprintf("r=x,s=%s,i=4096,x=1", base64.StdEncoding.EncodeToString(testSalt()))
		return c.auth(11, []byte(sf))
	})
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrScramParams)
	f.result(t)
}

func TestGuard_RefusesBadServerSignature(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		c.startup()
		if _, err := c.scram(scramOpts{badSig: true}); err != nil {
			return err
		}
		return c.ready()
	})
	_, err := dial(t, f.target(t))
	if err == nil {
		t.Fatal("dial accepted a wrong server signature")
	}
	if r := f.result(t); bytes.IndexByte(r.types(), 'Q') >= 0 {
		t.Fatalf("client went on after a wrong signature: %q", r.types())
	}
}

func TestGuard_RefusesAuthOkBeforeFinal(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		c.startup()
		if _, err := c.scram(scramOpts{noFinal: true}); err != nil {
			return err
		}
		c.read()
		return c.ready()
	})
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrNotScram)
	f.result(t)
}

func TestGuard_RefusesSCRAMPlusOnly(t *testing.T) {
	f := newFake(t, func(c *fconn) error { c.startup(); return c.auth(10, []byte("SCRAM-SHA-256-PLUS\x00\x00")) })
	_, err := dial(t, f.target(t))
	wantErr(t, err, ErrNotScram)
	if r := f.result(t); len(r.types()) != 0 {
		t.Fatalf("fake received %q", r.types())
	}
}

func TestGuard_SanitizesServerError(t *testing.T) {
	hostile := "S\x00FATAL\x00C\x0028000\x00M\x1b]8;;x\x07click\x1b[31m red \xff\xfe\u0085end\x00\x00"
	f := newFake(t, func(c *fconn) error { c.startup(); return c.send('E', []byte(hostile)) })
	_, err := dial(t, f.target(t))
	if err == nil {
		t.Fatal("dial succeeded")
	}
	assertClean(t, err.Error())
	if !strings.Contains(err.Error(), "click") {
		t.Fatalf("server text dropped entirely: %q", err.Error())
	}
	f.result(t)
}

func assertClean(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("invalid UTF-8: %q", s)
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			t.Fatalf("control character %U in %q", r, s)
		}
	}
}

// ───────── config tests ─────────

func TestConfig_NoFallbacksNoEnv(t *testing.T) {
	elsewhere := t.TempDir()
	svc := filepath.Join(elsewhere, "pg_service.conf")
	os.WriteFile(svc, []byte("[svc]\nhost="+elsewhere+"\nport=6543\nsslmode=require\noptions=-c search_path=public\n"), 0o600)
	t.Setenv("PGHOST", elsewhere+","+elsewhere)
	t.Setenv("PGPORT", "6543")
	t.Setenv("PGSSLMODE", "require")
	t.Setenv("PGSERVICEFILE", svc)
	t.Setenv("PGSERVICE", "svc")
	t.Setenv("PGOPTIONS", "-c search_path=public")
	t.Setenv("PGAPPNAME", "other")
	t.Setenv("PGTARGETSESSIONATTRS", "read-write")
	t.Setenv("PGDATABASE", "other")

	f := newFake(t, func(c *fconn) error { return c.login() })
	tg := f.target(t)
	cfg, err := config(tg, tg.Budget.withDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Fallbacks) != 0 || cfg.TLSConfig != nil || cfg.Host != "/pgsock" || cfg.Database != "postgres" ||
		cfg.ValidateConnect != nil || cfg.AfterConnect != nil || cfg.AfterNetConnect != nil {
		t.Fatalf("config: host %q db %q fallbacks %d tls %v", cfg.Host, cfg.Database, len(cfg.Fallbacks), cfg.TLSConfig != nil)
	}
	if !maps.Equal(cfg.RuntimeParams, StartupParams(true)) {
		t.Fatalf("runtime params %v", cfg.RuntimeParams)
	}
	if cfg.ChannelBinding != "disable" || cfg.MinProtocolVersion != "3.0" || cfg.MaxProtocolVersion != "3.0" ||
		cfg.SSLCertMode != "disable" || cfg.RequireAuth != "scram-sha-256" {
		t.Fatalf("config: channel binding %q protocol %q..%q certmode %q require_auth %q",
			cfg.ChannelBinding, cfg.MinProtocolVersion, cfg.MaxProtocolVersion, cfg.SSLCertMode, cfg.RequireAuth)
	}
	// With any PG* variable set the dial does not start at all.
	_, err = dial(t, tg)
	wantErr(t, err, ErrEnvironment)
	f.noConnection(t)
}

var want28 = map[string]string{
	"search_path": "pg_catalog,pg_temp", "role": "none", "default_transaction_read_only": "off",
	"statement_timeout": "0", "lock_timeout": "0", "idle_in_transaction_session_timeout": "0",
	"idle_session_timeout": "0", "transaction_timeout": "0", "local_preload_libraries": "",
	"exit_on_error": "off", "default_transaction_isolation": "read committed",
	"default_transaction_deferrable": "off", "standard_conforming_strings": "on",
	"backslash_quote": "safe_encoding", "synchronous_commit": "on", "client_encoding": "UTF8",
	"DateStyle": "ISO, MDY", "TimeZone": "UTC", "IntervalStyle": "postgres", "bytea_output": "hex",
	"extra_float_digits": "1", "quote_all_identifiers": "off", "transform_null_equals": "off",
	"row_security": "on", "check_function_bodies": "on", "default_tablespace": "",
	"temp_tablespaces": "", "client_min_messages": "notice",
}

func TestConfig_StartupParameters(t *testing.T) {
	if len(want28) != 28 {
		t.Fatalf("test list has %d entries", len(want28))
	}
	for _, super := range []bool{false, true} {
		f := newFake(t, func(c *fconn) error { return c.login() })
		tg := f.target(t)
		tg.Superuser = super
		c, err := dial(t, tg)
		if err != nil {
			t.Fatal(err)
		}
		c.close()
		r := f.result(t)
		got := maps.Clone(r.params)
		if got["user"] != testUser || got["database"] != "postgres" {
			t.Fatalf("user/database %v", got)
		}
		delete(got, "user")
		delete(got, "database")
		want := maps.Clone(want28)
		want["application_name"] = "supapace-agent"
		if super {
			want["event_triggers"] = "off"
		}
		if !maps.Equal(got, want) {
			t.Fatalf("superuser=%v: startup parameters\n got %v\nwant %v", super, got, want)
		}
	}
}

func TestConfig_StartupParamsMatchE15(t *testing.T) {
	b, err := os.ReadFile("../../test/harness/experiments/e15.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "\nLIST='")
	if i < 0 {
		t.Fatal("LIST not found in e15.sh")
	}
	s = s[i+len("\nLIST='"):]
	s = s[:strings.IndexByte(s, '\'')]
	got := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("bad LIST line %q", line)
		}
		got[k] = v
	}
	want := StartupParams(false)
	delete(want, "application_name")
	if !maps.Equal(got, want) {
		t.Fatalf("e15.sh LIST\n got %v\nwant %v", got, want)
	}
}

// ───────── budget tests ─────────
// Each test makes one bound small and the others large, and requires the
// session to end within a margin of the small bound with ErrBudget.

func budget(mod func(b *Budget)) Budget {
	b := Budget{Connect: 20 * time.Second, Statement: 20 * time.Second, Session: 30 * time.Second,
		Bytes: 1 << 40, MessageBytes: 32 << 20, ParamStatus: 1 << 20, Notices: 1 << 20}
	mod(&b)
	return b
}

func runBudget(t *testing.T, b Budget, within time.Duration, script func(c *fconn) error, query bool) record {
	t.Helper()
	f := newFake(t, script)
	tg := f.target(t)
	tg.Budget = b
	start := time.Now()
	c, err := dial(t, tg)
	if err == nil {
		if !query {
			t.Fatal("dial succeeded")
		}
		_, err = c.c.Exec(context.Background(), "select 1")
	} else if query {
		t.Fatalf("dial: %v", err)
	}
	if el := time.Since(start); el > within {
		t.Fatalf("ended after %v, bound %v (err %v)", el, within, err)
	}
	wantErr(t, err, ErrBudget)
	if c != nil {
		c.close()
	}
	return f.result(t)
}

func afterQuery(then func(c *fconn) error) func(c *fconn) error {
	return func(c *fconn) error {
		if err := c.login(); err != nil {
			return err
		}
		if _, _, err := c.read(); err != nil {
			return err
		}
		return then(c)
	}
}

func TestBudget_MessageTooLargeRefusedOnHeader(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	runBudget(t, budget(func(b *Budget) { b.MessageBytes = 1 << 20 }), 2*time.Second, afterQuery(func(c *fconn) error {
		// announce 2 MiB and send no body: the refusal must come from the header
		_, err := c.Write([]byte{'D', 0, 0x20, 0, 0})
		return err
	}), true)
	runtime.ReadMemStats(&after)
	if d := after.TotalAlloc - before.TotalAlloc; d > 4<<20 {
		t.Fatalf("allocated %d bytes for a refused message", d)
	}
}

func TestBudget_MessageCapDuringAuth(t *testing.T) {
	runBudget(t, budget(func(b *Budget) { b.MessageBytes = 1 << 20 }), 2*time.Second, func(c *fconn) error {
		c.startup()
		_, err := c.Write([]byte{'R', 0, 0x20, 0, 0})
		return err
	}, false)
}

func TestBudget_TotalBytes(t *testing.T) {
	runBudget(t, budget(func(b *Budget) { b.Bytes = 256 << 10 }), 3*time.Second, afterQuery(func(c *fconn) error {
		row := msg('D', append([]byte{0, 1, 0, 0, 0x7f, 0xf9}, bytes.Repeat([]byte{'x'}, 0x7ff9)...))
		for {
			if _, err := c.Write(row); err != nil {
				return nil
			}
		}
	}), true)
}

// A row stream that never ends, at the default byte budget.
func TestBudget_EndlessRows(t *testing.T) {
	runBudget(t, budget(func(b *Budget) { b.Bytes = DefaultBudget.Bytes }), 5*time.Second, afterQuery(func(c *fconn) error {
		var b []byte
		b = append(b, msg('T', []byte{0, 1, 'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0})...)
		row := msg('D', []byte{0, 1, 0, 0, 0, 1, '1'})
		for len(b) < 64<<10 {
			b = append(b, row...)
		}
		for {
			if _, err := c.Write(b); err != nil {
				return nil
			}
		}
	}), true)
}

func TestBudget_ParamStatusFlood(t *testing.T) {
	runBudget(t, budget(func(b *Budget) { b.ParamStatus = 64 }), 2*time.Second, func(c *fconn) error {
		c.startup()
		if _, err := c.scram(scramOpts{}); err != nil {
			return err
		}
		c.auth(0, nil)
		for i := 0; ; i++ {
			if err := c.send('S', []byte(fmt.Sprintf("p%d\x00v\x00", i))); err != nil {
				return nil
			}
		}
	}, false)
}

func TestBudget_ParamStatusAtLimitIsAccepted(t *testing.T) {
	f := newFake(t, func(c *fconn) error {
		c.startup()
		if _, err := c.scram(scramOpts{}); err != nil {
			return err
		}
		c.auth(0, nil)
		for i := 0; i < 64; i++ {
			c.send('S', []byte(fmt.Sprintf("p%d\x00v\x00", i)))
		}
		c.send('K', []byte{0, 0, 0, 42, 1, 2, 3, 4})
		return c.send('Z', []byte{'I'})
	})
	tg := f.target(t)
	tg.Budget.ParamStatus = 64
	c, err := dial(t, tg)
	if err != nil {
		t.Fatal(err)
	}
	c.close()
	f.result(t)
}

func TestBudget_NoticeFlood(t *testing.T) {
	notice := []byte("SNOTICE\x00C00000\x00Mhello\x00\x00")
	runBudget(t, budget(func(b *Budget) { b.Notices = 256 }), 2*time.Second, func(c *fconn) error {
		c.startup()
		for {
			if err := c.send('N', notice); err != nil {
				return nil
			}
		}
	}, false)
	runBudget(t, budget(func(b *Budget) { b.Notices = 256 }), 2*time.Second, afterQuery(func(c *fconn) error {
		for {
			if err := c.send('A', []byte{0, 0, 0, 1, 'c', 0, 'p', 0}); err != nil {
				return nil
			}
		}
	}), true)
}

func TestBudget_SilentDuringAuth(t *testing.T) {
	runBudget(t, budget(func(b *Budget) { b.Connect = 300 * time.Millisecond }), 2*time.Second, func(c *fconn) error {
		c.startup()
		return c.auth(10, []byte("SCRAM-SHA-256\x00\x00"))
	}, false)
}

func TestBudget_SilentAfterQuery(t *testing.T) {
	runBudget(t, budget(func(b *Budget) { b.Statement = 300 * time.Millisecond }), 2*time.Second, afterQuery(func(c *fconn) error { return nil }), true)
}

// One byte at a time keeps the stream alive but not the statement.
func TestBudget_SlowDrip(t *testing.T) {
	runBudget(t, budget(func(b *Budget) { b.Statement = 500 * time.Millisecond }), 3*time.Second, afterQuery(func(c *fconn) error {
		m := msg('N', []byte("SNOTICE\x00Mslow\x00\x00"))
		for {
			for _, x := range m {
				if _, err := c.Write([]byte{x}); err != nil {
					return nil
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}), true)
}

func TestBudget_SessionDeadline(t *testing.T) {
	b := budget(func(b *Budget) { b.Session = 700 * time.Millisecond })
	f := newFake(t, func(c *fconn) error {
		if err := c.login(); err != nil {
			return err
		}
		for {
			if err := c.answer(); err != nil {
				return nil
			}
		}
	})
	tg := f.target(t)
	tg.Budget = b
	start := time.Now()
	c, err := dial(t, tg)
	if err != nil {
		t.Fatal(err)
	}
	for err == nil {
		_, err = c.c.Exec(context.Background(), "select 1")
		time.Sleep(50 * time.Millisecond)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("session ended after %v", el)
	}
	wantErr(t, err, ErrBudget)
	c.close()
	f.result(t)
}

func TestBudget_UnpromptedCopyOut(t *testing.T) {
	runBudget(t, budget(func(b *Budget) {}), 2*time.Second, afterQuery(func(c *fconn) error {
		c.send('H', []byte{0, 0, 0})
		for {
			if err := c.send('d', []byte("data")); err != nil {
				return nil
			}
		}
	}), true)
}

func TestBudget_ZeroValueIsDefault(t *testing.T) {
	if got := (Budget{}).withDefaults(); got != DefaultBudget {
		t.Fatalf("zero budget = %+v", got)
	}
	want := Budget{Connect: 5 * time.Second, Statement: 10 * time.Second, Session: 60 * time.Second,
		Bytes: 4 << 20, MessageBytes: 1 << 20, ParamStatus: 64, Notices: 256}
	if DefaultBudget != want {
		t.Fatalf("DefaultBudget = %+v", DefaultBudget)
	}
}

func TestStmt_Deadline(t *testing.T) {
	ctx, cancel := Stmt(context.Background(), Budget{Statement: 50 * time.Millisecond})
	defer cancel()
	dl, ok := ctx.Deadline()
	// a backstop slightly after the guard's own statement bound
	if d := time.Until(dl); !ok || d <= 50*time.Millisecond || d > 100*time.Millisecond {
		t.Fatalf("deadline in %v %v", d, ok)
	}
	<-ctx.Done()
	if !errors.Is(context.Cause(ctx), ErrBudget) {
		t.Fatalf("cause %v", context.Cause(ctx))
	}
	ctx2, cancel2 := Stmt(context.Background(), Budget{})
	defer cancel2()
	if dl, _ := ctx2.Deadline(); time.Until(dl) < 9*time.Second {
		t.Fatalf("zero budget statement deadline %v", time.Until(dl))
	}
}

// ───────── sanitize ─────────

func TestSanitize_RemovesControlAndInvalidUTF8(t *testing.T) {
	in := "a\x00b\x1b[31mc\x1b]8;;x\x07d\ne\tf\x7fg\u0085h\u009bi\xff\xfej✓"
	got := Sanitize(in, 1000)
	if got != "ab[31mc]8;;xdefghij✓" {
		t.Fatalf("Sanitize = %q", got)
	}
	assertClean(t, got)
}

func TestSanitize_CapsAtMaxWithoutSplittingRune(t *testing.T) {
	if got := Sanitize("ab✓cd", 4); got != "ab" {
		t.Fatalf("got %q", got)
	}
	if got := Sanitize("ab✓cd", 5); got != "ab✓" {
		t.Fatalf("got %q", got)
	}
	if got := Sanitize("abc", 0); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := Sanitize(strings.Repeat("\x00", 10)+"abc", 2); got != "ab" {
		t.Fatalf("got %q", got)
	}
}

// ───────── proc ─────────

func TestProcStart_ParsesCommWithSpacesAndParens(t *testing.T) {
	tail := " S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20 21\n"
	for _, comm := range []string{"postgres", "a b", "x) (y", "))", "new\nline) 9 9", "("} {
		ppid, start, err := parseStat([]byte("4242 (" + comm + ")" + tail))
		if err != nil || start != 987654 || ppid != 1 {
			t.Fatalf("comm %q: ppid %d start %d err %v", comm, ppid, start, err)
		}
	}
	for _, bad := range []string{"", "4242 postgres S 1", "4242 (x) S 1 2", "4242 (x)" + strings.Replace(tail, "987654", "-1", 1)} {
		if _, _, err := parseStat([]byte(bad)); err == nil {
			t.Fatalf("parsed %q", bad)
		}
	}
	a, err := ProcStart(os.Getpid())
	if err != nil || a == 0 {
		t.Fatalf("ProcStart(self) = %d, %v", a, err)
	}
	if _, err := ProcStart(1 << 30); err == nil {
		t.Fatal("ProcStart of a missing pid succeeded")
	}
}

// ───────── SCRAM ─────────

func TestScramSalt_KeyedPerProjectAndRole(t *testing.T) {
	base := mustSalt(testDEK, testRef, "postgres")
	if len(base) != 16 || !bytes.Equal(base, mustSalt(testDEK, testRef, "postgres")) {
		t.Fatalf("salt %x not 16 stable bytes", base)
	}
	other := append([]byte(nil), testDEK...)
	other[0] ^= 1
	for name, s := range map[string][]byte{
		"dek":   mustSalt(other, testRef, "postgres"),
		"ref":   mustSalt(testDEK, "bbcdefghij0123456789", "postgres"),
		"role":  mustSalt(testDEK, testRef, "authenticator"),
		"split": mustSalt(testDEK, testRef+"\x00post", "gres"),
	} {
		if bytes.Equal(s, base) {
			t.Fatalf("another %s gives the same salt", name)
		}
	}
	// Length prefixes keep ref and role apart whatever bytes they hold.
	if bytes.Equal(mustSalt(testDEK, "r\x00x", "y"), mustSalt(testDEK, "r", "x\x00y")) {
		t.Fatal("ambiguous MAC input")
	}
	m := hmac.New(sha256.New, testDEK)
	m.Write([]byte("supapace-scram-salt\x00"))
	m.Write(binary.BigEndian.AppendUint32(nil, uint32(len(testRef))))
	m.Write([]byte(testRef))
	m.Write(binary.BigEndian.AppendUint32(nil, uint32(len("postgres"))))
	m.Write([]byte("postgres"))
	if !bytes.Equal(base, m.Sum(nil)[:16]) {
		t.Fatal("salt is not HMAC-SHA-256(dek, label 0 len(ref) ref len(role) role)[:16]")
	}
	if _, err := ScramSalt(nil, testRef, "postgres"); err == nil {
		t.Fatal("empty key accepted")
	}
}

func TestScramVerifier_UsesGivenSalt(t *testing.T) {
	salt := testSalt()
	v, err := ScramVerifier(testPassword, salt)
	if err != nil {
		t.Fatal(err)
	}
	head, keys, _ := strings.Cut(v, "$")
	if head != "SCRAM-SHA-256" {
		t.Fatalf("verifier %q", v)
	}
	iterSalt, _, _ := strings.Cut(keys, "$")
	iter, b64, _ := strings.Cut(iterSalt, ":")
	if iter != "4096" || b64 != base64.StdEncoding.EncodeToString(salt) {
		t.Fatalf("verifier %q: iterations %s salt %s", v, iter, b64)
	}
	sp, _ := pbkdf2.Key(sha256.New, testPassword, salt, 4096, 32)
	stored := sha256.Sum256(hm(sp, "Client Key"))
	want := fmt.Sprintf("SCRAM-SHA-256$4096:%s$%s:%s", b64,
		base64.StdEncoding.EncodeToString(stored[:]), base64.StdEncoding.EncodeToString(hm(sp, "Server Key")))
	if v != want {
		t.Fatalf("verifier\n got %s\nwant %s", v, want)
	}
	v2, _ := ScramVerifier(testPassword, mustSalt(testDEK, testRef, "other"))
	if v2 == v {
		t.Fatal("another salt gives the same verifier")
	}
	for _, bad := range []struct {
		pw   string
		salt []byte
	}{{"", salt}, {testPassword, nil}, {testPassword, salt[:8]}, {"café", salt}, {"a\x00b", salt}} {
		if _, err := ScramVerifier(bad.pw, bad.salt); err == nil {
			t.Fatalf("accepted password %q salt %x", bad.pw, bad.salt)
		}
	}
}

// A real cluster: a role whose verifier comes from ScramVerifier logs in
// through Dial, and the stored verifier carries the pinned salt and count.
func TestScramVerifier_AcceptedByPostgres(t *testing.T) {
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
	if err := os.MkdirAll(sock, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(sock, 0o777)
	rnd := make([]byte, 8)
	rand.Read(rnd)
	name := "sp-test-pgsock-" + hex.EncodeToString(rnd)
	initPW := hex.EncodeToString(rnd) + "init"
	out, err := exec.Command("docker", "run", "-d", "--name", name, "--label", "supapace.test=1", "--network", "none",
		"-e", "POSTGRES_PASSWORD="+initPW, "-e", "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256",
		"-v", sock+":/var/run/postgresql", im.ControlPlane).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	pidOut, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(pidOut)))
	start, err := ProcStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	pw := make([]byte, 32)
	rand.Read(pw)
	password := hex.EncodeToString(pw)
	tg := Target{ProjectsDir: root, Ref: testRef, UID: 70, PostmasterPid: pid, PostmasterStart: start,
		User: "postgres", Password: password, ScramSalt: mustSalt(testDEK, testRef, "postgres"), Superuser: true}

	// Until ALTER ROLE the stored verifier has initdb's random salt: refused
	// before any proof is sent. The image's temporary init server is another
	// process and is refused as a peer meanwhile.
	deadline := time.Now().Add(90 * time.Second)
	for {
		_, err = Dial(context.Background(), tg)
		if errors.Is(err, ErrScramParams) {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "20", name).CombinedOutput()
			t.Fatalf("cluster not reachable: %v\n%s", err, logs)
		}
		time.Sleep(300 * time.Millisecond)
	}
	v, err := ScramVerifier(password, tg.ScramSalt)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "exec", "-e", "PGPASSWORD="+initPW, name, "psql", "-v", "ON_ERROR_STOP=1",
		"-U", "postgres", "-d", "postgres", "-c", "ALTER ROLE postgres PASSWORD '"+v+"'").CombinedOutput(); err != nil {
		t.Fatalf("alter role: %v %s", err, out)
	}
	c, err := Dial(context.Background(), tg)
	if err != nil {
		t.Fatalf("login with the password: %v", err)
	}
	defer c.Close(context.Background())
	var stored, user string
	ctx, cancel := Stmt(context.Background(), DefaultBudget)
	defer cancel()
	if err := c.QueryRow(ctx, "select current_user::text, rolpassword from pg_catalog.pg_authid where rolname = $1", "postgres").Scan(&user, &stored); err != nil {
		t.Fatal(err)
	}
	if user != "postgres" || stored != v {
		t.Fatalf("user %q stored verifier %q, want %q", user, stored, v)
	}
	if !strings.HasPrefix(stored, "SCRAM-SHA-256$4096:"+base64.StdEncoding.EncodeToString(tg.ScramSalt)+"$") {
		t.Fatalf("stored verifier %q lacks the pinned salt and count", stored)
	}
	bad := tg
	bad.Password = password + "x"
	if _, err := Dial(context.Background(), bad); err == nil {
		t.Fatal("wrong password accepted")
	}
}

// ───────── budget errors seen by callers ─────────

func TestIsBudget(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{ErrBudget, true},
		{fmt.Errorf("x: %w", budgetErr("deadline exceeded")), true},
		{context.DeadlineExceeded, true},
		{fmt.Errorf("timeout: %w", context.DeadlineExceeded), true},
		{context.Canceled, false},
		{ErrPeer, false},
		{nil, false},
		{errors.New("pgsock: session budget exceeded"), false},
	} {
		if got := IsBudget(tc.err); got != tc.want {
			t.Fatalf("IsBudget(%v) = %v", tc.err, got)
		}
	}
}

// A statement under a Stmt context on a silent server ends with the guard's
// ErrBudget, not the context's deadline: the context is only a backstop.
func TestStmt_GuardFiresFirst(t *testing.T) {
	b := budget(func(b *Budget) { b.Statement = 300 * time.Millisecond })
	f := newFake(t, afterQuery(func(c *fconn) error { return nil }))
	tg := f.target(t)
	tg.Budget = b
	c, err := dial(t, tg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := Stmt(context.Background(), b)
	defer cancel()
	start := time.Now()
	_, err = c.c.Exec(ctx, "select 1")
	if el := time.Since(start); el > time.Second {
		t.Fatalf("ended after %v", el)
	}
	if !errors.Is(err, ErrBudget) || !IsBudget(err) {
		t.Fatalf("error %v, want ErrBudget", err)
	}
	if !c.c.IsClosed() {
		t.Fatal("connection still open after a budget violation")
	}
	if r := f.result(t); r.err != nil {
		t.Fatal(r.err)
	}
}

// ───────── secrets in formatted output ─────────

func TestTarget_Redacted(t *testing.T) {
	tg := Target{ProjectsDir: "/p", Ref: testRef, UID: 70001, PostmasterPid: 42, User: testUser,
		Password: testPassword, ScramSalt: testSalt(), Superuser: true}
	salt := testSalt()
	secrets := []string{testPassword, base64.StdEncoding.EncodeToString(salt), hex.EncodeToString(salt),
		fmt.Sprint(salt), fmt.Sprintf("%v", []byte(testPassword)), fmt.Sprintf("%x", testPassword)}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		outs = append(outs, fmt.Sprintf(verb, tg), fmt.Sprintf(verb, &tg))
	}
	outs = append(outs, fmt.Sprint(tg), fmt.Sprintln(&tg), tg.String(), tg.GoString())
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewJSONHandler(&buf, nil), slog.NewTextHandler(&buf, nil)} {
		l := slog.New(h)
		l.Info("dial", "target", tg, "ptr", &tg)
		l.Info("dial", slog.Any("target", tg))
	}
	outs = append(outs, buf.String())
	for _, o := range outs {
		for _, sec := range secrets {
			if strings.Contains(o, sec) {
				t.Fatalf("secret printed: %q", o)
			}
		}
		if !strings.Contains(o, testRef) {
			t.Fatalf("ref not printed: %q", o)
		}
	}
}

// ───────── Unicode format and separator characters ─────────

func TestSanitize_DropsFormatAndSeparators(t *testing.T) {
	for _, r := range []rune{
		0x00AD, 0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069,
		0xFEFF, 0xFFF9, 0x2028, 0x2029, 0xE0001,
	} {
		in := "a" + string(r) + "b"
		if got := Sanitize(in, 100); got != "ab" {
			t.Fatalf("U+%04X kept: %q", r, got)
		}
	}
	if got := Sanitize("gone‮evil", 100); got != "goneevil" {
		t.Fatalf("got %q", got)
	}
	if got := Sanitize("é ✓ 日本", 100); got != "é ✓ 日本" {
		t.Fatalf("printable text changed: %q", got)
	}
}

// ───────── server errors ─────────

func errorResponse(code, text string) []byte {
	return []byte("SFATAL\x00VFATAL\x00C" + code + "\x00M" + text + "\x00DDETAIL-RAW\x00HHINT-RAW\x00\x00")
}

func assertServerError(t *testing.T, err error, code string) {
	t.Helper()
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		t.Fatalf("raw server error reachable: %#v", pe)
	}
	var se *ServerError
	if !errors.As(err, &se) {
		t.Fatalf("no ServerError in %v", err)
	}
	if se.Code != code {
		t.Fatalf("code %q, want %q", se.Code, code)
	}
	assertClean(t, se.Message)
	assertClean(t, err.Error())
	if strings.Contains(err.Error(), "DETAIL-RAW") || strings.Contains(err.Error(), "HINT-RAW") {
		t.Fatalf("detail or hint in %q", err)
	}
}

func TestClean_DialServerError(t *testing.T) {
	f := newFake(t, func(c *fconn) error { c.startup(); return c.send('E', errorResponse("28000", "bad‮\x1b[1m")) })
	_, err := dial(t, f.target(t))
	assertServerError(t, err, "28000")
	f.result(t)

	f = newFake(t, func(c *fconn) error { c.startup(); return c.send('E', errorResponse("2800\x01", "x")) })
	_, err = dial(t, f.target(t))
	assertServerError(t, err, "")
	f.result(t)
}

func TestClean_StatementError(t *testing.T) {
	f := newFake(t, afterQuery(func(c *fconn) error {
		c.send('E', []byte("SERROR\x00VERROR\x00C42P01\x00Mno such ⁦table\x00DDETAIL-RAW\x00\x00"))
		return c.send('Z', []byte{'I'})
	}))
	c, err := dial(t, f.target(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.c.Exec(context.Background(), "select 1")
	assertServerError(t, Clean(err), "42P01")
	c.close()
	f.result(t)
}

func TestClean_KeepsMatching(t *testing.T) {
	pe := &pgconn.PgError{Code: "57014", Message: "m"}
	for _, want := range []error{ErrBudget, context.DeadlineExceeded, context.Canceled, ErrNotScram} {
		err := Clean(fmt.Errorf("a: %w", errors.Join(want, pe)))
		if !errors.Is(err, want) {
			t.Fatalf("%v lost", want)
		}
		assertServerError(t, err, "57014")
	}
	if Clean(nil) != nil {
		t.Fatal("Clean(nil) != nil")
	}
	plain := fmt.Errorf("x \x1b[31m: %w", ErrBudget)
	cl := Clean(plain)
	if !errors.Is(cl, ErrBudget) || errors.Is(cl, plain) || cl.Error() != "x [31m: "+ErrBudget.Error() {
		t.Fatalf("an error without a server error: %q", cl)
	}
	if Clean(cl) != cl {
		t.Fatal("Clean is not idempotent")
	}
}

// ───────── environment ─────────

func TestCheckEnv(t *testing.T) {
	if err := CheckEnv(); err != nil {
		t.Fatalf("clean environment: %v", err)
	}
	t.Setenv("PGSSLMODE", "secret-value-1")
	t.Setenv("PGOPTIONS", "secret-value-2")
	err := CheckEnv()
	wantErr(t, err, ErrEnvironment)
	if !strings.Contains(err.Error(), "PGSSLMODE") || !strings.Contains(err.Error(), "PGOPTIONS") || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("error %q", err)
	}
	f := newFake(t, func(c *fconn) error { return c.login() })
	_, err = dial(t, f.target(t))
	wantErr(t, err, ErrEnvironment)
	f.noConnection(t)
}

// A socket nobody listens on (left by a server that died): the connect
// fails with ErrConnect, which survives Clean, and the text reads as it did
// before the sentinel existed.
func TestDial_RefusedConnectIsErrConnect(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, testRef, "sock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(dir, ".s.PGSQL.5432"))
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	tg := Target{ProjectsDir: root, Ref: testRef, UID: os.Getuid(), PostmasterPid: os.Getpid(), PostmasterStart: selfStart(t),
		User: testUser, Password: testPassword, ScramSalt: testSalt(), Budget: Budget{Connect: 5 * time.Second}}
	_, err = Dial(context.Background(), tg)
	if !errors.Is(err, ErrConnect) || IsBudget(err) {
		t.Fatalf("error %v: want ErrConnect, not a budget", err)
	}
	if want := "pgsock: project " + testRef + ": socket: connect: connect: connection refused"; err.Error() != want {
		t.Fatalf("text %q, want %q", err.Error(), want)
	}
	if errors.Is(Clean(errors.New("pgsock: project x: socket: connect: connect: connection refused")), ErrConnect) {
		t.Fatal("text alone reads as ErrConnect")
	}
}

// A connect that ran out of its budget is a budget error, not ErrConnect: a
// caller waiting for a cluster to come up must not wait on a timeout.
func TestDial_ConnectBudgetIsNotErrConnect(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, testRef, "sock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(dir, ".s.PGSQL.5432"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	afterCheck = func() { time.Sleep(50 * time.Millisecond) } // past the connect budget
	t.Cleanup(func() { afterCheck = nil })
	tg := Target{ProjectsDir: root, Ref: testRef, UID: os.Getuid(), PostmasterPid: os.Getpid(), PostmasterStart: selfStart(t),
		User: testUser, Password: testPassword, ScramSalt: testSalt(), Budget: Budget{Connect: time.Millisecond}}
	_, err = Dial(context.Background(), tg)
	if !IsBudget(err) || errors.Is(err, ErrConnect) {
		t.Fatalf("error %v: want a budget error, not ErrConnect", err)
	}
}
