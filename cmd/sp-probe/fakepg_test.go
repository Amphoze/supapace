package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	testPassword = "correct horse battery staple"
	testSaltHex  = "000102030405060708090a0b0c0d0e0f"
)

// recConn records every byte a test client writes, to compare with the fake's log.
type recConn struct {
	net.Conn
	sent bytes.Buffer
}

func (c *recConn) Write(p []byte) (int, error) {
	c.sent.Write(p)
	return c.Conn.Write(p)
}

// dialFake connects to the fake, sends the startup packet and gives the whole
// exchange 2 s.
func dialFake(t *testing.T, sock string) *recConn {
	t.Helper()
	nc, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	nc.SetDeadline(time.Now().Add(2 * time.Second))
	c := &recConn{Conn: nc}
	if _, err := c.Write(startupPacket()); err != nil {
		t.Fatal(err)
	}
	return c
}

func writeMsg(t *testing.T, c io.Writer, typ byte, body ...[]byte) {
	t.Helper()
	b := bytes.Join(body, nil)
	if _, err := c.Write(append(binary.BigEndian.AppendUint32([]byte{typ}, uint32(4+len(b))), b...)); err != nil {
		t.Fatal(err)
	}
}

// readHdr reads a backend message header: its type and body length.
func readHdr(t *testing.T, c io.Reader) (byte, int) {
	t.Helper()
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil {
		t.Fatalf("message header: %v", err)
	}
	return h[0], int(binary.BigEndian.Uint32(h[1:])) - 4
}

func readMsg(t *testing.T, c io.Reader) (byte, []byte) {
	t.Helper()
	typ, n := readHdr(t, c)
	if n < 0 || n > 1<<20 {
		t.Fatalf("message %q announces %d bytes", typ, n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("message %q body: %v", typ, err)
	}
	return typ, b
}

// expectAuth reads an authentication request and checks its code.
func expectAuth(t *testing.T, c io.Reader, code uint32) []byte {
	t.Helper()
	typ, b := readMsg(t, c)
	if typ != 'R' || len(b) < 4 || binary.BigEndian.Uint32(b) != code {
		t.Fatalf("got %q %q, want authentication request %d", typ, b, code)
	}
	return b[4:]
}

// expectSilence checks that nothing arrives for a while.
func expectSilence(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, err := c.Read(make([]byte, 1))
	var ne net.Error
	if n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read %d bytes (%v), want silence", n, err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
}

// readUntilReady reads backend messages up to ReadyForQuery.
func readUntilReady(t *testing.T, c io.Reader) {
	t.Helper()
	for {
		if typ, _ := readMsg(t, c); typ == 'Z' {
			return
		}
	}
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// scram runs the client side of SCRAM-SHA-256 after the SASL request, checking
// the server's salt, iteration count and signature, and returns what the server
// answered after the client-final message.
func scram(t *testing.T, c net.Conn, password string) (byte, []byte) {
	t.Helper()
	if mech := expectAuth(t, c, 10); string(mech) != "SCRAM-SHA-256\x00\x00" {
		t.Fatalf("mechanisms %q", mech)
	}
	const cnonce = "fyko+d2lbbFgONRv9qkxdawL"
	first := "n=,r=" + cnonce
	writeMsg(t, c, 'p', []byte("SCRAM-SHA-256\x00"), binary.BigEndian.AppendUint32(nil, uint32(3+len(first))), []byte("n,,"+first))
	sf := string(expectAuth(t, c, 11))
	attrs := map[string]string{}
	for _, kv := range strings.Split(sf, ",") {
		k, v, _ := strings.Cut(kv, "=")
		attrs[k] = v
	}
	salt, err := base64.StdEncoding.DecodeString(attrs["s"])
	if err != nil || !strings.HasPrefix(attrs["r"], cnonce) || len(attrs["r"]) <= len(cnonce) || attrs["i"] != "4096" {
		t.Fatalf("server-first %q", sf)
	}
	if want, _ := hex.DecodeString(testSaltHex); !bytes.Equal(salt, want) {
		t.Fatalf("salt %x, want %s", salt, testSaltHex)
	}
	sp, err := pbkdf2.Key(sha256.New, password, salt, 4096, 32)
	if err != nil {
		t.Fatal(err)
	}
	ck := hmacSHA256(sp, "Client Key")
	sk := sha256.Sum256(ck)
	final := "c=biws,r=" + attrs["r"]
	am := first + "," + sf + "," + final
	proof := hmacSHA256(sk[:], am)
	for i := range proof {
		proof[i] ^= ck[i]
	}
	writeMsg(t, c, 'p', []byte(final+",p="+base64.StdEncoding.EncodeToString(proof)))
	typ, b := readMsg(t, c)
	if typ == 'R' && len(b) >= 4 && binary.BigEndian.Uint32(b) == 12 {
		if v := "v=" + base64.StdEncoding.EncodeToString(hmacSHA256(hmacSHA256(sp, "Server Key"), am)); string(b[4:]) != v {
			t.Fatalf("server-final %q, want %q", b[4:], v)
		}
	}
	return typ, b
}

// login completes SCRAM with the fake's password and reads up to ReadyForQuery.
func login(t *testing.T, c net.Conn) {
	t.Helper()
	if typ, b := scram(t, c, testPassword); typ != 'R' || binary.BigEndian.Uint32(b) != 12 {
		t.Fatalf("after client-final: %q %q", typ, b)
	}
	expectAuth(t, c, 0)
	readUntilReady(t, c)
}

// query sends a simple query, or with extended a Parse, Describe and Sync.
func query(t *testing.T, c io.Writer, extended bool) {
	t.Helper()
	if !extended {
		writeMsg(t, c, 'Q', []byte("select 1\x00"))
		return
	}
	writeMsg(t, c, 'P', []byte("\x00select 1\x00\x00\x00"))
	writeMsg(t, c, 'D', []byte("S\x00"))
	writeMsg(t, c, 'S')
}

func startModeFake(t *testing.T, mode string) (string, string) {
	t.Helper()
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte(testPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if mode == "sasl-iter" {
		return startFake(t, "--mode", mode, "--salt", testSaltHex)
	}
	if !postAuth[mode] {
		return startFake(t, "--mode", mode)
	}
	return startFake(t, "--mode", mode, "--password-file", pw, "--salt", testSaltHex)
}

// Each mode of the untrusted server shows its behaviour to a client within 2 s;
// the post-authentication modes do so after a complete SCRAM exchange.
func TestFakePG_Modes(t *testing.T) {
	rowPrefix := func(t *testing.T, c net.Conn, extended bool) {
		if extended {
			for _, want := range []byte{'1', 't'} {
				if typ, _ := readMsg(t, c); typ != want {
					t.Fatalf("got %q, want %q", typ, want)
				}
			}
		}
		if typ, b := readMsg(t, c); typ != 'T' || binary.BigEndian.Uint16(b) != 1 {
			t.Fatalf("got %q %q, want a one-column RowDescription", typ, b)
		}
	}
	for _, c := range []struct {
		mode string
		run  func(t *testing.T, c *recConn)
	}{
		{"huge", func(t *testing.T, c *recConn) {
			if typ, n := readHdr(t, c); typ != 'R' || n != 1<<30-4 {
				t.Fatalf("header %q %d, want R announcing 1 GiB", typ, n)
			}
			if _, err := io.CopyN(io.Discard, c, 1<<20); err != nil {
				t.Fatalf("body: %v", err)
			}
		}},
		{"flood", func(t *testing.T, c *recConn) {
			seen := map[byte]int{}
			for range 5000 {
				typ, _ := readMsg(t, c)
				seen[typ]++
			}
			if len(seen) != 2 || seen['S'] == 0 || seen['N'] == 0 {
				t.Fatalf("message types %v, want only ParameterStatus and NoticeResponse", seen)
			}
		}},
		{"stall", func(t *testing.T, c *recConn) { expectSilence(t, c) }},
		{"trickle", func(t *testing.T, c *recConn) {
			b := make([]byte, 1)
			if _, err := io.ReadFull(c, b); err != nil || b[0] != 'R' {
				t.Fatalf("first byte %q (%v)", b, err)
			}
			t0 := time.Now()
			if _, err := io.ReadFull(c, b); err != nil || b[0] != 0 {
				t.Fatalf("second byte %q (%v)", b, err)
			}
			if d := time.Since(t0); d < 700*time.Millisecond {
				t.Fatalf("second byte after %v, want about 1 s", d)
			}
		}},
		{"md5", func(t *testing.T, c *recConn) {
			if salt := expectAuth(t, c, 5); len(salt) != 4 {
				t.Fatalf("salt %q", salt)
			}
		}},
		{"authok", func(t *testing.T, c *recConn) {
			expectAuth(t, c, 0)
			readUntilReady(t, c)
		}},
		{"sasl-iter", func(t *testing.T, c *recConn) {
			expectAuth(t, c, 10)
			first := "n=,r=abc"
			writeMsg(t, c, 'p', []byte("SCRAM-SHA-256\x00"), binary.BigEndian.AppendUint32(nil, uint32(3+len(first))), []byte("n,,"+first))
			sf := string(expectAuth(t, c, 11))
			if want, _ := hex.DecodeString(testSaltHex); !strings.HasPrefix(sf, "r=abc") || !strings.HasSuffix(sf, ",i=10000000") ||
				!strings.Contains(sf, ",s="+base64.StdEncoding.EncodeToString(want)+",") {
				t.Fatalf("server-first %q, want the given salt and ten million iterations", sf)
			}
		}},
		{"stall-auth", func(t *testing.T, c *recConn) {
			login(t, c)
			query(t, c, false)
			expectSilence(t, c)
		}},
		{"row-huge", func(t *testing.T, c *recConn) {
			login(t, c)
			query(t, c, false)
			rowPrefix(t, c, false)
			if typ, n := readHdr(t, c); typ != 'D' || n != 6+64<<20 {
				t.Fatalf("header %q %d, want a DataRow announcing 64 MiB", typ, n)
			}
			b := make([]byte, 6)
			io.ReadFull(c, b)
			if binary.BigEndian.Uint16(b) != 1 || binary.BigEndian.Uint32(b[2:]) != 64<<20 {
				t.Fatalf("row %q", b)
			}
			if _, err := io.CopyN(io.Discard, c, 1<<20); err != nil {
				t.Fatalf("column: %v", err)
			}
		}},
		{"rows-endless", func(t *testing.T, c *recConn) {
			login(t, c)
			query(t, c, true)
			rowPrefix(t, c, true)
			for range 5000 {
				if typ, b := readMsg(t, c); typ != 'D' || len(b)+5 != 1024 {
					t.Fatalf("got %q of %d bytes, want 1 KiB DataRows", typ, len(b)+5)
				}
			}
		}},
		{"escapes", func(t *testing.T, c *recConn) {
			login(t, c)
			query(t, c, false)
			notices := 0
			for {
				typ, b := readMsg(t, c)
				if typ == 'N' {
					notices++
					continue
				}
				if typ != 'E' || notices == 0 {
					t.Fatalf("got %q after %d notices, want NoticeResponses then ErrorResponse", typ, notices)
				}
				for _, s := range []string{"fake-marker", "\x1b[", "\x1b]"} {
					if !bytes.Contains(b, []byte(s)) {
						t.Errorf("error lacks %q: %q", s, b)
					}
				}
				if utf8.Valid(b) || bytes.Count(b, []byte("Mfake-marker")) != 2 {
					t.Errorf("error %q: want invalid UTF-8 and a message cut by NUL", b)
				}
				break
			}
			readUntilReady(t, c)
		}},
		{"wrong password", func(t *testing.T, c *recConn) {
			if typ, b := scram(t, c, "wrong"); typ != 'E' || !bytes.Contains(b, []byte("C28P01")) {
				t.Fatalf("got %q %q, want an authentication failure", typ, b)
			}
		}},
	} {
		t.Run(c.mode, func(t *testing.T) {
			mode := c.mode
			if mode == "wrong password" {
				mode = "stall-auth"
			}
			sock, _ := startModeFake(t, mode)
			c.run(t, dialFake(t, sock))
		})
	}
	// The extended protocol gets the same rows, after ParseComplete and
	// ParameterDescription.
	t.Run("row-huge extended", func(t *testing.T) {
		sock, _ := startModeFake(t, "row-huge")
		c := dialFake(t, sock)
		login(t, c)
		query(t, c, true)
		rowPrefix(t, c, true)
		if typ, n := readHdr(t, c); typ != 'D' || n != 6+64<<20 {
			t.Fatalf("header %q %d", typ, n)
		}
	})
}

// The log is a series of records "conn N LEN" + LEN raw bytes, in every mode,
// while the fake streams as well; a connection that sends nothing leaves none.
func TestFakePG_LogFormat(t *testing.T) {
	t.Run("post-authentication", func(t *testing.T) {
		sock, logf := startModeFake(t, "escapes")
		silent, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		silent.Close()
		c := dialFake(t, sock)
		login(t, c)
		query(t, c, false)
		readUntilReady(t, c)
		writeMsg(t, c, 'X')
		c.Close()
		waitLog(t, logf, c.sent.Bytes())
		raw, _ := os.ReadFile(logf)
		if !bytes.HasPrefix(raw, []byte("conn 2 ")) {
			t.Fatalf("log %q: the silent first connection left a record", raw)
		}
	})
	t.Run("while streaming", func(t *testing.T) {
		sock, logf := startModeFake(t, "huge")
		c := dialFake(t, sock)
		readHdr(t, c)
		io.CopyN(io.Discard, c, 1<<16)
		c.Write([]byte("sent while the fake streams"))
		waitLog(t, logf, c.sent.Bytes())
	})
}

// readGreeting reads what follows AuthenticationOk and checks each message's
// shape: ParameterStatus is two strings, BackendKeyData two 32-bit integers,
// ReadyForQuery one status byte.
func readGreeting(t *testing.T, c io.Reader) {
	t.Helper()
	for {
		typ, b := readMsg(t, c)
		switch {
		case typ == 'S' && bytes.Count(b, []byte{0}) == 2 && b[len(b)-1] == 0:
		case typ == 'K' && len(b) == 8:
		case typ == 'Z' && string(b) == "I":
			return
		default:
			t.Fatalf("malformed or unexpected %q %q after AuthenticationOk", typ, b)
		}
	}
}

// What follows authentication is well-formed in authok and after a SCRAM login,
// so a client gets past it to the behaviour under test.
func TestFakePG_GreetingWellFormed(t *testing.T) {
	sock, _ := startFake(t, "--mode", "authok")
	c := dialFake(t, sock)
	expectAuth(t, c, 0)
	readGreeting(t, c)

	sock, _ = startModeFake(t, "stall-auth")
	c = dialFake(t, sock)
	if typ, b := scram(t, c, testPassword); typ != 'R' || binary.BigEndian.Uint32(b) != 12 {
		t.Fatalf("after client-final: %q %q", typ, b)
	}
	expectAuth(t, c, 0)
	readGreeting(t, c)
}

// Each endless DataRow is well-formed: one column whose length is the rest.
func TestFakePG_RowsEndlessWellFormed(t *testing.T) {
	sock, _ := startModeFake(t, "rows-endless")
	c := dialFake(t, sock)
	login(t, c)
	query(t, c, false)
	if typ, _ := readMsg(t, c); typ != 'T' {
		t.Fatalf("got %q, want RowDescription", typ)
	}
	for range 100 {
		typ, b := readMsg(t, c)
		if typ != 'D' || len(b) < 6 || binary.BigEndian.Uint16(b) != 1 || int(binary.BigEndian.Uint32(b[2:])) != len(b)-6 {
			t.Fatalf("malformed DataRow %q of %d bytes", typ, len(b))
		}
	}
}

// A client-final message must carry the nonce the fake sent: one with another
// nonce gets no AuthenticationOk, even with a proof valid for what it signed.
func TestFakePG_RefusesForeignNonce(t *testing.T) {
	sock, _ := startModeFake(t, "stall-auth")
	c := dialFake(t, sock)
	expectAuth(t, c, 10)
	const cnonce = "abcdefghijklmnop"
	first := "n=,r=" + cnonce
	writeMsg(t, c, 'p', []byte("SCRAM-SHA-256\x00"), binary.BigEndian.AppendUint32(nil, uint32(3+len(first))), []byte("n,,"+first))
	sf := string(expectAuth(t, c, 11))
	salt, _ := hex.DecodeString(testSaltHex)
	sp, _ := pbkdf2.Key(sha256.New, testPassword, salt, 4096, 32)
	ck := hmacSHA256(sp, "Client Key")
	sk := sha256.Sum256(ck)
	final := "c=biws,r=" + cnonce + "foreign"
	proof := hmacSHA256(sk[:], first+","+sf+","+final)
	for i := range proof {
		proof[i] ^= ck[i]
	}
	writeMsg(t, c, 'p', []byte(final+",p="+base64.StdEncoding.EncodeToString(proof)))
	expectSilence(t, c)
}

// A streaming mode stops after 1 GiB on a connection and then holds it.
func TestFakePG_StreamStopsAt1GiB(t *testing.T) {
	sock, _ := startFake(t, "--mode", "flood")
	c := dialFake(t, sock)
	c.SetDeadline(time.Now().Add(60 * time.Second))
	if n, err := io.CopyN(io.Discard, c, 1<<30); err != nil {
		t.Fatalf("after %d bytes: %v", n, err)
	}
	expectSilence(t, c)
}

// As a container's init the fake stops on SIGTERM and on SIGINT (the stop
// signal Postgres images declare) and exits 0.
func TestFakePG_ExitsZeroOnStopSignals(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		dir := t.TempDir()
		cmd := exec.Command(exe)
		cmd.Env = append(os.Environ(), testArgsEnv+"="+strings.Join([]string{"fakepg", "--socket",
			filepath.Join(dir, "s"), "--log", filepath.Join(dir, "log"), "--mode", "stall"}, "\n"))
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		line := make([]byte, 9)
		if _, err := io.ReadFull(out, line); err != nil || string(line) != "listening" {
			cmd.Process.Kill()
			t.Fatalf("%v: first output %q (%v)", sig, line, err)
		}
		go io.Copy(io.Discard, out)
		cmd.Process.Signal(sig)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%v: %v, want exit 0", sig, err)
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			t.Errorf("%v: still running after 5 s", sig)
		}
	}
}

// startFakeProcess runs `sp-probe fakepg ARGS` in a process of its own and
// returns a function that kills it with SIGKILL and waits, once it printed
// "listening"; or its exit error and output when it stopped without.
func startFakeProcess(t *testing.T, args ...string) (func(), error, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), testArgsEnv+"="+strings.Join(append([]string{"fakepg"}, args...), "\n"))
	var out bytes.Buffer
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); pw.Close() }()
	line := make([]byte, 9)
	n, _ := io.ReadFull(pr, line)
	out.Write(line[:n])
	if string(line[:n]) == "listening" {
		go io.Copy(io.Discard, pr)
		var once sync.Once
		kill := func() { once.Do(func() { cmd.Process.Kill(); <-done }) }
		t.Cleanup(kill)
		return kill, nil, ""
	}
	io.Copy(&out, pr)
	return nil, <-done, out.String()
}

// A fake killed without cleanup leaves its socket; the next fake on the same
// path removes it and binds. Anything at the path that is not a socket stays
// and makes the fake fail with exit 3.
func TestFakePG_ReplacesStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sock, logf := filepath.Join(dir, "s"), filepath.Join(dir, "log")
	first, err, out := startFakeProcess(t, "--socket", sock, "--log", logf)
	if first == nil {
		t.Fatalf("first fake: %v %q", err, out)
	}
	first()
	if fi, err := os.Lstat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("no stale socket after SIGKILL: %v", err)
	}
	second, err, out := startFakeProcess(t, "--socket", sock, "--log", logf)
	if second == nil {
		t.Fatalf("second fake on the same path: %v %q", err, out)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("second fake unreachable: %v", err)
	}
	c.Close()

	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, err, _ := startFakeProcess(t, "--socket", plain, "--log", logf)
	var ee *exec.ExitError
	if cmd != nil || !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("fake on a regular file: %v, want exit 3", err)
	}
	if b, err := os.ReadFile(plain); err != nil || string(b) != "keep" {
		t.Fatalf("regular file changed: %q %v", b, err)
	}
}

// The error of escapes carries each control byte a log line or terminal could
// act on in its message, detail and hint fields: LF, CR, TAB, backspace, DEL and
// a raw single-byte C1 CSI (0x9b, not part of a UTF-8 sequence).
func TestFakePG_EscapesCarryControls(t *testing.T) {
	sock, _ := startModeFake(t, "escapes")
	c := dialFake(t, sock)
	login(t, c)
	query(t, c, false)
	var errBody []byte
	for errBody == nil {
		if typ, b := readMsg(t, c); typ == 'E' {
			errBody = b
		}
	}
	fields := map[byte][]byte{}
	for _, f := range bytes.Split(bytes.TrimSuffix(errBody, []byte{0, 0}), []byte{0}) {
		if len(f) > 0 {
			fields[f[0]] = append(fields[f[0]], f[1:]...)
		}
	}
	for _, field := range []byte{'M', 'D', 'H'} {
		for _, ctl := range []string{"\n", "\r", "\t", "\x08", "\x7f", " \x9b"} {
			if !bytes.Contains(fields[field], []byte(ctl)) {
				t.Errorf("field %c lacks %q: %q", field, ctl, fields[field])
			}
		}
	}
}

// A fake refuses a path whose socket is live (exit 3, the live fake keeps it).
// A fake that stops removes only its own socket: when the path holds another
// socket by then, that socket stays and keeps answering.
func TestFakePG_StopKeepsTheSocketOfAFakeThatTookOver(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "s")
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), testArgsEnv+"="+strings.Join([]string{"fakepg", "--socket", sock,
		"--log", filepath.Join(dir, "log1"), "--mode", "stall"}, "\n"))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line := make([]byte, 9)
	if _, err := io.ReadFull(out, line); err != nil || string(line) != "listening" {
		t.Fatalf("first fake: %q %v", line, err)
	}
	go io.Copy(io.Discard, out)
	var ee *exec.ExitError
	if second, err, msg := startFakeProcess(t, "--socket", sock, "--log", filepath.Join(dir, "log2")); second != nil ||
		!errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("second fake on a live socket: %v %q, want exit 3", err, msg)
	}
	if c, err := net.Dial("unix", sock); err != nil {
		t.Fatalf("the live fake lost its socket to a refused one: %v", err)
	} else {
		c.Close()
	}
	// The path is given to another fake behind the first one's back.
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	if second, err, msg := startFakeProcess(t, "--socket", sock, "--log", filepath.Join(dir, "log2")); second == nil {
		t.Fatalf("second fake on a free path: %v %q", err, msg)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("the second fake's socket is gone after the first fake stopped: %v", err)
	}
	c.Close()
}

// On SIGTERM the fake removes its socket, so the path is free for the next one.
func TestFakePG_StopRemovesItsSocket(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "s")
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), testArgsEnv+"="+strings.Join([]string{"fakepg", "--socket", sock,
		"--log", filepath.Join(dir, "log"), "--mode", "stall"}, "\n"))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line := make([]byte, 9)
	if _, err := io.ReadFull(out, line); err != nil || string(line) != "listening" {
		t.Fatalf("fake: %q %v", line, err)
	}
	go io.Copy(io.Discard, out)
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("exit: %v", err)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket still at its path after SIGTERM: %v", err)
	}
}

// A socket at the path that cannot be tried (connect fails other than refused)
// is neither taken as stale nor removed: exit 3, and it stays.
func TestFakePG_UntriableSocketIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root connects whatever the socket's mode")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if err := os.Chmod(sock, 0); err != nil {
		t.Fatal(err)
	}
	stop, err, out := startFakeProcess(t, "--socket", sock, "--log", filepath.Join(dir, "log"))
	var ee *exec.ExitError
	if stop != nil || !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("fake on an untriable socket: %v %q, want exit 3", err, out)
	}
	if fi, err := os.Lstat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the socket was removed: %v", err)
	}
}

// With --listen the fake serves on TCP. scram-bad-signature completes the
// exchange with a well-formed final message whose signature is not the
// password's, then AuthenticationOk and ReadyForQuery; from there it is
// escapes. The log holds the client's bytes as with a socket.
func TestFakePG_ListenTCP_ScramBadSignature(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte(testPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logf := filepath.Join(t.TempDir(), "log")
	addr := start(t, "fakepg", "--listen", "127.0.0.1:0", "--log", logf, "--mode", "scram-bad-signature",
		"--password-file", pw, "--salt", testSaltHex)
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(2 * time.Second))
	c := &recConn{Conn: nc}
	c.Write(startupPacket())
	// scram fails the test on a wrong signature; read the final message by hand.
	expectAuth(t, c, 10)
	const cnonce = "abcdefghijklmnop"
	first := "n=,r=" + cnonce
	writeMsg(t, c, 'p', []byte("SCRAM-SHA-256\x00"), binary.BigEndian.AppendUint32(nil, uint32(3+len(first))), []byte("n,,"+first))
	sf := string(expectAuth(t, c, 11))
	salt, _ := hex.DecodeString(testSaltHex)
	sp, _ := pbkdf2.Key(sha256.New, testPassword, salt, 4096, 32)
	ck := hmacSHA256(sp, "Client Key")
	sk := sha256.Sum256(ck)
	nonce := strings.Split(sf, ",")[0][2:]
	final := "c=biws,r=" + nonce
	am := first + "," + sf + "," + final
	proof := hmacSHA256(sk[:], am)
	for i := range proof {
		proof[i] ^= ck[i]
	}
	writeMsg(t, c, 'p', []byte(final+",p="+base64.StdEncoding.EncodeToString(proof)))
	got := string(expectAuth(t, c, 12))
	right := "v=" + base64.StdEncoding.EncodeToString(hmacSHA256(hmacSHA256(sp, "Server Key"), am))
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "v="))
	if !strings.HasPrefix(got, "v=") || err != nil || len(sig) != 32 || got == right {
		t.Fatalf("server-final %q: want a well-formed, wrong signature (the right one is %q)", got, right)
	}
	expectAuth(t, c, 0)
	readGreeting(t, c)
	query(t, c, false)
	var got2 []byte
	for typ := byte(0); typ != 'Z'; {
		typ, _ = readMsg(t, c)
		got2 = append(got2, typ)
	}
	if string(got2) != "NNEZ" {
		t.Fatalf("answer %q, want the answer of escapes: NNEZ", got2)
	}
	writeMsg(t, c, 'X')
	c.Close()
	waitLog(t, logf, c.sent.Bytes())
}
