package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Request codes a client may send before its startup packet; a backend without
// TLS or GSSAPI declines each with 'N'.
const (
	sslRequest    = 80877103
	gssEncRequest = 80877104
)

// fakeModes are the behaviours of the fake server. postAuth modes first complete
// a SCRAM-SHA-256 exchange with the configured password and salt.
var (
	fakeModes = map[string]bool{"sasl": true, "cleartext": true, "md5": true, "authok": true, "sasl-iter": true,
		"huge": true, "flood": true, "stall": true, "trickle": true,
		"row-huge": true, "rows-endless": true, "stall-auth": true, "escapes": true}
	postAuth = map[string]bool{"row-huge": true, "rows-endless": true, "stall-auth": true, "escapes": true}
)

const (
	// fakeStreamCap bounds what one connection of a streaming mode sends; then
	// the fake holds the connection silently.
	fakeStreamCap = 1 << 30
	scramIter     = 4096
	// fakeMaxMessage bounds a client message the fake parses; after a longer one
	// it only logs.
	fakeMaxMessage = 10000
)

type fakeConfig struct {
	mode     string
	password string // post-authentication modes
	salt     []byte // post-authentication modes
}

// fakePG listens on a Unix socket like a Postgres backend and answers each
// client as cfg.mode says, and appends every byte any client sends to logFile.
// No mode lets a client do anything: the post-authentication modes accept a
// SCRAM login and then misbehave.
//
// The log is a series of chunks, each the header line "conn N LEN" (N numbers the
// connections from 1) followed by the LEN bytes as received. It is created once
// the socket is bound, and "listening" is printed after both. A reader takes a
// header line, then exactly LEN bytes, and repeats; the payload is client data
// and may itself contain text shaped like a header.
//
// A stale socket at the path (nothing accepts on it: a fake that was killed
// leaves one) is removed first; a live socket, or any other file, is an error.
// The fake may run as a container's init: it reaps nothing and on SIGTERM or
// SIGINT (the stop signal Postgres images declare) exits 0, removing its socket
// if the path still holds it.
func fakePG(socket string, cfg fakeConfig, logFile string, stdout io.Writer) error {
	if err := removeStaleSocket(socket); err != nil {
		return err
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	// Removed by inode, never by name: the path may hold another socket by then.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	own, err := os.Lstat(socket)
	if err != nil {
		l.Close()
		return err
	}
	removeOwn := func() {
		if fi, err := os.Lstat(socket); err == nil && os.SameFile(fi, own) {
			os.Remove(socket)
		}
	}
	defer removeOwn()
	defer l.Close()
	// Any local user may connect, as to a real backend's socket.
	if err := os.Chmod(socket, 0o777); err != nil {
		return err
	}
	logf, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-term; removeOwn(); os.Exit(0) }()
	fmt.Fprintln(stdout, "listening", socket)
	var mu sync.Mutex
	for n := 1; ; n++ {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go serveFake(c, io.TeeReader(c, &chunkLog{f: logf, mu: &mu, conn: n}), cfg)
	}
}

// removeStaleSocket removes a socket at path that refuses connections; a socket
// that accepts one belongs to a live server and is an error, as is any file that
// is not a socket or a socket that cannot be tried.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil // nothing there (or unreachable: the bind reports it)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		c.Close()
		return fmt.Errorf("%s is the socket of a live server", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%s: cannot tell whether the socket is stale: %v", path, err)
	}
	return os.Remove(path)
}

// chunkLog writes each chunk a connection sends as one framed record.
type chunkLog struct {
	f    *os.File
	mu   *sync.Mutex
	conn int
}

func (w *chunkLog) Write(p []byte) (int, error) {
	rec := append(fmt.Appendf(nil, "conn %d %d\n", w.conn, len(p)), p...)
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(rec); err != nil {
		return 0, err
	}
	return len(p), nil
}

// msg frames a backend message.
func msg(typ byte, body ...[]byte) []byte {
	b := bytes.Join(body, nil)
	return append(binary.BigEndian.AppendUint32([]byte{typ}, uint32(4+len(b))), b...)
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func authMsg(code uint32, data ...[]byte) []byte {
	return msg('R', append([][]byte{u32(code)}, data...)...)
}

var (
	saslRequest = authMsg(10, []byte("SCRAM-SHA-256\x00\x00"))
	// What a server sends after authentication up to ReadyForQuery.
	greeting = bytes.Join([][]byte{
		msg('S', []byte("server_version\x0017.0\x00")),
		msg('S', []byte("client_encoding\x00UTF8\x00")),
		msg('S', []byte("standard_conforming_strings\x00on\x00")),
		msg('S', []byte("integer_datetimes\x00on\x00")),
		msg('K', u32(4242), u32(4242)),
		msg('Z', []byte("I")),
	}, nil)
	rowDescription = msg('T', []byte{0, 1}, []byte("c\x00"), u32(0), []byte{0, 0}, u32(25), []byte{0xff, 0xff},
		u32(0xffffffff), []byte{0, 0})
	// Text a terminal or log viewer would interpret: CSI and OSC sequences,
	// C1 CSI as UTF-8 and as a raw byte, LF, CR, TAB, backspace, DEL, invalid
	// UTF-8, and (in the error) a NUL that ends the message field early, so the
	// rest arrives as a second message field.
	controlText = "line\nfeed\rreturn\ttab\x08back\x7fdel \x9b"
	escapeText  = "fake-marker \x1b[2J\x1b[31mred\x1b[0m \x1b]0;fake-title\x07 \x1b]8;;http://example.test/\x1b\\link\x1b]8;;\x1b\\ \xc2\x9b \xff\xfe\xc3\x28 " + controlText
	escapes     = bytes.Join([][]byte{
		msg('N', []byte("SNOTICE\x00VNOTICE\x00C00000\x00M"+escapeText+"\x00\x00")),
		msg('N', []byte("SWARNING\x00VWARNING\x00C01000\x00Mfake-marker \x1b[1mbold\x1b[0m\x00\x00")),
		msg('E', []byte("SERROR\x00VERROR\x00CXX000\x00M"+escapeText+"\x00Mfake-marker after NUL \x1b[0m\xff "+controlText+
			"\x00Dfake-marker detail "+escapeText+"\x00Hfake-marker hint "+escapeText+"\x00\x00")),
		msg('Z', []byte("I")),
	}, nil)
)

// serveFake answers one client. Every byte the client sends passes through r
// and so reaches the log; the fake never closes a connection before the client
// does. After a client message too long to parse it only logs.
func serveFake(c net.Conn, r io.Reader, cfg fakeConfig) {
	defer c.Close()
	if !startup(c, r) {
		return
	}
	switch cfg.mode {
	case "sasl":
		c.Write(saslRequest)
	case "cleartext":
		c.Write(authMsg(3))
	case "md5":
		c.Write(authMsg(5, []byte(rand.Text()[:4])))
	case "authok":
		c.Write(append(authMsg(0), greeting...))
	case "stall":
	case "trickle":
		streamWhileLogging(r, func() {
			for i := range saslRequest {
				if _, err := c.Write(saslRequest[i : i+1]); err != nil {
					return
				}
				time.Sleep(time.Second)
			}
		})
		return
	case "huge":
		// An authentication message whose header announces 1 GiB.
		streamWhileLogging(r, func() { streamN(c, append([]byte{'R'}, u32(1<<30)...), make([]byte, 1<<16), 1<<30-4) })
		return
	case "flood":
		var chunk []byte
		for len(chunk) < 1<<16 {
			chunk = append(chunk, msg('S', []byte("fake_parameter\x00fake value\x00"))...)
			chunk = append(chunk, msg('N', []byte("SNOTICE\x00VNOTICE\x00C00000\x00Mfake notice\x00\x00"))...)
		}
		streamWhileLogging(r, func() { streamN(c, nil, chunk, fakeStreamCap) })
		return
	case "sasl-iter":
		c.Write(saslRequest)
		if cnonce, _, ok := clientFirst(r); ok {
			salt := make([]byte, 16)
			rand.Read(salt)
			c.Write(authMsg(11, []byte("r="+cnonce+rand.Text()+",s="+base64.StdEncoding.EncodeToString(salt)+",i=10000000")))
		}
	default: // post-authentication modes
		if scramLogin(c, r, cfg) {
			afterLogin(c, r, cfg.mode)
		}
	}
	io.Copy(io.Discard, r)
}

// startup declines SSL and GSS encryption requests and consumes the startup
// packet; false when the client went away.
func startup(c net.Conn, r io.Reader) bool {
	for {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return false
		}
		n := binary.BigEndian.Uint32(hdr)
		if n < 8 || n > fakeMaxMessage {
			return true
		}
		if _, err := io.CopyN(io.Discard, r, int64(n-8)); err != nil {
			return false
		}
		if code := binary.BigEndian.Uint32(hdr[4:]); n != 8 || code != sslRequest && code != gssEncRequest {
			return true
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return false
		}
	}
}

// streamWhileLogging runs send while the client's bytes keep reaching the log,
// then holds the connection until the client closes it.
func streamWhileLogging(r io.Reader, send func()) {
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, r); close(done) }()
	send()
	<-done
}

// readFrontend reads one frontend message; ok is false when the client went away or
// the message is longer than the fake parses.
func readFrontend(r io.Reader) (typ byte, body []byte, ok bool) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, false
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n < 4 || n > fakeMaxMessage {
		return 0, nil, false
	}
	body = make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, false
	}
	return hdr[0], body, true
}

// clientFirst reads a SASLInitialResponse and returns the client nonce and the
// client-first-message-bare.
func clientFirst(r io.Reader) (nonce, bare string, ok bool) {
	typ, body, ok := readFrontend(r)
	mech, rest, found := bytes.Cut(body, []byte{0})
	if !ok || typ != 'p' || !found || string(mech) != "SCRAM-SHA-256" || len(rest) < 4 {
		return "", "", false
	}
	data := string(rest[4:])
	// gs2-header "n,," (or "y,,"), then the bare message "n=USER,r=NONCE[,…]".
	parts := strings.SplitN(data, ",", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	bare = parts[2]
	for _, kv := range strings.Split(bare, ",") {
		if v, found := strings.CutPrefix(kv, "r="); found && v != "" {
			return v, bare, true
		}
	}
	return "", "", false
}

func hmacSum(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// scramLogin runs the server side of SCRAM-SHA-256 with cfg's password and salt
// and 4096 iterations, and on a valid proof sends the server signature,
// AuthenticationOk and the usual messages up to ReadyForQuery. A wrong proof gets
// an authentication failure.
func scramLogin(c net.Conn, r io.Reader, cfg fakeConfig) bool {
	c.Write(saslRequest)
	cnonce, bare, ok := clientFirst(r)
	if !ok {
		return false
	}
	nonce := cnonce + rand.Text()
	serverFirst := "r=" + nonce + ",s=" + base64.StdEncoding.EncodeToString(cfg.salt) + fmt.Sprintf(",i=%d", scramIter)
	if _, err := c.Write(authMsg(11, []byte(serverFirst))); err != nil {
		return false
	}
	typ, body, ok := readFrontend(r)
	final := string(body)
	i := strings.LastIndex(final, ",p=")
	if !ok || typ != 'p' || i < 0 || !strings.Contains(final[:i]+",", ",r="+nonce+",") {
		return false
	}
	proof, err := base64.StdEncoding.DecodeString(final[i+3:])
	salted, err2 := pbkdf2.Key(sha256.New, cfg.password, cfg.salt, scramIter, sha256.Size)
	if err != nil || err2 != nil || len(proof) != sha256.Size {
		return false
	}
	authMessage := bare + "," + serverFirst + "," + final[:i]
	clientKey := hmacSum(storedKey(salted), authMessage)
	for j := range clientKey {
		clientKey[j] ^= proof[j]
	}
	if sum := sha256.Sum256(clientKey); !hmac.Equal(sum[:], storedKey(salted)) {
		c.Write(msg('E', []byte("SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")))
		return false
	}
	sig := hmacSum(hmacSum(salted, "Server Key"), authMessage)
	_, err = c.Write(bytes.Join([][]byte{authMsg(12, []byte("v="+base64.StdEncoding.EncodeToString(sig))), authMsg(0), greeting}, nil))
	return err == nil
}

func storedKey(salted []byte) []byte {
	s := sha256.Sum256(hmacSum(salted, "Client Key"))
	return s[:]
}

// afterLogin answers queries — a simple Query, or the Sync that ends an extended
// protocol batch — as mode says, until the client stops.
func afterLogin(c net.Conn, r io.Reader, mode string) {
	for {
		typ, _, ok := readFrontend(r)
		if !ok {
			return
		}
		if typ != 'Q' && typ != 'S' {
			continue
		}
		var prefix []byte
		if typ == 'S' {
			prefix = append(msg('1'), msg('t', []byte{0, 0})...) // ParseComplete, no parameters
		}
		switch mode {
		case "escapes":
			if _, err := c.Write(escapes); err != nil {
				return
			}
		case "row-huge":
			// One DataRow whose single column announces 64 MiB.
			const size = 64 << 20
			head := bytes.Join([][]byte{prefix, rowDescription, {'D'}, u32(4 + 2 + 4 + size), {0, 1}, u32(size)}, nil)
			streamWhileLogging(r, func() { streamN(c, head, bytes.Repeat([]byte{'x'}, 1<<16), size) })
			return
		case "rows-endless":
			row := msg('D', []byte{0, 1}, u32(1024-11), bytes.Repeat([]byte{'x'}, 1024-11))
			streamWhileLogging(r, func() { streamN(c, append(prefix, rowDescription...), bytes.Repeat(row, 64), fakeStreamCap) })
			return
		}
		// stall-auth: no reply.
	}
}

// streamN writes head, then n bytes of chunk repeated, or until the client goes
// away. n is at most fakeStreamCap.
func streamN(c net.Conn, head, chunk []byte, n int) {
	if _, err := c.Write(head); err != nil {
		return
	}
	for ; n > 0; n -= len(chunk) {
		if n < len(chunk) {
			chunk = chunk[:n]
		}
		if _, err := c.Write(chunk); err != nil {
			return
		}
	}
}
