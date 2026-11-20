package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// start runs a never-ending subcommand in the background and returns the address
// it prints on its first stdout line ("listening ADDR").
func start(t *testing.T, args ...string) string {
	t.Helper()
	pr, pw := io.Pipe()
	go run(args, pw)
	line, err := bufio.NewReader(pr).ReadString('\n')
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	go io.Copy(io.Discard, pr)
	addr, ok := strings.CutPrefix(strings.TrimSpace(line), "listening ")
	if !ok {
		t.Fatalf("%v: first line %q", args, line)
	}
	return addr
}

func probe(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	return run(args, &out), out.String()
}

// expect runs a probe and checks its exit status and its single verdict line.
func expect(t *testing.T, name string, code int, line string, args ...string) {
	t.Helper()
	got, out := probe(t, args...)
	if got != code || out != line+"\n" {
		t.Errorf("%s: exit %d, output %q; want %d, %q", name, got, out, code, line)
	}
}

// closedPort returns a loopback address nothing listens on.
func closedPort(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := c.LocalAddr().String()
		c.Close()
		return a
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

// fullBacklog returns a loopback TCP address whose accept queue is full, so the
// kernel drops further SYNs and a connect times out.
func fullBacklog(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.(*syscall.SockaddrInet4).Port))
	for range 8 {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return addr
		}
		t.Cleanup(func() { c.Close() })
	}
	t.Fatal("accept queue never filled")
	return ""
}

// udpResponder answers every datagram on a loopback socket with reply(query);
// a nil reply means silence. from, when set, sends the answer from another socket.
func udpResponder(t *testing.T, reply func([]byte) []byte, from net.PacketConn) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			r := reply(append([]byte{}, buf[:n]...))
			if r == nil {
				continue
			}
			out := c
			if from != nil {
				out = from
			}
			out.WriteTo(r, peer)
		}
	}()
	return c.LocalAddr().String()
}

func TestTCP_ConnectedRefusedTimeout(t *testing.T) {
	open := start(t, "listen", "tcp", "127.0.0.1:0")
	expect(t, "connected", 0, "connected", "tcp", open, "--timeout", "300ms")
	expect(t, "refused", 1, "refused ECONNREFUSED", "tcp", closedPort(t, "tcp"), "--timeout", "300ms")
	expect(t, "timeout", 2, "timeout", "tcp", fullBacklog(t), "--timeout", "300ms")
}

func TestTCP_IPv6LoopbackAndExactBind(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	l.Close()
	port := heldPort(t)
	for try := 0; ; try++ { // until a port this test holds on 127.0.0.1 is free on [::1] too
		if l, err := net.Listen("tcp", net.JoinHostPort("::1", port)); err == nil {
			l.Close()
			break
		} else if try == 20 {
			t.Fatal(err)
		}
		port = heldPort(t)
	}
	// The canary binds exactly its address: it starts although the same port
	// of 127.0.0.1 is held by another socket, and that port stays closed.
	open := start(t, "listen", "tcp", net.JoinHostPort("::1", port))
	expect(t, "[::1] listener", 0, "connected", "tcp", open, "--timeout", "300ms")
	expect(t, "other address, same port", 1, "refused ECONNREFUSED", "tcp", net.JoinHostPort("127.0.0.1", port), "--timeout", "300ms")
}

// heldPort returns a TCP port of 127.0.0.1 that a socket of this test holds
// until the test ends — bound, not listening, without address reuse — so that
// no other process can listen there meanwhile and a connect is refused. A port
// the kernel picks for another address may be anyone's on 127.0.0.1.
func heldPort(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(sa.(*syscall.SockaddrInet4).Port)
}

// Failing to resolve HOST is neither "refused" (1) nor "timeout" (2).
func TestTCP_UnresolvableHostIsError(t *testing.T) {
	if got, out := probe(t, "tcp", "missing.sp.test:5432", "--timeout", "2s"); got != 3 || !strings.HasPrefix(out, "error ") {
		t.Errorf("exit %d, output %q", got, out)
	}
}

func TestUDP_EchoAndSilence(t *testing.T) {
	echo := start(t, "listen", "udp", "127.0.0.1:0")
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	other := udpResponder(t, func([]byte) []byte { return []byte("something else") }, nil)
	expect(t, "echo", 0, "answered", "udp", echo, "--timeout", "300ms")
	expect(t, "refused", 1, "refused ECONNREFUSED", "udp", closedPort(t, "udp"), "--timeout", "300ms")
	expect(t, "silence", 2, "timeout", "udp", silent.LocalAddr().String(), "--timeout", "300ms")
	expect(t, "answer without the nonce", 2, "timeout", "udp", other, "--timeout", "300ms")
}

// An answer from any address other than the probed one is not an answer.
func TestUDP_AnswerFromAnotherSourceIsTimeout(t *testing.T) {
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	addr := udpResponder(t, func(q []byte) []byte { return q }, other)
	expect(t, "other source", 2, "timeout", "udp", addr, "--timeout", "300ms")
}

// A broadcast target is answered from a unicast address; that echo counts.
func TestUDP_BroadcastAnsweredFromUnicast(t *testing.T) {
	echo := start(t, "listen", "udp", "0.0.0.0:0")
	_, port, _ := net.SplitHostPort(echo)
	expect(t, "broadcast", 0, "answered", "udp", net.JoinHostPort("127.255.255.255", port), "--timeout", "500ms")
}

// A timeout that cannot be honoured is a usage error, never "timeout" (2).
func TestTimeout_NonPositiveIsUsage(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	for _, v := range []string{"0", "-1s"} {
		if got, out := probe(t, "udp", silent.LocalAddr().String(), "--timeout", v); got != 3 || !strings.HasPrefix(out, "error ") {
			t.Errorf("--timeout %s: exit %d, output %q", v, got, out)
		}
	}
}

func TestUsage_ExitCodes(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"nope"},
		{"tcp"},
		{"tcp", "127.0.0.1:1", "127.0.0.1:2"},
		{"dns", "a.sp.test"},
		{"dns", "a.sp.test", "--server", "127.0.0.1", "--type", "MX"},
		{"listen", "sctp", "127.0.0.1:0"},
		{"listen", "tcp", "127.0.0.1:0", "--join", "ff02::fb"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "undefined"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "huge", "--salt", "00"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "sasl-iter"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "sasl-iter", "--salt", "zz"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "sasl-iter", "--password-file", "/dev/null", "--salt", "00"},
		{"fakepg", "--socket", "s", "--log", "l", "--password-file", "/dev/null"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "md5", "--password-file", "/dev/null", "--salt", "00"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "row-huge", "--salt", "00"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "row-huge", "--password-file", "/dev/null"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "row-huge", "--password-file", "/dev/null", "--salt", "zz"},
		{"fakepg", "--socket", "s", "--log", "l", "--mode", "row-huge", "--password-file", "missing-file", "--salt", "00"},
		{"fakepg", "--log", "l"},
		{"fakepg", "--socket", "s", "--listen", "127.0.0.1:0", "--log", "l"},
		{"fakepg", "--listen", "127.0.0.1:0", "--log", "l", "--mode", "scram-bad-signature"},
		{"fakepg", "--listen", "127.0.0.1:0", "--log", "l", "--mode", "sasl", "--salt", "00"},
		{"fakepg", "--listen", "127.0.0.1:0", "--log", "l", "--mode", "scram-low"},
		{"fakepg", "--listen", "127.0.0.1:0", "--log", "l", "--mode", "scram-low", "--password-file", "/dev/null", "--salt", "00"},
		{"fakepg", "--listen", "127.0.0.1:0", "--log", "l", "--mode", "copy-both", "--salt", "00"},
		{"fakepg", "--listen", "127.0.0.1:0", "--log", "l", "--mode", "param-flood", "--password-file", "/dev/null"},
		{"tcp", "127.0.0.1:1", "--bogus"},
		{"tcp", "127.0.0.1"},
	} {
		if got, out := probe(t, args...); got != 3 || !strings.HasPrefix(out, "error ") {
			t.Errorf("%q: exit %d, output %q", args, got, out)
		}
	}
}

// dnsReply builds a response to query q with rcode and the given records of the
// queried type (4 bytes: A, 16 bytes: AAAA).
func dnsReply(q []byte, rcode byte, records ...[]byte) []byte {
	end := 12
	for end < len(q) && q[end] != 0 {
		end += int(q[end]) + 1
	}
	end += 5
	r := append([]byte{}, q[:end]...)
	r[2], r[3] = 0x81, 0x80|rcode
	binary.BigEndian.PutUint16(r[6:], uint16(len(records)))
	for _, a := range records {
		typ := byte(1)
		if len(a) == 16 {
			typ = 28
		}
		r = append(r, 0xc0, 12, 0, typ, 0, 1, 0, 0, 0, 60, 0, byte(len(a)))
		r = append(r, a...)
	}
	return r
}

// Only an address of the queried type means "this name resolves"; a negative
// answer must not exit 0, or "an external name does not resolve" could never be
// asserted.
func TestDNS_AnswerAndNegative(t *testing.T) {
	v4, v6 := []byte{192, 0, 2, 10}, net.ParseIP("2001:db8::10").To16()
	for _, c := range []struct {
		name, qtype string
		reply       func([]byte) []byte
		want        int
		line        string
	}{
		{"address", "A", func(q []byte) []byte { return dnsReply(q, 0, v4) }, 0, "answered 192.0.2.10"},
		{"aaaa", "AAAA", func(q []byte) []byte { return dnsReply(q, 0, v6) }, 0, "answered 2001:db8::10"},
		{"wrong type only", "AAAA", func(q []byte) []byte { return dnsReply(q, 0, v4) }, 1, "negative NOERROR"},
		{"nxdomain", "A", func(q []byte) []byte { return dnsReply(q, 3) }, 1, "negative NXDOMAIN"},
		{"nodata", "A", func(q []byte) []byte { return dnsReply(q, 0) }, 1, "negative NOERROR"},
		{"servfail", "A", func(q []byte) []byte { return dnsReply(q, 2) }, 1, "negative SERVFAIL"},
		{"refused", "A", func(q []byte) []byte { return dnsReply(q, 5) }, 1, "negative REFUSED"},
		{"truncated", "A", func(q []byte) []byte { r := dnsReply(q, 0); r[2] |= 0x02; return r }, 3, "error truncated answer"},
		{"silence", "A", func([]byte) []byte { return nil }, 2, "timeout"},
	} {
		srv := udpResponder(t, c.reply, nil)
		expect(t, c.name, c.want, c.line, "dns", "a.sp.test", "--server", srv, "--type", c.qtype, "--timeout", "300ms")
	}
}

func TestDNS_ServerPortClosedIsRefused(t *testing.T) {
	expect(t, "closed", 1, "refused ECONNREFUSED", "dns", "a.sp.test", "--server", closedPort(t, "udp"))
}

// Random garbage after a matching id and QR bit never crashes the parser (a Go
// panic exits 2, which a caller would read as "timeout").
func TestDNS_GarbageNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	var mu sync.Mutex
	srv := udpResponder(t, func(q []byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		r := make([]byte, 12+rng.IntN(200))
		for i := range r {
			r[i] = byte(rng.Uint32())
		}
		copy(r, q[:2])
		r[2] |= 0x80
		return r
	}, nil)
	for range 500 {
		if code, out := probe(t, "dns", "a.sp.test", "--server", srv); code == 2 || out == "error panic\n" {
			t.Fatalf("exit %d, output %q on an answered query", code, out)
		}
	}
}

func startFake(t *testing.T, args ...string) (sock, logf string) {
	t.Helper()
	dir := t.TempDir()
	sock, logf = filepath.Join(dir, "s"), filepath.Join(dir, "log")
	start(t, append([]string{"fakepg", "--socket", sock, "--log", logf}, args...)...)
	return sock, logf
}

// logStreams splits the fake's log into the bytes of each connection. The log is
// a series of chunks, each a header line "conn N LEN" and LEN raw bytes.
func logStreams(b []byte) (map[int][]byte, error) {
	out := map[int][]byte{}
	for len(b) > 0 {
		line, rest, ok := bytes.Cut(b, []byte("\n"))
		var conn, n int
		if _, err := fmt.Sscanf(string(line), "conn %d %d", &conn, &n); !ok || err != nil || n > len(rest) {
			return nil, fmt.Errorf("bad chunk at %q", line)
		}
		out[conn] = append(out[conn], rest[:n]...)
		b = rest[n:]
	}
	return out, nil
}

// waitLog waits until the log holds exactly one connection's bytes, equal to want.
func waitLog(t *testing.T, logf string, want []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, _ := os.ReadFile(logf)
		got, err := logStreams(raw)
		if err == nil && len(got) == 1 {
			for _, b := range got {
				if bytes.Equal(b, want) {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("log %q (%v), want one connection with %q", raw, err, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func startupPacket() []byte {
	params := "user\x00u1\x00database\x00postgres\x00\x00"
	p := binary.BigEndian.AppendUint32(nil, uint32(8+len(params)))
	p = binary.BigEndian.AppendUint32(p, 196608) // protocol 3.0
	return append(p, params...)
}

func passwordMessage() []byte {
	return append([]byte{'p', 0, 0, 0, 11}, "secret\x00"...)
}

func TestFakePG_LogsEveryByte(t *testing.T) {
	for _, c := range []struct {
		args []string
		want []byte // the authentication request after the 'R' header
	}{
		{[]string{"--mode", "cleartext"}, []byte{0, 0, 0, 3}},
		{[]string{"--mode", "sasl"}, append([]byte{0, 0, 0, 10}, "SCRAM-SHA-256\x00\x00"...)},
		{nil, append([]byte{0, 0, 0, 10}, "SCRAM-SHA-256\x00\x00"...)}, // sasl by default
	} {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			sock, logf := startFake(t, c.args...)
			conn, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write(startupPacket()); err != nil {
				t.Fatal(err)
			}
			hdr := make([]byte, 5)
			if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 'R' {
				t.Fatalf("response header %q: %v", hdr, err)
			}
			body := make([]byte, binary.BigEndian.Uint32(hdr[1:])-4)
			if _, err := io.ReadFull(conn, body); err != nil || !bytes.Equal(body, c.want) {
				t.Fatalf("authentication request %q, want %q (%v)", body, c.want, err)
			}
			if _, err := conn.Write(passwordMessage()); err != nil {
				t.Fatal(err)
			}
			conn.Close()
			waitLog(t, logf, append(startupPacket(), passwordMessage()...))
		})
	}
}

// A client that pipelines its startup packet and password and hangs up at once
// still has every byte logged.
func TestFakePG_LogsPipelinedBytesAfterHangup(t *testing.T) {
	sock, logf := startFake(t, "--mode", "cleartext")
	msg := append(startupPacket(), passwordMessage()...)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitLog(t, logf, msg)
}

// SSLRequest and GSSENCRequest are each declined with 'N', as a backend without
// TLS or GSSAPI does; the startup packet then gets the authentication request.
func TestFakePG_DeclinesSSLAndGSSEnc(t *testing.T) {
	sock, logf := startFake(t)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	var sent []byte
	for _, code := range []uint32{80877104, 80877103} { // GSSENCRequest, SSLRequest
		req := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), code)
		sent = append(sent, req...)
		if _, err := c.Write(req); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil || b[0] != 'N' {
			t.Fatalf("request %d: answer %q (%v), want N", code, b, err)
		}
	}
	sent = append(sent, startupPacket()...)
	c.Write(startupPacket())
	hdr := make([]byte, 1)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 'R' {
		t.Fatalf("after startup: %q (%v), want R", hdr, err)
	}
	c.Close()
	waitLog(t, logf, sent)
}

// Garbage, short and oversized headers never stop the fake; many concurrent
// clients are all logged.
func TestFakePG_GarbageAndManyClients(t *testing.T) {
	sock, logf := startFake(t)
	junk := [][]byte{
		{0, 0, 0},
		{0, 0, 0, 1, 0, 0, 0, 0},
		{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0},
		bytes.Repeat([]byte{'x'}, 70000),
	}
	var want int
	var wg sync.WaitGroup
	for i := range 64 {
		msg := junk[i%len(junk)]
		want += len(msg)
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Error(err)
				return
			}
			c.Write(msg)
			c.(*net.UnixConn).CloseWrite()
			io.Copy(io.Discard, c)
			c.Close()
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw, _ := os.ReadFile(logf)
		got, err := logStreams(raw)
		total := 0
		for _, b := range got {
			total += len(b)
		}
		if err == nil && total == want {
			if len(got) != 64 {
				t.Fatalf("%d connections logged, want 64", len(got))
			}
			for conn, b := range got {
				if !slices.ContainsFunc(junk, func(j []byte) bool { return bytes.Equal(j, b) }) {
					t.Fatalf("connection %d logged %d bytes that no client sent", conn, len(b))
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("logged %d bytes (%v), want %d", total, err, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("fake gone after garbage: %v", err)
	}
	c.Close()
}

// Two clients whose bytes arrive interleaved are logged apart.
func TestFakePG_LogsEachConnectionApart(t *testing.T) {
	sock, logf := startFake(t, "--mode", "cleartext")
	a, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := []byte("aaaa-first "), []byte("bbbb-first ")
	for _, w := range []struct {
		c   net.Conn
		msg []byte
	}{{a, pa}, {b, pb}, {a, []byte("aaaa-second")}, {b, []byte("bbbb-second")}} {
		if _, err := w.c.Write(w.msg); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.Close()
	b.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, _ := os.ReadFile(logf)
		got, err := logStreams(raw)
		var streams []string
		for _, s := range got {
			streams = append(streams, string(s))
		}
		slices.Sort(streams)
		if err == nil && slices.Equal(streams, []string{"aaaa-first aaaa-second", "bbbb-first bbbb-second"}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log %q (%v)", raw, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The log is created only once the socket is bound, and "listening" follows both:
// a failed bind leaves no log, and a caller that saw the line finds the log.
func TestFakePG_ListeningOnlyWhenBoundAndLogging(t *testing.T) {
	dir := t.TempDir()
	logf := filepath.Join(dir, "log")
	if code, out := probe(t, "fakepg", "--socket", filepath.Join(dir, "missing", "s"), "--log", logf); code != 3 || out != "" {
		t.Errorf("bind failure: exit %d, output %q", code, out)
	}
	if _, err := os.Stat(logf); !os.IsNotExist(err) {
		t.Errorf("log after a failed bind: %v", err)
	}
	_, logf = startFake(t)
	if fi, err := os.Stat(logf); err != nil || fi.Size() != 0 {
		t.Errorf("log after listening: %v", err)
	}
}

// --device binds tcp and udp probes to an interface; it is refused for every
// other subcommand and when empty or longer than an interface name can be. A
// failing setsockopt is a local error (exit 3) that names the option.
func TestDevice_Arguments(t *testing.T) {
	open := start(t, "listen", "tcp", "127.0.0.1:0")
	echo := start(t, "listen", "udp", "127.0.0.1:0")
	expect(t, "tcp on lo", 0, "connected", "tcp", open, "--device", "lo", "--timeout", "500ms")
	expect(t, "udp on lo", 0, "answered", "udp", echo, "--device", "lo", "--timeout", "500ms")
	for _, args := range [][]string{
		{"tcp", open, "--device", ""},
		{"udp", echo, "--device", "abcdefghijklmnop"},
		{"dns", "a.sp.test", "--server", "127.0.0.1", "--device", "lo"},
		{"listen", "tcp", "127.0.0.1:0", "--device", "lo"},
		{"fakepg", "--socket", "s", "--log", "l", "--device", "lo"},
		{"sys", "--device", "lo"},
	} {
		if got, out := probe(t, args...); got != 3 || !strings.HasPrefix(out, "error usage") {
			t.Errorf("%q: exit %d, output %q", args, got, out)
		}
	}
	for _, args := range [][]string{
		{"tcp", open, "--device", "sp-none0", "--timeout", "500ms"},
		{"udp", echo, "--device", "sp-none0", "--timeout", "500ms"},
		// Multicast and broadcast targets take the unconnected-socket path.
		{"udp", "[ff02::1]:9", "--device", "sp-none0", "--timeout", "500ms"},
		{"udp", "127.255.255.255:9", "--device", "sp-none0", "--timeout", "500ms"},
	} {
		got, out := probe(t, args...)
		if got != 3 || !strings.HasPrefix(out, "error ") || !strings.Contains(out, "SO_BINDTODEVICE") ||
			strings.Count(out, "\n") != 1 {
			t.Errorf("%q: exit %d, output %q", args, got, out)
		}
	}
}
