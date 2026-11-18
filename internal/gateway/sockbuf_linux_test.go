package gateway

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// sockopts returns the kernel's SO_RCVBUF and SO_SNDBUF of c.
func sockopts(t *testing.T, c net.Conn) (rcv, snd int) {
	t.Helper()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("%T is not a TCP connection", c)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var e1, e2 error
	if err := raw.Control(func(fd uintptr) {
		rcv, e1 = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		snd, e2 = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}); err != nil || e1 != nil || e2 != nil {
		t.Fatal(err, e1, e2)
	}
	return rcv, snd
}

// TestSocketBuffers: accepted client connections and upstream connections
// carry fixed kernel buffers (Linux reports twice the value set), so the
// kernel cannot autotune them to megabytes per connection.
func TestSocketBuffers(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := NewLimiter(10, 10).Listen(raw)
	go func() {
		if c, err := net.Dial("tcp", raw.Addr().String()); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if rcv, snd := sockopts(t, c.(*limitConn).Conn); rcv != 2*sockBuf || snd != 2*sockBuf {
		t.Errorf("client side: SO_RCVBUF %d SO_SNDBUF %d, want %d", rcv, snd, 2*sockBuf)
	}

	up, err := New(nil).transport.DialContext(context.Background(), "tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if rcv, snd := sockopts(t, up); rcv != 2*sockBuf || snd != 2*sockBuf {
		t.Errorf("upstream side: SO_RCVBUF %d SO_SNDBUF %d, want %d", rcv, snd, 2*sockBuf)
	}
}
