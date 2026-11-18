package gateway

import (
	"net"
	"net/netip"
	"sync"
)

// Connection caps of the public listeners.
const (
	MaxConns          = 2048
	MaxConnsPerSource = 64

	// sockBuf is the kernel receive and send buffer of every client and
	// upstream connection; Linux doubles it for its bookkeeping. Left alone,
	// the kernel autotunes them to megabytes per connection, memory the heap
	// limit does not see. The buffer also caps a connection's speed at about
	// one window per round trip each way: 32 to 58 KiB received (the window
	// is a share of the 64 KiB the kernel accounts). Within the 60 s read
	// timeout a body of at least 18 MiB fits at a 100 ms round trip, 9.4 MiB
	// at 200 ms and 4.7 MiB at 400 ms (up to 34, 17 and 8.5 MiB with the
	// larger window); the 8 MiB body limit always fits up to 200 ms.
	sockBuf = 32 << 10
)

// Limiter caps open connections in total and per source across every listener
// it wraps. A source is the address for IPv4 (IPv4-mapped IPv6 included) and
// the /64 for IPv6, the smallest block one IPv6 host is usually given. A
// connection over either cap is closed at accept.
type Limiter struct {
	total, perSource int

	mu    sync.Mutex
	n     int
	bySrc map[netip.Prefix]int
}

func NewLimiter(total, perSource int) *Limiter {
	return &Limiter{total: total, perSource: perSource, bySrc: map[netip.Prefix]int{}}
}

// Listen wraps ln.
func (l *Limiter) Listen(ln net.Listener) net.Listener { return &limitListener{ln, l} }

func (l *Limiter) acquire(src netip.Prefix) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n >= l.total || l.bySrc[src] >= l.perSource {
		return false
	}
	l.n++
	l.bySrc[src]++
	return true
}

func (l *Limiter) release(src netip.Prefix) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n--
	if l.bySrc[src]--; l.bySrc[src] == 0 {
		delete(l.bySrc, src)
	}
}

type limitListener struct {
	net.Listener
	l *Limiter
}

func (ll *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := ll.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ap, _ := netip.ParseAddrPort(c.RemoteAddr().String()) // unparsable: one shared zero bucket
		src := source(ap.Addr())
		if ll.l.acquire(src) {
			fixBuffers(c)
			return &limitConn{Conn: c, release: func() { ll.l.release(src) }}, nil
		}
		c.Close()
	}
}

// fixBuffers sets c's kernel buffers to sockBuf.
func fixBuffers(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetReadBuffer(sockBuf)
		tc.SetWriteBuffer(sockBuf)
	}
}

// source is the per-source key of a: its /32 for IPv4, its /64 for IPv6.
func source(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, _ := a.Prefix(bits) // the zero address: the zero prefix
	return p
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}
