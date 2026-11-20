package s3x

import (
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// dropping is a loopback address whose connection attempts are never
// answered: a listener with a full backlog that never accepts, so the
// kernel drops each further SYN, as a filtered address does.
func dropping(t *testing.T) netip.AddrPort {
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
	sa, _ := syscall.Getsockname(fd)
	a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(sa.(*syscall.SockaddrInet4).Port))
	// Fill the backlog until a dial hangs.
	for i := 0; i < 16; i++ {
		c, err := net.DialTimeout("tcp4", a.String(), 300*time.Millisecond)
		if err != nil {
			return a
		}
		t.Cleanup(func() { c.Close() })
	}
	t.Skip("could not make a loopback address that drops connection attempts")
	return a
}

// A handed address that drops connection attempts costs one bounded dial
// (dialMax), not the call's whole timeout: the next address is tried within
// it and the call succeeds.
func TestDial_ADroppingAddressCostsTheDialBoundThenTheNextIsTried(t *testing.T) {
	f := newFake(t)
	cfg := f.config()
	cfg.Timeout = 40 * time.Second
	cfg.Addrs = []netip.AddrPort{dropping(t), f.addr()}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.Put(bg, "k", []byte("x"), nil, false); err != nil {
		t.Fatalf("after %v: %v", time.Since(start), err)
	}
	if d := time.Since(start); d < dialMax-time.Second || d > dialMax+10*time.Second {
		t.Errorf("took %v, want about the dial bound %v", d, dialMax)
	}
}
