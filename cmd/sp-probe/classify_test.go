package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// Only an errno of a connect, send or receive call is an answer of the network;
// the same errno from socket, bind or setsockopt is a local failure (exit 3).
func TestClassify_ErrnoBySyscall(t *testing.T) {
	op := func(call string, errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError(call, errno)}
	}
	for _, c := range []struct {
		err  error
		code int
		line string
	}{
		{op("connect", syscall.ECONNREFUSED), 1, "refused ECONNREFUSED"},
		{op("read", syscall.ECONNRESET), 1, "refused ECONNRESET"},
		{op("connect", syscall.EHOSTUNREACH), 1, "unreachable EHOSTUNREACH"},
		{op("connect", syscall.ENETUNREACH), 1, "unreachable ENETUNREACH"},
		{op("write", syscall.EPERM), 1, "unreachable EPERM"},
		{op("recvfrom", syscall.EACCES), 1, "unreachable EACCES"},
		{op("connect", syscall.ETIMEDOUT), 2, "timeout"},
		{op("socket", syscall.EPERM), 3, ""},
		{op("socket", syscall.EACCES), 3, ""},
		{op("socket", syscall.EMFILE), 3, ""},
		{op("bind", syscall.EACCES), 3, ""},
		{op("setsockopt", syscall.EPERM), 3, ""},
		{op("connect", syscall.EINVAL), 3, ""},
		{op("connect", syscall.EADDRNOTAVAIL), 3, ""},
		{&net.DNSError{Err: "no such host", Name: "a.sp.test", IsNotFound: true}, 3, ""},
		{&net.DNSError{Err: "i/o timeout", Name: "a.sp.test", IsTimeout: true}, 3, ""},
	} {
		v := classify(c.err)
		if v.code != c.code || (c.line != "" && v.line != c.line) || (c.code == 3 && !strings.HasPrefix(v.line, "error ")) {
			t.Errorf("%v: got %d %q, want %d %q", c.err, v.code, v.line, c.code, c.line)
		}
	}
}

// A response whose id or QR bit does not match is not the answer; the probe keeps
// waiting for the real one.
func TestDNS_IgnoresForeignResponses(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte{}, buf[:n]...)
			bad := dnsReply(q, 0, []byte{192, 0, 2, 66})
			bad[0] ^= 0xff // another id
			c.WriteTo(bad, peer)
			noqr := dnsReply(q, 0, []byte{192, 0, 2, 67})
			noqr[2] &^= 0x80 // a query, not a response
			c.WriteTo(noqr, peer)
			c.WriteTo(dnsReply(q, 3), peer)
		}
	}()
	expect(t, "foreign first", 1, "negative NXDOMAIN", "dns", "a.sp.test", "--server", c.LocalAddr().String(), "--timeout", "500ms")
}

// An answer section that claims more than the datagram holds is an error, never a
// verdict about the name.
func TestDNS_MalformedAnswerIsError(t *testing.T) {
	srv := udpResponder(t, func(q []byte) []byte {
		r := dnsReply(q, 0, []byte{192, 0, 2, 10})
		binary.BigEndian.PutUint16(r[6:], 2) // two answers, one present
		return r
	}, nil)
	expect(t, "malformed", 3, "error malformed answer", "dns", "a.sp.test", "--server", srv, "--timeout", "300ms")
}

// A negative rcode with an address record attached is still negative.
func TestDNS_NegativeWithRecordsIsNegative(t *testing.T) {
	for rc, name := range map[byte]string{2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"} {
		srv := udpResponder(t, func(q []byte) []byte { return dnsReply(q, rc, []byte{192, 0, 2, 10}) }, nil)
		expect(t, name, 1, "negative "+name, "dns", "a.sp.test", "--server", srv, "--timeout", "300ms")
	}
}

// A broadcast target accepts an answer from any source, but only one that echoes
// the nonce.
func TestUDP_BroadcastNeedsNonce(t *testing.T) {
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			_, peer, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			c.WriteTo([]byte("something else\n"), peer)
		}
	}()
	_, port, _ := net.SplitHostPort(c.LocalAddr().String())
	expect(t, "broadcast, wrong payload", 2, "timeout", "udp", net.JoinHostPort("127.255.255.255", port), "--timeout", "300ms")
}

// A multicast canary answers from its unicast address; that echo counts. Needs a
// multicast-capable interface (skipped otherwise). The group is in MCAST-TEST-NET
// and the datagram has TTL 1.
func TestUDP_MulticastAnsweredFromUnicast(t *testing.T) {
	group := net.IPv4(233, 252, 0, 42).String() // MCAST-TEST-NET
	// The interface the kernel sends the group's datagrams through.
	d, err := net.Dial("udp4", group+":9")
	if err != nil {
		t.Skip("no multicast route:", err)
	}
	src := d.LocalAddr().(*net.UDPAddr).IP
	d.Close()
	ifi, err := interfaceOf(src)
	if err != nil || ifi.Flags&net.FlagMulticast == 0 {
		t.Skip("no multicast-capable interface")
	}
	c, err := net.ListenMulticastUDP("udp4", ifi, &net.UDPAddr{IP: net.ParseIP(group)})
	if err != nil {
		t.Skip("cannot join a group:", err)
	}
	defer c.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			c.WriteTo(buf[:n], peer)
		}
	}()
	_, port, _ := net.SplitHostPort(c.LocalAddr().String())
	if code, out := probe(t, "udp", net.JoinHostPort(group, port), "--timeout", "500ms"); code != 0 || out != "answered\n" {
		if code == 1 && out == "unreachable ENETUNREACH\n" {
			t.Skip("no multicast route")
		}
		t.Errorf("exit %d, output %q; want 0, \"answered\"", code, out)
	}
}

// A panic inside a subcommand still prints one verdict line and exits 3, never 2
// (which a caller would read as "timeout").
func TestRun_PanicIsError(t *testing.T) {
	saved := dispatch
	t.Cleanup(func() { dispatch = saved })
	dispatch = func([]string, io.Writer) verdict { panic("boom") }
	expect(t, "panic", 3, "error panic", "udp", "127.0.0.1:9")
}

// A canary bound to the wildcard address must answer from the address the probe
// sent to; otherwise a connected probe drops the echo and a reached canary reads
// as "timeout". 127.0.0.2 is local through lo's /8 but is not the source the
// kernel picks for a reply to 127.0.0.1.
func TestUDP_WildcardCanaryAnswersFromProbedAddress(t *testing.T) {
	echo := start(t, "listen", "udp", "0.0.0.0:0")
	_, port, _ := net.SplitHostPort(echo)
	expect(t, "secondary local address", 0, "answered", "udp", net.JoinHostPort("127.0.0.2", port), "--timeout", "300ms")
	expect(t, "primary local address", 0, "answered", "udp", net.JoinHostPort("127.0.0.1", port), "--timeout", "300ms")
}

// An IPv4 ADDR binds IPv4 only: the wildcard canary is not reachable over IPv6.
func TestListen_BindsTheFamilyOfAddr(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback:", err)
	} else {
		c.Close()
	}
	for _, network := range []string{"tcp", "udp"} {
		addr := start(t, "listen", network, "0.0.0.0:0")
		host, port, _ := net.SplitHostPort(addr)
		if host != "0.0.0.0" {
			t.Errorf("listen %s 0.0.0.0:0 bound %s", network, addr)
		}
		expect(t, network+" over IPv6", 1, "refused ECONNREFUSED", network, net.JoinHostPort("::1", port), "--timeout", "300ms")
	}
}

func TestUDP_IPv6LoopbackCanaries(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback:", err)
	} else {
		c.Close()
	}
	exact := start(t, "listen", "udp", "[::1]:0")
	expect(t, "exact", 0, "answered", "udp", exact, "--timeout", "300ms")
	_, port, _ := net.SplitHostPort(start(t, "listen", "udp", "[::]:0"))
	expect(t, "wildcard", 0, "answered", "udp", net.JoinHostPort("::1", port), "--timeout", "300ms")
}

// A --join canary answers probes of its group and unicast probes of any local
// address. Needs a multicast route (skipped otherwise).
func TestUDP_JoinCanaryAnswersGroupAndUnicast(t *testing.T) {
	group := net.IPv4(233, 252, 0, 43).String() // MCAST-TEST-NET
	d, err := net.Dial("udp4", group+":9")
	if err != nil {
		t.Skip("no multicast route:", err)
	}
	src := d.LocalAddr().(*net.UDPAddr).IP
	d.Close()
	if ifi, err := interfaceOf(src); err != nil || ifi.Flags&net.FlagMulticast == 0 {
		t.Skip("no multicast-capable interface")
	}
	_, port, _ := net.SplitHostPort(start(t, "listen", "udp", "0.0.0.0:0", "--join", group))
	expect(t, "group", 0, "answered", "udp", net.JoinHostPort(group, port), "--timeout", "500ms")
	expect(t, "secondary local address", 0, "answered", "udp", net.JoinHostPort("127.0.0.2", port), "--timeout", "300ms")
}

// The echo's source override, from the destination the kernel reported.
func TestReplySource(t *testing.T) {
	in4 := func(dst net.IP) []byte {
		b, p := cmsg(syscall.IPPROTO_IP, syscall.IP_PKTINFO, syscall.SizeofInet4Pktinfo)
		pi := (*syscall.Inet4Pktinfo)(p)
		pi.Ifindex = 7
		copy(pi.Addr[:], dst.To4())
		copy(pi.Spec_dst[:], net.IPv4(127, 0, 0, 1).To4())
		return b
	}
	in6 := func(dst net.IP) []byte {
		b, p := cmsg(syscall.IPPROTO_IPV6, syscall.IPV6_PKTINFO, syscall.SizeofInet6Pktinfo)
		pi := (*syscall.Inet6Pktinfo)(p)
		pi.Ifindex = 7
		copy(pi.Addr[:], dst.To16())
		return b
	}
	parse := func(b []byte) (src net.IP, ifindex int) {
		msgs, err := syscall.ParseSocketControlMessage(b)
		if err != nil || len(msgs) != 1 {
			t.Fatalf("control message %x: %v", b, err)
		}
		if d := msgs[0].Data; msgs[0].Header.Level == syscall.IPPROTO_IP {
			pi := (*syscall.Inet4Pktinfo)(unsafe.Pointer(&d[0]))
			return net.IP(pi.Spec_dst[:]), int(pi.Ifindex)
		} else {
			pi := (*syscall.Inet6Pktinfo)(unsafe.Pointer(&d[0]))
			return net.IP(pi.Addr[:]), int(pi.Ifindex)
		}
	}
	v6 := func(b ...byte) net.IP { return net.IP(append(b, make([]byte, 16-len(b))...)) }
	doc6 := v6(0x20, 0x01, 0x0d, 0xb8)
	doc6[15] = 5
	ll6 := v6(0xfe, 0x80)
	ll6[15] = 1
	for _, c := range []struct {
		name    string
		oob     []byte
		src     net.IP // nil: no override
		ifindex int
	}{
		{"IPv4 unicast", in4(net.IPv4(127, 0, 0, 2)), net.IPv4(127, 0, 0, 2), 0},
		{"IPv4 multicast", in4(net.IPv4(224, 0, 0, 251)), nil, 0},
		{"IPv4 limited broadcast", in4(net.IPv4bcast), nil, 0},
		{"IPv4 subnet broadcast", in4(net.IPv4(127, 255, 255, 255)), nil, 0},
		{"IPv6 unicast", in6(doc6), doc6, 0},
		{"IPv6 link-local keeps its interface", in6(ll6), ll6, 7},
		{"IPv6 multicast", in6(net.IP{0xff, 0x02, 15: 0xfb}), nil, 0},
		{"no pktinfo", nil, nil, 0},
	} {
		out := replySource(c.oob)
		if c.src == nil {
			if out != nil {
				t.Errorf("%s: override %x, want none", c.name, out)
			}
			continue
		}
		if out == nil {
			t.Errorf("%s: no override, want source %v", c.name, c.src)
			continue
		}
		if src, ifi := parse(out); !src.Equal(c.src) || ifi != c.ifindex {
			t.Errorf("%s: source %v ifindex %d, want %v %d", c.name, src, ifi, c.src, c.ifindex)
		}
	}
}
