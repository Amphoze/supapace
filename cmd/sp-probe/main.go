// Command sp-probe is the static network helper of the reach suite. It runs inside
// a container's network namespace (nsenter) or inside a container (docker exec).
//
//	sp-probe tcp HOST:PORT [--device IFACE] [--timeout 1s]
//	                                            connect
//	sp-probe udp HOST:PORT [--device IFACE] [--timeout 1s]
//	                                            send a nonce, wait for it to be echoed
//	sp-probe dns NAME --server ADDR [--type A|AAAA] [--timeout 1s]
//	                                            one query over UDP
//	sp-probe listen tcp|udp ADDR:PORT [--join GROUP]
//	                                            echo canary bound to exactly ADDR, an IP
//	                                            address, in its family only (0.0.0.0 is
//	                                            IPv4 alone); with --join (udp) it binds the
//	                                            port on the wildcard address of that family
//	                                            and joins GROUP on the interface holding ADDR
//	                                            (the kernel's choice if ADDR is unspecified).
//	                                            A UDP echo to a unicast destination leaves
//	                                            from that destination address
//	sp-probe fakepg --socket PATH [--mode MODE] --log FILE [--password-file F --salt HEX]
//	                                            fake, untrusted Postgres backend on a Unix
//	                                            socket; mode defaults to sasl; FILE gets every
//	                                            byte sent, as "conn N LEN" + LEN bytes per
//	                                            chunk; --password-file and --salt are given
//	                                            for the post-authentication modes and refused
//	                                            for the others
//	sp-probe sys                                which system calls and socket types this
//	                                            process may use (see below)
//
// tcp, udp and dns print exactly one verdict line on stdout and exit with its code:
//
//	connected                 0  TCP handshake completed
//	answered [ADDR…]          0  udp: the nonce came back; dns: NOERROR with at least
//	                             one record of the queried type (its addresses)
//	refused ERRNO             1  the target port is closed (ECONNREFUSED, ECONNRESET)
//	unreachable ERRNO         1  an ICMP error or a local rule refused the packet
//	negative RCODE            1  dns: any other response (NXDOMAIN, NODATA as NOERROR,
//	                             SERVFAIL, REFUSED, …)
//	timeout                   2  no answer within --timeout
//	error TEXT                3  usage, name resolution, a failing socket, bind or
//	                             setsockopt call, a truncated or malformed DNS answer,
//	                             or a panic ("error panic")
//
// --device binds the tcp or udp socket to interface IFACE (SO_BINDTODEVICE)
// before it connects or sends, so the probe leaves by that interface whatever the
// routes say; it is a usage error when empty, longer than 15 bytes or given to any
// other subcommand. A failing setsockopt (no such device; a missing CAP_NET_RAW
// only before Linux 5.7) is "error … SO_BINDTODEVICE IFACE: setsockopt: …", exit 3.
//
// An exit status alone is not trustworthy through nsenter or docker exec (a bad
// namespace path exits 1, a Go runtime crash exits 2): callers must require the
// verdict line to agree with the exit status.
//
// Limits: a TCP handshake completed by a transparent proxy reads as "connected".
// A UDP target answering with ICMP host-unreachable reads as "timeout" (Linux
// reports it on a connected socket only for some codes). For a multicast or
// broadcast UDP target the socket is unconnected, so any echo of the nonce counts
// and ICMP errors are not seen. An IPv6 TCP target rejected by ICMPv6 reads as
// "timeout": the kernel keeps retrying the SYN. A seccomp or LSM denial of
// connect or write reads as "unreachable EPERM", like a netfilter output drop;
// the probe is meant to run without a seccomp profile. A blackhole route reads as
// "error" (EINVAL from connect), exit 3. listen --join needs a multicast-capable
// route on the interface it joins on.
//
// listen and fakepg print "listening ADDR" once ready. listen runs until killed;
// fakepg runs until killed, or until SIGTERM or SIGINT, on which it exits 0 (so
// it can be a container's init: it reaps nothing) and removes its socket — only
// if PATH still holds the socket it bound (same inode).
//
// fakepg first removes a stale socket at PATH (a connect to it is refused, as for
// one a killed fake left behind). A live socket (a connect succeeds; that live
// server sees one connection that sends nothing), any other file, or a socket
// that cannot be tried makes it fail with exit 3; it never takes over a live
// server's path. It declines SSL and GSS encryption requests with 'N'
// and, after the startup packet, behaves as MODE says. It never closes a
// connection first; whatever a mode streams stops after 1 GiB per connection,
// and the connection is then held. The modes before authentication never let a
// client authenticate; the post-authentication modes complete a real SCRAM login
// first. Clients need their own timeout in every mode.
//
//	sasl          AuthenticationSASL (SCRAM-SHA-256), nothing more
//	cleartext     AuthenticationCleartextPassword, nothing more
//	md5           AuthenticationMD5Password with a 4-byte salt, nothing more
//	authok        AuthenticationOk without any exchange, then ParameterStatus,
//	              BackendKeyData and ReadyForQuery; queries get no answer
//	sasl-iter     AuthenticationSASL; to the client-first message a server-first
//	              message with a random salt and i=10000000; nothing more
//	huge          a message header 'R' announcing 1 GiB, then its body of zeros
//	flood         ParameterStatus and NoticeResponse messages without end, never an
//	              authentication request
//	stall         nothing
//	trickle       AuthenticationSASL one byte per second
//
// The post-authentication modes need --password-file (its content less one
// trailing newline is the password) and --salt (hex). They complete a SCRAM-SHA-256
// exchange with that password, that salt and 4096 iterations (a wrong proof gets
// ErrorResponse 28P01), send ReadyForQuery, and then answer a Query, or the Sync
// of an extended-protocol batch (after ParseComplete and an empty
// ParameterDescription), as follows:
//
//	row-huge      a one-column RowDescription and a DataRow whose column announces
//	              64 MiB, streamed; nothing after it
//	rows-endless  a one-column RowDescription and 1 KiB DataRows without end
//	stall-auth    nothing, to any query
//	escapes       two NoticeResponses and an ErrorResponse whose texts carry CSI and
//	              OSC escape sequences, C1 CSI (as UTF-8 and as the raw byte 0x9b),
//	              LF, CR, TAB, backspace, DEL and invalid UTF-8, in the message,
//	              detail and hint fields; the error's message field is cut by a NUL,
//	              so a second message field follows; every message, detail and
//	              hint field starts with the marker "fake-marker"; then
//	              ReadyForQuery
//
// sys prints four lines from /proc/self/status — "seccomp 0|1|2", "nonewprivs
// 0|1", "capeff HEX16", "capbnd HEX16" — then one line per call, in this order:
// getpid, unshare-user, keyctl, add_key, request_key, mount, bpf, perf_event_open,
// userfaultfd, io_uring_setup, kexec_load, init_module, open_by_handle_at,
// clock_settime, syslog (SYSLOG_ACTION_SIZE_UNREAD: reads nothing, needs
// CAP_SYSLOG whatever dmesg_restrict says), socket-icmp (an AF_INET ping
// socket), socket-raw (an AF_INET raw ICMP socket). Each line is
// "sys NAME VERDICT":
//
//	ok                  permitted: the call succeeded, or failed with an errno only
//	                    its own argument checks return (it passed the seccomp filter
//	                    and the capability checks the kernel makes before those)
//	errno N SYMBOL      denied: EPERM (a seccomp filter's errno action or a missing
//	                    capability), or EACCES for socket-icmp
//	                    (net.ipv4.ping_group_range)
//	signal 31 SIGSYS    denied: the child was killed by a seccomp kill action
//	unknown host SWITCH could not be determined: EPERM, and a host-wide setting is
//	                    the only reason — without it, and without a seccomp filter,
//	                    the call would have passed its permission checks for this
//	                    process. For calls open to unprivileged processes:
//	                    io_uring_disabled, unprivileged_bpf_disabled (kernels before
//	                    6.5), unprivileged_userfaultfd (before 5.11),
//	                    unprivileged_userns_clone, each when set and not overridden
//	                    by a capability held. For calls that need a capability on
//	                    every host, only while it is held: kexec_load_disabled,
//	                    kexec_load_limit_reboot (0) or lockdown with CAP_SYS_BOOT for
//	                    kexec_load, modules_disabled with CAP_SYS_MODULE for
//	                    init_module; without the capability EPERM is a denial.
//	                    While the capability is held, a setting that cannot be read
//	                    counts as set (a container never sees the lockdown file);
//	                    otherwise an unreadable setting counts as not set
//	unknown DETAIL      could not be determined: any other errno ("unknown errno 38
//	                    ENOSYS"), signal or failure, or no answer within 2 s
//
// For a consumer: "ok" means the call went through; "errno …" and "signal 31
// SIGSYS" mean it was refused for this process; "unknown host SWITCH" means it
// was refused, but by a host setting, so the line says nothing about the sandbox;
// any other "unknown …" means the probe could not tell. A seccomp kill-thread
// action — what SCMP_ACT_KILL means in a Docker profile — leaves the child hung
// and reads "unknown timeout"; a profile should use kill-process or an errno
// action. An LSM denial (AppArmor's user-namespace mediation, for one) reads as
// its errno, EACCES or EPERM; it is not handled as a host switch.
//
// Every call runs in its own short-lived, non-dumpable child process (a child
// killed by a seccomp kill action dumps no core), with arguments that change
// nothing when the call is allowed. unshare-user probes clone(2) with
// CLONE_NEWUSER — the child is created in a new user namespace — not unshare(2).
// The header shows this process's status; the children are re-executed, so a
// non-root caller whose capabilities are not ambient probes with fewer than capeff
// shows. Each child therefore reports its own effective capabilities, and a host
// switch is judged against those (for unshare-user, against this process's,
// which made the clone). A verdict holds for the arguments probed: a filter that tells arguments
// apart may treat other arguments of the same call differently. A run takes at
// most 2 s per call. sys exits 0 once every line is printed, 3 (one "error …"
// line) on a usage error or an unreadable status file.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	exitOK      = 0
	exitRefused = 1
	exitTimeout = 2
	exitError   = 3
)

func main() {
	if name := sysChildName(os.Args[1:], os.Getenv(sysChildEnv)); name != "" {
		os.Exit(sysChild(name, os.Stdout))
	}
	os.Exit(run(os.Args[1:], os.Stdout))
}

// verdict is the one line tcp, udp and dns print, with its exit status.
type verdict struct {
	code int
	line string
}

func errorVerdict(format string, a ...any) verdict {
	return verdict{exitError, "error " + fmt.Sprintf(format, a...)}
}

func run(args []string, stdout io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "sp-probe: panic:", r)
			fmt.Fprintln(stdout, "error panic")
			code = exitError
		}
	}()
	v := dispatch(args, stdout)
	if v.line != "" {
		fmt.Fprintln(stdout, v.line)
	}
	return v.code
}

// dispatch runs one subcommand; listen and fakepg return only on failure. A
// variable, so a test can make it panic.
var dispatch = command

func command(args []string, stdout io.Writer) verdict {
	if len(args) == 0 {
		return errorVerdict("usage: no subcommand")
	}
	fs := flag.NewFlagSet("sp-probe "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", time.Second, "")
	server := fs.String("server", "", "")
	qtype := fs.String("type", "A", "")
	join := fs.String("join", "", "")
	socket := fs.String("socket", "", "")
	mode := fs.String("mode", "sasl", "")
	logFile := fs.String("log", "", "")
	passwordFile := fs.String("password-file", "", "")
	saltHex := fs.String("salt", "", "")
	device := fs.String("device", "", "")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return errorVerdict("usage: %v", err)
	}
	deviceSet := false
	fs.Visit(func(f *flag.Flag) { deviceSet = deviceSet || f.Name == "device" })
	if deviceSet && (args[0] != "tcp" && args[0] != "udp" || *device == "" || len(*device) >= syscall.IFNAMSIZ) {
		return errorVerdict("usage: --device takes an interface name and only with tcp or udp")
	}
	if *timeout <= 0 {
		return errorVerdict("usage: --timeout must be positive")
	}
	switch {
	case args[0] == "sys" && len(pos) == 0 && fs.NFlag() == 0:
		return sysCommand(stdout)
	case args[0] == "tcp" && len(pos) == 1:
		return probeTCP(pos[0], *device, *timeout)
	case args[0] == "udp" && len(pos) == 1:
		return probeUDP(pos[0], *device, *timeout)
	case args[0] == "dns" && len(pos) == 1 && *server != "" && (*qtype == "A" || *qtype == "AAAA"):
		return probeDNS(pos[0], *server, *qtype, *timeout)
	case args[0] == "listen" && len(pos) == 2 && (pos[0] == "tcp" || pos[0] == "udp") && (*join == "" || pos[0] == "udp"):
		err = listen(pos[0], pos[1], *join, stdout)
	case args[0] == "fakepg" && len(pos) == 0 && *socket != "" && *logFile != "" && fakeModes[*mode] &&
		postAuth[*mode] == (*passwordFile != "") && postAuth[*mode] == (*saltHex != ""):
		cfg := fakeConfig{mode: *mode}
		if postAuth[*mode] {
			if cfg.salt, err = hex.DecodeString(*saltHex); err != nil || len(cfg.salt) == 0 {
				return errorVerdict("usage: --salt must be hex")
			}
			pw, err := os.ReadFile(*passwordFile)
			if err != nil {
				return errorVerdict("%v", err)
			}
			cfg.password = strings.TrimSuffix(string(pw), "\n")
		}
		err = fakePG(*socket, cfg, *logFile, stdout)
	default:
		return errorVerdict("usage: bad arguments %q", args)
	}
	fmt.Fprintln(os.Stderr, "sp-probe:", err)
	return verdict{code: exitError}
}

// parse accepts flags before, between and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// Errno names of the answers the network can give. Only an error of a connect,
// send or receive call is such an answer; the same errno from socket, bind or
// setsockopt is a local failure.
var (
	refusedErrnos     = map[syscall.Errno]string{syscall.ECONNREFUSED: "ECONNREFUSED", syscall.ECONNRESET: "ECONNRESET"}
	unreachableErrnos = map[syscall.Errno]string{syscall.EHOSTUNREACH: "EHOSTUNREACH", syscall.ENETUNREACH: "ENETUNREACH",
		syscall.EACCES: "EACCES", syscall.EPERM: "EPERM"}
	networkCalls = map[string]bool{"connect": true, "read": true, "write": true, "recvfrom": true, "sendto": true,
		"recvmsg": true, "sendmsg": true}
)

// classify maps a probe error to its verdict.
func classify(err error) verdict {
	var dnsErr *net.DNSError
	var ne net.Error
	var se *os.SyscallError
	var errno syscall.Errno
	switch {
	case err == nil:
		return verdict{exitOK, "connected"}
	case errors.As(err, &dnsErr):
		return errorVerdict("%v", err)
	case errors.As(err, &se) && networkCalls[se.Syscall] && errors.As(se.Err, &errno):
		if n, ok := refusedErrnos[errno]; ok {
			return verdict{exitRefused, "refused " + n}
		}
		if n, ok := unreachableErrnos[errno]; ok {
			return verdict{exitRefused, "unreachable " + n}
		}
		if errno == syscall.ETIMEDOUT {
			return verdict{exitTimeout, "timeout"}
		}
	case errors.As(err, &se):
	case errors.As(err, &ne) && ne.Timeout():
		return verdict{exitTimeout, "timeout"}
	}
	return errorVerdict("%v", err)
}

// bindDevice returns a socket control function that binds the socket to
// device (SO_BINDTODEVICE) before it connects or sends; nil for no device.
func bindDevice(device string) func(string, string, syscall.RawConn) error {
	if device == "" {
		return nil
	}
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("SO_BINDTODEVICE %s: %w", device, os.NewSyscallError("setsockopt", serr))
		}
		return nil
	}
}

func probeTCP(addr, device string, timeout time.Duration) verdict {
	c, err := (&net.Dialer{Timeout: timeout, Control: bindDevice(device)}).Dial("tcp", addr)
	if err == nil {
		c.Close()
	}
	return classify(err)
}

// exchange sends msg to addr over UDP and returns the first datagram accept
// takes. A unicast target gets a connected socket, so only its own answers count
// and ICMP errors surface as receive errors. A multicast or broadcast target gets
// an unconnected socket, since its answers come from unicast addresses.
func exchange(addr, device string, msg []byte, timeout time.Duration, accept func([]byte) bool) ([]byte, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	if ua.IP.IsMulticast() || isBroadcast(ua.IP) {
		network := "udp4"
		if ua.IP.To4() == nil {
			network = "udp6"
		}
		c, err := (&net.ListenConfig{Control: bindDevice(device)}).ListenPacket(context.Background(), network, ":0")
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if err := c.SetDeadline(deadline); err != nil {
			return nil, err
		}
		if _, err := c.WriteTo(msg, ua); err != nil {
			return nil, err
		}
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return nil, err
			}
			if accept(buf[:n]) {
				return buf[:n], nil
			}
		}
	}
	nc, err := (&net.Dialer{Control: bindDevice(device)}).Dial("udp", ua.String())
	if err != nil {
		return nil, err
	}
	c := nc.(*net.UDPConn)
	defer c.Close()
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if accept(buf[:n]) {
			return buf[:n], nil
		}
	}
}

// isBroadcast reports the limited broadcast address or the broadcast address of
// one of this namespace's IPv4 networks.
func isBroadcast(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.Equal(net.IPv4bcast) {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || len(n.Mask) != net.IPv4len {
			continue
		}
		b := make(net.IP, net.IPv4len)
		for i := range b {
			b[i] = n.IP.To4()[i] | ^n.Mask[i]
		}
		if b.Equal(ip4) && !b.Equal(n.IP.To4()) {
			return true
		}
	}
	return false
}

func probeUDP(addr, device string, timeout time.Duration) verdict {
	nonce := []byte("sp-probe " + rand.Text() + "\n")
	_, err := exchange(addr, device, nonce, timeout, func(b []byte) bool { return bytes.Equal(b, nonce) })
	if err == nil {
		return verdict{exitOK, "answered"}
	}
	return classify(err)
}

var rcodes = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

func probeDNS(name, server, qtype string, timeout time.Duration) verdict {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	typ, size := uint16(1), 4
	if qtype == "AAAA" {
		typ, size = 28, 16
	}
	var idb [2]byte
	rand.Read(idb[:])
	q := append(idb[:], 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0) // RD; one question
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" || len(l) > 63 {
			return errorVerdict("usage: bad name %q", name)
		}
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, typ)
	q = append(q, 0, 1) // class IN
	r, err := exchange(server, "", q, timeout, func(b []byte) bool {
		return len(b) >= 12 && b[0] == idb[0] && b[1] == idb[1] && b[2]&0x80 != 0
	})
	if err != nil {
		return classify(err)
	}
	if r[2]&0x02 != 0 {
		return errorVerdict("truncated answer")
	}
	rcode := int(r[3] & 0x0f)
	rname := fmt.Sprintf("RCODE%d", rcode)
	if rcode < len(rcodes) {
		rname = rcodes[rcode]
	}
	if rcode != 0 {
		return verdict{exitRefused, "negative " + rname}
	}
	addrs, err := answers(r, typ, size)
	if err != nil {
		return errorVerdict("%v", err)
	}
	if len(addrs) == 0 {
		return verdict{exitRefused, "negative " + rname}
	}
	return verdict{exitOK, "answered " + strings.Join(addrs, " ")}
}

// answers returns the addresses of the records of type typ in the answer section.
func answers(r []byte, typ uint16, size int) ([]string, error) {
	malformed := errors.New("malformed answer")
	p := 12
	for range binary.BigEndian.Uint16(r[4:]) {
		if p = skipName(r, p) + 4; p > len(r) {
			return nil, malformed
		}
	}
	var out []string
	for range binary.BigEndian.Uint16(r[6:]) {
		if p = skipName(r, p); p+10 > len(r) {
			return nil, malformed
		}
		t, n := binary.BigEndian.Uint16(r[p:]), int(binary.BigEndian.Uint16(r[p+8:]))
		if p += 10; p+n > len(r) {
			return nil, malformed
		}
		if t == typ && n == size {
			out = append(out, net.IP(r[p:p+n]).String())
		}
		p += n
	}
	return out, nil
}

// skipName returns the offset after the (possibly compressed) name at p, or
// past the end of r when the name is cut short.
func skipName(r []byte, p int) int {
	for p < len(r) {
		switch l := int(r[p]); {
		case l == 0:
			return p + 1
		case l&0xc0 != 0:
			return p + 2
		default:
			p += l + 1
		}
	}
	return len(r) + 1
}

// listen binds the family of ADDR only (tcp4/udp4 or tcp6/udp6), so 0.0.0.0 is
// IPv4 and [::] is IPv6 alone.
func listen(network, addr, group string, stdout io.Writer) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("ADDR must be an IP address: %v", err)
	}
	v6 := !ip.Is4()
	if v6 {
		network += "6"
	} else {
		network += "4"
	}
	if network[:3] == "tcp" {
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, "listening", l.Addr())
		for {
			c, err := l.Accept()
			if err != nil {
				return err
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}
	var c *net.UDPConn
	if group != "" {
		c, err = listenMulticast(network, addr, group)
	} else {
		var ua *net.UDPAddr
		if ua, err = net.ResolveUDPAddr(network, addr); err == nil {
			c, err = net.ListenUDP(network, ua)
		}
	}
	if err != nil {
		return err
	}
	if err := recvPktinfo(c, v6); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "listening", c.LocalAddr())
	buf, oob := make([]byte, 65536), make([]byte, 256)
	for {
		n, oobn, _, from, err := c.ReadMsgUDP(buf, oob)
		if err != nil {
			return err
		}
		c.WriteMsgUDP(buf[:n], replySource(oob[:oobn]), from)
	}
}

// recvPktinfo makes every datagram carry its destination address and interface.
func recvPktinfo(c *net.UDPConn, v6 bool) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	level, opt := syscall.IPPROTO_IP, syscall.IP_PKTINFO
	if v6 {
		level, opt = syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), level, opt, 1) }); err != nil {
		return err
	}
	return os.NewSyscallError("setsockopt", serr)
}

// replySource returns the control message that makes a reply leave from the
// address the datagram was sent to, when that is a unicast address; a probe of a
// unicast target accepts an echo from the probed address only, and on a wildcard
// socket the kernel would otherwise pick the source by route. A datagram to a
// multicast group or a broadcast address gets nil: the kernel picks the source,
// and the probe accepts any source for such targets. An IPv6 link-local
// destination keeps its interface.
func replySource(oob []byte) []byte {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_PKTINFO && len(m.Data) >= syscall.SizeofInet4Pktinfo:
			in := (*syscall.Inet4Pktinfo)(unsafe.Pointer(&m.Data[0]))
			dst := net.IP(in.Addr[:])
			if dst.IsMulticast() || isBroadcast(dst) {
				return nil
			}
			b, out := cmsg(syscall.IPPROTO_IP, syscall.IP_PKTINFO, syscall.SizeofInet4Pktinfo)
			(*syscall.Inet4Pktinfo)(out).Spec_dst = in.Addr
			return b
		case m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == syscall.IPV6_PKTINFO && len(m.Data) >= syscall.SizeofInet6Pktinfo:
			in := (*syscall.Inet6Pktinfo)(unsafe.Pointer(&m.Data[0]))
			dst := net.IP(in.Addr[:])
			if dst.IsMulticast() {
				return nil
			}
			b, out := cmsg(syscall.IPPROTO_IPV6, syscall.IPV6_PKTINFO, syscall.SizeofInet6Pktinfo)
			p := (*syscall.Inet6Pktinfo)(out)
			p.Addr = in.Addr
			if dst.IsLinkLocalUnicast() {
				p.Ifindex = in.Ifindex
			}
			return b
		}
	}
	return nil
}

// cmsg returns a zeroed control message of size data bytes and its data.
func cmsg(level, typ, size int) ([]byte, unsafe.Pointer) {
	b := make([]byte, syscall.CmsgSpace(size))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = int32(level), int32(typ)
	h.SetLen(syscall.CmsgLen(size))
	return b, unsafe.Pointer(&b[syscall.CmsgLen(0)])
}

// listenMulticast binds the port of addr on the wildcard address of its family
// and joins group on the interface that holds addr's IP (the kernel's choice when
// it is unspecified).
func listenMulticast(network, addr, group string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	g := net.ParseIP(group)
	if g == nil || !g.IsMulticast() || (g.To4() == nil) != (network == "udp6") {
		return nil, fmt.Errorf("bad multicast group %q for %s", group, addr)
	}
	var ifi *net.Interface
	if !ua.IP.IsUnspecified() {
		if ifi, err = interfaceOf(ua.IP); err != nil {
			return nil, err
		}
	}
	return net.ListenMulticastUDP(network, ifi, &net.UDPAddr{IP: g, Port: ua.Port})
}

func interfaceOf(ip net.IP) (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifs {
		addrs, _ := ifs[i].Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return &ifs[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface holds %s", ip)
}
