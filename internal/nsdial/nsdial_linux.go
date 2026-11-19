//go:build linux && (amd64 || arm64)

package nsdial

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

var errNotRoot = errors.New("nsdial: entering a namespace needs root")

// DialTCP connects to addr from inside the network namespace of t's process.
//
// It opens the namespace by handle, then requires that t's pid still names
// a process with t's start time, and that recheck — the caller's second
// inspection of the container — reports the same Target; otherwise it
// returns ErrChanged and makes no connection. The entry runs on a goroutine
// that locks its OS thread and never unlocks it: setns, one socket, a
// non-blocking connect under ctx's deadline; the goroutine then returns and
// the runtime ends the thread with it, so nothing else ever runs in the
// namespace. The returned connection keeps the namespace it was made in and
// may be used from any goroutine.
func DialTCP(ctx context.Context, t Target, recheck func(context.Context) (Target, error), addr netip.AddrPort) (net.Conn, error) {
	ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", t.PID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return nil, fmt.Errorf("%w: %v", ErrChanged, err)
		}
		return nil, fmt.Errorf("nsdial: %w", err)
	}
	defer ns.Close()
	ticks, err := startTicks(t.PID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChanged, err)
	}
	if ticks != t.StartTicks {
		return nil, ErrChanged
	}
	again, err := recheck(ctx)
	if err != nil {
		return nil, err
	}
	if again != t {
		return nil, ErrChanged
	}
	if os.Geteuid() != 0 {
		return nil, errNotRoot
	}

	type result struct {
		c   net.Conn
		err error
	}
	done := make(chan result, 1) // buffered: the goroutine never waits on the caller
	go func() {
		// No UnlockOSThread: a goroutine that exits locked takes its thread
		// with it, so a thread that entered the namespace never runs anything
		// else.
		runtime.LockOSThread()
		if _, _, e := syscall.RawSyscall(sysSetns, ns.Fd(), syscall.CLONE_NEWNET, 0); e != 0 {
			done <- result{err: fmt.Errorf("nsdial: setns: %w", e)}
			return
		}
		// An address literal: the dialer resolves no name.
		d := dialer()
		c, err := d.DialContext(ctx, "tcp", addr.String())
		done <- result{c, err}
	}()
	r := <-done
	return r.c, r.err
}

// dialer is the one used inside the namespace. MPTCP is off whatever GODEBUG
// says: its first use runs process-wide one-time probes and opens a probe
// socket, which would then happen inside the entered namespace.
func dialer() *net.Dialer {
	d := &net.Dialer{}
	d.SetMultipathTCP(false)
	return d
}

// TargetOf returns pid with its start time. A process that is gone is an
// error wrapping ErrChanged.
func TargetOf(pid int) (Target, error) {
	ticks, err := startTicks(pid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return Target{}, fmt.Errorf("%w: %v", ErrChanged, err)
		}
		return Target{}, fmt.Errorf("nsdial: %w", err)
	}
	return Target{PID: pid, StartTicks: ticks}, nil
}

// startTicks reads field 22 of /proc/<pid>/stat: the start time in clock ticks.
func startTicks(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	return parseStartTicks(b)
}

func parseStartTicks(b []byte) (uint64, error) {
	// The command name (field 2) may hold spaces and parentheses: count from
	// the last ')'. After it, field 3 is the first and field 22 the 20th.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, errors.New("nsdial: stat: no command field")
	}
	f := bytes.Fields(b[i+1:])
	if len(f) < 20 {
		return 0, errors.New("nsdial: stat: short line")
	}
	return strconv.ParseUint(string(f[19]), 10, 64)
}
