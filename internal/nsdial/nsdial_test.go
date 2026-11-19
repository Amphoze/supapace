//go:build linux && (amd64 || arm64)

package nsdial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// closedAddr is a loopback port nothing listens on; a dial that got this far
// would be refused, so no test here opens a connection.
var closedAddr = netip.MustParseAddrPort("127.0.0.1:1")

func self(t *testing.T) Target {
	t.Helper()
	ticks, err := startTicks(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return Target{PID: os.Getpid(), StartTicks: ticks}
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestTarget_StartTimeMismatchIsChanged(t *testing.T) {
	me := self(t)
	called := false
	same := func(context.Context) (Target, error) { called = true; return me, nil }

	stale := me
	stale.StartTicks++
	c, err := DialTCP(ctx5(t), stale, same, closedAddr)
	if !errors.Is(err, ErrChanged) || c != nil {
		t.Fatalf("start time differs: got %v, %v; want ErrChanged", c, err)
	}
	if called {
		t.Fatal("recheck called after the start time already differed")
	}

	// The second inspection reports another process.
	other := func(context.Context) (Target, error) { return Target{PID: me.PID, StartTicks: me.StartTicks + 1}, nil }
	if c, err := DialTCP(ctx5(t), me, other, closedAddr); !errors.Is(err, ErrChanged) || c != nil {
		t.Fatalf("recheck differs: got %v, %v; want ErrChanged", c, err)
	}

	// A process that is gone is a changed container.
	gone := Target{PID: 1 << 30}
	if _, err := DialTCP(ctx5(t), gone, same, closedAddr); !errors.Is(err, ErrChanged) {
		t.Fatalf("no such process: got %v; want ErrChanged", err)
	}

	// An error of the second inspection is returned as it is.
	boom := errors.New("inspect failed")
	if _, err := DialTCP(ctx5(t), me, func(context.Context) (Target, error) { return Target{}, boom }, closedAddr); !errors.Is(err, boom) {
		t.Fatalf("recheck error: got %v; want %v", err, boom)
	}

	// Control: the same path with a matching target passes both comparisons.
	called = false
	_, err = DialTCP(ctx5(t), me, same, closedAddr)
	if errors.Is(err, ErrChanged) || !called {
		t.Fatalf("matching target: got %v (recheck called %v); want past the comparisons", err, called)
	}
}

func TestDialTCP_NotRootRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root; the refusal is for any other uid")
	}
	me := self(t)
	c, err := DialTCP(ctx5(t), me, func(context.Context) (Target, error) { return me, nil }, closedAddr)
	if !errors.Is(err, errNotRoot) || c != nil {
		t.Fatalf("got %v, %v; want errNotRoot", c, err)
	}
}

func TestStartTicks_ParsesACommandWithSpacesAndParens(t *testing.T) {
	// Field 22 counted after the last ')', whatever the command name holds.
	line := "4242 (a) b (c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20 21\n"
	got, err := parseStartTicks([]byte(line))
	if err != nil || got != 987654 {
		t.Fatalf("got %d, %v; want 987654", got, err)
	}
	for _, bad := range []string{"", "4242 (a S 1", "4242 (a) S 1 2", "4242 (a) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 x 20"} {
		if _, err := parseStartTicks([]byte(bad)); err == nil {
			t.Errorf("%q: parsed", bad)
		}
	}
}

func TestTargetOf_FillsTheStartTimeAndAGoneProcessIsChanged(t *testing.T) {
	got, err := TargetOf(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if got != self(t) || got.StartTicks == 0 {
		t.Fatalf("TargetOf(self) = %+v; want %+v", got, self(t))
	}
	// The result is what DialTCP accepts: control on the same path.
	if _, err := DialTCP(ctx5(t), got, func(context.Context) (Target, error) { return TargetOf(os.Getpid()) }, closedAddr); errors.Is(err, ErrChanged) {
		t.Fatalf("DialTCP refused TargetOf's own result: %v", err)
	}
	if _, err := TargetOf(1 << 30); !errors.Is(err, ErrChanged) {
		t.Fatalf("no such process: %v; want ErrChanged", err)
	}
}

// The dialer that runs inside the namespace never takes the MPTCP path,
// whose first use opens a probe socket and runs the process-wide IP-stack
// probe — inside the namespace, if that first dial were ours.
func TestDialer_MultipathOffWhateverGODEBUGSays(t *testing.T) {
	for _, v := range []string{"multipathtcp=1", "multipathtcp=3"} {
		t.Setenv("GODEBUG", v)
		var plain net.Dialer
		if !plain.MultipathTCP() {
			t.Fatalf("%s: a plain dialer does not take MPTCP: the control is void", v)
		}
		if d := dialer(); d.MultipathTCP() {
			t.Fatalf("%s: the namespace dialer would take MPTCP", v)
		}
	}
}
