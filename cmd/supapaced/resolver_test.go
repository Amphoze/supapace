package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/secrets"
)

// resolverWorld is a resolver whose seams are fakes: a declaration, an answer
// of the endpoint, and an addresses file that only install changes (as
// nft.InstallSet is its one writer) unless a test plays another writer.
type resolverWorld struct {
	r *resolver

	mu         sync.Mutex
	decl       offsite.Declaration
	state      offsite.State
	loadErr    error
	answer     []netip.AddrPort
	resolveErr error
	resolves   int
	saved      []netip.AddrPort // the file's set
	savedErr   error            // a refused file or a lock not obtained
	installErr error
	installs   [][]netip.AddrPort
	installDue []time.Duration // time left on each install's context
	handed     [][]netip.AddrPort
}

func addrs(ss ...string) []netip.AddrPort {
	out := []netip.AddrPort{}
	for _, s := range ss {
		out = append(out, netip.MustParseAddrPort(s))
	}
	return out
}

const (
	addrA = "192.0.2.10:443"
	addrB = "198.51.100.7:443"
	// inside the default configuration's project block: every check refuses it
	addrInBlock = "10.213.0.9:443"
)

func newResolverWorld(t *testing.T) *resolverWorld {
	w := &resolverWorld{state: offsite.StateDeclared,
		decl: offsite.Declaration{Endpoint: "https://store.example.test"}}
	r := newResolver(nodecfg.Default("sp.test"), nodecfg.Paths{Root: t.TempDir()}, secrets.KEK{})
	r.load = func(nodecfg.Paths, secrets.KEK) (offsite.Declaration, offsite.State, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.decl, w.state, w.loadErr
	}
	r.resolve = func(_ context.Context, d offsite.Declaration, _ nodecfg.Config) ([]netip.AddrPort, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.resolves++
		if w.resolveErr != nil {
			return nil, w.resolveErr
		}
		return slices.Clone(w.answer), nil
	}
	r.saved = func(nodecfg.Paths) ([]netip.AddrPort, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.savedErr != nil {
			return nil, w.savedErr
		}
		return slices.Clone(w.saved), nil
	}
	r.install = func(ctx context.Context, _ nodecfg.Paths, _ nodecfg.Config, set []netip.AddrPort) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("InstallSet called on a context without a deadline")
		}
		w.installDue = append(w.installDue, time.Until(dl))
		w.installs = append(w.installs, slices.Clone(set))
		if w.installErr != nil {
			return w.installErr
		}
		w.saved, w.savedErr = slices.Clone(set), nil // the writer repairs a refused file
		return nil
	}
	r.onChange = func(set []netip.AddrPort) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.handed = append(w.handed, slices.Clone(set))
	}
	w.r = r
	return w
}

func (w *resolverWorld) set(f func(w *resolverWorld)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f(w)
}

func (w *resolverWorld) counts() (installs, handed int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.installs), len(w.handed)
}

func (w *resolverWorld) wantInstalls(t *testing.T, want ...[]netip.AddrPort) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if fmt.Sprint(w.installs) != fmt.Sprint(want) {
		t.Errorf("installs %v, want %v", w.installs, want)
	}
}

func (w *resolverWorld) wantHanded(t *testing.T, want ...[]netip.AddrPort) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if fmt.Sprint(w.handed) != fmt.Sprint(want) {
		t.Errorf("handed out %v, want %v", w.handed, want)
	}
}

func (w *resolverWorld) wantCurrent(t *testing.T, want []netip.AddrPort) {
	t.Helper()
	_, st, got, err := w.r.current()
	if err != nil || st != w.state || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("current() = %s, %v, %v; want %s, %v, nil", st, got, err, w.state, want)
	}
}

func TestResolver_ChangeInstallsOnce_ThenCallsOnChange(t *testing.T) {
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) { w.answer = addrs(addrA, addrB) })
	// The hand-out comes after the install: the set handed out is the one
	// the tables hold.
	w.r.onChange = func(set []netip.AddrPort) {
		w.handed = append(w.handed, slices.Clone(set)) // called with w.mu free
		if len(w.installs) != 1 {
			t.Errorf("onChange before the install (%d installs)", len(w.installs))
		}
	}
	w.r.round(t.Context())
	w.r.round(t.Context())
	w.wantInstalls(t, addrs(addrA, addrB))
	w.wantHanded(t, addrs(addrA, addrB))
	w.wantCurrent(t, addrs(addrA, addrB))
}

func TestResolver_SameSetDoesNothing(t *testing.T) {
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) { w.answer, w.saved = addrs(addrA), addrs(addrA) })
	w.r.round(t.Context())
	// A set never handed out differs from every set: the first round hands
	// out the saved one, without an install.
	w.wantHanded(t, addrs(addrA))
	w.r.round(t.Context())
	w.r.round(t.Context())
	w.wantInstalls(t)
	w.wantHanded(t, addrs(addrA))
}

func TestResolver_FailedResolveKeepsTheLastSet(t *testing.T) {
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) { w.answer = addrs(addrA) })
	w.r.round(t.Context())
	w.set(func(w *resolverWorld) { w.resolveErr = errors.New("no answer") })
	w.r.round(t.Context())
	w.r.round(t.Context())
	w.wantInstalls(t, addrs(addrA))
	w.wantHanded(t, addrs(addrA))
	w.wantCurrent(t, addrs(addrA))
	// Control: the same world with an answer again installs it.
	w.set(func(w *resolverWorld) { w.resolveErr, w.answer = nil, addrs(addrB) })
	w.r.round(t.Context())
	w.wantInstalls(t, addrs(addrA), addrs(addrB))
}

// The resolver's answer is only what offsite.Resolve returned: an answer that
// names an address inside a node block is refused whole and the last set kept.
// The endpoint is an address literal, so the real Resolve answers it without
// a lookup.
func TestResolver_AnswerInsideANodeBlockKeepsTheLastSet(t *testing.T) {
	w := newResolverWorld(t)
	w.r.resolve = offsite.Resolve
	w.set(func(w *resolverWorld) { w.decl.Endpoint = "https://192.0.2.10" })
	w.r.round(t.Context())
	w.wantInstalls(t, addrs(addrA))
	for _, ep := range []string{"https://10.213.0.9", "https://10.212.0.5:9443", "https://127.0.0.1", "https://169.254.169.254"} {
		w.set(func(w *resolverWorld) { w.decl.Endpoint = ep })
		w.r.round(t.Context())
	}
	w.wantInstalls(t, addrs(addrA))
	w.wantHanded(t, addrs(addrA))
	w.wantCurrent(t, addrs(addrA))
	// Control: an answer outside every block is installed.
	w.set(func(w *resolverWorld) { w.decl.Endpoint = "https://198.51.100.7" })
	w.r.round(t.Context())
	w.wantInstalls(t, addrs(addrA), addrs(addrB))
}

func TestResolver_UndeclaredInstallsTheEmptySet(t *testing.T) {
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) { w.saved, w.state = addrs(addrA), offsite.StateUndeclared })
	w.r.round(t.Context())
	w.r.round(t.Context())
	w.wantInstalls(t, addrs())
	w.wantHanded(t, addrs()) // the empty set the tables hold, not an error's
	w.wantCurrent(t, nil)
	if w.resolves != 0 {
		t.Errorf("%d resolutions of an undeclared endpoint", w.resolves)
	}
	// A declaration that does not load is not "undeclared": the set is kept.
	w2 := newResolverWorld(t)
	w2.set(func(w *resolverWorld) { w.saved, w.loadErr = addrs(addrA), errors.New("does not open") })
	w2.r.round(t.Context())
	w2.wantInstalls(t)
	w2.wantHanded(t, addrs(addrA))
}

func TestResolver_PicksUpANewDeclarationWithoutRestart(t *testing.T) {
	w := newResolverWorld(t)
	w.r.resolve = offsite.Resolve
	// The first load finds one endpoint, every later one another: an
	// operator's `offsite set` between two rounds.
	loads := 0
	load := w.r.load
	w.r.load = func(p nodecfg.Paths, k secrets.KEK) (offsite.Declaration, offsite.State, error) {
		d, st, err := load(p, k)
		if loads++; loads == 1 {
			d.Endpoint = "https://192.0.2.10"
		} else {
			d.Endpoint = "https://198.51.100.7"
		}
		return d, st, err
	}
	ticks := make(chan time.Time)
	w.r.ticks = ticks
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { w.r.run(ctx); close(done) }()
	ticks <- time.Time{} // received after the first round
	ticks <- time.Time{} // received after the second
	cancel()
	<-done
	w.wantInstalls(t, addrs(addrA), addrs(addrB))
	w.wantHanded(t, addrs(addrA), addrs(addrB))
}

func TestResolver_InstallByAnotherProcessIsHandedOut(t *testing.T) {
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) { w.answer = addrs(addrA) })
	w.r.round(t.Context())
	// Another writer (offsite check) installs B, and the resolver's own
	// resolution now equals it.
	w.set(func(w *resolverWorld) { w.saved, w.answer = addrs(addrB), addrs(addrB) })
	w.wantCurrent(t, addrs(addrB)) // read at the call, not cached
	w.r.round(t.Context())
	w.r.round(t.Context())
	w.wantInstalls(t, addrs(addrA))
	w.wantHanded(t, addrs(addrA), addrs(addrB))
}

func TestResolver_AFailedInstallLeavesTheSavedSet(t *testing.T) {
	for _, ierr := range []error{
		fmt.Errorf("nft: load: %w", nft.ErrUnverified),
		fmt.Errorf("nft: lock not obtained: %w", context.DeadlineExceeded),
	} {
		t.Run(ierr.Error(), func(t *testing.T) {
			w := newResolverWorld(t)
			w.set(func(w *resolverWorld) { w.saved, w.answer, w.installErr = addrs(addrA), addrs(addrB), ierr })
			w.r.round(t.Context())
			w.r.round(t.Context())
			// tried again at the next round
			w.wantInstalls(t, addrs(addrB), addrs(addrB))
			w.wantCurrent(t, addrs(addrA))
			w.wantHanded(t, addrs(addrA))
		})
	}
}

func TestResolver_FirstRoundDropsASavedSetTheChecksRefuse(t *testing.T) {
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) { w.saved, w.resolveErr = addrs(addrA, addrInBlock), errors.New("no answer") })
	w.r.round(t.Context())
	w.wantInstalls(t, addrs())
	w.wantHanded(t, addrs())
	// Only the first round checks: a later refused set (another writer's) is
	// the resolution's business, not this check's.
	w.set(func(w *resolverWorld) { w.saved = addrs(addrInBlock) })
	w.r.round(t.Context())
	w.wantInstalls(t, addrs())

	// Control: a saved set the checks accept is kept on the first round.
	w2 := newResolverWorld(t)
	w2.set(func(w *resolverWorld) { w.saved, w.resolveErr = addrs(addrA), errors.New("no answer") })
	w2.r.round(t.Context())
	w2.wantInstalls(t)
	w2.wantHanded(t, addrs(addrA))

	// A refused set beside a good answer: the answer is installed.
	w3 := newResolverWorld(t)
	w3.set(func(w *resolverWorld) { w.saved, w.answer = addrs(addrInBlock), addrs(addrB) })
	w3.r.round(t.Context())
	w3.wantInstalls(t, addrs(addrB))

	// A saved set that cannot be read on the first round is checked at the
	// first round that reads it.
	w4 := newResolverWorld(t)
	w4.set(func(w *resolverWorld) {
		w.saved, w.savedErr, w.resolveErr = addrs(addrInBlock), errors.New("refused"), errors.New("no answer")
	})
	w4.r.round(t.Context())
	w4.wantInstalls(t)
	w4.set(func(w *resolverWorld) { w.savedErr = nil })
	w4.r.round(t.Context())
	w4.wantInstalls(t, addrs())
	w4.wantHanded(t, addrs())
}

func TestResolver_ASavedSetThatCannotBeReadIsUnknownNeverEmpty(t *testing.T) {
	for _, serr := range []error{
		errors.New("nft: /etc/supapace/offsite.addrs is not a regular file of mode 0600"),
		fmt.Errorf("nft: lock not obtained: %w", context.DeadlineExceeded),
	} {
		t.Run(serr.Error(), func(t *testing.T) {
			w := newResolverWorld(t)
			// The resolved set equals what the file would say, and the install
			// fails: only the read can hand anything out.
			w.set(func(w *resolverWorld) {
				w.saved, w.savedErr, w.answer = addrs(addrA), serr, addrs(addrA)
				w.installErr = fmt.Errorf("nft: lock not obtained: %w", context.DeadlineExceeded)
			})
			if d, st, set, err := w.r.current(); err == nil || set != nil || st != "" || d.Endpoint != "" {
				t.Errorf("current() with an unreadable set = %v, %s, %v, %v; want only an error", d, st, set, err)
			}
			w.r.round(t.Context())
			w.r.round(t.Context())
			if _, handed := w.counts(); handed != 0 {
				t.Errorf("handed out %v while the set could not be read", w.handed)
			}
			// Each round still installs the set it resolved and checked,
			// within 50 s.
			w.wantInstalls(t, addrs(addrA), addrs(addrA))
			for _, left := range w.installDue {
				if left > 50*time.Second {
					t.Errorf("InstallSet's context ends in %v, want within 50s", left)
				}
			}
			// Once a read succeeds, the set is handed out once.
			w.set(func(w *resolverWorld) { w.savedErr, w.installErr = nil, nil })
			w.r.round(t.Context())
			w.r.round(t.Context())
			w.wantHanded(t, addrs(addrA))
			w.wantCurrent(t, addrs(addrA))
		})
	}
	// The install repairs the refused file, and the read after it hands the
	// set out in the same round.
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) { w.savedErr, w.answer = errors.New("refused"), addrs(addrB) })
	w.r.round(t.Context())
	w.wantInstalls(t, addrs(addrB))
	w.wantHanded(t, addrs(addrB))

	// Undeclared beside an unreadable file: the empty set is still installed,
	// which rewrites the file the readers refuse.
	w2 := newResolverWorld(t)
	w2.set(func(w *resolverWorld) { w.savedErr, w.state = errors.New("refused"), offsite.StateUndeclared })
	w2.r.round(t.Context())
	w2.wantInstalls(t, addrs())
	w2.wantHanded(t, addrs())
}

// An unreadable saved set is logged at most once a minute, whatever the
// number of rounds, and nothing is installed or handed out meanwhile.
func TestResolver_UnreadableSetLoggedOnceAMinute(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) {
		w.savedErr, w.resolveErr = errors.New("refused"), errors.New("no answer")
	})
	for i := 0; i < 5; i++ {
		w.r.round(t.Context())
	}
	if n := strings.Count(buf.String(), "cannot be read"); n != 1 {
		t.Errorf("%d log lines for an unreadable set in 5 rounds, want 1:\n%s", n, buf.String())
	}
	w.wantInstalls(t)
	w.wantHanded(t)
}

// A first-round refusal whose empty install fails is checked again at the
// next round, so the refused set is still dropped once an install succeeds.
func TestResolver_RefusedSavedSetDroppedAfterAFailedFirstInstall(t *testing.T) {
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) {
		w.saved, w.resolveErr = addrs(addrInBlock), errors.New("no answer")
		w.installErr = fmt.Errorf("nft: lock not obtained: %w", context.DeadlineExceeded)
	})
	w.r.round(t.Context())
	w.set(func(w *resolverWorld) { w.installErr = nil })
	w.r.round(t.Context())
	w.wantInstalls(t, addrs(), addrs())
	// The refused set is never handed out, also while its drop fails.
	w.wantHanded(t, addrs())
}

// current() answers nothing but an error when the declaration cannot be
// loaded, even though the saved set reads.
func TestResolver_CurrentWithAnUnloadableDeclarationIsAnError(t *testing.T) {
	w := newResolverWorld(t)
	w.set(func(w *resolverWorld) { w.saved, w.loadErr = addrs(addrA), errors.New("does not open") })
	if d, st, set, err := w.r.current(); err == nil || set != nil || st != "" || d.Endpoint != "" {
		t.Errorf("current() = %v, %s, %v, %v; want only an error", d, st, set, err)
	}
}
