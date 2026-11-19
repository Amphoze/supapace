package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/secrets"
)

const (
	resolveEvery = 60 * time.Second // a round: load the declaration, resolve, install
	installMax   = 50 * time.Second // an install's bound: a lock held elsewhere costs one round, not the loop
	savedLogMin  = time.Minute      // an unreadable saved set is logged at most this often
)

// resolver keeps the egress set of the tables at the declared endpoint's
// addresses. The answer comes from DNS: only what offsite.Resolve returned,
// every address checked, is ever installed. The set the tables hold is the
// addresses file, read at each use; a set that cannot be read is unknown,
// never empty.
type resolver struct {
	cfg   nodecfg.Config
	paths nodecfg.Paths
	kek   secrets.KEK

	// onChange is called from the loop with the saved set whenever it differs
	// from the one last handed out (after this loop's install or another
	// process's); a set never handed out differs from every set. Never with
	// a set that could not be read.
	onChange func([]netip.AddrPort)

	// seams; tests substitute their own
	load    func(nodecfg.Paths, secrets.KEK) (offsite.Declaration, offsite.State, error)
	resolve func(context.Context, offsite.Declaration, nodecfg.Config) ([]netip.AddrPort, error)
	check   func(nodecfg.Config, []netip.AddrPort) error
	saved   func(nodecfg.Paths) ([]netip.AddrPort, error)
	install func(context.Context, nodecfg.Paths, nodecfg.Config, []netip.AddrPort) error
	ticks   <-chan time.Time // nil: a ticker of resolveEvery

	// the loop's own state
	checked   bool // the saved set found at start passed the checks, or a set was installed since
	handedAny bool
	handed    []netip.AddrPort
	savedLog  time.Time
}

func newResolver(cfg nodecfg.Config, paths nodecfg.Paths, kek secrets.KEK) *resolver {
	return &resolver{cfg: cfg, paths: paths, kek: kek,
		onChange: func([]netip.AddrPort) {},
		load:     offsite.Load, resolve: offsite.Resolve, check: offsite.CheckAddrs,
		saved: nft.SavedSet, install: nft.InstallSet}
}

// current returns the declaration, its state and the saved set — the set the
// tables hold, read at this call. A set that cannot be read (a refused file, a
// lock not obtained within nft's bound) is an error and no set: the caller
// keeps the set it has.
func (r *resolver) current() (offsite.Declaration, offsite.State, []netip.AddrPort, error) {
	d, st, err := r.load(r.paths, r.kek)
	if err != nil {
		return offsite.Declaration{}, "", nil, err
	}
	set, err := r.saved(r.paths)
	if err != nil {
		return offsite.Declaration{}, "", nil, err
	}
	return d, st, set, nil
}

// run runs a round at once and then every resolveEvery until ctx ends.
func (r *resolver) run(ctx context.Context) {
	ticks := r.ticks
	if ticks == nil {
		t := time.NewTicker(resolveEvery)
		defer t.Stop()
		ticks = t.C
	}
	for {
		r.round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
	}
}

// round installs the set the endpoint resolves to when it differs from the
// saved one (the empty set when undeclared), then hands the saved set out
// when it changed. A failed load of the declaration or a failed or refused
// resolve installs nothing: the last set stays.
func (r *resolver) round(ctx context.Context) {
	want, ok := r.want(ctx)
	saved, serr := r.saved(r.paths)
	force := serr != nil // the install is what repairs a refused file
	refused := false
	if serr == nil && !r.checked {
		// The set found at start may predate init or a bridge: an element
		// the checks refuse (an unreadable interface list included) drops it.
		if err := r.check(r.cfg, saved); err != nil {
			slog.Error("offsite: the saved address set is refused; installing the empty set", "err", clean(err))
			force, refused = true, true
			if !ok {
				want, ok = nil, true
			}
		} else {
			r.checked = true
		}
	}
	if ok && (force || !slices.Equal(want, saved)) {
		ictx, cancel := context.WithTimeout(ctx, installMax)
		err := r.install(ictx, r.paths, r.cfg, want)
		cancel()
		switch {
		case err == nil:
			r.checked = true
		case errors.Is(err, nft.ErrUnverified):
			slog.Error("offsite: the address set could not be loaded; the previous one stays", "err", clean(err))
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			slog.Warn("offsite: the ruleset lock was not obtained; trying again next round", "err", clean(err))
		default:
			slog.Error("offsite: installing the address set", "err", clean(err))
		}
		saved, serr = r.saved(r.paths)
	}
	if serr != nil {
		if time.Since(r.savedLog) >= savedLogMin {
			r.savedLog = time.Now()
			slog.Error("offsite: the saved address set cannot be read; nothing handed out", "err", clean(serr))
		}
		return
	}
	if refused && !r.checked {
		return // the refused set is still the saved one: never handed out
	}
	if !r.handedAny || !slices.Equal(saved, r.handed) {
		r.handedAny, r.handed = true, slices.Clone(saved)
		r.onChange(saved)
	}
}

// want is the set the declaration asks for: none when undeclared, else the
// endpoint's checked addresses. ok is false when nothing is to be installed.
func (r *resolver) want(ctx context.Context) (set []netip.AddrPort, ok bool) {
	d, st, err := r.load(r.paths, r.kek)
	if err != nil {
		slog.Error("offsite: loading the declaration; the address set stays", "err", clean(err))
		return nil, false
	}
	if st == offsite.StateUndeclared {
		return nil, true
	}
	set, err = r.resolve(ctx, d, r.cfg)
	if err != nil {
		slog.Warn("offsite: resolving the endpoint; the address set stays", "err", clean(err))
		return nil, false
	}
	return set, true
}
