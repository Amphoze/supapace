package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/nft"
)

// unverifiedStrikes: consecutive checks that could not examine the ruleset
// (nft did not run) before the node is treated as not contained.
const unverifiedStrikes = 3

// driftLoop runs driftTick on every tick until ctx ends. It runs on its own
// goroutine and waits on no ensure loop and no cluster session.
func (d *daemon) driftLoop(ctx context.Context) {
	ticks := d.ticks
	if ticks == nil {
		t := time.NewTicker(d.driftEvery)
		defer t.Stop()
		ticks = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			d.driftTick(ctx)
		}
	}
}

// driftTick is one firewall check. A wrong ruleset is reloaded once; if it
// is still wrong (or could not be examined three times running) the node is
// marked not contained, then every route drained, then every tenant
// stopped, in that order. While the flag is set the tick also runs the node
// check, and the first tick on which the firewall check and every blocking
// row (agent.Blocking) pass clears the flag and signals
// the ensure loop. Only host-side facts reach the flag.
func (d *daemon) driftTick(ctx context.Context) {
	switch honoured, age, err := d.hold(); {
	case err != nil:
		slog.Warn("drift hold unreadable; checking", "err", clean(err))
	case honoured:
		slog.Warn(fmt.Sprintf("drift check skipped: hold file present, age %ds", int64(age/time.Second)))
		return
	case age < 0:
		slog.Warn(fmt.Sprintf("drift hold dated in the future (age %ds); checking", int64(age/time.Second)))
	}
	if err := d.bridgeNF(); err != nil {
		slog.Warn("drift: bridge-nf switches", "err", clean(err))
	}
	err := d.nftCheck(ctx)
	if errors.Is(err, nft.ErrUnverified) {
		d.strikes++
		if d.strikes < unverifiedStrikes {
			slog.Warn("drift: firewall state could not be examined", "strike", d.strikes, "err", clean(err))
			if d.ag.ContainmentFailed() {
				d.stopTenants(ctx) // still flagged: one may have been started since
			}
			return
		}
	} else {
		d.strikes = 0
	}
	if err != nil {
		slog.Error("drift: firewall tables wrong; reloading", "err", clean(err))
		if lerr := d.nftLoad(ctx); lerr != nil {
			slog.Error("drift: reload", "err", clean(lerr))
		}
		if err = d.nftCheck(ctx); err == nil {
			d.strikes = 0
			slog.Info("drift: tables restored by the reload")
		}
	}
	if err != nil {
		if !d.ag.ContainmentFailed() {
			slog.Error("drift: containment failed; draining every route and stopping every tenant", "err", clean(err))
			d.ag.SetContainmentFailed(true)
			if _, derr := d.ag.DrainAllRoutes(ctx); derr != nil {
				slog.Error("drift: draining routes", "err", clean(derr))
			}
			d.stopTenants(ctx)
			d.markRefill()
			rctx, cancel := context.WithTimeout(ctx, refillMax)
			if rerr := d.refill(rctx); rerr != nil {
				slog.Error("drift: listing projects; retried by the adoption loop", "err", clean(rerr))
			}
			cancel()
			return
		}
		d.stopTenants(ctx) // again: one may have been started since
		return
	}
	if !d.ag.ContainmentFailed() {
		return
	}
	for _, r := range d.ag.NodeCheck(ctx) {
		if agent.Blocking(r) {
			slog.Warn("drift: node check still failing", "check", r.Name, "detail", clean(errors.New(r.Detail)))
			d.stopTenants(ctx)
			return
		}
	}
	d.ag.SetContainmentFailed(false)
	slog.Info("drift: containment shown again; adopting the pending projects")
	d.signalEnsure()
}

func (d *daemon) stopTenants(ctx context.Context) {
	if err := d.ag.StopAllTenants(ctx); err != nil {
		slog.Error("drift: stopping tenants", "err", clean(err))
	}
}

// hold reads the drift hold file: honoured when present, not dated in the
// future and younger than holdMax; age is 0 when it is absent. The drift
// tick and the round's project repairs both pause on it.
func (d *daemon) hold() (honoured bool, age time.Duration, err error) {
	fi, err := os.Lstat(d.p.DriftHold())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		return false, 0, err
	}
	age = d.now().Sub(fi.ModTime())
	return age >= 0 && age < d.holdMax, age, nil
}
