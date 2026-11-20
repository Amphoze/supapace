package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/poolcfg"
)

// defaultShare is a project's share at the default max_connections.
var defaultShare = poolcfg.ProjectConns(poolcfg.Allowance(120))

// Two creates race for the last free share of the proxy's ceiling: exactly
// one is placed, every round.
func TestAdmit_ConnectionsTerm(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 50; round++ {
		a, b := ref(2*round+1), ref(2*round+2)
		mustCreate(t, s, a)
		mustCreate(t, s, b)
		must(t, s.SetNodeAllocs(ctx, poolcfg.ProxyFixedConns+defaultShare*(round+1), 1<<40))
		errs := race(2, func(i int) error { _, err := s.Place(ctx, []string{a, b}[i]); return err })
		placed := 0
		for _, err := range errs {
			switch {
			case err == nil:
				placed++
			case !errors.Is(err, ErrNodeFull) || !strings.Contains(err.Error(), "connections through the proxy"):
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if placed != 1 {
			t.Fatalf("round %d: %d placed (%v)", round, placed, errs)
		}
		// The loser stays a create that was never placed; it no longer counts.
		for _, r := range []string{a, b} {
			if p, _ := s.GetProject(ctx, r); p.UID == nil {
				sqlExec(t, s, "update project set state = 'aborted' where ref = $1", r)
			}
		}
	}
	// The refusal carries the figures.
	mustCreate(t, s, ref(999))
	_, err := s.Place(ctx, ref(999))
	want := "50 projects hold 3600 of the node's 3712 connections through the proxy; a project needs 72"
	if !errors.Is(err, ErrNodeFull) || !strings.Contains(err.Error(), want) {
		t.Fatalf("Place: %v, want %q", err, want)
	}
}

func TestAdmit_DescriptorTerm(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	one := int64(defaultConfig.MemMB+postgrestMemMB) << 20 / 230
	must(t, s.SetNodeAllocs(ctx, 1<<20, 2*one))
	newActive(t, s, 1)
	newActive(t, s, 2)
	wantErr(t, s.CheckAdmission(ctx, defaultConfig.MemMB, defaultShare), ErrNodeFull)
	mustCreate(t, s, ref(3))
	_, err := s.Place(ctx, ref(3))
	if !errors.Is(err, ErrNodeFull) || !strings.Contains(err.Error(), "2 projects hold") || !strings.Contains(err.Error(), "descriptors") {
		t.Fatalf("Place over the descriptor term: %v", err)
	}
	// Control: one descriptor more and it fits.
	must(t, s.SetNodeAllocs(ctx, 1<<20, 3*one+1))
	mustPlace(t, s, ref(3))
	must(t, s.SetNodeAllocs(ctx, 1<<20, 4*one+1))
	must(t, s.CheckAdmission(ctx, defaultConfig.MemMB, defaultShare))
	// A ceiling that is not above zero is refused.
	wantErr(t, s.SetNodeAllocs(ctx, 0, 1), ErrConflict)
	wantErr(t, s.SetNodeAllocs(ctx, 1, 0), ErrConflict)
}

func TestCheckConns_LargerShareRefusedAtTheCeiling(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	a := newActive(t, s, 1)
	b := newActive(t, s, 2)
	ceiling := poolcfg.ProxyFixedConns + 2*defaultShare + 10
	must(t, s.SetNodeAllocs(ctx, ceiling, 1<<40))
	must(t, s.CheckConns(ctx, b, defaultShare+10))
	err := s.CheckConns(ctx, b, defaultShare+11)
	want := "1 projects hold 72 of the node's 266 connections through the proxy; a project needs 83"
	if !errors.Is(err, ErrNodeFull) || !strings.Contains(err.Error(), want) {
		t.Fatalf("CheckConns over the ceiling: %v, want %q", err, want)
	}
	// The larger share recorded counts against the other project.
	must(t, s.SetConns(ctx, b, defaultShare+10))
	wantErr(t, s.CheckConns(ctx, a, defaultShare+1), ErrNodeFull)
	must(t, s.CheckConns(ctx, a, defaultShare))
	// A share below zero is refused, by both.
	wantErr(t, s.CheckConns(ctx, a, -1), ErrConflict)
	wantErr(t, s.SetConns(ctx, a, -1), ErrConflict)
	wantErr(t, s.SetConns(ctx, ref(9), 1), ErrNotFound)
}

func TestRelease_AbortedSliceHeldOnlyWhenSet(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	abort := func(n int) int {
		r := ref(n)
		mustCreate(t, s, r)
		i := mustPlace(t, s, r).SubnetIndex
		must(t, s.MarkAborted(ctx, r))
		return i
	}
	place := func(n int) int { mustCreate(t, s, ref(n)); return mustPlace(t, s, ref(n)).SubnetIndex }
	// Unset: the index is free at once.
	i := abort(1)
	if got := place(2); got != i {
		t.Fatalf("unset: placed at %d, the aborted index %d is not free", got, i)
	}
	if n := count(t, s, "select count(*) from slice_hold"); n != 0 {
		t.Fatalf("unset: %d holds", n)
	}
	// Set: Place passes over it until the hold has passed.
	s.SetAbortSliceHold(time.Hour)
	t.Cleanup(func() { s.SetAbortSliceHold(0) })
	i = abort(3)
	if got := place(4); got == i {
		t.Fatalf("set: placed on the held index %d", i)
	}
	sqlExec(t, s, "update slice_hold set free_after = now() - interval '1 second'")
	if got := place(5); got != i {
		t.Fatalf("set: after the hold placed at %d, want %d", got, i)
	}
	// A purge's hold is the slice hold's, which is unset here.
	p := newActive(t, s, 6)
	holdPurge(t, s, p)
	if n := count(t, s, "select count(*) from slice_hold"); n != 0 {
		t.Fatalf("a purge held %d with the slice hold unset", n)
	}
}

// The advisory check counts the new project at the share it is given, so it
// refuses what Place would refuse.
func TestCheckAdmission_CountsTheNewProjectsShare(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	newActive(t, s, 1)
	must(t, s.SetNodeAllocs(ctx, poolcfg.ProxyFixedConns+2*defaultShare-1, 1<<40))
	err := s.CheckAdmission(ctx, defaultConfig.MemMB, defaultShare)
	if !errors.Is(err, ErrNodeFull) || !strings.Contains(err.Error(), "a project needs 72") {
		t.Fatalf("CheckAdmission: %v", err)
	}
	mustCreate(t, s, ref(2))
	_, err = s.Place(ctx, ref(2))
	wantErr(t, err, ErrNodeFull)
	sqlExec(t, s, "update project set state = 'aborted' where ref = $1", ref(2))
	// Control: one connection less fits.
	must(t, s.CheckAdmission(ctx, defaultConfig.MemMB, defaultShare-1))
	wantErr(t, s.CheckAdmission(ctx, defaultConfig.MemMB, -1), ErrConflict)
	// The share of a configuration is the one Place counts.
	c := defaultConfig
	c.GUC = map[string]string{"max_connections": "300"}
	if n, err := ProjectShare(c); err != nil || n != 252 {
		t.Fatalf("ProjectShare = %d, %v", n, err)
	}
}
