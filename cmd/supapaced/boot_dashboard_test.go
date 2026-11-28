package main

import (
	"context"
	"errors"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// dashRemover is an agent that can remove the dashboard's containers, as the
// node's agent can.
type dashRemover struct {
	*fakeAgent
	err error
}

func (r dashRemover) RemoveDashboard(context.Context) error {
	r.c.add("RemoveDashboard")
	return r.err
}

// TestBoot_RemovesAnUnconfiguredDashboardBeforeTheNodeCheck: the dashboard's
// containers on a node whose dashboard is not configured are members the node
// check refuses, and a refusing row at a start stops every project. The
// agent's removal runs first; a removal that fails is logged and the check
// still decides.
func TestBoot_RemovesAnUnconfiguredDashboardBeforeTheNodeCheck(t *testing.T) {
	w := newWorld(t)
	w.d.ag = dashRemover{fakeAgent: w.ag}
	w.d.boot(context.Background())
	i, j := w.c.index("RemoveDashboard"), w.c.index("NodeCheck")
	if i < 0 || j < 0 || i > j || w.c.count("RemoveDashboard") != 1 {
		t.Fatalf("the removal is not made once before the node check: %q", w.c.all())
	}
	if w.ag.ContainmentFailed() {
		t.Fatal("a passing node check after the removal marked the node")
	}

	w = newWorld(t)
	w.d.ag = dashRemover{fakeAgent: w.ag, err: errors.New("docker: daemon busy")}
	w.ag.nodeCheck = func() []nodecfg.CheckResult {
		return []nodecfg.CheckResult{{Name: "platform-members", Detail: "foreign member sp-pgcap"}}
	}
	w.d.boot(context.Background())
	if i, j := w.c.index("RemoveDashboard"), w.c.index("NodeCheck"); i < 0 || i > j || !w.ag.ContainmentFailed() {
		t.Fatalf("after a failed removal the node check did not decide: %q, marked %v", w.c.all(), w.ag.ContainmentFailed())
	}
}
