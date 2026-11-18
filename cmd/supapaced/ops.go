package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

// ops is the admin API's view of the daemon (adminapi.Ops).
type ops struct{ d *daemon }

// Submit queues a restart or delete through the worker; a project not yet
// adopted since boot (or since the last containment failure) is refused.
func (o ops) Submit(ctx context.Context, kind, ref string, params json.RawMessage) (int64, error) {
	if o.d.isPending(ref) {
		return 0, fmt.Errorf("%w: not yet adopted", store.ErrConflict)
	}
	return o.d.rn.Submit(ctx, kind, ref, params)
}

func (o ops) Abort(ctx context.Context, ref string) (int64, error) { return o.d.rn.Abort(ctx, ref) }

// VerifyProject is one session to the project's cluster: the operational
// facts decide the code, the findings are its drift.
func (o ops) VerifyProject(ctx context.Context, ref string) (code, message string, drift []nodecfg.CheckResult) {
	ctx, cancel := context.WithTimeout(ctx, o.d.verifyMax)
	defer cancel()
	spec, err := o.d.rn.SpecFor(ctx, ref)
	if err == nil {
		drift, err = o.d.ag.CheckCluster(ctx, spec)
	}
	switch {
	case err == nil:
		return "", "", drift
	case errors.Is(err, pgsock.ErrPeer):
		code = "peer"
	case pgsock.IsBudget(err):
		code = "timeout"
	default:
		code = "internal"
	}
	return code, clean(err), drift
}

func (o ops) NodeCheck(ctx context.Context) []nodecfg.CheckResult {
	ctx, cancel := context.WithTimeout(ctx, o.d.verifyMax)
	defer cancel()
	return o.d.ag.NodeCheck(ctx)
}

func (o ops) ContainmentOK() bool { return !o.d.ag.ContainmentFailed() }
