package saga

import (
	"context"
	"time"
)

// Delete steps: the route goes first, nothing may route to a container that
// is going away; the slice index stays allocated until the purge.
var deleteSteps = []step{
	{"D1", (*job).unroute},
	{"D2", func(x *job, ctx context.Context) error { return x.r.ag.StopPostgREST(ctx, x.op.Ref) }},
	{"D3", func(x *job, ctx context.Context) error { return x.r.ag.StopCluster(ctx, x.op.Ref) }},
	{"D4", func(x *job, ctx context.Context) error { return x.r.ag.RemoveNetwork(ctx, x.op.Ref) }},
	{"D5", (*job).markDeleted},
}

// D1: deleting, the route removed, the gateway at that route file.
func (x *job) unroute(ctx context.Context) error {
	if err := x.r.st.SetProjectState(ctx, x.op.Ref, "deleting"); err != nil {
		return err
	}
	gen, err := x.r.ag.SetRoute(ctx, x.op.Ref, nil)
	if err != nil {
		return err
	}
	return x.r.waitGateway(ctx, gen)
}

// D5: deleted, with the purge queued at now + retention (idempotent: a
// resumed step gets the same purge operation back).
func (x *job) markDeleted(ctx context.Context) error {
	retention, err := time.ParseDuration(x.r.cfg.Retention)
	if err != nil {
		return err
	}
	_, err = x.r.st.MarkDeleted(ctx, x.op.Ref, retention)
	return err
}
