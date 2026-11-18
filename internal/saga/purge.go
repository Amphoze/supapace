package saga

import "context"

// Purge steps. Key material dies first and the root-owned render tree (the
// plaintext pgsodium key, PostgREST's database password) next, so a
// directory purge that can never finish keeps no secret alive beside the
// data. Only P5 frees the slice, and with it the platform address.
var purgeSteps = []step{
	{"P1", (*job).stopLeftovers},
	{"P2", func(x *job, ctx context.Context) error { return x.r.st.DestroyKeys(ctx, x.op.Ref) }},
	{"P3", func(x *job, ctx context.Context) error { return x.r.ag.RemoveRender(ctx, x.op.Ref) }},
	{"P4", (*job).purgeDir},
	{"P5", func(x *job, ctx context.Context) error { return x.r.st.MarkPurged(ctx, x.op.Ref) }},
}

// P1: both containers stopped; no-ops when absent, the normal case after D2/D3.
func (x *job) stopLeftovers(ctx context.Context) error {
	if err := x.r.ag.StopPostgREST(ctx, x.op.Ref); err != nil {
		return err
	}
	return x.r.ag.StopCluster(ctx, x.op.Ref)
}

// P4 (and abort C6): the project tree removed at the project's uid; an absent
// tree is done.
func (x *job) purgeDir(ctx context.Context) error {
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return err
	}
	if p.UID == nil {
		return nil // never placed: there is no tree
	}
	s, err := bareSpec(p, x.op.Epoch, p.Generation, p.Config)
	if err != nil {
		return err
	}
	return x.r.ag.PurgeDir(ctx, s)
}
