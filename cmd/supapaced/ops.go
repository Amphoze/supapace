package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
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

// VerifyProject reads the project's host-side facts (its containers and its
// route), then opens one session to its cluster. The failing host-side rows
// come first in the drift; the session's operational facts decide the code;
// when the session passes, a failing host-side row makes the check fail with
// code internal and those rows in the message.
func (o ops) VerifyProject(ctx context.Context, ref string) (code, message string, drift []nodecfg.CheckResult) {
	ctx, cancel := context.WithTimeout(ctx, o.d.verifyMax)
	defer cancel()
	spec, err := o.d.rn.SpecFor(ctx, ref)
	var host []string
	if err == nil {
		rows := o.d.ag.CheckHost(ctx, spec)
		for _, r := range rows {
			if !r.OK {
				host = append(host, r.Name+": "+r.Detail)
			}
		}
		drift, err = o.d.ag.CheckCluster(ctx, spec)
		drift = append(rows, drift...)
	}
	switch {
	case err == nil && len(host) > 0:
		return "internal", pgsock.Sanitize("host-side: "+strings.Join(host, "; "), 1024), drift
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

// DiskUsage reads the uid's user-quota accounting on the projects mount.
func (o ops) DiskUsage(ctx context.Context, uid int) (int64, error) {
	return nodefs.DiskUsage(ctx, o.d.p, uid)
}
