package store

import (
	"context"
	"testing"
	"time"
)

// The way out of a failed restart is for a restarting project only: once a
// delete of it has moved it to deleting and failed, its newest restart is
// still the failed one, yet neither a restart nor another delete is
// accepted (op retry of the delete continues it).
func TestSubmitOperation_FailedRestartOnlyWhileRestarting(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := ref(1)
	activate(t, s, r, mustCreate(t, s, r))
	id, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.BeginRestart(ctx, r, 2, ProjectConfig{DiskQuotaMB: 1024, MemMB: 512, GUC: map[string]string{}}))
	must(t, s.FinishOperation(ctx, id, "failed", "internal: x"))
	del, err := s.SubmitOperation(ctx, r, "delete", nil, 2, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, del))
	must(t, s.SetProjectState(ctx, r, "deleting"))
	must(t, s.FinishOperation(ctx, del, "failed", "internal: y"))
	for _, k := range []string{"restart", "delete"} {
		_, err := s.SubmitOperation(ctx, r, k, nil, 2, time.Now())
		wantErr(t, err, ErrConflict)
	}
}
