package saga

import (
	"context"
	"fmt"
)

// ResumeAll reports the operations a stopped worker left running; it changes
// no state. Run's queue takes a running operation like a pending one
// (StartOperation resumes it) and continues it at the step after its
// recorded one, so nothing has to move for it to resume.
func (r *Runner) ResumeAll(ctx context.Context) error {
	ops, err := r.st.ListOperations(ctx, "")
	if err != nil {
		return fmt.Errorf("saga: listing operations: %w", err)
	}
	for _, op := range ops {
		if op.State == "running" || op.State == "aborting" {
			r.log.Info("resuming", "op", op.ID, "ref", op.Ref, "kind", op.Kind, "state", op.State, "after", op.Step)
		}
	}
	return nil
}
