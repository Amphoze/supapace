package saga

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Amphoze/supapace/internal/store"
)

// Restore steps: none yet. The kind is known so that its operations are
// tables like any other; a restore cannot be submitted.
var restoreSteps = []step{}

func (r *Runner) submitRestore(ctx context.Context, ref string, params json.RawMessage) (int64, error) {
	return 0, fmt.Errorf("%w: this node does not restore projects yet", store.ErrConflict)
}
