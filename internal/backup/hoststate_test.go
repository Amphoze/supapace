package backup

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Amphoze/supapace/internal/agent"
)

// The launcher joins a refusal of a file it wrote itself with the result of
// removing the job's files: a mount-source refusal is host_state wherever it
// stands in the error.
func TestRecord_AJoinedMountSourceRefusalIsHostState(t *testing.T) {
	refusal := fmt.Errorf("%w: /var/lib/supapace/platform/jobs/7.cred is not owned by 65530:65530", agent.ErrHostState)
	for name, err := range map[string]error{"plain": refusal, "joined": errors.Join(refusal, nil), "joined second": errors.Join(errors.New("x"), refusal),
		"wrapped join": fmt.Errorf("agent: job-x-push: %w", errors.Join(refusal, errors.New("rm")))} {
		if !isHostState(err) {
			t.Errorf("%s: not recognised as a mount-source refusal: %v", name, err)
		}
	}
	if isHostState(errors.New("docker run: no space")) || isHostState(nil) {
		t.Error("another error is a mount-source refusal")
	}
}
