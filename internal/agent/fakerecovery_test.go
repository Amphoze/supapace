package agent

import (
	"context"
	"testing"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/jackc/pgx/v5"
)

// rcPG replaces the recovery start's session seams (recovery.go) and the
// statistics reset (cluster.go). Each call is recorded in the fake host's
// log, after the dial clFakePG records, so the order of a session's
// statements reads from f.calls().
type rcPG struct {
	inRecovery          bool
	inRecoveryErr       error
	rekeyErr            error
	rekeySecrets        bootstrap.Secrets
	timeline            int
	timelineErr         error
	reset               bool
	resetErr            error
	rekeyCalls, inCalls int
}

func rcFake(t *testing.T, f *fakeHost) *rcPG {
	rc := &rcPG{timeline: 2, reset: true}
	saved := []func(){
		swap(&bootstrapRekey, func(ctx context.Context, c *pgx.Conn, s bootstrap.Secrets) error {
			f.record("rekey")
			rc.rekeyCalls++
			rc.rekeySecrets = s
			return rc.rekeyErr
		}),
		swap(&bootstrapInRecovery, func(ctx context.Context, c *pgx.Conn) (bool, error) {
			f.record("in recovery")
			rc.inCalls++
			return rc.inRecovery, rc.inRecoveryErr
		}),
		swap(&bootstrapReadTimeline, func(ctx context.Context, c *pgx.Conn) (int, error) {
			f.record("read timeline")
			return rc.timeline, rc.timelineErr
		}),
		swap(&bootstrapResetStatementStats, func(ctx context.Context, c *pgx.Conn) (bool, error) {
			f.record("reset statement stats")
			return rc.reset, rc.resetErr
		}),
	}
	t.Cleanup(func() {
		for _, r := range saved {
			r()
		}
	})
	return rc
}
