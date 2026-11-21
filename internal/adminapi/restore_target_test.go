package adminapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/store"
)

// A target the recovery start would refuse (a position 0/0, a time whose UTC
// year is 10000) passes the request's own checks and is refused by the
// submit, which wraps the value error: the answer is a bad request naming the
// field, not a conflict of the project's state, and never an internal error.
func TestRestore_TargetTheRecoveryRefusesIsBadRequest(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	_, perr := pgconf.RecoveryPins(pgconf.RecoveryTarget{LSN: "0/0", Timeline: "1"})
	if perr == nil {
		t.Fatal("the recovery pins took 0/0")
	}
	for name, err := range map[string]error{
		"wrapped-with-the-conflict": fmt.Errorf("%w: %w", store.ErrConflict, perr),
		"the-value-error-alone":     perr,
	} {
		t.Run(name, func(t *testing.T) {
			e.ops.submitErr = err
			code, b := e.do(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"0/0"}`)
			if code != 400 || !strings.Contains(string(b), `"code":"bad_request"`) || !strings.Contains(string(b), "recovery target") {
				t.Fatalf("%d %s", code, b)
			}
			if strings.Contains(string(b), "conflict") || strings.Contains(string(b), "pgconf") {
				t.Fatalf("the message carries the wrapping: %s", b)
			}
		})
	}
	// A refusal for the project's state stays a conflict.
	e.ops.submitErr = fmt.Errorf("%w: timeline 7 is not a recorded timeline", store.ErrConflict)
	if code, b := e.do(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"latest","timeline":7}`); code != 409 || !strings.Contains(string(b), `"code":"conflict"`) {
		t.Fatalf("%d %s", code, b)
	}
}
