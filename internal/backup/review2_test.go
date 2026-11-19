package backup

import (
	"testing"
	"time"
)

// A push stays queued while its subject's slot is busy: the scheduler adds no
// second one however long it waits, so a subject's queued pushes stay one.
func TestScheduler_NoSecondPushWhileOneIsQueued(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.tick()
	for range 3 {
		e.clock.Add(2 * time.Minute)
		e.tick()
	}
	if n := e.jobs(ref, "push"); n != 1 {
		t.Fatalf("%d pushes queued for one subject, want 1", n)
	}
}
