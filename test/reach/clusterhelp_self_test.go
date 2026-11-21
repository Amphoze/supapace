//go:build !reach

package reach

import (
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// TestClusterhelp_RepeatWhile: the background runner fails the test on any
// failed run and on fewer than three runs (fails is a self-test helper of
// helpers_self_test.go, built without the reach tag).
func TestClusterhelp_RepeatWhile(t *testing.T) {
	if fails(func(tb testing.TB) {
		// Stopped once three runs have ended, not after a fixed time: on a
		// busy machine three runs of a command can take longer than any
		// sleep chosen here.
		var runs atomic.Int32
		ok := commandOK(nil, "true")
		stop := repeatWhile(tb, "true", 10*time.Millisecond, func() error { defer runs.Add(1); return ok() })
		for deadline := time.Now().Add(30 * time.Second); runs.Load() < 3; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				tb.Fatalf("%d runs in 30 s", runs.Load())
			}
		}
		stop()
	}) {
		t.Fatal("a command that always succeeds failed the test")
	}
	if !fails(func(tb testing.TB) {
		stop := repeatWhile(tb, "false", 10*time.Millisecond, commandOK(nil, "false"))
		time.Sleep(100 * time.Millisecond)
		stop()
	}) {
		t.Fatal("a failing command passed")
	}
	if !fails(func(tb testing.TB) { repeatWhile(tb, "true", time.Hour, commandOK(nil, "true"))() }) {
		t.Fatal("fewer than three runs passed")
	}
}

// TestClusterhelp_InBackground: the result arrives; a short wait reports an
// unfinished step and a later wait still gets it; the cleanup waits for an
// unread step and fails the test only if it outlasts its bound.
func TestClusterhelp_InBackground(t *testing.T) {
	saved := backgroundBound
	defer func() { backgroundBound = saved }()
	// failsWithCleanup is fails with the cleanups' failures counted too.
	failsWithCleanup := func(f func(testing.TB)) bool {
		m := &mainT{out: io.Discard}
		m.run(f)
		m.cleanup()
		return m.failed
	}
	var ended atomic.Bool
	if failsWithCleanup(func(tb testing.TB) {
		wait := inBackground(tb, func() int { time.Sleep(200 * time.Millisecond); ended.Store(true); return 7 })
		if _, ok := wait(time.Millisecond); ok {
			tb.Error("an unfinished step reported done")
		}
		if v, ok := wait(5 * time.Second); !ok || v != 7 {
			tb.Errorf("result %d %v", v, ok)
		}
	}) || !ended.Load() {
		t.Fatal("a step that ends failed the test")
	}
	ended.Store(false)
	if failsWithCleanup(func(tb testing.TB) {
		inBackground(tb, func() int { time.Sleep(200 * time.Millisecond); ended.Store(true); return 1 })
	}) || !ended.Load() {
		t.Fatal("the cleanup did not wait for an unread step")
	}
	backgroundBound = 50 * time.Millisecond
	if !failsWithCleanup(func(tb testing.TB) { inBackground(tb, func() int { time.Sleep(time.Second); return 1 }) }) {
		t.Fatal("a step outlasting the cleanup's bound passed")
	}
}
