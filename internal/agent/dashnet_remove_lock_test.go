package agent

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestRemoveProxy_WaitsForAnAttachInFlight: the removal takes the table's
// lock. One that arrives while an attach is at its network call waits for
// the attach to finish — the proxy on the network, the slice written — and
// removes the proxy after it: it never takes the container from under a call
// that is changing it.
func TestRemoveProxy_WaitsForAnAttachInFlight(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	x.ensure(t, x.projects(3)...)
	s := x.project(9)
	started := make(chan struct{})
	var once sync.Once
	x.f.before = func(args []string) {
		if len(args) > 1 && args[0] == "network" && args[1] == "connect" {
			once.Do(func() { close(started) })
			time.Sleep(20 * time.Millisecond)
		}
	}
	x.f.resetLog()
	var wg sync.WaitGroup
	var attachErr, removeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		attachErr = x.a.AttachProxy(ctx, s)
	}()
	go func() {
		defer wg.Done()
		<-started // the attach is at its network call
		removeErr = x.a.RemoveProxy(ctx)
	}()
	wg.Wait()
	if attachErr != nil || removeErr != nil {
		t.Errorf("the attach: %v; the removal: %v", attachErr, removeErr)
	}
	wantEvents(t, "the removal after the attach", x.events(), "connect proj-"+s.Ref+" "+x.addr(9), `table {"3":{"meta":5},"9":{"meta":5}}`, "rm")
	if x.ctr() != nil {
		t.Error("the proxy is still there")
	}
}
