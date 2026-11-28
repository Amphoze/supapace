package agent

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestProxyTable_NoWriteIsLost: attaches and detaches of different projects
// that overlap leave the table with every attached slice and no detached
// one — with no ensure after them to mend it. Each holds the table's lock
// from its read of the file to its last change, so none writes over what
// another has added or removed.
func TestProxyTable_NoWriteIsLost(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	going := x.projects(20, 21, 22, 23)
	x.ensure(t, going...)
	coming := x.projects(1, 2, 3, 4, 5, 6, 7, 8)
	// Every change of an attachment takes a moment: calls that did not exclude
	// each other would all have read the table before any had written it.
	x.f.before = func(args []string) {
		if len(args) > 1 && args[0] == "network" && (args[1] == "connect" || args[1] == "disconnect") {
			time.Sleep(5 * time.Millisecond)
		}
	}
	var wg sync.WaitGroup
	run := func(what string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				t.Errorf("%s: %v", what, err)
			}
		}()
	}
	for _, s := range coming {
		run("attach", func() error { return x.a.AttachProxy(ctx, s) })
	}
	for _, s := range going {
		run("detach", func() error { return x.a.DetachProxy(ctx, s.Ref) })
	}
	wg.Wait()
	want := `{"1":{"meta":5},"2":{"meta":5},"3":{"meta":5},"4":{"meta":5},"5":{"meta":5},"6":{"meta":5},"7":{"meta":5},"8":{"meta":5}}`
	if got := x.slices(t); got != want {
		t.Errorf("slices %s, want %s", got, want)
	}
	c := x.ctr()
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	if len(c.Nets) != 9 {
		t.Errorf("attached to %v, want the platform and the eight", c.Nets)
	}
	for _, s := range coming {
		if c.Nets["proj-"+s.Ref] != x.addr(s.SubnetIndex) {
			t.Errorf("proj-%s: at %q, want %s", s.Ref, c.Nets["proj-"+s.Ref], x.addr(s.SubnetIndex))
		}
	}
}

// TestProxyTable_EnsureAndDetachOverlap: a detach that arrives while an
// ensure is attaching waits for it, or the ensure would write a slice it saw
// attached after the detach has taken the proxy off that network. Whichever
// goes first, the table names exactly the slices the proxy is attached to.
func TestProxyTable_EnsureAndDetachOverlap(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	there := x.projects(20, 21, 22, 23)
	x.ensure(t, there...)
	live := append(x.projects(1, 2, 3, 4, 5, 6, 7, 8), there...)
	started := make(chan struct{})
	var once sync.Once
	x.f.before = func(args []string) {
		if len(args) > 1 && args[0] == "network" && args[1] == "connect" {
			once.Do(func() { close(started) })
			time.Sleep(5 * time.Millisecond)
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := x.a.EnsureProxy(ctx, listed(live)); err != nil {
			t.Errorf("ensure: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		<-started // the ensure is attaching
		if err := x.a.DetachProxy(ctx, there[0].Ref); err != nil {
			t.Errorf("detach: %v", err)
		}
	}()
	wg.Wait()
	tb := x.table(t)
	c := x.ctr()
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	if len(tb.Slices) != len(c.Nets)-1 {
		t.Errorf("the table names %d slices, the proxy is on %d project networks", len(tb.Slices), len(c.Nets)-1)
	}
	for _, s := range live {
		_, named := tb.Slices[strconv.Itoa(s.SubnetIndex)]
		if _, on := c.Nets["proj-"+s.Ref]; on != named {
			t.Errorf("slice %d: in the table %v, attached %v", s.SubnetIndex, named, on)
		}
	}
}
