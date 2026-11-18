package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/adminapi"
)

// The listing at start fails once (store slow to answer): the active
// project is still adopted by the adoption loop.
func TestBoot_ListingFailureAtStartIsRetried(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.d.retryEvery = 50 * time.Millisecond
	fs := &flakyStore{fakeStore: w.st}
	fs.listFail.Store(1)
	w.d.connect = func(context.Context) (*backend, error) {
		return &backend{st: fs, rn: w.rn, api: func(adminapi.Ops) http.Handler { return http.NotFoundHandler() }}, nil
	}
	w.start()
	eventually(t, 5*time.Second, "adopted after the failed listing", func() bool { return w.ag.route(refN(1)) == "active" })
}

// A round whose due listing hangs ends within the listing's bound.
func TestEnsureActive_DueListingBounded(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	fs := &flakyStore{fakeStore: w.st}
	fs.listStall.Store(true)
	w.d.st, w.d.rn = fs, w.rn
	w.d.markRefill()
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { w.d.ensureActive(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("round blocked on a hung listing")
	}
}
