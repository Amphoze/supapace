package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/gateway"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"gw.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// TestRun_SignalDrains: on the first signal run restores default signal
// handling at once (a second signal ends the process), refuses new
// connections, lets the request in flight finish and returns within the grace.
func TestRun_SignalDrains(t *testing.T) {
	arrived, release := make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-release
	})
	tlsLn, plainLn := listen(t), listen(t)
	addr := tlsLn.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stopped atomic.Bool
	const grace = 30 * time.Second
	done := make(chan error, 1)
	go func() { done <- run(ctx, func() { stopped.Store(true) }, grace, h, selfSigned(t), tlsLn, plainLn) }()

	got := make(chan int, 1)
	go func() {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		resp, err := c.Get("https://" + addr + "/")
		if err != nil {
			got <- 0
			return
		}
		resp.Body.Close()
		got <- resp.StatusCode
	}()
	<-arrived
	start := time.Now()
	cancel()
	refused := false
	for deadline := time.Now().Add(10 * time.Second); !refused && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		c, err := net.Dial("tcp", addr)
		if refused = err != nil; !refused {
			c.Close()
		}
	}
	if !refused {
		t.Error("new connection accepted after the signal")
	}
	if !stopped.Load() {
		t.Error("signal handling not restored while a request is in flight")
	}
	// The request is still held, so run must still be waiting for it. A run
	// that gave up on it returns here; slowness can only hide that, never fail
	// a correct run.
	early := false
	select {
	case err := <-done:
		early = true
		t.Errorf("run returned (%v) %v after the signal, with a request in flight", err, time.Since(start))
	case <-time.After(time.Second):
	}
	close(release)
	if c := <-got; c != 200 {
		t.Errorf("in-flight request: %d", c)
	}
	if early {
		return
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run: %v", err)
		}
		if d := time.Since(start); d > 15*time.Second { // well inside the grace: it returned when the request ended
			t.Errorf("run returned after %v", d)
		}
	case <-time.After(grace + time.Second):
		t.Fatal("run did not return within the grace")
	}
}

// TestRun_ServerFailureClosesBoth: when one server fails, run closes the
// other one too before it returns the error.
func TestRun_ServerFailureClosesBoth(t *testing.T) {
	tlsLn, plainLn := listen(t), listen(t)
	tlsLn.Close()
	plainAddr := plainLn.Addr().String()
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), func() {}, time.Second, http.NotFoundHandler(), selfSigned(t), tlsLn, plainLn)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after a server failed")
	}
	for deadline := time.Now().Add(time.Second); ; time.Sleep(10 * time.Millisecond) {
		c, err := net.Dial("tcp", plainAddr)
		if err != nil {
			return
		}
		c.Close()
		if time.Now().After(deadline) {
			plainLn.Close()
			t.Fatal("the other listener still accepts")
		}
	}
}

// TestListeners_BehindLimiter: both public listeners take their connections
// from the one limiter, and so get its fixed socket buffers: with room for a
// single connection, either listener refuses while the other holds it.
func TestListeners_BehindLimiter(t *testing.T) {
	tlsLn, plainLn, err := listeners(gateway.NewLimiter(1, 1), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tlsLn.Close()
	defer plainLn.Close()
	accepted := func(ln net.Listener) chan net.Conn {
		ch := make(chan net.Conn, 4)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				ch <- c
			}
		}()
		return ch
	}
	tlsCh, plainCh := accepted(tlsLn), accepted(plainLn)
	// served dials ln and reports whether the connection was accepted (true)
	// or closed at accept (false).
	served := func(ln net.Listener, ch chan net.Conn) (net.Conn, bool) {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		select {
		case s := <-ch:
			return s, true
		case <-time.After(300 * time.Millisecond):
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("connection to %v neither accepted nor closed: %v", ln.Addr(), err)
		}
		return nil, false
	}
	held, ok := served(tlsLn, tlsCh)
	if !ok {
		t.Fatal("first connection refused")
	}
	if _, ok := served(plainLn, plainCh); ok {
		t.Error("plain listener accepted past the limiter's cap")
	}
	held.Close()
	if held, ok = served(plainLn, plainCh); !ok {
		t.Fatal("plain listener refused with the cap free")
	}
	if _, ok := served(tlsLn, tlsCh); ok {
		t.Error("TLS listener accepted past the limiter's cap")
	}
	held.Close()
}

// TestImage_UserAndHeapLimit: the image runs the gateway as its own numeric
// user (the last USER line decides) with the heap limit sized for its 768 MiB
// container.
func TestImage_UserAndHeapLimit(t *testing.T) {
	b, err := os.ReadFile("../../deploy/gateway/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	user := ""
	lines := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		lines[strings.TrimSpace(l)] = true
		if strings.HasPrefix(strings.TrimSpace(l), "USER ") {
			user = strings.TrimSpace(l)
		}
	}
	for _, want := range []string{"FROM scratch", "USER 65531:65531", "ENV GOMEMLIMIT=460MiB"} {
		if !lines[want] {
			t.Errorf("Dockerfile has no line %q", want)
		}
	}
	if user != "USER 65531:65531" {
		t.Errorf("last USER line is %q", user)
	}
}
