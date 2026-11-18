// Package gateway is the node's public entry point. It resolves the project
// from the host name, verifies every token against that project's keys, binds
// each key class to its roles, rewrites the forwarding headers and proxies to
// the project's PostgREST.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	maxBody            = 8 << 20 // bytes of one request body
	maxInFlight        = 2048    // proxied requests at once, gateway-wide
	maxProjectInFlight = 128     // proxied requests at once, per project; also upstream connections per project

	// HTTP/2 receive windows: request body buffered before the handler reads
	// it, per stream and per connection. The library's connection minimum is
	// 65,535 bytes, the initial window of the protocol. The socket's receive
	// buffer (sockBuf) is smaller and caps upload speed first.
	maxH2StreamWindow = 128 << 10
	maxH2ConnWindow   = 128 << 10

	// maxH2Frame is the largest HTTP/2 frame read, the protocol's minimum. A
	// connection's read buffer grows to the largest frame it has read and is
	// kept; the library's default would let each connection hold 1 MiB.
	maxH2Frame = 16 << 10

	// maxH2Streams is the number of requests one HTTP/2 connection runs at
	// once. Each open stream holds its decoded request header, so with the
	// connection cap it bounds the header memory of HTTP/2 clients.
	maxH2Streams = 8
)

// Gateway is the HTTPS handler.
type Gateway struct {
	table     *Table
	transport *http.Transport
	inflight  chan struct{} // semaphore of proxied requests

	mu         sync.Mutex
	projectCap int
	byProject  map[string]int // proxied requests in flight per ref; no zero entries
}

func New(t *Table) *Gateway {
	return &Gateway{table: t, transport: newTransport(), inflight: make(chan struct{}, maxInFlight),
		projectCap: maxProjectInFlight, byProject: map[string]int{}}
}

// acquireProject takes one of ref's in-flight slots. Counts are keyed by ref
// and live outside the route table, so a reload neither resets nor leaks them;
// a ref's entry goes away when its count is back to zero.
func (g *Gateway) acquireProject(ref string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.byProject[ref] >= g.projectCap {
		return false
	}
	g.byProject[ref]++
	return true
}

func (g *Gateway) releaseProject(ref string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.byProject[ref]--; g.byProject[ref] <= 0 {
		delete(g.byProject, ref)
	}
}

// ServeHTTP answers /-/health, then resolves the project, checks the
// credentials and the route, and forwards. Every refusal is a JSON body
// {"code":…}, for a refused credential with a fixed "message" naming the
// cause, carrying nothing from the request, the keys or the upstream.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// HTTP/2 keeps a stream's request until its response is on the wire, so a
	// client that does not read would pin up to the header limit per stream.
	// Neither server reads the header after the handler has returned.
	defer func() { r.Header = nil }()
	switch {
	case r.ProtoMajor == 1 && r.ProtoMinor == 0:
		fail(w, http.StatusHTTPVersionNotSupported, "http_version_not_supported")
		return
	case r.Method == http.MethodConnect || r.URL.Scheme != "" || r.URL.Host != "":
		fail(w, http.StatusBadRequest, "bad_request") // only origin-form targets
		return
	case r.URL.Path == "/-/health":
		w.Header().Set("Content-Type", "application/json")
		sandbox(w.Header())
		fmt.Fprintf(w, `{"generation":%d}`, g.table.Generation())
		return
	}
	tb := g.table.cur.Load()
	if tb == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	name, ref, p := tb.resolve(r.Host)
	switch {
	case p == nil:
		fail(w, http.StatusNotFound, "not_found")
		return
	case !sniAgrees(r, name):
		fail(w, http.StatusMisdirectedRequest, "misdirected")
		return
	case p.draining:
		fail(w, http.StatusServiceUnavailable, "project_restarting")
		return
	case len(headerValues(r.Header, "Upgrade")) > 0:
		fail(w, http.StatusBadRequest, "upgrade_not_supported")
		return
	}
	query, queryKeys, ok := splitQuery(r.URL.RawQuery)
	if !ok {
		fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	bearer, code, msg := authenticate(r.Header, queryKeys, p, time.Now())
	if code != "" {
		refuse(w, http.StatusUnauthorized, code, msg)
		return
	}
	path, graphql, ok := route(r)
	if !ok {
		fail(w, http.StatusNotFound, "not_found")
		return
	}
	if r.ContentLength > maxBody {
		fail(w, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	// The project's slot first: a project at its cap takes no global slot.
	if !g.acquireProject(ref) {
		fail(w, http.StatusTooManyRequests, "too_many_requests")
		return
	}
	defer g.releaseProject(ref)
	select {
	case g.inflight <- struct{}{}:
		defer func() { <-g.inflight }()
	default:
		fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	g.forward(w, r, name, ref, p, path, query, bearer, graphql)
}

func fail(w http.ResponseWriter, status int, code string) { refuse(w, status, code, "") }

// refuse writes the gateway's error body: the code, and a message from a
// fixed list when one is given.
func refuse(w http.ResponseWriter, status int, code, msg string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	sandbox(h)
	switch status {
	case http.StatusServiceUnavailable:
		h.Set("Retry-After", "5")
	case http.StatusTooManyRequests:
		h.Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	if msg == "" {
		fmt.Fprintf(w, `{"code":%q}`, code)
		return
	}
	fmt.Fprintf(w, `{"code":%q,"message":%q}`, code, msg)
}

// NewServer returns a server with the gateway's timeouts, header cap and TLS
// floor; the caller adds the certificate.
// ponytail: the 60 s write timeout caps a single response; raise per route when a long export needs it.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second, // a whole request; see sockBuf for the body that fits
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		// With the per-source connection cap this bounds what one source holds open.
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: maxH2Streams, MaxReadFrameSize: maxH2Frame,
			MaxReceiveBufferPerStream: maxH2StreamWindow, MaxReceiveBufferPerConnection: maxH2ConnWindow},
	}
}

// Shutdown stops every server from accepting and waits up to grace for their
// requests in flight; it returns the first error, context.DeadlineExceeded
// when the grace ran out.
func Shutdown(grace time.Duration, servers ...*http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	errs := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = s.Shutdown(ctx) }()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Redirect sends every plain-HTTP request to the same host and target over
// HTTPS.
func Redirect() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		sandbox(w.Header())
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}
