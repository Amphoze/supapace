package gateway

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// maxUpstreamHeader bounds the header of an upstream response, the same as
// the clients' request header limit.
const maxUpstreamHeader = 32 << 10

// maxInformational is the number of 1xx responses relayed per request.
const maxInformational = 8

// dialer opens upstream connections.
var dialer = &net.Dialer{Timeout: 5 * time.Second}

// newTransport is the upstream transport. Proxy is nil on purpose: no
// environment variable may send tenant traffic elsewhere. Upstream
// connections get the same fixed kernel buffers as client ones. Connections per
// upstream equal the per-project cap, so no admitted request waits inside the
// gateway for a connection.
func newTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				fixBuffers(c)
			}
			return c, err
		},
		ResponseHeaderTimeout:  30 * time.Second,
		MaxConnsPerHost:        maxProjectInFlight,
		MaxIdleConnsPerHost:    16,
		MaxResponseHeaderBytes: maxUpstreamHeader,
	}
}

// route maps the request path to the upstream path: /rest/v1/* to /*, and
// POST /graphql/v1 to /rpc/graphql. The match is on the path as sent, so an
// escaped slash never forms a prefix.
func route(r *http.Request) (path string, graphql, ok bool) {
	ep := r.URL.EscapedPath()
	if rest, ok := strings.CutPrefix(ep, "/rest/v1/"); ok {
		return "/" + rest, false, true
	}
	if ep == "/graphql/v1" && r.Method == http.MethodPost {
		return "/rpc/graphql", true, true
	}
	return "", false, false
}

// stripped reports whether an inbound header is removed before forwarding.
func stripped(name string) bool {
	switch n := strings.ToLower(name); {
	case n == "authorization", n == "apikey", n == "x-connection-encrypted", n == "forwarded",
		n == "x-pg-application-name", n == "x-real-ip", n == "true-client-ip", strings.HasPrefix(n, "x-forwarded-"):
		return true
	}
	return false
}

// forward proxies r to p. It uses Rewrite, not Director: the hop-by-hop
// headers a client names in Connection are removed before Rewrite runs, so
// they cannot remove what Rewrite sets.
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, name, ref string, p *project,
	rawPath, query, bearer string, graphql bool) {
	upPath, err := url.PathUnescape(rawPath)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found")
		return
	}
	// The body is read on the upstream connection's writing goroutine: its
	// limit must not reach the server's writer from there (see the 413 below).
	b := &body{ReadCloser: http.MaxBytesReader(nil, r.Body, maxBody)}
	r.Body = b
	// The server sees b as the request's body and, after the handler, reads
	// up to 256 KiB of an unread one before it answers unless the original is
	// closed: a client waiting for 100-continue would never get the answer.
	defer b.ReadCloser.Close()
	sw := w // the server's writer
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	rp := &httputil.ReverseProxy{
		Transport: g.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			out.URL = &url.URL{Scheme: "http", Host: p.upstream.Host, Path: upPath, RawPath: rawPath, RawQuery: query}
			out.Host = p.upstream.Host
			for k := range out.Header {
				if stripped(k) {
					delete(out.Header, k)
				}
			}
			out.Header["Authorization"] = []string{"Bearer " + bearer}
			out.Header.Set("X-Forwarded-Host", name)
			out.Header.Set("X-Forwarded-Proto", "https")
			out.Header.Set("X-Forwarded-For", peer)
			out.Header.Set("X-Pg-Application-Name", "supapace-gateway")
			if graphql {
				out.Header.Set("Content-Profile", "graphql_public")
			}
		},
		// 1xx responses bypass ModifyResponse; informational filters them.
		ModifyResponse: func(resp *http.Response) error {
			filterResponse(resp.Header)
			sandbox(resp.Header)
			resp.Body = &trailerFilter{resp.Body, resp}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			// The upstream may give up on a body that is still arriving (its
			// own guard against slow senders): read the rest, within the
			// server's read timeout and the body cap, to learn whose fault it
			// is. A complete body is answered as the upstream's failure. Only
			// a body the transport began to send is read: an upstream never
			// reached has asked for nothing, and reading would send a client
			// that expects 100-continue its go-ahead.
			if b.started.Load() { // a finished or failed body returns at once
				_, derr := io.Copy(io.Discard, b)
				err = errors.Join(err, derr)
			}
			var tooLarge *http.MaxBytesError
			var ne net.Error
			switch {
			case errors.As(err, &tooLarge):
				// Tell the server, on the handler's goroutine, that the body went
				// over the limit: it then closes an HTTP/1.1 connection after the
				// answer, leaving the client time to read it.
				http.MaxBytesReader(sw, io.NopCloser(strings.NewReader("x")), 0).Read(make([]byte, 1))
				fail(w, http.StatusRequestEntityTooLarge, "body_too_large")
				return
			case b.failed.Load() || r.Context().Err() != nil:
				// The client's read timed out or it went away: nothing is
				// answered (a write now could break mid-record once the write
				// deadline, equal to the read one, has passed). The server
				// closes the HTTP/1.1 connection or resets the HTTP/2 stream.
				panic(http.ErrAbortHandler)
			case errors.As(err, &ne) && ne.Timeout():
				fail(w, http.StatusGatewayTimeout, "upstream_timeout")
			default:
				fail(w, http.StatusBadGateway, "upstream_unavailable")
			}
			log.Printf("gateway: %s: upstream: %v", ref, err)
		},
	}
	iw := &informational{ResponseWriter: w, drop: r.ProtoMajor == 2 || len(r.Header["Expect"]) > 0}
	// The proxy relays each 1xx from its own trace hook, which runs before this
	// one; an error here ends the upstream request and closes its connection.
	ctx := httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(int, textproto.MIMEHeader) error {
			if iw.n > maxInformational {
				return errTooManyInformational
			}
			return nil
		}})
	rp.ServeHTTP(iw, r.WithContext(ctx))
}

var errTooManyInformational = errors.New("too many 1xx responses")

// informational applies filterResponse to the 1xx responses the proxy relays
// and drops those past maxInformational; the request then ends in a 502.
// Over HTTP/2 it relays none (they still count): the server writes a 1xx
// frame from the handler's header map on another goroutine and may stop
// waiting for it (stream reset, connection closed) while the proxy changes
// the map. Nor does it relay any for a request that carries an Expect
// header: the server writes its own 100 Continue under a lock from the
// goroutine that first reads the body, and a relayed 1xx would be written
// beside it without that lock. The server sends its own 100 Continue.
type informational struct {
	http.ResponseWriter
	n    int
	drop bool
}

func (w *informational) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		filterResponse(w.Header())
		if w.n++; w.n > maxInformational || w.drop {
			return
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the server's writer.
func (w *informational) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// trailerFilter applies filterResponse to the response trailers, which the
// transport has filled in by the time the body reports io.EOF.
type trailerFilter struct {
	io.ReadCloser
	resp *http.Response
}

func (t *trailerFilter) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if err == io.EOF {
		filterResponse(t.resp.Trailer)
	}
	return n, err
}

// filterResponse removes from an upstream header or trailer what must not
// reach the client: the Server header (the upstream's product and version),
// every Set-Cookie with a Domain attribute (the upstream could scope it to the
// parent domain, and browsers would send it to every other project's host),
// the obsolete Set-Cookie2 and Clear-Site-Data (projects share the parent
// domain, so it could clear sibling hosts' storage). Host-only cookies pass.
func filterResponse(h http.Header) {
	delete(h, "Server")
	delete(h, "Set-Cookie2")
	delete(h, "Clear-Site-Data")
	if vs, ok := h["Set-Cookie"]; ok {
		h["Set-Cookie"] = slices.DeleteFunc(vs, hasDomain)
	}
}

// hasDomain reports whether a Set-Cookie value has a Domain attribute; the
// first pair is the cookie itself, whatever its name and value.
func hasDomain(cookie string) bool {
	_, attrs, _ := strings.Cut(cookie, ";")
	for _, a := range strings.Split(attrs, ";") {
		if name, _, _ := strings.Cut(a, "="); strings.EqualFold(strings.TrimSpace(name), "domain") {
			return true
		}
	}
	return false
}

// body records whether reading the client's body failed (a timeout or a
// broken connection), so that is not reported as an upstream fault, and
// whether the transport began reading it. The transport's Close is ignored,
// so the error handler can still read the rest; forward closes it on return.
type body struct {
	io.ReadCloser
	started, failed atomic.Bool
}

func (b *body) Read(p []byte) (int, error) {
	b.started.Store(true)
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		b.failed.Store(true)
	}
	return n, err
}

func (b *body) Close() error { return nil }

// sandbox sets the headers every final response carries, replacing any
// upstream value: no content sniffing, and a sandboxed origin, so a response
// rendered in a browser cannot script against sibling project hosts.
func sandbox(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox")
}
