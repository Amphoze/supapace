package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashtok"
)

const (
	dashIdleConns    = 32 // idle connections to Studio kept
	assertionSeconds = 30 // lifetime of the assertion the gateway signs
	maxLogPath       = 256
	maxLogMethod     = 16
)

func init() { dashForward = forwardDash }

// dashTransport carries dashboard requests to Studio; the project API's
// transport is never used for them.
var dashTransport = newDashTransport()

// newDashTransport is the transport to Studio: the gateway's dialer and
// socket buffers, the header wait of the bounds table, as many connections
// as dashboard requests may be in flight, a bounded response header, and no
// transparent compression (it neither asks for an encoding nor undoes one).
// Proxy is nil on purpose, as for the project API.
func newDashTransport() *http.Transport {
	l := dashcfg.Limits
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				fixBuffers(c)
			}
			return c, err
		},
		ResponseHeaderTimeout: time.Duration(l.StudioHeaderMS) * time.Millisecond,
		MaxConnsPerHost:       l.StudioConns,
		MaxIdleConnsPerHost:   dashIdleConns,
		// Below the upstream's own keep-alive, so a request is never written onto
		// a connection the upstream is closing.
		IdleConnTimeout:        4 * time.Second,
		MaxResponseHeaderBytes: int64(l.HeaderBytes),
		DisableCompression:     true,
	}
}

// dashMethod reports whether the forwarder carries method to Studio.
func dashMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}

// dashStripped reports whether a request header is removed before it goes to
// Studio: credentials and the gateway's own, forwarding headers (set again
// below), headers by which a framework lets a request restate its method or
// path (the rules judged the ones the gateway saw), and on an API path
// Accept-Encoding. A host field an HTTP/2 client sent as an ordinary header
// is never written: the transport writes Host from the request's Host alone.
func dashStripped(name string, api bool) bool {
	switch n := strings.ToLower(name); {
	case n == "authorization", n == "apikey", n == "x-connection-encrypted", n == "forwarded", n == "x-real-ip",
		n == "x-supapace-assertion", strings.HasPrefix(n, "x-forwarded-"),
		n == "x-http-method-override", n == "x-http-method", n == "x-method-override", n == "x-original-url", n == "x-rewrite-url",
		api && n == "accept-encoding":
		return true
	}
	return false
}

// stripPlatformCookies removes every cookie whose name begins __Host-sp- (in
// any letter case) from the Cookie fields of h; the others go on, in their
// order, in one field.
func stripPlatformCookies(h http.Header) {
	var keep []string
	for k, vs := range h {
		if !strings.EqualFold(k, "Cookie") {
			continue
		}
		delete(h, k)
		for _, v := range vs {
			for _, c := range strings.Split(v, ";") {
				if c = strings.TrimSpace(c); c != "" && !platformCookie(c) {
					keep = append(keep, c)
				}
			}
		}
	}
	if len(keep) > 0 {
		h["Cookie"] = []string{strings.Join(keep, "; ")}
	}
}

// forwardDash is rule 11: it forwards an admitted request to Studio, holding
// the request's slots, and writes the access line.
func forwardDash(w http.ResponseWriter, r *http.Request, dr *dashRequest) {
	start := time.Now()
	aw := &dashWriter{ResponseWriter: w, drop: r.ProtoMajor == 2 || len(r.Header["Expect"]) > 0}
	defer func() { accessLine(r, dr, aw.status, time.Since(start).Milliseconds()) }()
	// Past the server's own timeouts, which stay as built for the project
	// API: the header wait and the transfer. Set here and below on the
	// handler's goroutine, never from a hook of the transport.
	l := dashcfg.Limits
	rc := http.NewResponseController(w)
	end := start.Add(time.Duration(l.StudioHeaderMS+l.TransferMS) * time.Millisecond)
	rc.SetWriteDeadline(end)
	rc.SetReadDeadline(end)
	if !dashMethod(r.Method) {
		writeDash(aw, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	s, now := dr.Session, start.Unix()
	assertion, err := dashtok.SignAssertion(dr.Dash.priv, dashtok.Assertion{Node: dr.Table.Node, Iss: s.Iss, Sub: s.Sub,
		Name: s.Name, Ref: dr.Ref, Role: dr.Role, Purpose: dr.Purpose, Iat: now, Exp: now + assertionSeconds})
	if err != nil {
		log.Printf("gateway: dashboard %s: assertion: %v", dr.Ref, err)
		writeDash(aw, http.StatusServiceUnavailable, "unavailable")
		return
	}
	file := dr.Table
	studio := strings.TrimPrefix(file.Studio, "http://") // the file's reader allows only a plain-HTTP IPv4 address and port
	host := dr.Ref + "." + dr.Dash.domain                // the host the request was classified by
	target, query, hasQuery := strings.Cut(r.RequestURI, "?")
	api := apiPath(dr.Lower)
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	// The body is under the cap's reader, which holds no writer: it is read on
	// the upstream connection's writing goroutine (see the 413 below).
	b := &body{ReadCloser: r.Body}
	r.Body = b
	// The server reads up to 256 KiB of an unread body after the handler
	// unless the original is closed (see forward).
	defer b.ReadCloser.Close()
	rp := &httputil.ReverseProxy{
		Transport: dashTransport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			// The target as sent: rule 0 accepted these bytes, and Opaque keeps
			// the transport from writing the path in another form.
			out.URL = &url.URL{Scheme: "http", Host: studio, Opaque: target, RawQuery: query, ForceQuery: hasQuery && query == ""}
			out.Host = host
			for k := range out.Header {
				if dashStripped(k, api) {
					delete(out.Header, k)
				}
			}
			stripPlatformCookies(out.Header)
			out.Header.Set("X-Forwarded-Host", host)
			out.Header.Set("X-Forwarded-Proto", "https")
			out.Header.Set("X-Forwarded-For", peer)
			out.Header.Set("X-Supapace-Assertion", assertion)
		},
		// Runs on the handler's goroutine once Studio's header is in. 1xx
		// responses bypass it; dashWriter filters them.
		ModifyResponse: func(resp *http.Response) error {
			// Row 1 from now. The read deadline moves with it: on HTTP/1.1 it
			// also ends the request when it passes, body read or not.
			row1 := time.Now().Add(time.Duration(l.TransferMS) * time.Millisecond)
			rc.SetWriteDeadline(row1)
			rc.SetReadDeadline(row1)
			filterDashResponse(resp.Header, resp.StatusCode, api)
			filterDashTrailer(resp.Trailer) // before the proxy announces them
			resp.Body = &dashTrailers{resp.Body, resp}
			return nil
		},
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
			// As forward: read the rest of a body Studio stopped reading, to
			// learn whose fault it is.
			if b.started.Load() {
				_, derr := io.Copy(io.Discard, b)
				err = errors.Join(err, derr)
			}
			var tooLarge *http.MaxBytesError
			var ne net.Error
			switch {
			case errors.As(err, &tooLarge):
				// Tell the server, on this goroutine, that the body went over the
				// cap: it closes an HTTP/1.1 connection after the answer.
				http.MaxBytesReader(w, io.NopCloser(strings.NewReader("x")), 0).Read(make([]byte, 1))
				writeDash(aw, http.StatusRequestEntityTooLarge, "body_too_large")
				return
			case b.failed.Load() || r.Context().Err() != nil:
				panic(http.ErrAbortHandler) // the client went away or its body failed
			case errors.As(err, &ne) && ne.Timeout():
				writeDash(aw, http.StatusGatewayTimeout, "upstream_timeout")
			default:
				writeDash(aw, http.StatusBadGateway, "upstream_unavailable")
			}
			log.Printf("gateway: dashboard %s: upstream: %v", dr.Ref, err)
		},
	}
	// The proxy relays each 1xx from its own trace hook, which runs before
	// this one; an error here ends the upstream request and its connection.
	// This hook reads the count only.
	ctx := httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(int, textproto.MIMEHeader) error {
			if aw.n > maxInformational {
				return errTooManyInformational
			}
			return nil
		}})
	rp.ServeHTTP(aw, r.WithContext(ctx))
}

// dashWriter is the forwarder's writer. It filters the 1xx responses the
// proxy relays, as the final header is filtered, counts them, and relays
// none past maxInformational, none over HTTP/2 and none to a client that
// sent Expect (the reasons of informational). It records the final status
// for the access line.
type dashWriter struct {
	http.ResponseWriter
	n      int // upstream 1xx responses; used on the upstream connection's reading goroutine only
	drop   bool
	status int // the final status; used on the handler's goroutine only
}

func (w *dashWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		filterDash(w.Header())
		dashHeaders(w.Header())
		if w.n++; w.n > maxInformational || w.drop {
			return
		}
	} else if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *dashWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the server's writer.
func (w *dashWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// accessLine writes the dashboard's access line for a forwarded request or a
// refusal of rules 5 to 10: who, which project, the method, the path without
// its query (at most maxLogPath bytes, no control character), the status and
// the milliseconds spent forwarding (0 for a refusal). Never a cookie, a
// token, a query or a body.
func accessLine(r *http.Request, dr *dashRequest, status int, ms int64) {
	path, _, _ := strings.Cut(r.RequestURI, "?")
	b, _ := json.Marshal(struct {
		T      string `json:"t"`
		Ref    string `json:"ref"`
		Iss    string `json:"iss"`
		Sub    string `json:"sub"`
		Role   string `json:"role"`
		Method string `json:"method"`
		Path   string `json:"path"`
		Status int    `json:"status"`
		MS     int64  `json:"ms"`
	}{time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), dr.Ref, dr.Session.Iss, dr.Session.Sub, dr.Role,
		logField(r.Method, maxLogMethod), logField(path, maxLogPath), status, ms})
	log.Print(string(b))
}

// logField is s without control characters, cut to max bytes.
func logField(s string, max int) string {
	s = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, s)
	return s[:min(len(s), max)]
}
