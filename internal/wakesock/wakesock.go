// Package wakesock is the wake socket: the gateway asks the daemon to wake a
// sleeping project and tells it which projects are idle. HTTP/1.1 over one
// Unix socket that the daemon listens on and the gateway's uid alone may
// open. The gateway faces the internet, so the listener bounds every request
// in size and time and trusts nothing in it but a ref of the fixed form.
//
//	POST /v1/wake/<ref>   no body   204 woken | 409 busy | 504 failed or not in time
//	POST /v1/idle         {"refs":[<ref>,…]}, at most 1,024 refs   204
//
// Every other request, and any not of HTTP/1.1, is refused (400, 404, 405,
// 505) without reaching the handler. Bodies are at most 64 KiB of strict JSON.
package wakesock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const SocketName = "wake.sock"

// MaxIdleRefs is the most refs one idle report carries; the listener refuses more.
const MaxIdleRefs = 1024

const (
	WakeBound = 10 * time.Second // the gateway's hold and the daemon's bound for one wake
	Backoff   = 60 * time.Second // after a failed wake: none is asked for that project
)

const (
	maxBody    = 64 << 10 // request and answer bodies
	maxHeader  = 8 << 10  // request line and header; answer header
	maxConns   = 16       // open connections to the listener
	peerWindow = 2 * time.Second
	wakePath   = "/v1/wake/"
	idlePath   = "/v1/idle"
)

var (
	ErrBusy        = errors.New("wakesock: an operation holds the project")
	ErrFailed      = errors.New("wakesock: the wake failed")
	ErrUnavailable = errors.New("wakesock: no answer from the wake socket")
)

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// Handler is the daemon's half.
type Handler interface {
	Wake(ctx context.Context, ref string) error // nil when the project's route is active again; it must return within WakeBound
	Idle(ctx context.Context, refs []string)
}

// Client is the gateway's half.
type Client struct {
	path string
	hc   *http.Client
}

// NewClient returns a client of the socket at path. Each call opens one
// connection and closes it at its end; none is kept idle.
func NewClient(path string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxHeader,
	}
	return &Client{path: path, hc: &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Wake asks for ref to be woken: nil once its route is active, ErrBusy while
// an operation holds it, ErrFailed when the daemon gave up, ErrUnavailable
// when there is no socket or no answer (joined with the context's error when
// the call ran out of time). It returns within WakeBound whatever ctx allows.
func (c *Client) Wake(ctx context.Context, ref string) error {
	if !refRE.MatchString(ref) {
		return ErrUnavailable
	}
	switch code, err := c.post(ctx, wakePath+ref, nil); {
	case err != nil:
		return err
	case code == http.StatusNoContent:
		return nil
	case code == http.StatusConflict:
		return ErrBusy
	case code == http.StatusGatewayTimeout:
		return ErrFailed
	default:
		return ErrUnavailable
	}
}

// Idle reports refs as idle; at most 1,024, each of the ref form.
func (c *Client) Idle(ctx context.Context, refs []string) error {
	if len(refs) > MaxIdleRefs {
		return fmt.Errorf("wakesock: %d refs, at most %d", len(refs), MaxIdleRefs)
	}
	b, err := json.Marshal(struct {
		Refs []string `json:"refs"`
	}{refs})
	if err != nil {
		return err
	}
	if code, err := c.post(ctx, idlePath, b); err != nil {
		return err
	} else if code != http.StatusNoContent {
		return ErrUnavailable
	}
	return nil
}

// post sends one request and reads at most maxBody of the answer. Without a
// socket at the path nothing is dialled.
func (c *Client) post(ctx context.Context, target string, body []byte) (int, error) {
	if fi, err := os.Stat(c.path); err != nil || fi.Mode().Type() != fs.ModeSocket {
		return 0, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, WakeBound)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://wake"+target, bytes.NewReader(body))
	if err != nil {
		return 0, ErrUnavailable
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, errors.Join(ErrUnavailable, ctx.Err())
		}
		return 0, ErrUnavailable
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	resp.Body.Close()
	return resp.StatusCode, nil
}

// chown sets the socket's owner; a test that does not run as root cannot.
func chown(path string, gid int) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Chown(path, 0, gid)
}

// Serve listens at path (a stale socket there is replaced; anything else is an
// error, left alone), sets it root:<peerUID> 0660 and answers h until ctx
// ends; it then closes the listener and returns nil. A connection whose peer
// is not of peerUID is closed unanswered. At most 16 connections are open; a
// request header must arrive within 2 s and 8 KiB, a body within 2 s; each
// handler call gets a context that ends at WakeBound and is answered then,
// whether or not it has returned.
func Serve(ctx context.Context, path string, peerUID int, h Handler) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return fmt.Errorf("wakesock: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("wakesock: stale socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("wakesock: %w", err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("wakesock: %w", err)
	}
	if err := chown(path, peerUID); err == nil {
		err = os.Chmod(path, 0o660)
	}
	if err != nil {
		l.Close()
		return fmt.Errorf("wakesock: %w", err)
	}
	hs := &http.Server{
		Handler:           server{h},
		ReadHeaderTimeout: peerWindow,
		ReadTimeout:       peerWindow,
		WriteTimeout:      WakeBound + peerWindow,
		IdleTimeout:       peerWindow,
		MaxHeaderBytes:    maxHeader - 4096, // the server reads 4,096 bytes more
	}
	stop := context.AfterFunc(ctx, func() { hs.Close() })
	defer stop()
	err = hs.Serve(&peerListener{Listener: l, uid: peerUID, sem: make(chan struct{}, maxConns), done: make(chan struct{})})
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type server struct{ h Handler }

func (s server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ref, isWake := strings.CutPrefix(r.RequestURI, wakePath)
	switch {
	case r.ProtoMajor != 1 || r.ProtoMinor != 1:
		answer(w, http.StatusHTTPVersionNotSupported, "http_version_not_supported")
		return
	case isWake && !refRE.MatchString(ref), !isWake && r.RequestURI != idlePath:
		answer(w, http.StatusNotFound, "not_found")
		return
	case r.Method != http.MethodPost:
		answer(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if isWake {
		if r.ContentLength != 0 {
			answer(w, http.StatusBadRequest, "bad_request")
			return
		}
		switch err := bounded(r.Context(), func(ctx context.Context) error { return s.h.Wake(ctx, ref) }); {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, ErrBusy):
			answer(w, http.StatusConflict, "busy")
		default:
			answer(w, http.StatusGatewayTimeout, "failed")
		}
		return
	}
	var body struct {
		Refs []string `json:"refs"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || len(body.Refs) > MaxIdleRefs {
		answer(w, http.StatusBadRequest, "bad_request")
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		answer(w, http.StatusBadRequest, "bad_request")
		return
	}
	for _, ref := range body.Refs {
		if !refRE.MatchString(ref) {
			answer(w, http.StatusBadRequest, "bad_request")
			return
		}
	}
	if err := bounded(r.Context(), func(ctx context.Context) error { s.h.Idle(ctx, body.Refs); return nil }); err != nil {
		answer(w, http.StatusGatewayTimeout, "failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bounded runs f with a context that ends at WakeBound and returns its
// result, or the context's error once that has ended: a handler that does
// not return holds its own goroutine, never the answer.
func bounded(parent context.Context, f func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, WakeBound)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f(ctx) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func answer(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":%q}`, code)
}

// peerListener caps open connections and closes, unanswered, every one whose
// peer is not of uid.
type peerListener struct {
	net.Listener
	uid  int
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		select {
		case l.sem <- struct{}{}:
		case <-l.done:
			return nil, net.ErrClosed
		}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			return nil, err
		}
		if uid, err := peerUID(c); err != nil || uid != l.uid {
			c.Close()
			<-l.sem
			continue
		}
		return &capConn{Conn: c, release: sync.OnceFunc(func() { <-l.sem })}, nil
	}
}

func (l *peerListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type capConn struct {
	net.Conn
	release func()
}

func (c *capConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

// peerUID reads the uid of the process at the other end of a Unix socket.
func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("wakesock: not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var u *syscall.Ucred
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		u, gerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if gerr != nil {
		return 0, gerr
	}
	return int(u.Uid), nil
}
