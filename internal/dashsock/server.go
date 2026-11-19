package dashsock

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
)

// Members answers the role a principal holds in a project's own table. Any
// error but the end of the request's context is read as "no such member".
type Members interface {
	MemberRole(ctx context.Context, ref, issuer, subject string) (string, error)
}

// Facts is what the control plane knows of a project placed on this node.
type Facts struct {
	Name, State string
	Generation  int64
	SubnetIndex int
}

// Projects reads a project's facts and secrets.
type Projects interface {
	Facts(ctx context.Context, ref string) (Facts, error) // ErrNotHere: unknown, not placed on this node, or not live
	Passwords(ctx context.Context, ref string) (rw, ro string, err error)
	Keys(ctx context.Context, ref string) (anon, service string, public []jwtx.Key, err error)
}

// ErrNotHere is what Projects.Facts returns for a project that is unknown, not
// placed on this node, or not live.
var ErrNotHere = errors.New("dashsock: project not placed on this node")

const (
	socketFile     = "dash.sock"
	maxConns       = 64
	maxHeaderBytes = 8 << 10
	headerTimeout  = 2 * time.Second
	requestTimeout = 800 * time.Millisecond
	// The per-ref rate, 20 a second with a burst of 40, as a credit of time:
	// each request costs perRequest and the credit never exceeds burstCredit.
	perRequest  = time.Second / 20
	burstCredit = 40 * perRequest
	// Buckets are pruned of full ones above this many refs; refs come only
	// from verified assertions, so the map stays near the node's projects.
	maxBuckets = 4096
)

var b64 = base64.RawURLEncoding

// chown is os.Chown; a test that does not run as root replaces it.
var chown = os.Chown

// Server answers the dashboard socket's two requests. Log, when set before
// Serve, receives the resolutions and key releases; nil logs to slog.Default.
type Server struct {
	Log *slog.Logger

	pub      ed25519.PublicKey
	node     string
	base     string
	addrs    dashcfg.Addrs
	members  Members
	projects Projects
	now      func() time.Time
	peerUID  func(net.Conn) (uint32, error)
	maxConns int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	credit time.Duration
	at     time.Time
}

// NewServer returns a server for the node's assertion key and id. a must be
// dashcfg.For's: a resolve that would carry a connection string rendered from
// a zero address is answered unavailable.
func NewServer(pub ed25519.PublicKey, node, baseDomain string, a dashcfg.Addrs, m Members, p Projects) *Server {
	return &Server{pub: pub, node: node, base: baseDomain, addrs: a, members: m, projects: p,
		now: time.Now, peerUID: socketPeerUID, maxConns: maxConns, buckets: map[string]*bucket{}}
}

// Listen creates SocketDir (root, group StudioUID, 0750), removes a stale socket
// at the socket's path (anything else there is an error, left alone), and
// listens there (root, group StudioUID, 0660).
func Listen(p dashcfg.Paths) (net.Listener, error) {
	dir := p.SocketDir()
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, fmt.Errorf("dashsock: %w", err)
	}
	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("dashsock: %w", err)
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("dashsock: %s is not a directory", dir)
	}
	if err := chown(dir, 0, dashcfg.StudioUID); err != nil {
		return nil, fmt.Errorf("dashsock: %w", err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return nil, fmt.Errorf("dashsock: %w", err)
	}
	sock := filepath.Join(dir, socketFile)
	if fi, err := os.Lstat(sock); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("dashsock: %s exists and is not a socket", sock)
		}
		if err := os.Remove(sock); err != nil {
			return nil, fmt.Errorf("dashsock: stale socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("dashsock: %w", err)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("dashsock: %w", err)
	}
	if err := chown(sock, 0, dashcfg.StudioUID); err != nil {
		l.Close()
		return nil, fmt.Errorf("dashsock: %w", err)
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		l.Close()
		return nil, fmt.Errorf("dashsock: %w", err)
	}
	return l, nil
}

type peerKey struct{}

type peer struct {
	uid uint32
	ok  bool
}

// Serve answers on l until it is closed: at most 64 connections, the request
// header within 2 s and 8 KiB, the whole request read and its answer written
// within 2 s each, an idle connection closed after 2 s.
func (s *Server) Serve(l net.Listener) error {
	hs := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       headerTimeout,
		// A body that never arrives, or an answer never read, frees its slot
		// within these; the 800 ms handler budget fits the write bound.
		ReadTimeout:  headerTimeout,
		WriteTimeout: headerTimeout,
		// The server reads up to MaxHeaderBytes + 4096 bytes of request line
		// and header; this makes that 8 KiB.
		MaxHeaderBytes: maxHeaderBytes - 4096,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if cc, ok := c.(*capConn); ok {
				c = cc.Conn
			}
			uid, err := s.peerUID(c)
			return context.WithValue(ctx, peerKey{}, peer{uid, err == nil})
		},
	}
	return hs.Serve(&capListener{Listener: l, sem: make(chan struct{}, s.maxConns), done: make(chan struct{})})
}

// socketPeerUID reads the uid of the process at the other end of a Unix socket.
func socketPeerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("dashsock: not a Unix socket")
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
	return u.Uid, nil
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func refuse(w http.ResponseWriter, status int, code string) {
	answer(w, status, struct {
		Code string `json:"code"`
	}{code})
}

func answer(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusServiceUnavailable, []byte(`{"code":"unavailable"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p, _ := r.Context().Value(peerKey{}).(peer); !p.ok || p.uid != dashcfg.StudioUID {
		refuse(w, http.StatusForbidden, "peer")
		return
	}
	if r.RequestURI != "/v1/resolve" && r.RequestURI != "/v1/keys" {
		refuse(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if r.ContentLength != 0 {
		refuse(w, http.StatusBadRequest, "bad_request")
		return
	}
	toks := r.Header.Values(HeaderAssertion)
	if len(toks) != 1 {
		refuse(w, http.StatusUnauthorized, "bad_assertion")
		return
	}
	a, err := dashtok.VerifyAssertion(s.pub, toks[0], s.node, s.now())
	if err != nil {
		refuse(w, http.StatusUnauthorized, "bad_assertion")
		return
	}
	if !s.allow(a.Ref) {
		refuse(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	f, err := s.projects.Facts(ctx, a.Ref)
	if errors.Is(err, ErrNotHere) {
		refuse(w, http.StatusNotFound, "not_here")
		return
	}
	if err != nil {
		s.unavailable(w, a, "facts")
		return
	}
	switch f.State {
	case "active", "restarting", "restoring":
	default:
		refuse(w, http.StatusNotFound, "not_here")
		return
	}
	role, err := s.members.MemberRole(ctx, a.Ref, a.Iss, a.Sub)
	if err != nil && ctx.Err() != nil {
		s.unavailable(w, a, "member")
		return
	}
	// Any other error is no member: a refusal, never an outage Studio would
	// answer from its cache.
	if err != nil || role != a.Role {
		refuse(w, http.StatusForbidden, "not_a_member")
		return
	}
	if r.RequestURI == "/v1/resolve" {
		s.resolve(ctx, w, a, f)
	} else {
		s.keys(ctx, w, a)
	}
}

// unavailable answers 503 and logs the step; never the error, whose text may
// come from a secret's source.
func (s *Server) unavailable(w http.ResponseWriter, a dashtok.Assertion, step string) {
	s.log().Warn("dashboard socket: unavailable", "ref", a.Ref, "step", step)
	refuse(w, http.StatusServiceUnavailable, "unavailable")
}

func (s *Server) resolve(ctx context.Context, w http.ResponseWriter, a dashtok.Assertion, f Facts) {
	rw, ro, err := s.projects.Passwords(ctx, a.Ref)
	if err != nil {
		s.unavailable(w, a, "passwords")
		return
	}
	ver, err := nodecfg.LockedPostgresVersion()
	if err != nil {
		s.unavailable(w, a, "version")
		return
	}
	ans := ResolveAnswer{
		Ref: a.Ref, Name: f.Name, State: f.State, DBVersion: ver, PgMeta: dashcfg.PgMetaIndex(f.SubnetIndex),
		APIURL: "https://" + a.Ref + "." + s.base,
		DataAPI: DataAPI{Schemas: strings.Split(pgconf.PostgRESTSchemas, ", "),
			ExtraSearchPath: strings.Split(pgconf.PostgRESTExtraSearchPath, ", ")},
		Generation: f.Generation, At: s.now().UTC().Format(time.RFC3339),
	}
	var ok bool
	if RoleClass(a.Role) == "rw" {
		if ans.DSNRW, ok = s.dsn(dashcfg.LoginRW, rw, f.SubnetIndex); !ok {
			s.unavailable(w, a, "dsn_rw")
			return
		}
	}
	if ro != "" {
		if ans.DSNRO, ok = s.dsn(dashcfg.LoginRO, ro, f.SubnetIndex); !ok {
			s.unavailable(w, a, "dsn_ro")
			return
		}
	}
	s.log().Info("dashboard resolve", "ref", a.Ref, "iss", a.Iss, "sub", a.Sub, "role", a.Role)
	answer(w, http.StatusOK, ans)
}

// dsn renders a connection string and holds it to the form Studio accepts.
func (s *Server) dsn(login, password string, subnet int) (string, bool) {
	d := dashcfg.DSN(s.addrs, login, password, subnet)
	_, _, err := dashcfg.ParseDSN(s.addrs, d)
	return d, err == nil
}

func (s *Server) keys(ctx context.Context, w http.ResponseWriter, a dashtok.Assertion) {
	anon, service, pub, err := s.projects.Keys(ctx, a.Ref)
	if err != nil {
		s.unavailable(w, a, "keys")
		return
	}
	ans := KeysAnswer{AnonKey: anon, SigningKeys: make([]SigningKey, 0, len(pub))}
	for _, k := range pub {
		if k.Pub == nil || k.Pub.N == nil {
			s.unavailable(w, a, "keys")
			return
		}
		ans.SigningKeys = append(ans.SigningKeys, SigningKey{Kid: k.KID, Class: string(k.Class), Alg: "RS256",
			Kty: "RSA", N: b64.EncodeToString(k.Pub.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(k.Pub.E)).Bytes())})
	}
	if a.Role == dashcfg.RoleOwner && a.Purpose == "reveal" {
		ans.ServiceRoleKey = service
		s.log().Info("dashboard service key released", "ref", a.Ref, "iss", a.Iss, "sub", a.Sub)
	}
	answer(w, http.StatusOK, ans)
}

// allow takes one request from ref's bucket.
func (s *Server) allow(ref string) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[ref]
	if b == nil {
		if len(s.buckets) >= maxBuckets {
			for k, o := range s.buckets {
				if o.credit+now.Sub(o.at) >= burstCredit {
					delete(s.buckets, k)
				}
			}
		}
		b = &bucket{credit: burstCredit, at: now}
		s.buckets[ref] = b
	}
	if d := now.Sub(b.at); d > 0 {
		b.credit, b.at = min(burstCredit, b.credit+d), now
	}
	if b.credit < perRequest {
		return false
	}
	b.credit -= perRequest
	return true
}

// capListener holds a unit of its semaphore for every open connection.
type capListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func (l *capListener) Accept() (net.Conn, error) {
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
	return &capConn{Conn: c, release: sync.OnceFunc(func() { <-l.sem })}, nil
}

func (l *capListener) Close() error {
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
