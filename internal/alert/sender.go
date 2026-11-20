package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// Store is what the sender needs of *store.Store.
type Store interface {
	PendingAlerts(ctx context.Context, repeat time.Duration, limit int) ([]store.Alert, error)
	MarkAlertSent(ctx context.Context, a store.Alert) error
}

// The delivery rules; tests shorten the two durations.
var (
	deliveryTimeout = 10 * time.Second
	roundEvery      = 15 * time.Second
)

const (
	repeatEvery   = time.Hour // a row whose count moved is sent again at most this often
	perRound      = 64
	maxRespHeader = 16 << 10
)

// ErrNoDeadman: no dead-man address is declared; nothing was requested.
var ErrNoDeadman = errors.New("alert: no dead-man address declared")

// ErrUndeclared: no alert destination is declared; nothing was requested.
var ErrUndeclared = errors.New("alert: no alert destination declared")

// Sender delivers the store's pending alert rows and the dead-man pings.
type Sender struct {
	st   Store
	node string
	load func() (Declaration, bool, error)
	log  *slog.Logger

	mu               sync.Mutex
	lastOK, lastFail time.Time
	quiet            string // the last state logged by a round, so a lasting one is logged once
}

// NewSender returns a sender of node's alerts; load reads the declaration at
// every round and ping, so a new one takes effect without a restart.
func NewSender(st Store, node string, load func() (Declaration, bool, error)) *Sender {
	return &Sender{st: st, node: node, load: load, log: slog.Default()}
}

// Status returns the time of the last delivery that succeeded and of the
// last that failed (zero: none since the start).
func (s *Sender) Status() (lastOK, lastFail time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastOK, s.lastFail
}

// Run delivers pending rows at once and then every 15 s until ctx ends.
func (s *Sender) Run(ctx context.Context) {
	t := time.NewTicker(roundEvery)
	defer t.Stop()
	for {
		s.round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// round reads at most 64 pending rows and sends each, marking it after its
// delivery: a stop between the two sends it again, never loses it. The
// first failed delivery ends the round, so a destination that is down costs
// one attempt a round; the rest wait for the next. A row no document can
// carry (a code off the list, a subject of another form) is logged and
// delivered in a fixed form (unlisted), then marked as any other.
func (s *Sender) round(ctx context.Context) {
	d, ok, err := s.load()
	switch {
	case err != nil:
		s.note("load", "alert: the destination declaration does not load; alerts stay rows", "err", err.Error())
		return
	case !ok:
		s.note("undeclared", "alert: no destination declared; alerts stay rows")
		return
	}
	rows, err := s.st.PendingAlerts(ctx, repeatEvery, perRound)
	if err != nil {
		s.note("store", "alert: reading pending alerts", "err", err.Error())
		return
	}
	if len(rows) == 0 {
		s.note("", "")
	}
	for _, a := range rows {
		doc := Document{Node: s.node, Subject: a.Subject, Code: a.Code, Severity: a.Severity, Count: a.Count,
			FirstAt: a.FirstAt, LastAt: a.LastAt, Figures: a.Figures}
		if err := checkDoc(doc); err != nil {
			s.log.Error("alert: a row no document can carry is sent as unlisted-code", "subject", bounded(a.Subject),
				"code", bounded(a.Code), "err", err.Error())
			doc = unlisted(s.node, a)
		}
		if err := s.Send(ctx, d, doc); err != nil {
			s.note("send", "alert: delivery failed; retried every round", "subject", a.Subject, "code", a.Code, "err", err.Error())
			return
		} else {
			s.note("", "")
		}
		if err := s.st.MarkAlertSent(ctx, a); err != nil {
			s.log.Error("alert: marking a delivered alert", "subject", a.Subject, "code", a.Code, "err", err.Error())
			return
		}
	}
}

// note logs msg when the round's state changes to what; "" resets it.
func (s *Sender) note(what, msg string, args ...any) {
	s.mu.Lock()
	same := s.quiet == what
	s.quiet = what
	s.mu.Unlock()
	if !same && what != "" {
		s.log.Warn(msg, args...)
	}
}

// bounded quotes at most 64 bytes of a value no form was checked on.
func bounded(v string) string { return fmt.Sprintf("%.64q", v) }

// Send delivers one document: a POST of its JSON, 10 s, no redirect
// followed, the answer's body unread; any 2xx is delivered. The error names
// the destination by scheme and host and the answer by its status code
// alone.
func (s *Sender) Send(ctx context.Context, d Declaration, doc Document) error {
	err := s.send(ctx, d, doc)
	s.mu.Lock()
	if err == nil {
		s.lastOK = time.Now()
	} else {
		s.lastFail = time.Now()
	}
	s.mu.Unlock()
	return err
}

func (s *Sender) send(ctx context.Context, d Declaration, doc Document) error {
	if d.URL == "" {
		return ErrUndeclared
	}
	if err := check(d); err != nil {
		return err
	}
	if err := checkDoc(doc); err != nil {
		return err
	}
	if doc.Figures == nil {
		doc.Figures = map[string]int64{}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return request(ctx, d, http.MethodPost, d.URL, body)
}

// Ping requests the dead-man address of stanza (GET, the template's
// {stanza} replaced), under the same rules as Send. It is independent of
// the alert destination: either may fail while the other works, and a
// failed ping is only returned — the missing ping is the dead-man's signal.
func (s *Sender) Ping(ctx context.Context, stanza string) error {
	if !stanzaRE.MatchString(stanza) {
		return errors.New("alert: the stanza is not [a-z0-9][a-z0-9-]{0,62}")
	}
	d, ok, err := s.load()
	if err != nil {
		return err
	}
	if !ok || d.DeadmanURL == "" {
		return ErrNoDeadman
	}
	if err := check(d); err != nil {
		return err
	}
	return request(ctx, d, http.MethodGet, strings.ReplaceAll(d.DeadmanURL, stanzaVar, stanza), nil)
}

// request makes one bounded request: no proxy, no redirect, no connection
// kept, at most 16 KiB of response header, the body closed unread.
func request(ctx context.Context, d Declaration, method, target string, body []byte) error {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if d.CAPEM != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(d.CAPEM))
		tc.RootCAs = pool
	}
	c := &http.Client{
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: tc, DisableKeepAlives: true,
			MaxResponseHeaderBytes: maxRespHeader, DialContext: (&net.Dialer{}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       deliveryTimeout,
	}
	defer c.CloseIdleConnections()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return fmt.Errorf("alert: %s: the request could not be made", Redact(target))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "supapaced")
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("alert: %s: %s", Redact(target), why(ctx, err))
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("alert: %s: the destination answered HTTP %d", Redact(target), resp.StatusCode)
	}
	return nil
}

// why names a failed request by a fixed text: the errors of the HTTP
// client quote the request's address and, for a malformed answer, what the
// destination sent, and a certificate's names are the destination's too.
func why(ctx context.Context, err error) string {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var rec tls.RecordHeaderError
	var ne net.Error
	switch {
	case ctx.Err() != nil:
		return "the request was cancelled"
	case errors.As(err, &ne) && ne.Timeout():
		return fmt.Sprintf("no answer within %v", deliveryTimeout)
	case errors.As(err, &dns):
		return "the host name does not resolve"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "the connection was refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "the destination is unreachable"
	case errors.As(err, &cert):
		return "the destination's certificate is not trusted"
	case errors.As(err, &rec):
		return "the destination does not speak TLS"
	}
	return "the destination's answer is not HTTP/1.1, the only version this client speaks"
}

// unlisted is the fixed form of a row no document can carry: code
// unlisted-code, the row's subject when it is one else node, its severity
// when it is one else page, its count and times, no figures. Nothing of the
// row's code or figures is sent.
func unlisted(node string, a store.Alert) Document {
	d := Document{Node: node, Subject: "node", Code: "unlisted-code", Severity: "page", Count: a.Count, FirstAt: a.FirstAt, LastAt: a.LastAt}
	if subjectRE.MatchString(a.Subject) {
		d.Subject = a.Subject
	}
	if a.Severity == "warn" || a.Severity == "page" {
		d.Severity = a.Severity
	}
	return d
}
