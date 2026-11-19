// Package pooler is the client of the connection pooler's admin API: tenant
// registration, update, terminate, delete and the clearing of network bans,
// each over one connection the caller's dial makes (from inside the pooler's
// own network namespace).
//
// An answer is hostile input: at most 64 KiB of it is read, and only the
// status is used. The one body read is the ban list, which carries addresses
// only. The pooler's answers to tenant calls hold the manager's password in
// clear; none of them is parsed, kept or logged, and no error carries any
// part of an answer, the token or the API secret.
package pooler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"time"

	"github.com/Amphoze/supapace/internal/poolcfg"
)

// maxAnswer bounds what is read of an answer, status line and headers included.
const maxAnswer = 64 << 10

// Bounds of a whole call, dial included. Registration is synchronous (the
// pooler logs in to the cluster); terminate waits for the pooler's own
// fan-out, which it bounds at 60 s.
const (
	healthBound = 5 * time.Second
	putBound    = 30 * time.Second
	stopBound   = 75 * time.Second
	bansBound   = 30 * time.Second
)

var (
	ErrRefused     = errors.New("pooler: the call was refused")       // a 4xx: the status alone is in the message
	ErrUnavailable = errors.New("pooler: no answer within the bound") // dial, deadline, 5xx
	// ErrTooLarge: the ban list is longer than the read bound (about 1,000
	// entries); nothing is cleared. Name the addresses instead.
	ErrTooLarge = errors.New("pooler: the ban list is larger than the bound")
)

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// Client calls the pooler's admin API.
type Client struct {
	dial   func(context.Context) (net.Conn, error)
	secret []byte
}

// New returns a client that opens each call's connection with dial and signs
// its token with apiSecret. apiSecret is kept, not copied: the caller must
// not change it while the client is in use.
func New(dial func(context.Context) (net.Conn, error), apiSecret []byte) *Client {
	return &Client{dial: dial, secret: apiSecret}
}

// token is an HS256 JWT over secret whose only claim is exp, 60 s after now.
func token(secret []byte, now time.Time) string {
	enc := base64.RawURLEncoding
	s := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc.EncodeToString(fmt.Appendf(nil, `{"exp":%d}`, now.Unix()+60))
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(s))
	return s + "." + enc.EncodeToString(m.Sum(nil))
}

// Health asks the pooler's health endpoint.
func (c *Client) Health(ctx context.Context) error {
	_, err := c.call(ctx, healthBound, http.MethodGet, "/api/health", nil, false)
	return err
}

// PutTenant registers or updates the tenant ref.
func (c *Client) PutTenant(ctx context.Context, ref string, t poolcfg.Tenant) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	body, err := t.Body()
	if err != nil {
		return err
	}
	_, err = c.call(ctx, putBound, http.MethodPut, "/api/tenants/"+ref, body, false)
	return err
}

// Terminate stops the tenant's pools and cuts its sessions; nil when there
// is no tenant.
func (c *Client) Terminate(ctx context.Context, ref string) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	_, err := c.call(ctx, stopBound, http.MethodGet, "/api/tenants/"+ref+"/terminate", nil, false)
	return absentIsNil(err)
}

// Delete terminates the tenant, then deletes it; nil when there is no
// tenant. Two requests, each bounded at 75 s: the terminate, then the
// DELETE. A failed terminate sends no DELETE: a delete alone leaves the
// tenant's pools and sessions running.
func (c *Client) Delete(ctx context.Context, ref string) error {
	if err := c.Terminate(ctx, ref); err != nil {
		return err
	}
	_, err := c.call(ctx, stopBound, http.MethodDelete, "/api/tenants/"+ref, nil, false)
	return absentIsNil(err)
}

// ClearBans clears the tenant's network bans of addrs, or with no address
// all of them: the bans are listed and every listed IPv4 address is cleared
// (an entry that is not one is left out: it matches no client's address).
// One request with addresses; with none, two (the list, then the clear),
// each bounded at 30 s. A list over the read bound is ErrTooLarge and
// nothing is cleared.
func (c *Client) ClearBans(ctx context.Context, ref string, addrs []netip.Addr) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	list := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if !a.Is4() {
			return fmt.Errorf("pooler: ban of %v: not an IPv4 address", a)
		}
		list = append(list, a.String())
	}
	path := "/api/tenants/" + ref + "/network_bans"
	if len(list) == 0 {
		b, err := c.call(ctx, bansBound, http.MethodGet, path, nil, true)
		if err != nil {
			return err
		}
		if list, err = bannedAddrs(b); err != nil {
			return err
		}
		if len(list) == 0 {
			return nil
		}
	}
	body, err := json.Marshal(struct {
		Addrs []string `json:"ipv4_addresses"`
	}{list})
	if err != nil {
		return err
	}
	_, err = c.call(ctx, bansBound, http.MethodDelete, path, body, false)
	return err
}

// bannedAddrs reads the ban list document and keeps the entries that are
// IPv4 addresses (ParseAddr takes only the canonical dotted form).
func bannedAddrs(b []byte) ([]string, error) {
	var doc struct {
		Bans *[]struct {
			Addr json.RawMessage `json:"banned_address"`
		} `json:"banned_ipv4_addresses"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.Bans == nil {
		return nil, errors.New("pooler: the ban list is not the expected document")
	}
	var out []string
	for _, e := range *doc.Bans {
		var s string
		if json.Unmarshal(e.Addr, &s) != nil {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			out = append(out, s)
		}
	}
	return out, nil
}

func checkRef(ref string) error {
	if !refRE.MatchString(ref) {
		return fmt.Errorf("pooler: %q is not a project ref", ref)
	}
	return nil
}

func absentIsNil(err error) error {
	var s statusError
	if errors.As(err, &s) && s.code == http.StatusNotFound {
		return nil
	}
	return err
}

// statusError is an answer's status that is not a success.
type statusError struct {
	kind error
	code int
}

func (e statusError) Error() string { return fmt.Sprintf("%v: status %d", e.kind, e.code) }
func (e statusError) Unwrap() error { return e.kind }

// call makes one request on a connection of its own, under bound and ctx,
// and returns nil for a 2xx answer. Of the answer's body (at most what is
// left of maxAnswer) it returns the bytes only when keep is set; otherwise
// they are read and discarded.
func (c *Client) call(ctx context.Context, bound time.Duration, method, path string, body []byte, keep bool) ([]byte, error) {
	if len(c.secret) == 0 {
		return nil, errors.New("pooler: no API secret")
	}
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	req, err := http.NewRequest(method, "http://127.0.0.1"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Close = true
	req.Header.Set("Authorization", "Bearer "+token(c.secret, time.Now()))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("%w: the request was not sent: %w", ErrUnavailable, unavailable(ctx))
	}
	// Errors of the answer's reading are not wrapped: they can quote it.
	lr := &io.LimitedReader{R: conn, N: maxAnswer}
	resp, err := http.ReadResponse(bufio.NewReader(lr), req)
	if err != nil {
		return nil, fmt.Errorf("%w: no well-formed answer: %w", ErrUnavailable, unavailable(ctx))
	}
	var kept []byte
	if keep {
		kept, err = io.ReadAll(resp.Body)
	} else {
		_, err = io.Copy(io.Discard, resp.Body)
	}
	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		// The bound reached with more to come (a body cut short, or a byte
		// beyond it): the list is too large, not the pooler unavailable.
		if keep && lr.N == 0 && (err != nil || oneMore(conn)) {
			return nil, ErrTooLarge
		}
		if keep && err != nil {
			return nil, fmt.Errorf("%w: the answer was cut: %w", ErrUnavailable, unavailable(ctx))
		}
		return kept, nil
	case code >= 400 && code < 500:
		return nil, statusError{ErrRefused, code}
	default:
		return nil, statusError{ErrUnavailable, code}
	}
}

// oneMore reports whether the connection holds a byte beyond what was read.
func oneMore(r io.Reader) bool {
	n, _ := r.Read(make([]byte, 1))
	return n == 1
}

// unavailable names the context's end, or nothing more.
func unavailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("the connection ended")
}
