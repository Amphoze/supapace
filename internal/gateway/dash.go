package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// dashCSP is the policy of every answer on a dashboard host.
const dashCSP = "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"

// Dashboard is the gateway's dashboard class: the studio domain, its
// certificate, the key that signs sessions and assertions, the dashboard
// table, and the dashboard's in-flight slots and refusal counts.
type Dashboard struct {
	domain string
	cert   *tls.Certificate
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	broken error // a file that did not load: no studio class until a restart
	table  *DashTable

	slots chan struct{} // dashboard requests in flight, node-wide

	mu       sync.Mutex
	byRef    map[string]int       // dashboard requests in flight per ref; no zero entries
	refused  map[string]*[5]int64 // refusals of rules 0 to 4 per ref ("_": the sign-in host) since the last log line
	projects int                  // GatewayDashProject
}

// dashRequest is what the sign-in and forwarding handlers get of a request
// the rules have classified.
type dashRequest struct {
	Table   *dashfile.File  // the table this request was classified against
	Ref     string          // the host's ref; "_" on the sign-in host
	Path    []string        // the segments rule 0 accepted, percent-decoded, case as sent
	Lower   []string        // the same, ASCII lower-cased
	Session dashtok.Session // zero on the paths that need none
	Role    string
	Purpose string
	Keys    []jwtx.Key // Table's issuer keys as dashboard keys
	Dash    *Dashboard // the domain, the signing key, the slots
	// Unpresented: rule 5's exception — a navigation without a session that
	// comes from this host's session page; a session cookie was set and did
	// not come back.
	Unpresented bool
}

// The sign-in handler (rule 1, the sign-in host, rule 5's exception) and the
// forwarder (rule 11).
// While one is nil a request that reaches it is answered 503 unavailable.
var (
	dashAuth    func(http.ResponseWriter, *http.Request, *dashRequest)
	dashForward func(http.ResponseWriter, *http.Request, *dashRequest)
)

// LoadDashboard reads the dashboard's files under the gateway directory dir.
// Without dash/domain it returns nil: the gateway has no studio class. A
// domain, studio pair or assertion key that does not load is logged and
// returns a Dashboard that serves nothing; it never stops the gateway.
func LoadDashboard(dir string) *Dashboard {
	b, err := os.ReadFile(filepath.Join(dir, "dash", "domain"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	l := dashcfg.Limits
	d := &Dashboard{slots: make(chan struct{}, l.GatewayDashNode), byRef: map[string]int{},
		refused: map[string]*[5]int64{}, projects: l.GatewayDashProject}
	if d.broken = d.load(dir, b, err); d.broken != nil {
		log.Printf("gateway: dashboard unavailable until restarted, project API served: %v", d.broken)
		return d
	}
	d.table = &DashTable{path: filepath.Join(dir, "dashboard.json"), domain: d.domain}
	return d
}

func (d *Dashboard) load(dir string, domain []byte, err error) error {
	if err != nil {
		return err
	}
	d.domain = strings.TrimSuffix(string(domain), "\n")
	if !nodecfg.ValidDomain(d.domain) {
		return fmt.Errorf("%s: not a domain name", filepath.Join(dir, "dash", "domain"))
	}
	certFile, keyFile := filepath.Join(dir, "tls-studio", "cert.pem"), filepath.Join(dir, "tls-studio", "key.pem")
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("%s, %s: %w", certFile, keyFile, err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return fmt.Errorf("%s: %w", certFile, err)
	}
	if !slices.Contains(leaf.DNSNames, d.domain) || !slices.Contains(leaf.DNSNames, "*."+d.domain) {
		return fmt.Errorf("%s: does not name %s and *.%s", certFile, d.domain, d.domain)
	}
	d.cert = &c
	keyPath := filepath.Join(dir, "dash", "assert.key")
	kb, err := os.ReadFile(keyPath)
	if err == nil {
		d.priv, err = dashtok.ParsePrivate(kb)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", keyPath, err)
	}
	d.pub = d.priv.Public().(ed25519.PublicKey)
	return nil
}

// usable reports whether d serves the studio class.
func (d *Dashboard) usable() bool { return d != nil && d.broken == nil }

// health is the value of the X-Supapace-Dashboard header on /-/health.
func (d *Dashboard) health() string {
	if d.usable() {
		return "ok"
	}
	return "unavailable"
}

// SetDashboard gives g its dashboard class; call before serving.
func (g *Gateway) SetDashboard(d *Dashboard) { g.dash = d }

// Certificate is a tls.Config GetCertificate: the studio pair for the studio
// domain and every name under it; nil otherwise, so the server falls back to
// its first certificate.
func (g *Gateway) Certificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	d := g.dash
	if !d.usable() {
		return nil, nil
	}
	if n := strings.ToLower(hi.ServerName); n == d.domain || strings.HasSuffix(n, "."+d.domain) {
		return d.cert, nil
	}
	return nil, nil
}

// Reload re-reads the dashboard table (see DashTable.Reload).
func (d *Dashboard) Reload() error {
	if !d.usable() {
		return nil
	}
	return d.table.Reload()
}

// Watch reloads the table every interval and logs the counted refusals once a
// minute, until ctx ends. A table error is logged when it changes.
func (d *Dashboard) Watch(ctx context.Context, every time.Duration) {
	if !d.usable() {
		return
	}
	tick, minute := time.NewTicker(every), time.NewTicker(time.Minute)
	defer tick.Stop()
	defer minute.Stop()
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-minute.C:
			d.logRefusals()
			continue
		case <-tick.C:
		}
		msg := ""
		if err := d.table.Reload(); err != nil {
			msg = err.Error()
		}
		if msg != last && msg != "" {
			log.Printf("gateway: dashboard file ignored, last good table kept: %s", msg)
		}
		last = msg
	}
}

// count records a refusal of rule n (0 to 4) for ref.
func (d *Dashboard) count(ref string, n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.refused[ref]
	if c == nil {
		c = new([5]int64)
		d.refused[ref] = c
	}
	c[n]++
}

// logRefusals writes one line per ref with its counts of refusals of rules 0
// to 4 since the last call, and resets them. Those refusals are not logged
// per request, so a flood of refused paths cannot fill the log.
func (d *Dashboard) logRefusals() {
	d.mu.Lock()
	counts := d.refused
	d.refused = map[string]*[5]int64{}
	d.mu.Unlock()
	refs := make([]string, 0, len(counts))
	for ref := range counts {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	for _, ref := range refs {
		c := counts[ref]
		log.Printf("gateway: dashboard refusals in the last minute: ref %s: rule0 %d rule2 %d rule3 %d rule4 %d", ref, c[0], c[2], c[3], c[4])
	}
}

// acquire takes one of ref's dashboard slots.
func (d *Dashboard) acquire(ref string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byRef[ref] >= d.projects {
		return false
	}
	d.byRef[ref]++
	return true
}

func (d *Dashboard) release(ref string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byRef[ref]--; d.byRef[ref] <= 0 {
		delete(d.byRef, ref)
	}
}

// studioHost classifies a Host value against the studio domain: the studio
// domain itself (label "", redirect only), the sign-in host (label
// dashcfg.SignInLabel) or a dashboard host (any other label one level under
// it). name is the host without its port; ok is false for any other host.
func (d *Dashboard) studioHost(host string) (name, label string, ok bool) {
	if !d.usable() {
		return "", "", false
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		port := host[i+1:]
		if port == "" || strings.Trim(port, "0123456789") != "" {
			return "", "", false
		}
		host = host[:i]
	}
	if host == d.domain {
		return host, "", true
	}
	label, ok = strings.CutSuffix(host, "."+d.domain)
	if !ok || label == "" || strings.IndexByte(label, '.') >= 0 {
		return "", "", false
	}
	return host, label, true
}

// dashHeaders sets the headers every answer on a studio host carries,
// replacing any value: no sniffing, no framing, the page's own origin for
// bases, forms, openers, resources and referrers; HTTPS only. Never the
// sandbox.
func dashHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", dashCSP)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Strict-Transport-Security", "max-age=31536000") // each host for itself: never includeSubDomains
}

// writeDash writes a refusal on a studio host: the gateway's error body with
// the dashboard's headers and no-store.
func writeDash(w http.ResponseWriter, status int, code string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	dashHeaders(h)
	switch status {
	case http.StatusServiceUnavailable:
		h.Set("Retry-After", "5")
	case http.StatusTooManyRequests:
		h.Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":%q}`, code)
}

// serveDash answers a request on a studio host: the studio domain's fixed
// answer; else the host's class, rule 0, then the sign-in handler (the
// sign-in host, rule 1) or the request rules and the forwarder.
func (g *Gateway) serveDash(w http.ResponseWriter, r *http.Request, name, label string) {
	d := g.dash
	if label == dashcfg.SignInLabel {
		w.Header().Set("Origin-Agent-Cluster", "?1") // every answer of the sign-in host, the refusals below too
	}
	if !sniAgrees(r, name) {
		writeDash(w, http.StatusMisdirectedRequest, "misdirected")
		return
	}
	if label == "" {
		d.serveStudioDomain(w, r)
		return
	}
	dt := d.table.cur.Load()
	if dt == nil {
		writeDash(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	ref := label
	if label == dashcfg.SignInLabel {
		ref = "_"
	} else if _, ok := dt.file.Projects[label]; !ok {
		writeDash(w, http.StatusNotFound, "not_found")
		return
	}
	raw, _, _ := strings.Cut(r.RequestURI, "?")
	path, ok := readPath(r.RequestURI)
	if !ok {
		d.count(ref, 0)
		writeDash(w, http.StatusBadRequest, "bad_request")
		return
	}
	dr := &dashRequest{Table: &dt.file, Ref: ref, Path: path, Lower: lower(path), Keys: dt.keys, Dash: d}
	if ref == "_" || strings.HasPrefix(raw, "/-/auth/") {
		call(dashAuth, w, r, dr)
		return
	}
	if !d.rules(w, r, dt, dr, raw) {
		return
	}
	release, ok := g.dashSlots(w, r, dr)
	if !ok {
		return
	}
	defer release()
	call(dashForward, w, r, dr)
}

// serveStudioDomain is the studio domain's one answer: a GET or HEAD of
// exactly "/" (any query) is 302 to the sign-in host; anything else is 404.
// It needs no table, applies no path rule, reads and sets no cookie, and
// nothing of the request reaches the answer.
func (d *Dashboard) serveStudioDomain(w http.ResponseWriter, r *http.Request) {
	raw, _, _ := strings.Cut(r.RequestURI, "?")
	if raw != "/" || r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeDash(w, http.StatusNotFound, "not_found")
		return
	}
	h := w.Header()
	h.Set("Location", "https://"+dashcfg.SignInLabel+"."+d.domain+"/")
	h.Set("Cache-Control", "no-store")
	dashHeaders(h)
	w.WriteHeader(http.StatusFound)
}

func call(h func(http.ResponseWriter, *http.Request, *dashRequest), w http.ResponseWriter, r *http.Request, dr *dashRequest) {
	if h == nil {
		writeDash(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	h(w, r, dr)
}

// dashSlots takes, in this order, a slot of the project, of the dashboard and
// of the gateway; a refusal is answered and logged here.
func (g *Gateway) dashSlots(w http.ResponseWriter, r *http.Request, dr *dashRequest) (release func(), ok bool) {
	d, ref := g.dash, dr.Ref
	if !d.acquire(ref) {
		accessLine(r, dr, http.StatusTooManyRequests, 0)
		writeDash(w, http.StatusTooManyRequests, "too_many_requests")
		return nil, false
	}
	select {
	case d.slots <- struct{}{}:
	default:
		d.release(ref)
		accessLine(r, dr, http.StatusServiceUnavailable, 0)
		writeDash(w, http.StatusServiceUnavailable, "unavailable")
		return nil, false
	}
	select {
	case g.inflight <- struct{}{}:
	default:
		<-d.slots
		d.release(ref)
		accessLine(r, dr, http.StatusServiceUnavailable, 0)
		writeDash(w, http.StatusServiceUnavailable, "unavailable")
		return nil, false
	}
	return func() { <-g.inflight; <-d.slots; d.release(ref) }, true
}
