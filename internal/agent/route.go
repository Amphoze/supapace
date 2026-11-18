package agent

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/routes"
)

const routeFile = "routes.json"

// routeMu serialises the writers of the one route file of a node (one Agent
// per daemon, so it is package-level); the containment flag is read from the
// Agent under it.
var routeMu sync.Mutex

// lastGen is the last generation this process wrote (guarded by routeMu):
// a new table never starts below it.
var lastGen int64

// nowMilli is the clock of the generation seed (a seam for the tests).
var nowMilli = func() int64 { return time.Now().UnixMilli() }

// Seams for the gateway probes: the tests point the dial at a local server
// and shorten the deadline.
var (
	gatewayDial  = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	probeTimeout = 10 * time.Second
)

// jwkMembers is the base64url modulus and exponent of k's public key.
func jwkMembers(k jwtx.Key) (n, e string) {
	return base64.RawURLEncoding.EncodeToString(k.Pub.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.Pub.E)).Bytes())
}

// RouteFor is the route entry of s in state: its upstream is
// PlatformAddr(s.SubnetIndex), computed, never read from Docker; keys and
// user roles come from s.
func (a *Agent) RouteFor(s Spec, state string) routes.Project {
	r := routes.Project{State: state, Rest: "http://" + a.cfg.PlatformAddr(s.SubnetIndex).String() + ":3000",
		UserRoles: append([]string{}, s.UserRoles...), Keys: []routes.Key{}}
	for _, k := range s.Keys {
		rk := routes.Key{KID: k.KID, Class: string(k.Class), Kty: "RSA"}
		if k.Pub != nil && k.Pub.N != nil {
			rk.N, rk.E = jwkMembers(k)
		}
		r.Keys = append(r.Keys, rk)
	}
	return r
}

// SetRoute writes ref's entry (r == nil removes it) and returns the new
// generation. An entry must point at a PostgREST platform address no other
// entry holds, and carry only keys the token package accepts: anything else
// is refused and the file left as it is. While the node is
// containment_failed an active entry is refused with ErrContainment; the
// check is made under the same lock as DrainAllRoutes, so once the flag is
// set and the routes drained nothing re-activates them. An active entry
// must also point at PlatformAddr of the index its project network
// (proj-<ref>, read from Docker) belongs to; draining entries and removals
// need no Docker read. A route file that does not parse is never
// overwritten here (it would drop other projects' entries).
func (a *Agent) SetRoute(ctx context.Context, ref string, r *routes.Project) (int64, error) {
	if err := checkRef(ref); err != nil {
		return 0, err
	}
	if r != nil && r.State == "active" {
		if err := a.checkUpstream(ctx, ref, r.Rest); err != nil {
			return 0, err
		}
	}
	routeMu.Lock()
	defer routeMu.Unlock()
	if r != nil && r.State == "active" && a.ContainmentFailed() {
		return 0, refuse(nil, "route %s not activated: node is containment_failed", ref)
	}
	f, err := a.readRoutes()
	if err != nil {
		return 0, err
	}
	if r == nil {
		delete(f.Projects, ref)
	} else {
		if err := a.checkRoute(f, ref, *r); err != nil {
			return 0, err
		}
		f.Projects[ref] = *r
	}
	return a.writeRoutes(f)
}

// DrainAllRoutes sets every entry to draining in one generation step. It
// always writes: a route file that does not parse is replaced by an empty
// table (fail closed; every entry is rebuilt from the store later). A file
// that exists but cannot be read for another reason (not a regular file, an
// I/O error) still fails the drain.
func (a *Agent) DrainAllRoutes(ctx context.Context) (int64, error) {
	routeMu.Lock()
	defer routeMu.Unlock()
	f, err := a.readRoutes()
	if errors.Is(err, errUnparsable) {
		f, err = routes.File{Domain: a.cfg.Domain, Projects: map[string]routes.Project{}}, nil
	}
	if err != nil {
		return 0, err
	}
	for ref, p := range f.Projects {
		p.State = "draining"
		f.Projects[ref] = p
	}
	return a.writeRoutes(f)
}

// checkRoute refuses an entry the gateway would ignore or that could reach
// another project's PostgREST.
func (a *Agent) checkRoute(f routes.File, ref string, r routes.Project) error {
	if r.State != "active" && r.State != "draining" {
		return fmt.Errorf("agent: route %s: bad state %q", ref, r.State)
	}
	host, ok := strings.CutPrefix(r.Rest, "http://")
	if ok {
		host, ok = strings.CutSuffix(host, ":3000")
	}
	addr, err := netip.ParseAddr(host)
	if !ok || err != nil || !a.isPlatformAddr(addr) {
		return fmt.Errorf("agent: route %s: %q is not a PostgREST platform address", ref, r.Rest)
	}
	for other, p := range f.Projects {
		if other != ref && p.Rest == r.Rest {
			return fmt.Errorf("agent: route %s: %s is %s's upstream", ref, r.Rest, other)
		}
	}
	var kids []string
	for _, k := range r.Keys {
		if _, err := jwtx.KeyFromJWK(k.KID, jwtx.Class(k.Class), k.N, k.E); err != nil || k.Kty != "RSA" {
			return fmt.Errorf("agent: route %s: key %q refused: %w", ref, k.KID, errors.Join(err, jwtx.ErrKey))
		}
		if slices.Contains(kids, k.KID) {
			return fmt.Errorf("agent: route %s: duplicate key %q", ref, k.KID)
		}
		kids = append(kids, k.KID)
	}
	return nil
}

func (a *Agent) isPlatformAddr(addr netip.Addr) bool {
	for i := range a.cfg.Slices() {
		if a.cfg.PlatformAddr(i) == addr {
			return true
		}
	}
	return false
}

// checkUpstream requires rest to be the platform address of the slice whose
// project network proj-<ref> is, as Docker reports it: the index is taken
// from the bridge name and confirmed against the network's options and
// subnet, as the node check does. A failed read or a mismatch refuses.
func (a *Agent) checkUpstream(ctx context.Context, ref, rest string) error {
	pn, err := dockerInspectNetwork(ctx, networkName(ref))
	if err != nil {
		return fmt.Errorf("agent: route %s: project network: %w", ref, err)
	}
	if pn == nil {
		return fmt.Errorf("agent: route %s: no project network", ref)
	}
	i, err := strconv.Atoi(strings.TrimPrefix(pn.BridgeName, "spp"))
	if err != nil || i < 0 || i >= a.cfg.Slices() || nodecfg.BridgeName(i) != pn.BridgeName || a.projectNetMismatch(pn, i) != "" {
		return fmt.Errorf("agent: route %s: project network is not the platform's", ref)
	}
	if want := "http://" + a.cfg.PlatformAddr(i).String() + ":3000"; rest != want {
		return fmt.Errorf("agent: route %s: upstream %q, want %q", ref, rest, want)
	}
	return nil
}

func (a *Agent) routePath() string { return filepath.Join(a.p.GatewayDir(), routeFile) }

// readRoutes returns the current file, or an empty table when there is
// none. A file that does not parse is an error: it is never overwritten
// blindly.
func (a *Agent) readRoutes() (routes.File, error) {
	b, err := os.ReadFile(a.routePath())
	if errors.Is(err, fs.ErrNotExist) {
		return routes.File{Domain: a.cfg.Domain, Projects: map[string]routes.Project{}}, nil
	}
	if err != nil {
		return routes.File{}, fmt.Errorf("agent: route file: %w", err)
	}
	f, err := routes.Parse(b)
	if err != nil {
		return routes.File{}, fmt.Errorf("%w: %w", errUnparsable, err)
	}
	if f.Projects == nil {
		f.Projects = map[string]routes.Project{}
	}
	return f, nil
}

// errUnparsable: the route file exists and does not parse.
var errUnparsable = errors.New("agent: route file does not parse")

// writeRoutes advances the generation and replaces the file by rename
// (nodefs.WriteFile: temporary file, sync, rename, directory sync), root
// 0444 in the root-owned gateway directory: the gateway reads it, nothing
// but the daemon writes it.
func (a *Agent) writeRoutes(f routes.File) (int64, error) {
	if f.Generation < 1 {
		// No previous generation (file absent or replaced): start above every
		// value handed out before, which callers may still be waiting on —
		// the wall clock, and never below what this process wrote even if the
		// clock stepped back or the file was lost twice in one millisecond.
		f.Generation = max(nowMilli(), lastGen)
	}
	f.Generation++
	f.Domain = a.cfg.Domain
	b, err := f.Marshal()
	if err != nil {
		return 0, err
	}
	if err := a.ensurePlatformDir(); err != nil {
		return 0, err
	}
	if err := ensureDir(a.p.GatewayDir(), 0o755, -1, -1); err != nil {
		return 0, err
	}
	if err := writeFile(a.p, a.p.GatewayDir(), routeFile, b, 0o444, os.Geteuid(), os.Getegid()); err != nil {
		return 0, err
	}
	lastGen = f.Generation
	return f.Generation, nil
}

// gatewayClient talks to the gateway at gateway_ingress_ip:8443 only, and
// trusts exactly the certificate the agent deployed to it. Responses are
// bounded: 64 KiB of headers, no connection reuse.
func (a *Agent) gatewayClient() (*http.Client, error) {
	b, err := os.ReadFile(filepath.Join(a.p.GatewayDir(), "tls", "cert.pem"))
	if err != nil {
		return nil, fmt.Errorf("agent: gateway certificate: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("agent: gateway certificate: no PEM certificate")
	}
	pinned := blk.Bytes
	addr := net.JoinHostPort(a.cfg.GatewayIngressIP, "8443")
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return gatewayDial(ctx, "tcp", addr)
			},
			// The leaf is compared byte for byte with the deployed one, which is
			// stricter than a chain check.
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 || string(cs.PeerCertificates[0].Raw) != string(pinned) {
						return errors.New("agent: gateway presented another certificate")
					}
					return nil
				}},
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 64 << 10,
			ResponseHeaderTimeout:  probeTimeout,
		},
	}, nil
}

// gatewayGet sends one GET to the gateway under the probe deadline and hands
// the response to read; the body is closed unread unless read reads it.
func (a *Agent) gatewayGet(ctx context.Context, url string, header http.Header, read func(*http.Response) error) error {
	c, err := a.gatewayClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("agent: gateway: %w", err)
	}
	defer resp.Body.Close()
	return read(resp)
}

// GatewayGeneration is the generation of the route table the gateway is
// serving (GET /-/health at the ingress address).
func (a *Agent) GatewayGeneration(ctx context.Context) (int64, error) {
	var g int64
	err := a.gatewayGet(ctx, "https://"+net.JoinHostPort(a.cfg.GatewayIngressIP, "8443")+"/-/health", nil, func(r *http.Response) error {
		if r.StatusCode != http.StatusOK {
			return fmt.Errorf("agent: gateway health: status %d", r.StatusCode)
		}
		var h struct {
			Generation *int64 `json:"generation"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&h); err != nil || h.Generation == nil {
			return fmt.Errorf("agent: gateway health: unreadable answer: %v", err)
		}
		if _, err := dec.Token(); err != io.EOF {
			return errors.New("agent: gateway health: trailing data")
		}
		g = *h.Generation
		return nil
	})
	return g, err
}

// ProbeREST sends GET /rest/v1/ for ref through the gateway with anonToken
// as apikey (host and TLS server name <ref>.<domain>); 200 is nil. It reads
// the status line only.
func (a *Agent) ProbeREST(ctx context.Context, ref, anonToken string) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	if strings.ContainsAny(anonToken, "\r\n\x00") {
		return errors.New("agent: probe token holds a control character")
	}
	return a.gatewayGet(ctx, "https://"+ref+"."+a.cfg.Domain+"/rest/v1/", http.Header{"Apikey": {anonToken}}, func(r *http.Response) error {
		if r.StatusCode != http.StatusOK {
			return fmt.Errorf("agent: probe %s: status %d", ref, r.StatusCode)
		}
		return nil
	})
}
