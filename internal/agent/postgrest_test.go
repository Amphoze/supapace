package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/routes"
)

// ───────── helpers (prefix pr) ─────────

var (
	prKeyOnce sync.Once
	prKeySet  []jwtx.Key
	prKeyErr  error
)

// prKeys returns one anon, one service_role and one issuer key, generated
// once per test binary.
func prKeys(t testing.TB) []jwtx.Key {
	t.Helper()
	prKeyOnce.Do(func() {
		for _, class := range []jwtx.Class{"anon", "service_role", "issuer"} {
			priv, kid, err := jwtx.GenerateKey()
			if err != nil {
				prKeyErr = err
				return
			}
			prKeySet = append(prKeySet, jwtx.Key{KID: kid, Class: class, Pub: &priv.PublicKey})
		}
	})
	if prKeyErr != nil {
		t.Fatal(prKeyErr)
	}
	return slices.Clone(prKeySet)
}

// prAgent is newTestAgent with a healthy node for slice i and a spec that
// carries keys, user roles and a random authenticator password.
func prAgent(t testing.TB, i int) (*Agent, *fakeHost, Spec) {
	t.Helper()
	a, f, s := newTestAgent(t)
	s.SubnetIndex = i
	s.Keys = prKeys(t)
	s.UserRoles = []string{"authenticated"}
	pw := make([]byte, 24)
	rand.Read(pw)
	s.Secrets.AuthenticatorPassword = hex.EncodeToString(pw) + "$/@"
	healthy(a, f, s)
	writeSeccomp(t, a)
	return a, f, s
}

// prLabel is a.configLabel or the end of the test.
func prLabel(t testing.TB, a *Agent, fileHash string, args []string) string {
	t.Helper()
	l, err := a.configLabel(fileHash, args)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// prIndex is the position of the first log line with prefix p, or -1.
func prIndex(log []string, p string) int {
	return slices.IndexFunc(log, func(l string) bool { return strings.HasPrefix(l, p) })
}

// prOrder fails unless each prefix appears in the log after the previous one.
func prOrder(t testing.TB, log []string, prefixes ...string) {
	t.Helper()
	last := -1
	for _, p := range prefixes {
		i := prIndex(log[last+1:], p)
		if i < 0 {
			t.Fatalf("no %q after position %d in:\n%s", p, last, strings.Join(log, "\n"))
		}
		last += 1 + i
	}
}

func prCreateArgv(t testing.TB, f *fakeHost) []string {
	t.Helper()
	c := f.argv("create")
	if len(c) != 1 {
		t.Fatalf("%d create calls, want 1", len(c))
	}
	return c[0]
}

// prPair reports whether flag is directly followed by value in args.
func prPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--" {
			break
		}
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func prRoutePath(a *Agent) string { return filepath.Join(a.p.GatewayDir(), "routes.json") }

func prReadRoutes(t testing.TB, a *Agent) routes.File {
	t.Helper()
	b, err := os.ReadFile(prRoutePath(a))
	if err != nil {
		t.Fatal(err)
	}
	f, err := routes.Parse(b)
	if err != nil {
		t.Fatalf("route file does not parse: %v", err)
	}
	return f
}

// prRef is a distinct ref for n.
func prRef(n int) string { return fmt.Sprintf("r%019d", n) }

// prRoute is the route of project slice i in state.
func prRoute(t testing.TB, a *Agent, i int, state string) *routes.Project {
	t.Helper()
	r := a.RouteFor(Spec{Ref: prRef(i), SubnetIndex: i, Keys: prKeys(t), UserRoles: []string{"authenticated"}}, state)
	return &r
}

func prSmallKey() jwtx.Key {
	n := new(big.Int).SetBit(big.NewInt(1), 1023, 1)
	return jwtx.Key{KID: "small", Class: "issuer", Pub: &rsa.PublicKey{N: n, E: 65537}}
}

// prCert makes a self-signed certificate for the fake gateway.
func prCert(t testing.TB) (tls.Certificate, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"*.sp.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// prGateway starts a TLS server standing in for the gateway, pins its
// certificate as the gateway's (tls/cert.pem in the gateway directory) and
// routes the agent's gateway dials to it. It returns the server and a
// function listing the addresses the agent dialled.
func prGateway(t testing.TB, a *Agent, h http.Handler) (*httptest.Server, func() []string) {
	t.Helper()
	cert, certPEM := prCert(t)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsDir := filepath.Join(a.p.GatewayDir(), "tls")
	if err := a.ensurePlatformDir(); err != nil {
		t.Fatal(err)
	}
	mkdirs(t, a.p.GatewayDir(), tlsDir)
	os.Remove(filepath.Join(tlsDir, "cert.pem"))
	if err := os.WriteFile(filepath.Join(tlsDir, "cert.pem"), certPEM, 0o444); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var dialed []string
	t.Cleanup(swap(&gatewayDial, func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}))
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(dialed) }
}

// ───────── EnsurePostgREST ─────────

func TestEnsurePostgREST_DeterministicPlatformAddr(t *testing.T) {
	for _, i := range []int{0, 14, 1023} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			a, f, s := prAgent(t, i)
			if err := a.EnsurePostgREST(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			want := nodecfg.Default("sp.test").PlatformAddr(i).String()
			if want == "invalid IP" {
				t.Fatalf("no platform address for %d", i)
			}
			log := f.calls()
			render := filepath.Join(a.p.RenderDir(s.Ref), "postgrest")
			prOrder(t, log, "write "+filepath.Join(render, "jwks.json"), "write "+filepath.Join(render, "postgrest.conf"),
				"docker create", "docker network connect", "bridge-nf", "nft check", "docker start")
			create := prCreateArgv(t, f)
			if !prPair(create, "--network", "proj-"+s.Ref) || !prPair(create, "--ip", a.cfg.PostgRESTAddr(i).String()) {
				t.Errorf("create not on proj-%s at base+3: %q", s.Ref, create)
			}
			conn := f.argv("network", "connect")
			if len(conn) != 1 || !slices.Equal(conn[0], []string{"network", "connect", "--ip", want, "--", "platform", "postgrest-" + s.Ref}) {
				t.Fatalf("connect: %q, want --ip %s platform", conn, want)
			}
			if c := f.ctrs["postgrest-"+s.Ref]; !c.Running || c.Nets["platform"] != want {
				t.Fatalf("container: %+v", c)
			}
			// No inspect read is the source of an address: the only inspects are the
			// container lookup, the gate's and nothing between connect and start
			// but the gate.
			for _, l := range log[prIndex(log, "docker network connect"):prIndex(log, "docker start")] {
				if strings.HasPrefix(l, "docker network connect") || strings.HasPrefix(l, "bridge-nf") || strings.HasPrefix(l, "nft check") ||
					strings.HasPrefix(l, "inspect ") || strings.HasPrefix(l, "ip ") || strings.HasPrefix(l, "docker container inspect") ||
					strings.HasPrefix(l, "docker network inspect --format ") || l == "docker ps -a -q --no-trunc" { // the gate's reads
					continue
				}
				t.Errorf("unexpected call between connect and start: %q", l)
			}
		})
	}
}

func TestEnsurePostgREST_Flags(t *testing.T) {
	a, f, s := prAgent(t, 14)
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	argv := prCreateArgv(t, f)
	render := filepath.Join(a.p.RenderDir(s.Ref), "postgrest")
	for _, p := range [][2]string{
		{"--name", "postgrest-" + s.Ref},
		{"--user", "65532:65532"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"},
		{"--security-opt", "seccomp=" + filepath.Join(a.p.PlatformDir(), "seccomp.json")},
		{"--memory", "256m"},
		{"--memory-swap", "256m"},
		{"--pids-limit", "64"},
		{"--ulimit", "core=0"},
		{"--ulimit", "nofile=65536:65536"},
		{"--ipc", "private"},
		{"--sysctl", "net.ipv4.ping_group_range=1 0"},
		{"--sysctl", "net.ipv6.conf.all.disable_ipv6=1"},
		{"-e", "GHCRTS=-N2"},
		{"--network", "proj-" + s.Ref},
		{"--ip", a.cfg.PostgRESTAddr(14).String()},
		{"-v", render + ":/etc/postgrest:ro"},
		{"--label", "supapace.role=postgrest"},
		{"--label", "supapace.ref=" + s.Ref},
		{"--label", "supapace.generation=1"},
		{"--label", "supapace.epoch=1"},
		{"--label", "supapace.image=" + a.cfg.Images.PostgREST},
	} {
		if !prPair(argv, p[0], p[1]) {
			t.Errorf("create lacks %s %s", p[0], p[1])
		}
	}
	for _, flag := range []string{"--read-only", "--no-healthcheck"} {
		if !slices.Contains(argv, flag) {
			t.Errorf("create lacks %s", flag)
		}
	}
	for _, bad := range []string{"--restart", "--cap-add", "--privileged", "--env-file", "--entrypoint"} {
		if slices.Contains(argv, bad) {
			t.Errorf("create carries %s", bad)
		}
	}
	if envs := flagValues(argv, "-e"); !slices.Equal(envs, []string{"GHCRTS=-N2"}) {
		t.Errorf("environment %q, want only GHCRTS=-N2", envs)
	}
	if vs := flagValues(argv, "-v"); len(vs) != 1 {
		t.Errorf("mounts %q, want only the configuration directory", vs)
	}
	if tail := positional(argv); !slices.Equal(tail, []string{a.cfg.Images.PostgREST, "/bin/postgrest", "/etc/postgrest/postgrest.conf"}) {
		t.Errorf("image and command %q", tail)
	}
	// No secret anywhere in argv: the password and the private parts of the keys.
	for _, args := range f.argv() {
		joined := strings.Join(args, "\x00")
		if strings.Contains(joined, s.Secrets.AuthenticatorPassword) || strings.Contains(joined, "authenticator:") {
			t.Fatalf("a docker call carries the password: %q", args[0])
		}
	}
	// The files: postgrest.conf (0400, PostgREST's uid) is pgconf's render; jwks.json
	// (0444, root) holds exactly the spec's public keys.
	conf := f.writes[filepath.Join(render, "postgrest.conf")]
	want, err := pgconf.PostgREST(pgconf.PostgRESTConfig{ClusterAddr: a.cfg.ClusterAddr(14), AuthenticatorPassword: s.Secrets.AuthenticatorPassword})
	if err != nil {
		t.Fatal(err)
	}
	if conf.Mode != 0o400 || conf.UID != 65532 || conf.GID != 65532 || !bytes.Equal(conf.Data, want) {
		t.Errorf("postgrest.conf written %o %d:%d, want 0400 65532:65532 and pgconf's bytes", conf.Mode, conf.UID, conf.GID)
	}
	jw := f.writes[filepath.Join(render, "jwks.json")]
	if jw.Mode != 0o444 || jw.UID != os.Geteuid() {
		t.Errorf("jwks.json written %o %d, want 0444 root", jw.Mode, jw.UID)
	}
	keys, err := jwtx.ParseJWKS(jw.Data, "issuer")
	if err != nil || len(keys) != 3 {
		t.Fatalf("jwks.json: %d keys, %v", len(keys), err)
	}
	for i, k := range keys {
		if k.KID != s.Keys[i].KID || k.Pub.N.Cmp(s.Keys[i].Pub.N) != 0 {
			t.Errorf("jwks key %d differs from the spec", i)
		}
	}
	if bytes.Contains(jw.Data, []byte(`"d"`)) {
		t.Error("jwks.json carries a private member")
	}
	// The configuration label covers the hash of postgrest.conf as written and
	// the create arguments without the label.
	h := sha256.New()
	h.Write([]byte("postgrest.conf\x00"))
	h.Write(conf.Data)
	h.Write([]byte{0})
	ci := slices.IndexFunc(argv, func(s string) bool { return strings.HasPrefix(s, "supapace.config=") })
	if ci < 1 {
		t.Fatal("no config label")
	}
	label := "supapace.config=" + prLabel(t, a, hex.EncodeToString(h.Sum(nil)), slices.Delete(slices.Clone(argv), ci-1, ci+1))
	if !prPair(argv, "--label", label) {
		t.Errorf("config label is not over postgrest.conf and the arguments: %q", flagValues(argv, "--label"))
	}
	for _, d := range []string{a.p.RenderDir(s.Ref), render} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v, want 0755", d, fi, err)
		}
	}
}

func TestEnsurePostgREST_GHCRTSAndPids(t *testing.T) {
	a, f, s := prAgent(t, 14)
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	argv := prCreateArgv(t, f)
	if !prPair(argv, "-e", "GHCRTS=-N2") {
		t.Error("GHCRTS=-N2 is not a run argument")
	}
	conf := string(f.writes[filepath.Join(a.p.RenderDir(s.Ref), "postgrest", "postgrest.conf")].Data)
	if strings.Contains(conf, "GHCRTS") {
		t.Error("GHCRTS is in the configuration file")
	}
	pool := -1
	for _, l := range strings.Split(conf, "\n") {
		if v, ok := strings.CutPrefix(l, "db-pool = "); ok {
			pool, _ = strconv.Atoi(v)
		}
	}
	pids, err := strconv.Atoi(flagValue(argv, "--pids-limit"))
	if pool < 1 || err != nil || pids < pool+15 {
		t.Fatalf("pids limit %d (%v) below db-pool %d + 15", pids, err, pool)
	}
}

// prRunning brings postgrest-<ref> up through the agent itself and clears
// the log.
func prRunning(t testing.TB, a *Agent, f *fakeHost, s Spec) {
	t.Helper()
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	f.resetLog()
}

func TestEnsurePostgREST_EqualGenerationAdoptsRunning(t *testing.T) {
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	id := f.ctrs["postgrest-"+s.Ref].ID
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("adoption mutated: %q", m)
	}
	log := f.calls()
	if prIndex(log, "ip -j -d addr show dev spp14") < 0 || prIndex(log, "inspect network platform") < 0 {
		t.Fatalf("CheckAdopted not called:\n%s", strings.Join(log, "\n"))
	}
	if prIndex(log, "nft check") >= 0 {
		t.Fatal("adoption ran the start gate's condition 1")
	}
	if f.ctrs["postgrest-"+s.Ref].ID != id {
		t.Fatal("container replaced")
	}
}

func TestEnsurePostgREST_AdoptedFailsGate_Stops(t *testing.T) {
	faults := map[string]func(a *Agent, f *fakeHost, s Spec){
		"node flag": func(a *Agent, f *fakeHost, s Spec) { a.SetContainmentFailed(true) },
		"restart policy on the cluster": func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, CapDrop: []string{"ALL"}, Restart: "always"})
		},
		"foreign holder": func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "intruder", Running: true, CapDrop: []string{"ALL"},
				Nets: map[string]string{"platform": a.cfg.PlatformAddr(s.SubnetIndex).String()}})
		},
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			prRunning(t, a, f, s)
			fault(a, f, s)
			f.resetLog()
			wantContainment(t, a.EnsurePostgREST(context.Background(), s), name)
			prOrder(t, f.calls(), "docker stop -t 10 -- postgrest-"+s.Ref, "docker rm -- postgrest-"+s.Ref)
			if f.argv("start") != nil || f.argv("create") != nil {
				t.Fatal("started or created after a failed adoption")
			}
		})
	}
}

func TestEnsurePostgREST_RunningAtWrongAddressOrGeneration_Recreated(t *testing.T) {
	faults := map[string]func(a *Agent, c *fakeCtr){
		"platform address": func(a *Agent, c *fakeCtr) { c.Nets["platform"] = a.cfg.PlatformAddr(15).String() },
		"not on platform":  func(a *Agent, c *fakeCtr) { delete(c.Nets, "platform") },
		"project address":  func(a *Agent, c *fakeCtr) { c.Nets["proj-"+testRef] = a.cfg.ClusterAddr(14).String() },
		"generation":       func(a *Agent, c *fakeCtr) { c.Labels["supapace.generation"] = "2" },
		"epoch":            func(a *Agent, c *fakeCtr) { c.Labels["supapace.epoch"] = "2" },
		"image":            func(a *Agent, c *fakeCtr) { c.Labels["supapace.image"] = "other@sha256:00" },
		"config":           func(a *Agent, c *fakeCtr) { c.Labels["supapace.config"] = strings.Repeat("0", 64) },
		"role":             func(a *Agent, c *fakeCtr) { delete(c.Labels, "supapace.role") },
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			prRunning(t, a, f, s)
			fault(a, f.ctrs["postgrest-"+s.Ref])
			if err := a.EnsurePostgREST(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			m := f.mutations()
			if len(m) == 0 || m[0] != "docker rm -f -- postgrest-"+s.Ref {
				t.Fatalf("first mutation %q, want rm -f", m)
			}
			prOrder(t, f.calls(), "docker rm -f", "docker create", "docker network connect --ip "+a.cfg.PlatformAddr(14).String(),
				"nft check", "docker start")
			if c := f.ctrs["postgrest-"+s.Ref]; !c.Running || c.Nets["platform"] != a.cfg.PlatformAddr(14).String() ||
				c.Labels["supapace.generation"] != "1" {
				t.Fatalf("recreated container: %+v", c)
			}
		})
	}
}

func TestEnsurePostgREST_EqualGenerationStartsStopped(t *testing.T) {
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	old := f.ctrs["postgrest-"+s.Ref]
	old.Running, old.Pid = false, 0
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	addr := a.cfg.PlatformAddr(14).String()
	prOrder(t, f.calls(), "docker rm -f -- postgrest-"+s.Ref, "docker create", "docker network connect --ip "+addr, "nft check", "docker start")
	if c := f.ctrs["postgrest-"+s.Ref]; c.ID == old.ID || !c.Running || c.Nets["platform"] != addr {
		t.Fatalf("not re-created at the same address: %+v", c)
	}
}

func TestEnsurePostgREST_GateFailureStartsNothing(t *testing.T) {
	faults := map[string]func(a *Agent, f *fakeHost, s Spec){
		"nft drift":  func(a *Agent, f *fakeHost, s Spec) { f.nftErr = nft.ErrDrift },
		"bridge-nf":  func(a *Agent, f *fakeHost, s Spec) { f.bnfErr = errors.New("switch on") },
		"node flag":  func(a *Agent, f *fakeHost, s Spec) { a.SetContainmentFailed(true) },
		"no network": func(a *Agent, f *fakeHost, s Spec) { delete(f.nets, "proj-"+s.Ref) },
		"addr holder": func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "intruder", Running: true, CapDrop: []string{"ALL"},
				Nets: map[string]string{"platform": a.cfg.PlatformAddr(s.SubnetIndex).String()}})
		},
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			fault(a, f, s)
			wantContainment(t, a.EnsurePostgREST(context.Background(), s), name)
			if got := f.argv("start"); got != nil {
				t.Fatalf("started after a failed gate: %q", got)
			}
			if c := f.ctrs["postgrest-"+s.Ref]; c != nil && c.Running {
				t.Fatal("container running")
			}
		})
	}
}

func TestEnsurePostgREST_AddressInUseIsContainment(t *testing.T) {
	// Another container takes the address between the gate and the start: the
	// start fails as Docker's does.
	a, f, s := prAgent(t, 14)
	f.before = func(args []string) {
		if args[0] == "start" && f.ctrs["intruder"] == nil {
			f.ctr(fakeCtr{Name: "intruder", Running: true, CapDrop: []string{"ALL"},
				Nets: map[string]string{"platform": a.cfg.PlatformAddr(14).String()}})
		}
	}
	wantContainment(t, a.EnsurePostgREST(context.Background(), s), "address in use")
	if c := f.ctrs["postgrest-"+s.Ref]; c != nil {
		t.Fatalf("left beside the holder of its address: %+v", c)
	}

	a, f, s = prAgent(t, 14)
	other := errors.New("docker start: exit status 1: Error response from daemon: something else")
	f.failVerb["start"] = other
	if err := a.EnsurePostgREST(context.Background(), s); !errors.Is(err, other) || errors.Is(err, ErrContainment) {
		t.Fatalf("other start failure: %v, want it unchanged", err)
	}
}

func TestEnsurePostgREST_Refusals(t *testing.T) {
	cases := map[string]func(s *Spec){
		"bad ref":      func(s *Spec) { s.Ref = "UPPER" },
		"bad index":    func(s *Spec) { s.SubnetIndex = 1024 },
		"bad password": func(s *Spec) { s.Secrets.AuthenticatorPassword = "a\x00b" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			mod(&s)
			if err := a.EnsurePostgREST(context.Background(), s); err == nil {
				t.Fatal("accepted")
			}
			if m := f.mutations(); len(m) != 0 || len(f.writes) != 0 {
				t.Fatalf("acted on a refused spec: %q, %d writes", m, len(f.writes))
			}
		})
	}
}

// ───────── jwks.json ─────────

func prNothingWritten(t testing.TB, a *Agent, f *fakeHost, s Spec) {
	t.Helper()
	if len(f.writes) != 0 {
		t.Fatalf("files written: %v", sortedKeys(f.writes))
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("docker mutated: %q", m)
	}
	if _, err := os.Lstat(filepath.Join(a.p.RenderDir(s.Ref), "postgrest", "jwks.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("jwks.json exists: %v", err)
	}
}

func TestJWKS_RenderedOnlyFromValidatedKeys(t *testing.T) {
	cases := map[string]func([]jwtx.Key) []jwtx.Key{
		"1024-bit key": func(k []jwtx.Key) []jwtx.Key { return append(k, prSmallKey()) },
		"exponent 3": func(k []jwtx.Key) []jwtx.Key {
			return append(k, jwtx.Key{KID: "e3", Class: "issuer", Pub: &rsa.PublicKey{N: k[0].Pub.N, E: 3}})
		},
		"no kid":        func(k []jwtx.Key) []jwtx.Key { k[2].KID = ""; return k },
		"duplicate kid": func(k []jwtx.Key) []jwtx.Key { k[2].KID = k[1].KID; return k },
		"bad class":     func(k []jwtx.Key) []jwtx.Key { k[2].Class = "admin"; return k },
		"nil key":       func(k []jwtx.Key) []jwtx.Key { return append(k, jwtx.Key{KID: "n", Class: "issuer"}) },
		"no keys":       func(k []jwtx.Key) []jwtx.Key { return nil },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			s.Keys = mod(s.Keys)
			if err := a.EnsurePostgREST(context.Background(), s); err == nil {
				t.Fatal("accepted")
			}
			prNothingWritten(t, a, f, s)
		})
	}
}

// TestJWKS_ParsedBackBeforeRename feeds the parse-back with sets the
// serialiser must never produce: a symmetric key, a private member, an extra
// non-RSA entry, a missing key, truncated bytes. Each is refused before any
// file is written.
func TestJWKS_ParsedBackBeforeRename(t *testing.T) {
	cases := map[string]func(b []byte) []byte{
		"oct key with k": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"keys":[`), []byte(`"keys":[{"kty":"oct","kid":"s","k":"c2VjcmV0"},`), 1)
		},
		"oct key alone": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"keys":[`), []byte(`"keys":[{"kty":"oct","kid":"s"},`), 1)
		},
		"private member": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"kty":"RSA"`), []byte(`"kty":"RSA","d":"AQAB"`), 1)
		},
		"key dropped": func(b []byte) []byte {
			keys, _ := jwtx.ParseJWKS(b, "issuer")
			out, _ := jwtx.MarshalJWKS(keys[:2])
			return out
		},
		"key changed": func(b []byte) []byte {
			keys, _ := jwtx.ParseJWKS(b, "issuer")
			keys[0].KID = "other"
			out, _ := jwtx.MarshalJWKS(keys)
			return out
		},
		"truncated": func(b []byte) []byte { return b[:len(b)/2] },
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			t.Cleanup(swap(&marshalJWKS, func(k []jwtx.Key) ([]byte, error) {
				b, err := jwtx.MarshalJWKS(k)
				return corrupt(b), err
			}))
			if err := a.EnsurePostgREST(context.Background(), s); err == nil {
				t.Fatal("accepted")
			}
			prNothingWritten(t, a, f, s)
		})
	}
}

// ───────── StopPostgREST ─────────

func TestStopPostgREST(t *testing.T) {
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	if err := a.StopPostgREST(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); !slices.Equal(m, []string{"docker stop -t 10 -- postgrest-" + s.Ref, "docker rm -- postgrest-" + s.Ref}) {
		t.Fatalf("stop: %q", m)
	}
	if f.ctrs["postgrest-"+s.Ref] != nil {
		t.Fatal("still present")
	}
	f.resetLog()
	if err := a.StopPostgREST(context.Background(), s.Ref); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("absent: %v %q", err, f.mutations())
	}
	if err := a.StopPostgREST(context.Background(), "../x"); err == nil {
		t.Fatal("bad ref accepted")
	}
	boom := errors.New("daemon gone")
	f.ctr(fakeCtr{Name: "postgrest-" + s.Ref, Running: true})
	f.failVerb["stop"] = boom
	if err := a.StopPostgREST(context.Background(), s.Ref); !errors.Is(err, boom) {
		t.Fatalf("stop failure: %v", err)
	}
}

// ───────── RouteFor ─────────

func TestRouteFor_UsesPlatformAddr(t *testing.T) {
	a, _, s := prAgent(t, 14)
	for _, i := range []int{0, 14, 1023} {
		s.SubnetIndex = i
		r := a.RouteFor(s, "active")
		if want := "http://" + a.cfg.PlatformAddr(i).String() + ":3000"; r.Rest != want {
			t.Fatalf("rest %q, want %q", r.Rest, want)
		}
		if r.State != "active" || !slices.Equal(r.UserRoles, s.UserRoles) || len(r.Keys) != len(s.Keys) {
			t.Fatalf("route %+v", r)
		}
		for j, k := range r.Keys {
			if k.KID != s.Keys[j].KID || k.Class != string(s.Keys[j].Class) || k.Kty != "RSA" {
				t.Fatalf("key %d: %+v", j, k)
			}
			if _, err := jwtx.KeyFromJWK(k.KID, jwtx.Class(k.Class), k.N, k.E); err != nil {
				t.Fatalf("key %d refused by the token package: %v", j, err)
			}
		}
		b, err := routes.File{Generation: 1, Domain: "sp.test", Projects: map[string]routes.Project{s.Ref: r}}.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := routes.Parse(b); err != nil {
			t.Fatalf("route does not parse: %v", err)
		}
	}
	s.UserRoles = append(s.UserRoles, "x")
	if r := a.RouteFor(s, "draining"); r.State != "draining" || len(r.UserRoles) != 2 {
		t.Fatalf("draining route %+v", r)
	}
}

// ───────── the route file ─────────

func TestSetRoute_AtomicAndGenerationIncrements(t *testing.T) {
	a, f, _ := prRouteAgent(t)
	ctx := context.Background()
	// A reader polls the file while it is rewritten: every read must parse.
	var stop atomic.Bool
	var reads, bad atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			b, err := os.ReadFile(prRoutePath(a))
			if err != nil {
				continue
			}
			reads.Add(1)
			if _, err := routes.Parse(b); err != nil {
				bad.Add(1)
			}
		}
	}()
	var inodes []uint64
	var first int64
	for n := 1; n <= 30; n++ {
		g, err := a.SetRoute(ctx, prRef(n), prRoute(t, a, n, "active"))
		if err != nil {
			t.Fatal(err)
		}
		file := prReadRoutes(t, a)
		if n == 1 {
			first = g
		}
		if g != first+int64(n-1) || file.Generation != g || file.Domain != "sp.test" || len(file.Projects) != n {
			t.Fatalf("call %d: generation %d, file %d with %d projects", n, g, file.Generation, len(file.Projects))
		}
		fi, err := os.Stat(prRoutePath(a))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o444 {
			t.Fatalf("route file mode %o, want 0444", fi.Mode().Perm())
		}
		inodes = append(inodes, fi.Sys().(*syscall.Stat_t).Ino)
	}
	stop.Store(true)
	<-done
	if bad.Load() != 0 {
		t.Fatalf("%d of %d reads saw a file that does not parse", bad.Load(), reads.Load())
	}
	// Each write is a new file renamed over the old one, never an in-place rewrite.
	for i := 1; i < len(inodes); i++ {
		if inodes[i] == inodes[i-1] {
			t.Fatalf("write %d kept the inode: not replaced by rename", i+1)
		}
	}
	ents, err := os.ReadDir(a.p.GatewayDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "routes.json" {
		t.Fatalf("gateway directory: %v", ents)
	}
	w := f.writes[prRoutePath(a)]
	if w.Mode != 0o444 || w.UID != os.Geteuid() || w.GID != os.Getegid() {
		t.Fatalf("route file written %o %d:%d, want 0444 owned by the daemon", w.Mode, w.UID, w.GID)
	}
	for _, d := range []string{a.p.PlatformDir(), a.p.GatewayDir()} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %v %v, want 0755", d, fi, err)
		}
	}
}

func TestSetRoute_NilRemoves(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	var g2 int64
	for n := 1; n <= 2; n++ {
		g, err := a.SetRoute(ctx, prRef(n), prRoute(t, a, n, "active"))
		if err != nil {
			t.Fatal(err)
		}
		g2 = g
	}
	g, err := a.SetRoute(ctx, prRef(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	file := prReadRoutes(t, a)
	if _, ok := file.Projects[prRef(1)]; ok || len(file.Projects) != 1 || g != g2+1 || file.Generation != g {
		t.Fatalf("after removal: generation %d/%d, %v", g, file.Generation, sortedKeys(file.Projects))
	}
	// Removing an absent entry is not an error.
	if g, err := a.SetRoute(ctx, prRef(1), nil); err != nil || g != g2+2 {
		t.Fatalf("second removal: %d %v", g, err)
	}
	// Nor is removal before any file exists.
	b, _, _ := prRouteAgent(t)
	if g, err := b.SetRoute(ctx, prRef(1), nil); err != nil || g < 1 || len(prReadRoutes(t, b).Projects) != 0 {
		t.Fatalf("removal from no file: %d %v", g, err)
	}
}

func TestSetRoute_ActiveRefusedWhileContainmentFailed(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	if _, err := a.SetRoute(ctx, prRef(1), prRoute(t, a, 1, "draining")); err != nil {
		t.Fatal(err)
	}
	a.SetContainmentFailed(true)
	before, _ := os.ReadFile(prRoutePath(a))
	for _, n := range []int{1, 2} {
		_, err := a.SetRoute(ctx, prRef(n), prRoute(t, a, n, "active"))
		wantContainment(t, err, "SetRoute active")
	}
	if after, _ := os.ReadFile(prRoutePath(a)); !bytes.Equal(before, after) {
		t.Fatal("refused activation changed the file")
	}
	if _, err := a.SetRoute(ctx, prRef(2), prRoute(t, a, 2, "draining")); err != nil {
		t.Fatalf("draining refused while flagged: %v", err)
	}
	if _, err := a.SetRoute(ctx, prRef(1), nil); err != nil {
		t.Fatalf("removal refused while flagged: %v", err)
	}
	if _, err := a.DrainAllRoutes(ctx); err != nil {
		t.Fatalf("drain refused while flagged: %v", err)
	}
	a.SetContainmentFailed(false)
	if _, err := a.SetRoute(ctx, prRef(2), prRoute(t, a, 2, "active")); err != nil {
		t.Fatalf("activation after the flag cleared: %v", err)
	}
	if file := prReadRoutes(t, a); len(file.Projects) != 1 || file.Projects[prRef(2)].State != "active" {
		t.Fatalf("file %+v", file.Projects)
	}
}

// TestSetRoute_FlagThenDrain_NoReactivation runs activations continuously
// while the flag is set and every route drained: when the drain has
// returned, no entry is active, and no later activation succeeds.
func TestSetRoute_FlagThenDrain_NoReactivation(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	const n = 8
	for i := 1; i <= n; i++ {
		if _, err := a.SetRoute(ctx, prRef(i), prRoute(t, a, i, "active")); err != nil {
			t.Fatal(err)
		}
	}
	var drained atomic.Bool
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := prRoute(t, a, i, "active")
			for after := 0; after < 5; {
				was := drained.Load()
				_, err := a.SetRoute(ctx, prRef(i), r)
				if was {
					after++
					if !errors.Is(err, ErrContainment) {
						errs <- fmt.Errorf("activation after the drain: %v", err)
						return
					}
				} else if err != nil && !errors.Is(err, ErrContainment) {
					errs <- err
					return
				}
			}
		}()
	}
	time.Sleep(time.Millisecond)
	a.SetContainmentFailed(true)
	if _, err := a.DrainAllRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	drained.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for ref, p := range prReadRoutes(t, a).Projects {
		if p.State != "draining" {
			t.Fatalf("%s is %s after flag and drain", ref, p.State)
		}
	}
}

func TestSetRoute_Serialised(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	gens := make(chan int64, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := a.SetRoute(ctx, prRef(i), prRoute(t, a, i, "active"))
			if err != nil {
				t.Error(err)
			}
			gens <- g
		}()
	}
	wg.Wait()
	close(gens)
	var got []int64
	for g := range gens {
		got = append(got, g)
	}
	slices.Sort(got)
	for i, g := range got {
		if g != got[0]+int64(i) {
			t.Fatalf("generations returned %v, want 100 consecutive values once each", got)
		}
	}
	file := prReadRoutes(t, a)
	if len(file.Projects) != 100 || file.Generation != got[99] {
		t.Fatalf("%d entries, generation %d; want 100 entries at the last generation returned", len(file.Projects), file.Generation)
	}
}

func TestDrainAllRoutes(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	if g, err := a.DrainAllRoutes(ctx); err != nil || g < 1 || len(prReadRoutes(t, a).Projects) != 0 {
		t.Fatalf("drain without a file: %d %v", g, err)
	}
	for i := 1; i <= 3; i++ {
		state := "active"
		if i == 3 {
			state = "draining"
		}
		if _, err := a.SetRoute(ctx, prRef(i), prRoute(t, a, i, state)); err != nil {
			t.Fatal(err)
		}
	}
	before := prReadRoutes(t, a)
	g, err := a.DrainAllRoutes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after := prReadRoutes(t, a)
	if g != before.Generation+1 || after.Generation != g {
		t.Fatalf("generation %d → %d (returned %d), want one step", before.Generation, after.Generation, g)
	}
	if len(after.Projects) != len(before.Projects) {
		t.Fatal("entries lost")
	}
	for ref, p := range after.Projects {
		want := before.Projects[ref]
		want.State = "draining"
		if p.State != "draining" || p.Rest != want.Rest || !slices.Equal(p.UserRoles, want.UserRoles) || !slices.Equal(p.Keys, want.Keys) {
			t.Fatalf("%s: %+v, want %+v", ref, p, want)
		}
	}
}

func TestSetRoute_RefusesInvalid(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	if _, err := a.SetRoute(ctx, prRef(1), prRoute(t, a, 1, "active")); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() (string, *routes.Project){
		"bad ref":   func() (string, *routes.Project) { return "../x", prRoute(t, a, 2, "active") },
		"bad state": func() (string, *routes.Project) { return prRef(2), prRoute(t, a, 2, "up") },
		"gateway address": func() (string, *routes.Project) {
			r := prRoute(t, a, 2, "active")
			r.Rest = "http://" + a.cfg.GatewayIP + ":3000"
			return prRef(2), r
		},
		"docker range address": func() (string, *routes.Project) {
			r := prRoute(t, a, 2, "active")
			r.Rest = "http://10.212.6.9:3000"
			return prRef(2), r
		},
		"another project's address": func() (string, *routes.Project) { return prRef(2), prRoute(t, a, 1, "active") },
		"not a url": func() (string, *routes.Project) {
			r := prRoute(t, a, 2, "active")
			r.Rest = "http://" + a.cfg.PlatformAddr(2).String() + ":3001"
			return prRef(2), r
		},
		"1024-bit key": func() (string, *routes.Project) {
			r := prRoute(t, a, 2, "active")
			r.Keys = append(r.Keys, prRouteKey(a, prSmallKey()))
			return prRef(2), r
		},
		"duplicate kid": func() (string, *routes.Project) {
			r := prRoute(t, a, 2, "active")
			r.Keys[2].KID = r.Keys[1].KID
			return prRef(2), r
		},
		"no service key": func() (string, *routes.Project) {
			r := prRoute(t, a, 2, "active")
			r.Keys = slices.DeleteFunc(r.Keys, func(k routes.Key) bool { return k.Class == "service_role" })
			return prRef(2), r
		},
	}
	before, _ := os.ReadFile(prRoutePath(a))
	for name, c := range cases {
		ref, r := c()
		if _, err := a.SetRoute(ctx, ref, r); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if after, _ := os.ReadFile(prRoutePath(a)); !bytes.Equal(before, after) {
			t.Fatalf("%s: refused route changed the file", name)
		}
	}
	// The same entry may be rewritten at its own address.
	if _, err := a.SetRoute(ctx, prRef(1), prRoute(t, a, 1, "draining")); err != nil {
		t.Fatalf("rewrite at its own address: %v", err)
	}
	// A file that does not parse is never overwritten blindly.
	if err := os.Chmod(prRoutePath(a), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prRoutePath(a), []byte("{"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetRoute(ctx, prRef(1), nil); err == nil {
		t.Fatal("wrote over an unreadable route file")
	}
	// Draining is not refused: TestDrainAllRoutes_UnparsableFileFailsClosed.
}

// prRouteKey is the route key of k, as RouteFor writes it.
func prRouteKey(a *Agent, k jwtx.Key) routes.Key {
	return a.RouteFor(Spec{SubnetIndex: 0, Keys: []jwtx.Key{k}}, "active").Keys[0]
}

// ───────── gateway probes ─────────

func TestProbeREST_ThroughGatewayIngress(t *testing.T) {
	a, _, s := prAgent(t, 14)
	type seen struct{ sni, host, path, apikey, auth string }
	got := make(chan seen, 1)
	_, dialed := prGateway(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.TLS.ServerName, r.Host, r.URL.Path, r.Header.Get("apikey"), r.Header.Get("Authorization")}
	}))
	if err := a.ProbeREST(context.Background(), s.Ref, "anon.token.value"); err != nil {
		t.Fatal(err)
	}
	r := <-got
	host := s.Ref + ".sp.test"
	if r.sni != host || (r.host != host && r.host != host+":8443") || r.path != "/rest/v1/" || r.apikey != "anon.token.value" || r.auth != "" {
		t.Fatalf("request %+v", r)
	}
	if d := dialed(); len(d) != 1 || d[0] != a.cfg.GatewayIngressIP+":8443" {
		t.Fatalf("dialled %q, want %s:8443", d, a.cfg.GatewayIngressIP)
	}
}

func TestProbeREST_Refusals(t *testing.T) {
	a, _, s := prAgent(t, 14)
	var status atomic.Int64
	status.Store(503)
	prGateway(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(status.Load())) }))
	if err := a.ProbeREST(context.Background(), s.Ref, "t"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("503: %v", err)
	}
	status.Store(200)
	if err := a.ProbeREST(context.Background(), "../x", "t"); err == nil {
		t.Fatal("bad ref accepted")
	}
	if err := a.ProbeREST(context.Background(), s.Ref, "a\r\nb"); err == nil {
		t.Fatal("token with a line break accepted")
	}
	// A gateway presenting another certificate than the deployed one is refused.
	_, other := prCert(t)
	os.Remove(filepath.Join(a.p.GatewayDir(), "tls", "cert.pem"))
	if err := os.WriteFile(filepath.Join(a.p.GatewayDir(), "tls", "cert.pem"), other, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := a.ProbeREST(context.Background(), s.Ref, "t"); err == nil {
		t.Fatal("probe trusted a certificate other than the gateway's")
	}
	if _, err := a.GatewayGeneration(context.Background()); err == nil {
		t.Fatal("health trusted a certificate other than the gateway's")
	}
	os.Remove(filepath.Join(a.p.GatewayDir(), "tls", "cert.pem"))
	if err := a.ProbeREST(context.Background(), s.Ref, "t"); err == nil {
		t.Fatal("probe without the gateway's certificate")
	}
}

func TestProbeREST_StatusOnlyBounded(t *testing.T) {
	a, _, s := prAgent(t, 14)
	var mode atomic.Value
	var written atomic.Int64
	prGateway(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case "body":
			w.WriteHeader(200)
			chunk := bytes.Repeat([]byte("x"), 1<<16)
			for n := 0; n < 1<<14; n++ { // 1 GiB
				if _, err := w.Write(chunk); err != nil {
					return
				}
				written.Add(int64(len(chunk)))
			}
		case "header":
			w.Header().Set("X-Big", strings.Repeat("h", 1<<20))
			w.WriteHeader(200)
		}
	}))
	mode.Store("body")
	start := time.Now()
	if err := a.ProbeREST(context.Background(), s.Ref, "t"); err != nil {
		t.Fatalf("1 GiB body: %v", err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("1 GiB body: probe took %v", el)
	}
	time.Sleep(200 * time.Millisecond)
	if w := written.Load(); w > 64<<20 {
		t.Fatalf("the probe read the body: %d bytes went out", w)
	}
	mode.Store("header")
	start = time.Now()
	if err := a.ProbeREST(context.Background(), s.Ref, "t"); err == nil {
		t.Fatal("1 MiB header accepted")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("1 MiB header: probe took %v", el)
	}
	// A gateway that never answers is given up at the probe's deadline.
	mode.Store("stall")
	t.Cleanup(swap(&probeTimeout, 300*time.Millisecond))
	release := make(chan struct{})
	prGateway(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(func() { close(release) }) // before the server closes: it waits for its handlers
	start = time.Now()
	if err := a.ProbeREST(context.Background(), s.Ref, "t"); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("stalled gateway: %v after %v", err, time.Since(start))
	}
}

func TestGatewayGeneration(t *testing.T) {
	a, _, _ := prAgent(t, 14)
	var body atomic.Value
	body.Store(`{"generation":17}`)
	var path atomic.Value
	_, dialed := prGateway(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		io.WriteString(w, body.Load().(string))
	}))
	g, err := a.GatewayGeneration(context.Background())
	if err != nil || g != 17 {
		t.Fatalf("generation %d, %v", g, err)
	}
	if path.Load() != "/-/health" {
		t.Fatalf("path %v", path.Load())
	}
	if d := dialed(); len(d) != 1 || d[0] != a.cfg.GatewayIngressIP+":8443" {
		t.Fatalf("dialled %q", d)
	}
	for _, b := range []string{`{"generation":"17"}`, `{`, `{"generation":1,"x":2}`, `{"generation":1}{}`, strings.Repeat(" ", 8192) + `{"generation":1}`} {
		body.Store(b)
		if _, err := a.GatewayGeneration(context.Background()); err == nil {
			t.Errorf("body %.40q accepted", b)
		}
	}
}

// ───────── further route and adoption tests ─────────

// TestSetRoute_FlagDrainStress races activations of many projects against
// repeated rounds of "set the flag, drain everything, check, clear the flag":
// between the drain's return and the clear, the file never holds an active
// entry. PR_STRESS_SECONDS lengthens the run (default 2 s).
func TestSetRoute_FlagDrainStress(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	d := 2 * time.Second
	if v, err := strconv.Atoi(os.Getenv("PR_STRESS_SECONDS")); err == nil && v > 0 {
		d = time.Duration(v) * time.Second
	}
	const n = 16
	var stop atomic.Bool
	var wg sync.WaitGroup
	var accepted atomic.Int64
	errs := make(chan error, n)
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := prRoute(t, a, i, "active")
			for !stop.Load() {
				_, err := a.SetRoute(ctx, prRef(i), r)
				if err == nil {
					accepted.Add(1)
				} else if !errors.Is(err, ErrContainment) {
					errs <- err
					return
				}
			}
		}()
	}
	rounds := 0
	for end := time.Now().Add(d); time.Now().Before(end); rounds++ {
		a.SetContainmentFailed(true)
		if _, err := a.DrainAllRoutes(ctx); err != nil {
			t.Fatal(err)
		}
		for k := 0; k < 20; k++ {
			for ref, p := range prReadRoutes(t, a).Projects {
				if p.State != "draining" {
					t.Fatalf("round %d: %s is %s after flag and drain", rounds, ref, p.State)
				}
			}
		}
		a.SetContainmentFailed(false)
		time.Sleep(5 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if rounds < 10 || accepted.Load() == 0 {
		t.Fatalf("%d rounds, %d activations accepted: the race was not exercised", rounds, accepted.Load())
	}
	t.Logf("%d rounds, %d activations accepted", rounds, accepted.Load())
}

// The gateway keeps its last table while the route file is missing, and the
// saga waits for the gateway's generation to reach the one written. A
// generation that restarts at 1 after the file was lost reads as already
// reached against the old table.
func TestSetRoute_GenerationNeverGoesDownAfterFileLoss(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	var last int64
	for i := 1; i <= 3; i++ {
		g, err := a.SetRoute(ctx, prRef(i), prRoute(t, a, i, "active"))
		if err != nil {
			t.Fatal(err)
		}
		last = g
	}
	if err := os.Remove(prRoutePath(a)); err != nil {
		t.Fatal(err)
	}
	g, err := a.DrainAllRoutes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g <= last {
		t.Fatalf("generation %d after the file was lost, last written %d", g, last)
	}
}

// Draining is the containment response: a route file that does not parse
// must not keep it from being written. Every entry is rebuilt from the
// store by the ensure loop, so an empty table is the fail-closed answer.
func TestDrainAllRoutes_UnparsableFileFailsClosed(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	if _, err := a.SetRoute(ctx, prRef(1), prRoute(t, a, 1, "active")); err != nil {
		t.Fatal(err)
	}
	os.Remove(prRoutePath(a))
	if err := os.WriteFile(prRoutePath(a), []byte(`{"generation":5`), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DrainAllRoutes(ctx); err != nil {
		t.Fatalf("drain over an unparsable file: %v", err)
	}
	for ref, p := range prReadRoutes(t, a).Projects {
		if p.State != "draining" {
			t.Fatalf("%s is %s", ref, p.State)
		}
	}
}

// A running postgrest-<ref> attached to a network beyond its two is not the
// container the agent created; adopting it would leave a tenant's REST
// service on another project's network.
func TestEnsurePostgREST_ExtraNetworkNotAdopted(t *testing.T) {
	for name, net := range map[string]string{"another project": "proj-" + prRef(15), "ingress": "ingress"} {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			prRunning(t, a, f, s)
			f.ctrs["postgrest-"+s.Ref].Nets[net] = a.cfg.PostgRESTAddr(15).String()
			if err := a.EnsurePostgREST(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			if m := f.mutations(); len(m) == 0 || m[0] != "docker rm -f -- postgrest-"+s.Ref {
				t.Fatalf("adopted a container also on %s: %q", net, m)
			}
		})
	}
}

// No tenant-facing container may swap beyond its memory bound: the create
// carries --memory-swap equal to --memory.
func TestEnsurePostgREST_NoSwap(t *testing.T) {
	a, f, s := prAgent(t, 14)
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if argv := prCreateArgv(t, f); !prPair(argv, "--memory", "256m") || !prPair(argv, "--memory-swap", "256m") {
		t.Fatalf("create: %q", argv)
	}
}

// A gateway that answers the probe with a redirect is not followed: the
// probe fails and the target is never asked.
func TestProbeREST_RedirectNotFollowed(t *testing.T) {
	a, _, s := prAgent(t, 14)
	var hits atomic.Int64
	prGateway(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			hits.Add(1)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	if err := a.ProbeREST(context.Background(), s.Ref, "t"); err == nil {
		t.Fatal("redirect counted as success")
	}
	if hits.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

// Drains racing additions lose no entry: both hold the same lock around the
// read-modify-rename.
func TestDrainAllRoutes_SerialisedWithSetRoute(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	base, err := a.DrainAllRoutes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := a.SetRoute(ctx, prRef(i), prRoute(t, a, i, "draining")); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := a.DrainAllRoutes(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f := prReadRoutes(t, a); len(f.Projects) != 50 || f.Generation != base+100 {
		t.Fatalf("%d entries at generation %d, want 50 at %d", len(f.Projects), f.Generation, base+100)
	}
}

// A health answer other than 200, or one without a generation, is no
// generation.
func TestGatewayGeneration_StatusAndMissingField(t *testing.T) {
	a, _, _ := prAgent(t, 14)
	var status atomic.Int64
	var body atomic.Value
	prGateway(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		io.WriteString(w, body.Load().(string))
	}))
	for _, c := range []struct {
		status int64
		body   string
	}{{503, `{"generation":9}`}, {200, `{}`}, {200, `{"generation":null}`}} {
		status.Store(c.status)
		body.Store(c.body)
		if g, err := a.GatewayGeneration(context.Background()); err == nil {
			t.Errorf("%d %s: generation %d accepted", c.status, c.body, g)
		}
	}
}

// ───────── activation, labels and keys ─────────

// prNet registers proj-<ref> for slice i with the platform's options.
func prNet(a *Agent, f *fakeHost, ref string, i int) {
	f.net(fakeNet{Network: dockerx.Network{Name: "proj-" + ref, Internal: true, Subnet: a.cfg.Slice(i).String(),
		BridgeName: nodecfg.BridgeName(i), Options: map[string]string{
			"com.docker.network.bridge.name":              nodecfg.BridgeName(i),
			"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}})
}

// prRouteAgent is newTestAgent with the project networks of prRef(i) at
// slice i for i < 128, so that activations can be checked against them.
func prRouteAgent(t testing.TB) (*Agent, *fakeHost, Spec) {
	t.Helper()
	a, f, s := newTestAgent(t)
	for i := 0; i < 128; i++ {
		prNet(a, f, prRef(i), i)
	}
	return a, f, s
}

func TestSetRoute_ActiveBoundToProjectNetwork(t *testing.T) {
	a, f, _ := prRouteAgent(t)
	ctx := context.Background()
	// Project 1's address offered for project 2, while project 1 has no entry.
	_, err := a.SetRoute(ctx, prRef(2), prRoute(t, a, 1, "active"))
	if err == nil || errors.Is(err, ErrContainment) {
		t.Fatalf("another project's address for an active route: %v, want a plain refusal", err)
	}
	if _, err := os.Stat(prRoutePath(a)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused activation wrote the file: %v", err)
	}
	if _, err := a.SetRoute(ctx, prRef(2), prRoute(t, a, 2, "active")); err != nil {
		t.Fatalf("own address: %v", err)
	}
	// A project network that is not the platform's names no index.
	f.nets["proj-"+prRef(3)].Subnet = a.cfg.Slice(4).String()
	if _, err := a.SetRoute(ctx, prRef(3), prRoute(t, a, 3, "active")); err == nil {
		t.Fatal("activation over a project network with another subnet")
	}
	// No network, or Docker failing: active refused, draining and removal written.
	delete(f.nets, "proj-"+prRef(5))
	f.failInspect["proj-"+prRef(6)] = errors.New("daemon unavailable")
	for _, n := range []int{5, 6} {
		before, _ := os.ReadFile(prRoutePath(a))
		if _, err := a.SetRoute(ctx, prRef(n), prRoute(t, a, n, "active")); err == nil || errors.Is(err, ErrContainment) {
			t.Fatalf("project %d: activation without its network read: %v", n, err)
		}
		if after, _ := os.ReadFile(prRoutePath(a)); !bytes.Equal(before, after) {
			t.Fatalf("project %d: refused activation changed the file", n)
		}
		if _, err := a.SetRoute(ctx, prRef(n), prRoute(t, a, n, "draining")); err != nil {
			t.Fatalf("project %d: draining: %v", n, err)
		}
		if _, err := a.SetRoute(ctx, prRef(n), nil); err != nil {
			t.Fatalf("project %d: removal: %v", n, err)
		}
	}
}

func TestSetRoute_GenerationAfterFileLossBySetRoute(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	var seen []int64
	for i := 1; i <= 3; i++ {
		g, err := a.SetRoute(ctx, prRef(i), prRoute(t, a, i, "active"))
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, g)
	}
	if err := os.Remove(prRoutePath(a)); err != nil {
		t.Fatal(err)
	}
	g, err := a.SetRoute(ctx, prRef(4), prRoute(t, a, 4, "active"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range seen {
		if g <= s {
			t.Fatalf("generation %d after the file was lost, earlier %v", g, seen)
		}
	}
	if next, err := a.SetRoute(ctx, prRef(4), nil); err != nil || next != g+1 {
		t.Fatalf("after the seed: %d %v, want %d", next, err, g+1)
	}
}

func TestEnsurePostgREST_CreateArgsInConfigLabel(t *testing.T) {
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	c := f.ctrs["postgrest-"+s.Ref]
	argv := slices.Clone(c.Argv)
	label := c.Labels["supapace.config"]
	// The label is derived from the configuration file's hash and the create
	// arguments without the label itself.
	i := slices.Index(argv, "supapace.config="+label)
	if i < 1 {
		t.Fatalf("no config label in %q", argv)
	}
	args := slices.Delete(slices.Clone(argv), i-1, i+1)
	fileHash, err := renderedHash(a.postgrestDir(s.Ref), "postgrest.conf")
	if err != nil {
		t.Fatal(err)
	}
	if got := prLabel(t, a, fileHash, args); got != label {
		t.Fatalf("label %s, recomputed %s", label, got)
	}
	// A container created with one other argument and the same configuration.
	older := slices.Clone(args)
	older[slices.Index(older, "--pids-limit")+1] = "65"
	c.Labels["supapace.config"] = prLabel(t, a, fileHash, older)
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) == 0 || m[0] != "docker rm -f -- postgrest-"+s.Ref {
		t.Fatalf("container with older arguments adopted: %q", m)
	}
	if got := f.ctrs["postgrest-"+s.Ref].Labels["supapace.config"]; got != label {
		t.Fatalf("re-created with label %s, want %s", got, label)
	}
}

func TestEnsurePostgREST_MalformedKeyRefused(t *testing.T) {
	for name, pub := range map[string]*rsa.PublicKey{"nil modulus": {E: 65537}, "nil key": nil} {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			s.Keys[2].Pub = pub
			if err := a.EnsurePostgREST(context.Background(), s); err == nil {
				t.Fatal("accepted")
			}
			prNothingWritten(t, a, f, s)
			r := a.RouteFor(s, "draining")
			if _, err := a.SetRoute(context.Background(), s.Ref, &r); err == nil {
				t.Fatal("route with a malformed key accepted")
			}
		})
	}
}

// TestEnsurePostgREST_OneRunnerPerPlatformAddr: two projects whose specs
// name the same slice (a caller fault) never both have a running REST
// container at its platform address, whichever runs first or is stopped.
func TestEnsurePostgREST_OneRunnerPerPlatformAddr(t *testing.T) {
	a, f, sa := prAgent(t, 14)
	sb := sa
	sb.Ref = prRef(77)
	prNet(a, f, sb.Ref, 14)
	addr := a.cfg.PlatformAddr(14).String()
	holders := func() []string {
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []string
		for _, c := range f.ctrs {
			if c.Running && c.Nets["platform"] == addr {
				out = append(out, c.Name)
			}
		}
		slices.Sort(out)
		return out
	}
	ctx := context.Background()
	if err := a.EnsurePostgREST(ctx, sa); err != nil {
		t.Fatal(err)
	}
	wantContainment(t, a.EnsurePostgREST(ctx, sb), "second project at a held address")
	if h := holders(); !slices.Equal(h, []string{"postgrest-" + sa.Ref}) {
		t.Fatalf("running at %s: %q", addr, h)
	}
	// A stopped holder frees the address in Docker; then the other may run,
	// and the first can no longer start.
	f.ctrs["postgrest-"+sa.Ref].Running = false
	if err := a.EnsurePostgREST(ctx, sb); err != nil {
		t.Fatalf("project B with A stopped: %v", err)
	}
	wantContainment(t, a.EnsurePostgREST(ctx, sa), "first project after the other took its address")
	if h := holders(); !slices.Equal(h, []string{"postgrest-" + sb.Ref}) {
		t.Fatalf("running at %s: %q", addr, h)
	}
}

// ───────── gateway certificate ─────────

// A renewed node certificate re-creates the gateway, so the certificate the
// probes pin is the one the gateway serves after its restart.
func TestEnsureGateway_RenewedCertificateRecreatesForProbes(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	ctx := context.Background()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	f.resetLog()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("unchanged certificate: %q", m)
	}
	os.WriteFile(filepath.Join(a.p.TLSDir(), "cert.pem"), []byte("RENEWED"), 0o600)
	f.resetLog()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) == 0 || m[0] != "docker rm -f -- sp-gateway" {
		t.Fatalf("renewed certificate, gateway adopted: %q", m)
	}
	if b, _ := os.ReadFile(filepath.Join(a.p.GatewayDir(), "tls", "cert.pem")); string(b) != "RENEWED" {
		t.Fatalf("pinned file %q", b)
	}
	if c := f.ctrs["sp-gateway"]; c == nil || !c.Running {
		t.Fatal("gateway not running after the renewal")
	}
}

// A running container whose rendered configuration changed (here: another
// authenticator password) or whose command differs is not adopted.
func TestEnsurePostgREST_ConfigLabelCoversFileAndCommand(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		a, f, s := prAgent(t, 14)
		prRunning(t, a, f, s)
		s.Secrets.AuthenticatorPassword += "x"
		if err := a.EnsurePostgREST(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		if m := f.mutations(); len(m) == 0 || m[0] != "docker rm -f -- postgrest-"+s.Ref {
			t.Fatalf("container with another configuration adopted: %q", m)
		}
	})
	t.Run("command", func(t *testing.T) {
		a, f, s := prAgent(t, 14)
		prRunning(t, a, f, s)
		c := f.ctrs["postgrest-"+s.Ref]
		label := c.Labels["supapace.config"]
		args := slices.Clone(c.Argv)
		i := slices.Index(args, "supapace.config="+label)
		args = slices.Delete(args, i-1, i+1)
		args[len(args)-1] = "/etc/postgrest/other.conf"
		fileHash, err := renderedHash(a.postgrestDir(s.Ref), "postgrest.conf")
		if err != nil {
			t.Fatal(err)
		}
		c.Labels["supapace.config"] = prLabel(t, a, fileHash, args)
		if err := a.EnsurePostgREST(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		if m := f.mutations(); len(m) == 0 || m[0] != "docker rm -f -- postgrest-"+s.Ref {
			t.Fatalf("container with another command adopted: %q", m)
		}
	})
}

// ───────── generation counter, profile digest, refusal cleanup ─────────

// prClock pins the route file's clock to ms for the rest of the test.
func prClock(t testing.TB, ms int64) {
	t.Cleanup(swap(&nowMilli, func() int64 { return ms }))
}

func prLoseFile(t testing.TB, a *Agent) {
	t.Helper()
	if err := os.Remove(prRoutePath(a)); err != nil {
		t.Fatal(err)
	}
}

func TestSetRoute_GenerationMonotonicWhenClockStepsBack(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	var last int64
	for i := 1; i <= 3; i++ {
		g, err := a.SetRoute(ctx, prRef(i), prRoute(t, a, i, "active"))
		if err != nil {
			t.Fatal(err)
		}
		last = g
	}
	prClock(t, 5) // the clock stepped back far
	prLoseFile(t, a)
	g, err := a.SetRoute(ctx, prRef(4), prRoute(t, a, 4, "active"))
	if err != nil {
		t.Fatal(err)
	}
	if g <= last {
		t.Fatalf("generation %d after a clock step back and a lost file, last written %d", g, last)
	}
	prLoseFile(t, a)
	if d, err := a.DrainAllRoutes(ctx); err != nil || d <= g {
		t.Fatalf("drain after a second loss: %d %v, last written %d", d, err, g)
	}
}

func TestSetRoute_GenerationMonotonicTwoLossesInOneMillisecond(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	ctx := context.Background()
	prClock(t, time.Now().UnixMilli()+1<<40) // a fixed instant above every earlier value
	var seen []int64
	for n := 0; n < 3; n++ {
		g, err := a.SetRoute(ctx, prRef(1), prRoute(t, a, 1, "active"))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range seen {
			if g <= s {
				t.Fatalf("loss %d within one millisecond: generation %d, earlier %v", n, g, seen)
			}
		}
		seen = append(seen, g)
		prLoseFile(t, a)
	}
}

func TestEnsurePostgREST_SeccompProfileInConfigLabel(t *testing.T) {
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	old := f.ctrs["postgrest-"+s.Ref]
	// The profile changes on disk (another daemon release): not adoptable.
	changed := append(slices.Clone(seccompProfile), '\n')
	if err := nodefs.WriteFile(a.p, a.p.PlatformDir(), "seccomp.json", changed, 0o444, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) == 0 || m[0] != "docker rm -f -- postgrest-"+s.Ref {
		t.Fatalf("container started with another profile adopted: %q", m)
	}
	nc := f.ctrs["postgrest-"+s.Ref]
	if nc.ID == old.ID || !nc.Running || nc.Labels["supapace.config"] == old.Labels["supapace.config"] {
		t.Fatalf("not re-created with a new label: %+v", nc)
	}
	// Unchanged profile again: adopted.
	f.resetLog()
	if err := a.EnsurePostgREST(context.Background(), s); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("same profile: %v %q", err, f.mutations())
	}
}

func TestEnsurePostgREST_MissingSeccompProfile(t *testing.T) {
	for _, running := range []bool{false, true} {
		t.Run(fmt.Sprintf("running=%v", running), func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			if running {
				prRunning(t, a, f, s)
			}
			if err := os.Remove(filepath.Join(a.p.PlatformDir(), "seccomp.json")); err != nil {
				t.Fatal(err)
			}
			if err := a.EnsurePostgREST(context.Background(), s); err == nil {
				t.Fatal("no profile, accepted")
			}
			if m := f.mutations(); len(m) != 0 {
				t.Fatalf("docker mutated without a profile: %q", m)
			}
			if c := f.ctrs["postgrest-"+s.Ref]; running != (c != nil) {
				t.Fatalf("container: %+v", c)
			}
		})
	}
}

func TestEnsurePostgREST_RefusalRemovesCreated(t *testing.T) {
	faults := map[string]func(a *Agent, f *fakeHost, s Spec){
		"gate": func(a *Agent, f *fakeHost, s Spec) { f.nftErr = nft.ErrDrift },
		"address in use": func(a *Agent, f *fakeHost, s Spec) {
			f.before = func(args []string) {
				if args[0] == "start" && f.ctrs["intruder"] == nil {
					f.ctr(fakeCtr{Name: "intruder", Running: true, CapDrop: []string{"ALL"},
						Nets: map[string]string{"platform": a.cfg.PlatformAddr(14).String()}})
				}
			}
		},
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			fault(a, f, s)
			wantContainment(t, a.EnsurePostgREST(context.Background(), s), name)
			if c := f.ctrs["postgrest-"+s.Ref]; c != nil {
				t.Fatalf("refused container left behind: %+v", c)
			}
			last := "nft check"
			if name == "address in use" {
				last = "docker start"
			}
			prOrder(t, f.calls(), "docker create", "docker network connect", last, "docker rm -f -- postgrest-"+s.Ref)
		})
	}
	// A failing removal is reported beside the refusal, which stays matchable.
	a, f, s := prAgent(t, 14)
	f.nftErr = nft.ErrDrift
	boom := errors.New("rm failed")
	f.failVerb["rm"] = boom
	err := a.EnsurePostgREST(context.Background(), s)
	if !errors.Is(err, ErrContainment) || !errors.Is(err, boom) {
		t.Fatalf("refusal with a failed removal: %v", err)
	}
}

// TestSetRoute_GenerationSeededFromClock: a process that has written nothing
// yet (a restarted daemon) and finds no file starts from the wall clock.
func TestSetRoute_GenerationSeededFromClock(t *testing.T) {
	a, _, _ := prRouteAgent(t)
	t.Cleanup(swap(&lastGen, 0))
	const now = int64(1) << 41
	prClock(t, now)
	g, err := a.SetRoute(context.Background(), prRef(1), prRoute(t, a, 1, "active"))
	if err != nil || g != now+1 {
		t.Fatalf("first generation %d %v, want %d", g, err, now+1)
	}
}

// The removal after a refusal runs on its own context: a caller whose
// context has ended (the refusal may be that deadline) still has the created
// container removed.
func TestEnsurePostgREST_RefusalRemovesAfterCallerCancel(t *testing.T) {
	a, f, s := prAgent(t, 14)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.nftErr = nft.ErrDrift
	f.before = func(args []string) {
		if len(args) > 1 && args[0] == "network" && args[1] == "connect" {
			cancel()
		}
	}
	inner := dockerRun
	t.Cleanup(swap(&dockerRun, func(c context.Context, args ...string) (string, error) {
		if args[0] == "rm" && c.Err() != nil {
			return "", c.Err()
		}
		return inner(c, args...)
	}))
	wantContainment(t, a.EnsurePostgREST(ctx, s), "gate after cancel")
	if c := f.ctrs["postgrest-"+s.Ref]; c != nil {
		t.Fatalf("refused container left behind after the caller's context ended: %+v", c)
	}
}
