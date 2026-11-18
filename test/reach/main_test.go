//go:build reach

package reach

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
)

// TestMain resets the node (drift hold, failpoint, our tables, scratch
// objects, the second source address), then builds fixture projects A and B,
// runs the tests and runs the fixtures' cleanups. A and B are kept on the node
// between runs (a reboot test needs tenants that existed before the reboot),
// but only for the daemon build that created them: suiteDir records that
// build's sha256 beside the issuer keys. -test.list touches nothing.
func TestMain(m *testing.M) {
	flag.Parse()
	if f := flag.Lookup("test.list"); f != nil && f.Value.String() != "" {
		os.Exit(m.Run())
	}
	if msg := preflight(); msg != "" {
		fmt.Fprintf(os.Stderr, "reach: cannot run on this node:\n%s", msg)
		os.Exit(1)
	}
	if err := suiteReset(); err != nil {
		fmt.Fprintln(os.Stderr, "reach: suite reset:", err)
		os.Exit(1)
	}
	if fi, err := os.Stat(paths.AdminSock()); err != nil || fi.Mode()&fs.ModeSocket == 0 {
		fmt.Fprintf(os.Stderr, "reach: admin socket %s absent: supapaced serve is not running\n", paths.AdminSock())
		os.Exit(1)
	}
	mt := &mainT{}
	if !mt.run(buildFixtures) {
		mt.cleanup()
		fmt.Fprintln(os.Stderr, "reach: fixture projects A and B could not be built; no test ran")
		os.Exit(1)
	}
	code := m.Run()
	mt.cleanup()
	os.Exit(code)
}

// preflight names every missing piece the suite needs.
func preflight() string {
	var b strings.Builder
	if os.Geteuid() != 0 {
		b.WriteString("  not root: the suite runs on the node as root\n")
	}
	for _, c := range []struct{ path, what string }{
		{daemonBin, "the daemon supapaced"}, {cliBin, "the CLI supapace"}, {probeBin, "the probe sp-probe"},
	} {
		if fi, err := os.Stat(c.path); err != nil || fi.Mode()&0o111 == 0 {
			fmt.Fprintf(&b, "  %s not found: %s is not built\n", c.path, c.what)
		}
	}
	for _, tool := range []string{"docker", "nsenter", "nft", "ss", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Fprintf(&b, "  %s not on PATH\n", tool)
		}
	}
	return b.String()
}

// suiteReset is the reset the Makefile also runs before and after the binary:
// no drift hold, no failpoint, our tables loaded, no object labelled
// supapace.test=1, no second source address.
func suiteReset() error {
	var errs []error
	if err := os.Remove(paths.Failpoint()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	if r, err := run(cmdTimeout, nil, daemonBin, "nft", "load"); err != nil || r.code != 0 {
		return fmt.Errorf("supapaced nft load: %v exit %d %s", err, r.code, brief(r.stderr))
	}
	for _, kind := range [][]string{{"ps", "-aq"}, {"network", "ls", "-q"}} {
		r, err := run(cmdTimeout, nil, append(append([]string{"docker"}, kind...), "--filter", "label="+testLabel)...)
		if err != nil || r.code != 0 {
			errs = append(errs, fmt.Errorf("docker %s: %v %s", kind[0], err, brief(r.stderr)))
			continue
		}
		ids := strings.Fields(r.stdout)
		if len(ids) == 0 {
			continue
		}
		rm := []string{"docker", "rm", "-f", "-v"}
		if kind[0] == "network" {
			rm = []string{"docker", "network", "rm"}
		}
		if r, err := run(cmdTimeout, nil, append(rm, ids...)...); err != nil || r.code != 0 {
			errs = append(errs, fmt.Errorf("removing scratch objects: %v %s", err, brief(r.stderr)))
		}
	}
	// Probe listeners of a killed run keep scratch namespaces (and the routed
	// neighbour's veth) alive.
	if r, err := run(cmdTimeout, nil, "pkill", "-x", "-f", probeBin+" listen .*"); err != nil || r.code > 1 {
		errs = append(errs, fmt.Errorf("pkill of left-over listeners: %v exit %d", err, r.code))
	}
	if r, err := run(cmdTimeout, nil, "ip", "link", "del", "sp-nb0"); err != nil || (r.code != 0 && !strings.Contains(r.stderr, "Cannot find")) {
		errs = append(errs, fmt.Errorf("ip link del sp-nb0: %v %s", err, brief(r.stderr)))
	}
	if err := delSourceAddr(); err != nil {
		errs = append(errs, err)
	}
	// The drift hold goes last: scratch networks and members are gone by now.
	if err := os.Remove(paths.DriftHold()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func buildFixtures(t testing.TB) {
	if err := os.MkdirAll(suiteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suiteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	build := daemonSum(t)
	stored, _ := os.ReadFile(buildFile())
	sameBuild := string(stored) == build
	out, code := cli(t, "project", "list")
	if code != 0 {
		t.Fatalf("project list: exit %d", code)
	}
	var list projectsJSON
	decode(t, "project list", out, &list)
	for _, p := range list.Projects {
		if p.Name == scratchName && !removeProject(t, p.Ref) {
			t.Fatalf("a scratch project of an earlier run (%s) cannot be removed", p.Ref)
		}
	}
	a := suiteProject(t, list.Projects, "reach-a", true, sameBuild)
	b := suiteProject(t, list.Projects, "reach-b", false, sameBuild)
	fixA, fixB = &a, &b
	// Issuer keys of any other ref are stale.
	files, _ := filepath.Glob(filepath.Join(suiteDir, "issuer-*.der"))
	for _, f := range files {
		if f != issuerFile(a.Ref) && f != issuerFile(b.Ref) {
			if err := os.Remove(f); err != nil {
				t.Errorf("removing a stale issuer key: %v", err)
			}
		}
	}
	if err := os.WriteFile(buildFile(), []byte(build), 0o600); err != nil {
		t.Fatal(err)
	}
}

func buildFile() string { return filepath.Join(suiteDir, "supapaced.sha256") }

// daemonSum is the sha256 of the supapaced binary, in hex.
func daemonSum(t testing.TB) string {
	f, err := os.Open(daemonBin)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fixtureSQL creates the whoami() and headers() functions.
const fixtureSQL = `create or replace function public.whoami() returns text language sql stable as $$ select current_setting('request.jwt.claims', true)::json->>'role' $$;
create or replace function public.headers() returns json language sql stable as $$ select current_setting('request.headers', true)::json $$;
grant execute on function public.whoami(), public.headers() to anon, authenticated, service_role;`

// suiteProject returns the project called name: when reuse is set, an active
// one whose issuer key this suite kept; every other project of that name is
// taken to a terminal state and a fresh one created. It then installs the
// fixture functions (and pg_graphql when graphql is set) and waits until the
// gateway serves them.
func suiteProject(t testing.TB, existing []listedProject, name string, graphql, reuse bool) Project {
	var p *Project
	for _, e := range existing {
		if e.Name != name {
			continue
		}
		if reuse && e.State == "active" && p == nil {
			if priv, err := loadIssuer(e.Ref); err == nil {
				lp := loadProject(t, e.Ref, priv, jwtx.KID(&priv.PublicKey))
				p = &lp
				continue
			}
		}
		if !removeProject(t, e.Ref) {
			t.Fatalf("project %s (%s) of an earlier run cannot be removed", name, e.Ref)
		}
	}
	if p == nil {
		priv, kid, jwks := newIssuer(t)
		out, code := cli(t, "project", "create", "--name", name, "--issuer-jwks", jwks)
		var op Op
		decode(t, "project create", out, &op)
		if code != 0 || op.State != "done" {
			t.Fatalf("creating %s: exit %d, operation %s at step %q: %s", name, code, op.State, op.Step, op.LastError)
		}
		saveIssuer(t, op.Ref, priv)
		lp := loadProject(t, op.Ref, priv, kid)
		p = &lp
	}
	sql := fixtureSQL
	if graphql {
		sql += "\ncreate extension if not exists pg_graphql;"
	}
	if _, err := sqlAs(t, *p, "postgres", sql+"\nnotify pgrst, 'reload schema';"); err != nil {
		t.Fatalf("fixture functions in %s: %v", name, err)
	}
	waitServed(t, *p)
	return *p
}

func issuerFile(ref string) string { return filepath.Join(suiteDir, "issuer-"+ref+".der") }

func saveIssuer(t testing.TB, ref string, k *rsa.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(issuerFile(ref), der, 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadIssuer(ref string) (*rsa.PrivateKey, error) {
	der, err := os.ReadFile(issuerFile(ref))
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return priv, nil
}

// waitServed waits up to 60 s for p's whoami() to answer through the gateway
// both "anon" for p's anon key and "authenticated" for a token of p's issuer
// (which shows the kept issuer key is the one the project trusts).
func waitServed(t testing.TB, p Project) {
	deadline := time.Now().Add(time.Minute)
	for _, c := range []struct{ auth, role string }{{"", "anon"}, {"Bearer " + p.UserToken("authenticated", nil), "authenticated"}} {
		last := ""
		for {
			h := http.Header{}
			h.Set("apikey", p.AnonKey)
			if c.auth != "" {
				h.Set("Authorization", c.auth)
			}
			resp, err := gatewayRoundTrip(t, p, "GET", whoamiPath, h, nil, netip.Addr{})
			switch {
			case err != nil:
				last = errText(err)
			case resp.StatusCode == 200 && strings.TrimSpace(string(bodyOf(resp))) == `"`+c.role+`"`:
				last = ""
			default:
				last = redact(fmt.Sprintf("status %d: %s", resp.StatusCode, brief(string(bodyOf(resp)))))
			}
			if last == "" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("project %s: whoami() as %s not served through the gateway within 60 s (last: %s)", p.Ref, c.role, last)
			}
			time.Sleep(time.Second)
		}
	}
}
