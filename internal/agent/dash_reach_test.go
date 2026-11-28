//go:build reach

package agent

// The dashboard's containers on a bare node, as root, with the Studio image
// and the pinned postgres-meta image loaded (make node-proof PKG=internal/agent
// RUN=<these tests>). Each test makes the node a dashboard node, runs
// EnsureDashboard for real, and removes what it made.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashsock"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

const dashNodeDomain = "studio.test"

// dashNode makes this bare node a dashboard node and runs EnsureDashboard: the
// studio pair stored as init stores it, the seccomp profile, the platform
// networks. Cleanup removes the containers, the networks and every directory
// the dashboard made.
func dashNode(t *testing.T) (*Agent, dashcfg.Addrs) {
	t.Helper()
	a := nodeAgent(t)
	a.cfg.StudioDomain = dashNodeDomain
	ad, err := dashcfg.For(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	d := dashcfg.PathsFor(a.p)
	cleanup := func() {
		nodeDockerQuiet("rm", "-f", dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgMeta1Name)
		nodeDockerQuiet("network", "rm", platformNet, ingressNet)
		for _, p := range []string{d.KeyDir(), d.StudioTLS(), d.DashDir(), d.DataDir(), d.GatewayDash(), d.GatewayStudioTLS()} {
			os.RemoveAll(p)
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	if err := os.MkdirAll(filepath.Dir(d.StudioTLS()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(d.StudioTLS(), 0o700); err != nil {
		t.Fatal(err)
	}
	cert, key := dashSelfSigned(t, dashNodeDomain, "*."+dashNodeDomain)
	for n, b := range map[string][]byte{"key.pem": key, "cert.pem": cert} {
		if err := os.WriteFile(filepath.Join(d.StudioTLS(), n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.ensurePlatformDir(); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(a.p, a.p.PlatformDir(), "seccomp.json", seccompProfile, 0o444, 0, 0); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	return a, ad
}

func dashSelfSigned(t *testing.T, names ...string) (cert, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

// nodeExec runs node -e script in container (as its user, with its
// environment) and returns the trimmed standard output.
func dashExec(t *testing.T, container, script string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", container, "node", "-e", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %s: %v: %s", container, err, out)
	}
	return strings.TrimSpace(string(out))
}

// waitHTTP waits until a GET of url from inside container gets an answer
// (any status, printed), at most 120 s.
func dashWaitHTTP(t *testing.T, container, url string) string {
	t.Helper()
	script := `fetch(` + strconv.Quote(url) + `).then(r => console.log(r.status)).catch(e => console.log("error " + (e.cause ? e.cause.code : e)))`
	for deadline := time.Now().Add(120 * time.Second); ; {
		out, _ := exec.Command("docker", "exec", container, "node", "-e", script).CombinedOutput()
		s := strings.TrimSpace(string(out))
		if s != "" && !strings.HasPrefix(s, "error") && !strings.Contains(s, "Error") {
			return s
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "30", container).CombinedOutput()
			t.Fatalf("%s: %s did not answer: %s\n%s", container, url, s, logs)
		}
		time.Sleep(time.Second)
	}
}

type dashInspected struct {
	Config struct {
		User  string
		Env   []string
		Image string
	}
	HostConfig struct {
		ReadonlyRootfs bool
		CapDrop        []string
		CapAdd         []string
		Privileged     bool
		NetworkMode    string
	}
	State struct {
		Running bool
		Pid     int
	}
	Mounts []struct {
		Source, Destination string
		RW                  bool
	}
}

func dashInspect(t *testing.T, name string) dashInspected {
	t.Helper()
	var c []dashInspected
	if err := json.Unmarshal([]byte(nodeDocker(t, "container", "inspect", name)), &c); err != nil || len(c) != 1 {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return c[0]
}

// procIDs is the Uid and Gid lines of pid's status: real, effective, saved, fs.
func dashProcIDs(t *testing.T, pid int) (uid, gid string) {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Uid:"); ok {
			uid = strings.Join(strings.Fields(v), " ")
		}
		if v, ok := strings.CutPrefix(l, "Gid:"); ok {
			gid = strings.Join(strings.Fields(v), " ")
		}
	}
	return uid, gid
}

func envNames(env []string) []string {
	var n []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		n = append(n, k)
	}
	slices.Sort(n)
	return slices.Compact(n)
}

func TestPgMeta_RunsAsBuiltForThePlatform(t *testing.T) {
	a, _ := dashNode(t)
	d := dashcfg.PathsFor(a.p)
	crypto, err := os.ReadFile(filepath.Join(d.KeyDir(), keyCrypto))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := pgMetaImage()
	if err != nil {
		t.Fatal(err)
	}
	var image []struct{ Config struct{ Env []string } }
	if err := json.Unmarshal([]byte(nodeDocker(t, "image", "inspect", ref)), &image); err != nil || len(image) != 1 {
		t.Fatalf("image inspect %s: %v", ref, err)
	}
	want := envNames(slices.Concat(image[0].Config.Env, dashcfg.PgMetaEnv(dashcfg.Limits), []string{"CRYPTO_KEY_FILE="}))
	for _, n := range []string{dashcfg.PgMeta0Name, dashcfg.PgMeta1Name} {
		if s := dashWaitHTTP(t, n, "http://127.0.0.1:8080/health"); s != "200" {
			t.Errorf("%s: /health answered %s", n, s)
		}
		c := dashInspect(t, n)
		u := strconv.Itoa(dashcfg.PgMetaUID)
		if uid, gid := dashProcIDs(t, c.State.Pid); uid != strings.Repeat(u+" ", 3)+u || gid != strings.Repeat(u+" ", 3)+u {
			t.Errorf("%s runs as %s / %s", n, uid, gid)
		}
		if !c.HostConfig.ReadonlyRootfs || !slices.Equal(c.HostConfig.CapDrop, []string{"ALL"}) || len(c.HostConfig.CapAdd) != 0 ||
			c.HostConfig.Privileged || c.HostConfig.NetworkMode != platformNet ||
			len(c.Mounts) != 1 || c.Mounts[0].Source != pgmetaKeysDir(d) || c.Mounts[0].Destination != pgmetaKeysMount || c.Mounts[0].RW {
			t.Errorf("%s: %+v, mounts %+v", n, c.HostConfig, c.Mounts)
		}
		if got := envNames(c.Config.Env); !slices.Equal(got, want) {
			t.Errorf("%s: environment names %q, want %q", n, got, want)
		}
		if err := refuseLibpqNames(c.Config.Env); err != nil {
			t.Errorf("%s: %v", n, err)
		}
		// The key is in nothing Docker shows of the container.
		if strings.Contains(nodeDocker(t, "container", "inspect", n), string(crypto)) {
			t.Errorf("%s: the key is in docker inspect", n)
		}
		if got := dashExec(t, n, `console.log(process.env.CRYPTO_KEY === undefined && require("fs").readFileSync(process.env.CRYPTO_KEY_FILE, "utf8").length)`); got != "64" {
			t.Errorf("%s: the process's key: %s", n, got)
		}
		// What Studio seals with crypto.key is opened: a connection string
		// sealed with the file's bytes reaches the dead address (refused); one
		// sealed with another key, or with the image's built-in one, does not.
		query := func(key string) string {
			return dashExec(t, n, `const C = require("/usr/src/app/node_modules/crypto-js");
const h = C.AES.encrypt("postgresql://none:none@127.0.0.1:9/none", `+key+`).toString();
fetch("http://127.0.0.1:8080/query", {method: "POST", headers: {"content-type": "application/json", "x-connection-encrypted": h},
  body: JSON.stringify({query: "select 1"})}).then(async r => console.log(r.status + " " + await r.text()))`)
		}
		right := query(strconv.Quote(string(crypto)))
		wrong, builtin := query(`"another key of at least thirty-two bytes"`), query(`"SAMPLE_KEY"`)
		t.Logf("%s: with crypto.key %q; with another key %q; with the built-in one %q", n, right, wrong, builtin)
		if !strings.Contains(right, "ECONNREFUSED") || strings.Contains(wrong, "ECONNREFUSED") || strings.Contains(builtin, "ECONNREFUSED") {
			t.Errorf("%s: the file's key does not decide the connection string", n)
		}
	}
}

// dashSocket serves the real dashboard socket at SocketDir until the test
// ends; nothing is a member and no project is here.
func dashSocket(t *testing.T, a *Agent, ad dashcfg.Addrs) {
	t.Helper()
	d := dashcfg.PathsFor(a.p)
	b, err := os.ReadFile(filepath.Join(d.KeyDir(), keyAssertPub))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := dashtok.ParsePublic(b)
	if err != nil {
		t.Fatal(err)
	}
	l, err := dashsock.Listen(d)
	if err != nil {
		t.Fatal(err)
	}
	srv := dashsock.NewServer(pub, a.cfg.NodeID, a.cfg.Domain, ad, dashNoMembers{}, dashNoProjects{})
	go srv.Serve(l)
	t.Cleanup(func() { l.Close() })
}

type dashNoMembers struct{}

func (dashNoMembers) MemberRole(context.Context, string, string, string) (string, error) {
	return "", dashsock.ErrNotHere
}

type dashNoProjects struct{}

func (dashNoProjects) Facts(context.Context, string) (dashsock.Facts, error) {
	return dashsock.Facts{}, dashsock.ErrNotHere
}
func (dashNoProjects) Passwords(context.Context, string) (string, string, error) {
	return "", "", dashsock.ErrNotHere
}
func (dashNoProjects) Keys(context.Context, string) (string, string, []jwtx.Key, error) {
	return "", "", nil, dashsock.ErrNotHere
}

// dashSocketCall is a node script that posts /v1/resolve on the mounted socket
// with an assertion that does not verify and prints the status and body, or
// the connection's error code.
const dashSocketCall = `const r = require("http").request({socketPath: "/run/dash/dash.sock", method: "POST", path: "/v1/resolve",
  headers: {"X-Supapace-Assertion": "v1.x.y", "Content-Length": "0"}}, s => {
  let b = ""; s.on("data", d => b += d); s.on("end", () => console.log(s.statusCode + " " + b)) })
r.on("error", e => console.log("error " + e.code)); r.end()`

func TestSocketDir_ConnectThroughReadOnlyMount(t *testing.T) {
	a, ad := dashNode(t)
	dashSocket(t, a, ad)
	d := dashcfg.PathsFor(a.p)
	c := dashInspect(t, dashcfg.StudioName)
	ro := false
	for _, m := range c.Mounts {
		if m.Destination == studioSockMount {
			ro = !m.RW && m.Source == d.SocketDir()
		}
	}
	if !ro {
		t.Fatalf("the socket directory is not mounted read-only: %+v", c.Mounts)
	}
	dashWaitHTTP(t, dashcfg.StudioName, "http://127.0.0.1:3000/")
	// Studio's own container, through its read-only mount, reaches the server
	// past its peer check: the assertion is what fails.
	if got := dashExec(t, dashcfg.StudioName, dashSocketCall); got != `401 {"code":"bad_assertion"}` {
		t.Errorf("from sp-studio: %s", got)
	}
	if got := dashExec(t, dashcfg.StudioName, `try { require("fs").writeFileSync("/run/dash/x", "x"); console.log("written") } catch (e) { console.log(e.code) }`); got != "EROFS" {
		t.Errorf("writing into the mount: %s", got)
	}
}

func TestNode_SocketPeerCredentialsAreStudios(t *testing.T) {
	a, ad := dashNode(t)
	dashSocket(t, a, ad)
	d := dashcfg.PathsFor(a.p)
	call := func(name string, uid int, group bool) string {
		args := []string{"run", "--rm", "--name", "sp-test-dashpeer-" + name, "--label", "supapace.test=1", "--network", "none",
			"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(uid), "-v", d.SocketDir() + ":/run/dash:ro", "--entrypoint", "node"}
		if group {
			args = append(args, "--group-add", strconv.Itoa(dashcfg.StudioUID))
		}
		return nodeDocker(t, append(args, "--", dashcfg.StudioImage, "-e", dashSocketCall)...)
	}
	for _, c := range []struct {
		name  string
		uid   int
		group bool
		want  string
	}{
		{"studio", dashcfg.StudioUID, false, `401 {"code":"bad_assertion"}`}, // past the peer check
		{"pgmeta", dashcfg.PgMetaUID, true, `403 {"code":"peer"}`},
		{"other", 65530, true, `403 {"code":"peer"}`},
		{"outsider", 65530, false, "error EACCES"}, // the directory keeps it out
	} {
		if got := call(c.name, c.uid, c.group); got != c.want {
			t.Errorf("%s (uid %d, Studio's group %v): %s, want %s", c.name, c.uid, c.group, got, c.want)
		}
	}
}

func TestStudio_StartsReadOnlyAtItsUid(t *testing.T) {
	a, ad := dashNode(t)
	dashSocket(t, a, ad)
	d := dashcfg.PathsFor(a.p)
	status := dashWaitHTTP(t, dashcfg.StudioName, "http://127.0.0.1:3000/")
	t.Logf("Studio answered %s", status)
	c := dashInspect(t, dashcfg.StudioName)
	u := strconv.Itoa(dashcfg.StudioUID)
	if uid, gid := dashProcIDs(t, c.State.Pid); uid != strings.Repeat(u+" ", 3)+u || gid != strings.Repeat(u+" ", 3)+u {
		t.Errorf("Studio runs as %s / %s", uid, gid)
	}
	if !c.State.Running || !c.HostConfig.ReadonlyRootfs || !slices.Equal(c.HostConfig.CapDrop, []string{"ALL"}) ||
		len(c.HostConfig.CapAdd) != 0 || c.HostConfig.Privileged || c.HostConfig.NetworkMode != platformNet {
		t.Errorf("%+v", c.HostConfig)
	}
	want := map[string]string{studioSockMount: d.SocketDir() + " false", studioKeysMount: d.StudioKeys() + " false",
		studioDataMount: d.DataDir() + " true"}
	got := map[string]string{}
	for _, m := range c.Mounts {
		got[m.Destination] = m.Source + " " + strconv.FormatBool(m.RW)
	}
	if len(got) != 3 || got[studioSockMount] != want[studioSockMount] || got[studioKeysMount] != want[studioKeysMount] || got[studioDataMount] != want[studioDataMount] {
		t.Errorf("mounts %v, want %v", got, want)
	}
	// What the process sees beyond StudioEnv's list: the image's own ENV, and
	// Docker's HOSTNAME at run time.
	var image []struct {
		Config struct {
			Env    []string
			Labels map[string]string
		}
	}
	if err := json.Unmarshal([]byte(nodeDocker(t, "image", "inspect", dashcfg.StudioImage)), &image); err != nil || len(image) != 1 {
		t.Fatal(err)
	}
	var declared map[string]string
	json.Unmarshal([]byte(image[0].Config.Labels[labelStudioEnv]), &declared)
	list, err := dashcfg.StudioEnv(ad, a.cfg.NodeID, dashcfg.Limits, declared)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range c.Config.Env {
		if !slices.Contains(list, kv) && !slices.Contains(image[0].Config.Env, kv) {
			n, _, _ := strings.Cut(kv, "=")
			t.Errorf("%s reaches Studio from neither StudioEnv nor the image", n)
		}
	}
	seen := dashExec(t, dashcfg.StudioName, `console.log(Object.keys(process.env).sort().join(" "))`)
	for _, n := range strings.Fields(seen) {
		if !slices.Contains(envNames(slices.Concat(list, image[0].Config.Env)), n) && n != "HOSTNAME" && n != "HOME" {
			t.Errorf("the process sees %s", n)
		}
		if slices.Contains(dashcfg.ListenerNames, n) && !slices.Contains(envNames(list), n) {
			t.Errorf("the listener reads %s from outside the list", n)
		}
	}
	// Every fixed name is set, and each setting Studio reads at first use
	// holds as its reader checks it: absolute paths, the cache key's form,
	// the proxy's address and range, the fourteen limits; the data directory
	// writable, the key directory and the root not.
	for _, n := range dashcfg.FixedEnvNames() {
		if !slices.Contains(strings.Fields(seen), n) {
			t.Errorf("%s unset in Studio's process", n)
		}
	}
	check := dashExec(t, dashcfg.StudioName, `const fs = require("fs"), path = require("path"), e = process.env, bad = []
for (const n of ["SUPAPACE_DASH_SOCKET", "SUPAPACE_DASH_DATA", "SUPAPACE_DASH_KEYS"]) if (!path.isAbsolute(e[n] || "")) bad.push(n)
const text = fs.readFileSync(path.join(e.SUPAPACE_DASH_KEYS, "cache.key"), "latin1"), enc = text.replace(/=?\n?$/, "")
if (!/^[A-Za-z0-9_-]{43}$/.test(enc) || Buffer.from(enc, "base64url").toString("base64url") !== enc) bad.push("cache.key")
const m = /^(\d+\.\d+\.\d+\.\d+):(\d+):(\d+)$/.exec(e.SUPAPACE_PGCAP || ""); if (!m || +m[2] > +m[3] || +m[3] > 65535) bad.push("SUPAPACE_PGCAP")
const l = JSON.parse(e.SUPAPACE_LIMITS || "{}"); if (Object.keys(l).length !== 14 || !Object.values(l).every(v => Number.isSafeInteger(v) && v > 0)) bad.push("SUPAPACE_LIMITS")
if (!fs.statSync(path.dirname(e.SUPAPACE_DASH_SOCKET)).isDirectory()) bad.push("socket directory")
const probe = path.join(e.SUPAPACE_DASH_DATA, "probe"); fs.mkdirSync(probe, {mode: 0o700}); fs.writeFileSync(path.join(probe, "f"), "x"); fs.rmSync(probe, {recursive: true})
for (const p of [path.join(e.SUPAPACE_DASH_KEYS, "x"), "/x"]) try { fs.writeFileSync(p, "x"); bad.push(p + " writable") } catch (x) {}
for (const n of ["SUPAPACE_NODE_ID", "SUPAPACE_PGMETA"]) if (!e[n]) bad.push(n)
console.log(bad.length ? bad.join(", ") : "ok")`)
	if check != "ok" {
		t.Errorf("Studio's settings: %s", check)
	}
	// The real socket answers Studio's process through the mounted path.
	if got := dashExec(t, dashcfg.StudioName, dashSocketCall); got != `401 {"code":"bad_assertion"}` {
		t.Errorf("the socket from Studio: %s", got)
	}
	b, _ := os.ReadFile(filepath.Join(d.KeyDir(), keyCache))
	if bytes.Contains([]byte(nodeDocker(t, "container", "inspect", dashcfg.StudioName)), bytes.TrimSpace(b)) {
		t.Error("the cache key is in Studio's container configuration")
	}
}

// TestNode_StudioRestartLoopReported: Studio's container as the agent creates
// it, its process replaced by one that does what the server's start check
// does without a setting — one line, exit 1 (the image at hand may predate
// that check) — is restarted by Docker, which reports it running meanwhile;
// the node check's row fails with that line.
func TestNode_StudioRestartLoopReported(t *testing.T) {
	a, ad := dashNode(t)
	ctx := context.Background()
	opts, cmd, conf, err := a.dashConfig(ctx, ad, dashcfg.StudioName)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(opts, func(s string) bool { return strings.HasPrefix(s, "SUPAPACE_LIMITS=") })
	if i < 1 || opts[i-1] != "-e" {
		t.Fatalf("no SUPAPACE_LIMITS in %q", opts)
	}
	row := func() nodecfg.CheckResult {
		for _, r := range a.CheckDashboard(ctx) {
			if r.Name == dashcfg.StudioName {
				return r
			}
		}
		t.Fatal("no Studio row")
		return nodecfg.CheckResult{}
	}
	// A process that dies at once, and one that serves three seconds first:
	// once the first failing reading is in, every reading of the next 30 s
	// fails, with the line, though Docker reports it running.
	for _, c := range []struct{ name, script string }{
		{"at once", `console.error("supapace: SUPAPACE_LIMITS is not set"); process.exit(1)`},
		{"after 3 s", `setTimeout(() => { console.error("supapace: SUPAPACE_LIMITS is not set"); process.exit(1) }, 3000)`},
	} {
		o := append(slices.Delete(slices.Clone(opts), i-1, i+1), "--entrypoint", "node")
		nodeDocker(t, "rm", "-f", dashcfg.StudioName)
		nodeDocker(t, slices.Concat(o, []string{"--label", labelConfig + "=" + conf, "--"}, cmd, []string{"-e", c.script})...)
		nodeDocker(t, "start", dashcfg.StudioName)
		var r nodecfg.CheckResult
		for deadline := time.Now().Add(120 * time.Second); ; time.Sleep(time.Second) {
			if r = row(); !r.OK && strings.Contains(r.Detail, "restart") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: no restart loop reported: %+v", c.name, r)
			}
		}
		t.Logf("%s: %s", c.name, r.Detail)
		if !strings.Contains(r.Detail, "SUPAPACE_LIMITS") {
			t.Errorf("%s: the row does not carry the server's line: %s", c.name, r.Detail)
		}
		passed, up := 0, 0
		for range 60 {
			if row().OK {
				passed++
			}
			if c, err := dockerInspectContainer(ctx, dashcfg.StudioName); err == nil && c != nil && c.Running {
				up++
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Logf("%s: 60 readings, %d passing, Docker reported it running in %d", c.name, passed, up)
		if passed != 0 {
			t.Errorf("%s: %d of 60 readings passed", c.name, passed)
		}
	}
	// Control: the agent's own container, made again, passes. (The stand-in
	// carries the agent's label, so that only the restart rule can fail its
	// readings; the agent would adopt it.)
	nodeDocker(t, "rm", "-f", dashcfg.StudioName)
	if err := a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	dashWaitHTTP(t, dashcfg.StudioName, "http://127.0.0.1:3000/")
	if r := row(); !r.OK {
		t.Errorf("the agent's Studio: %+v", r)
	}
}

// dashListing is what a dashboard could leave on a node: every path under
// the node's configuration and state directories with its owner, mode and
// size, and Docker's containers, images, networks and volumes.
func dashListing(t *testing.T, a *Agent) string {
	t.Helper()
	var b strings.Builder
	for _, root := range []string{filepath.Dir(a.p.NodeJSON()), filepath.Dir(a.p.PlatformDir())} {
		err := filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				fmt.Fprintf(&b, "%s: %v\n", p, err)
				return nil
			}
			fi, err := e.Info()
			if err != nil {
				return err
			}
			st := fi.Sys().(*syscall.Stat_t)
			fmt.Fprintf(&b, "%s %d:%d %v %d\n", p, st.Uid, st.Gid, fi.Mode(), fi.Size())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}} {{.Image}} {{.Status}}"},
		{"images", "-a", "--no-trunc", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}"}, {"network", "ls", "--no-trunc", "-q"},
		{"volume", "ls", "-q"}} {
		b.WriteString(nodeDocker(t, args...) + "\n")
	}
	return b.String()
}

// TestNode_NoStudioDomain_LeavesTheNodeAsItWas: on a node without a studio
// domain the three methods change nothing a listing of the node shows — no
// directory, no file, no image, no container — and report nothing.
func TestNode_NoStudioDomain_LeavesTheNodeAsItWas(t *testing.T) {
	a := nodeAgent(t)
	if a.cfg.StudioDomain != "" {
		t.Fatal("the test node has a studio domain")
	}
	ctx := context.Background()
	before := dashListing(t, a)
	if err := a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := a.CheckDashboard(ctx); rows != nil {
		t.Errorf("rows %+v", rows)
	}
	after := dashListing(t, a)
	t.Logf("listing: %d lines", strings.Count(before, "\n"))
	if before != after {
		t.Errorf("the node changed:\nbefore\n%s\nafter\n%s", before, after)
	}
}

// TestNode_DashboardContainersRemovedWhereItIsNotConfigured: Studio and the
// two postgres-meta instances, made by the agent, on a node that then loses
// its studio domain: the node check's member row refuses them, the removal
// takes exactly them away, the row passes again, and the keys stay.
func TestNode_DashboardContainersRemovedWhereItIsNotConfigured(t *testing.T) {
	a, _ := dashNode(t)
	ctx := context.Background()
	names := []string{dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgMeta1Name}
	present := func() (out []string) {
		for _, n := range names {
			if c, err := dockerInspectContainer(ctx, n); err != nil {
				t.Fatal(err)
			} else if c != nil {
				out = append(out, n)
			}
		}
		return out
	}
	if err := a.checkPlatformMembers(ctx); err != nil {
		t.Fatalf("control: platform-members on the configured node: %v", err)
	}
	if err := a.RemoveDashboard(ctx); err != nil || len(present()) != 3 {
		t.Fatalf("on a configured node the removal acted: %v, left %q", err, present())
	}
	// A bystander on the platform network under a name of its own, with a
	// dashboard role label: not the platform's, never removed.
	const other = "sp-test-dash-bystander"
	nodeDockerQuiet("rm", "-f", other)
	t.Cleanup(func() { nodeDockerQuiet("rm", "-f", other) })
	im, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	nodeDocker(t, "create", "--name", other, "--label", "supapace.test=1", "--label", labelRole+"=studio", "--cap-drop", "ALL",
		"--entrypoint", "sleep", im.ControlPlane, "86400")

	a.cfg.StudioDomain = ""
	err = a.checkPlatformMembers(ctx)
	if err == nil || !strings.Contains(err.Error(), "foreign member") {
		t.Fatalf("control: platform-members with the containers left: %v", err)
	}
	t.Logf("before the removal, platform-members: %v", err)
	if err := a.RemoveDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if left := present(); len(left) != 0 {
		t.Errorf("still there: %q", left)
	}
	if c, err := dockerInspectContainer(ctx, other); err != nil || c == nil {
		t.Errorf("the bystander was removed (%v)", err)
	}
	if err := a.checkPlatformMembers(ctx); err != nil {
		t.Errorf("platform-members after the removal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dashcfg.PathsFor(a.p).KeyDir(), keyAssert)); err != nil {
		t.Errorf("the keys went with the containers: %v", err)
	}
}
