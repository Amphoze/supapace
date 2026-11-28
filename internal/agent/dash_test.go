package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
)

// ───────── fixture ─────────

type dashImage struct {
	id     string
	env    []string
	labels map[string]string
}

// dashFix is a test agent on a node with a studio domain: the studio pair
// stored as init stores it, the seccomp profile, the projects directory, the
// two images. Owners set through the chown seam and writeFile are what
// fileOwner reports; the standard input of every create is kept.
type dashFix struct {
	a      *Agent
	f      *fakeHost
	d      dashcfg.Paths
	ad     dashcfg.Addrs
	pgmeta string

	mu     sync.Mutex
	images map[string]dashImage
	owners map[string][2]int
	stdin  map[string][]byte // container name → standard input of its create
	quotas []string
	// restarting: containers Docker reports restarting (still Running, as
	// Docker does); logs: each one's last log line, on its standard error.
	restarting map[string]bool
	restarts   map[string]int       // RestartCount
	started    map[string]time.Time // State.StartedAt; an hour ago when unset
	logs       map[string]string
}

func newDashFix(t *testing.T, domain string) *dashFix {
	t.Helper()
	a, f, _ := newTestAgent(t)
	a.cfg.StudioDomain = domain
	x := &dashFix{a: a, f: f, d: dashcfg.PathsFor(a.p), owners: map[string][2]int{}, stdin: map[string][]byte{},
		restarting: map[string]bool{}, restarts: map[string]int{}, started: map[string]time.Time{}, logs: map[string]string{}}
	restartMu.Lock()
	clear(restartSeen) // no check of another test's node came before
	restartMu.Unlock()
	if domain != "" {
		ad, err := dashcfg.For(a.cfg)
		if err != nil {
			t.Fatal(err)
		}
		x.ad = ad
	}
	ref, err := nodecfg.PgMetaImage()
	if err != nil {
		t.Fatal(err)
	}
	x.pgmeta = ref
	x.images = map[string]dashImage{
		dashcfg.StudioImage: {"sha256:" + strings.Repeat("2", 64), []string{"PATH=/usr/bin", "NODE_VERSION=24", "YARN_VERSION=1"},
			map[string]string{"supapace.build": "studio", labelStudioEnv: `{"PORT":"3000"}`}},
		ref: {"sha256:" + strings.Repeat("3", 64), []string{"PATH=/usr/bin", "NODE_VERSION=22", "YARN_VERSION=1", "PG_META_PORT=8080"}, nil},
	}
	tls := x.d.StudioTLS()
	if err := os.Mkdir(tls, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string]string{"cert.pem": "studio certificate\n", "key.pem": "studio key\n"} {
		if err := os.WriteFile(filepath.Join(tls, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.ensurePlatformDir(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.seccompFile(), seccompProfile, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(a.p.ProjectsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swap(&chown, func(path string, uid, gid int) error {
		f.record(fmt.Sprintf("chown %s %d:%d", path, uid, gid))
		x.mu.Lock()
		x.owners[path] = [2]int{uid, gid}
		x.mu.Unlock()
		return nil
	}))
	write := writeFile // a write gives the file the owner it records
	t.Cleanup(swap(&writeFile, func(p nodecfg.Paths, dir, name string, data []byte, mode os.FileMode, uid, gid int) error {
		x.mu.Lock()
		delete(x.owners, filepath.Join(dir, name))
		x.mu.Unlock()
		return write(p, dir, name, data, mode, uid, gid)
	}))
	t.Cleanup(swap(&fileOwner, func(path string, fi os.FileInfo) (int, int) {
		x.mu.Lock()
		o, ok := x.owners[path]
		x.mu.Unlock()
		if ok {
			return o[0], o[1]
		}
		f.mu.Lock()
		w, ok := f.writes[path]
		f.mu.Unlock()
		if ok {
			return w.UID, w.GID
		}
		return os.Geteuid(), os.Getegid()
	}))
	t.Cleanup(swap(&repoSetQuota, func(mount string, id, mb int) error {
		f.record(fmt.Sprintf("quota %s %d %d", mount, id, mb))
		x.mu.Lock()
		x.quotas = append(x.quotas, fmt.Sprintf("%s %d %d", mount, id, mb))
		x.mu.Unlock()
		return nil
	}))
	t.Cleanup(swap(&dockerRunOutput, func(ctx context.Context, args ...string) (string, string, error) {
		f.record("docker " + strings.Join(args, " "))
		if len(args) != 5 || !slices.Equal(args[:4], []string{"logs", "--tail", "1", "--"}) {
			t.Errorf("unmodelled %q", args)
			return "", "", errors.New("fake: unmodelled")
		}
		x.mu.Lock()
		defer x.mu.Unlock()
		return "", x.logs[args[4]], nil
	}))
	f.onRun = func(args []string, stdin []byte) (string, error, bool) {
		if len(args) > 2 && args[0] == "image" && args[1] == "inspect" && flagValue(args, "--format") == imageConfFormat {
			x.mu.Lock()
			im, ok := x.images[positional(args)[0]]
			x.mu.Unlock()
			if !ok {
				return "", errors.New("docker: no such image"), true
			}
			conf := map[string]any{"Env": im.env}
			if im.labels != nil { // Docker leaves the member out for an image without labels
				conf["Labels"] = im.labels
			}
			b, _ := json.Marshal(map[string]any{"id": im.id, "config": conf})
			return string(b) + "\n", nil, true
		}
		if len(args) > 2 && args[0] == "container" && args[1] == "inspect" && flagValue(args, "--format") == restartFormat {
			name := positional(args)[0]
			f.mu.Lock()
			c, ok := f.ctrs[name]
			id := ""
			if ok {
				id = c.ID
			}
			f.mu.Unlock()
			if !ok {
				return "", errors.New("docker: no such container"), true
			}
			x.mu.Lock()
			defer x.mu.Unlock()
			st, ok := x.started[name]
			if !ok {
				st = time.Now().Add(-time.Hour)
			}
			return fmt.Sprintf("%s %t %d %s\n", id, x.restarting[name], x.restarts[name], st.UTC().Format(time.RFC3339Nano)), nil, true
		}
		if args[0] == "create" {
			x.mu.Lock()
			x.stdin[flagValue(args, "--name")] = slices.Clone(stdin)
			x.mu.Unlock()
		}
		// A removal by id, as Docker resolves one.
		if pos := positional(args); args[0] == "rm" && len(pos) == 1 {
			f.mu.Lock()
			defer f.mu.Unlock()
			if err := f.failVerb["rm"]; err != nil {
				return "", err, true
			}
			for name, c := range f.ctrs {
				if c.ID == pos[0] {
					delete(f.ctrs, name)
					return "", nil, true
				}
			}
		}
		return "", nil, false
	}
	return x
}

func (x *dashFix) image(ref string, im dashImage) {
	x.mu.Lock()
	x.images[ref] = im
	x.mu.Unlock()
}

// create is the argv of name's last create.
func (x *dashFix) create(t *testing.T, name string) []string {
	t.Helper()
	var last []string
	for _, a := range x.f.argv("create") {
		if flagValue(a, "--name") == name {
			last = a
		}
	}
	if last == nil {
		t.Fatalf("no create of %s", name)
	}
	return last
}

func (x *dashFix) creates() []string {
	var n []string
	for _, a := range x.f.argv("create") {
		n = append(n, flagValue(a, "--name"))
	}
	return n
}

// keyTexts is the content of every key file of KeyDir.
func (x *dashFix) keyTexts(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, n := range []string{keyAssert, keyAssertPub, keyCache, keyCrypto} {
		b, err := os.ReadFile(filepath.Join(x.d.KeyDir(), n))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.TrimSuffix(string(b), "\n"))
	}
	return out
}

func (x *dashFix) writes() []string {
	var w []string
	for _, c := range x.f.calls() {
		if strings.HasPrefix(c, "write ") {
			w = append(w, c)
		}
	}
	return w
}

func envOf(args []string) map[string]string {
	m := map[string]string{}
	for _, kv := range flagValues(args, "-e") {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// mounts maps each -v destination to "source mode" (mode "rw" when unstated).
func mounts(args []string) map[string]string {
	m := map[string]string{}
	for _, v := range flagValues(args, "-v") {
		p := strings.Split(v, ":")
		mode := "rw"
		if len(p) == 3 {
			mode = p[2]
		}
		m[p[1]] = p[0] + " " + mode
	}
	return m
}

func ownerMode(t *testing.T, x *dashFix, path string) string {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := fileOwner(path, fi)
	return fmt.Sprintf("%d:%d %04o", uid, gid, fi.Mode().Perm())
}

var dashRoot = fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())

// ───────── no domain, refused configuration ─────────

func TestEnsureDashboard_NoStudioDomain_DoesNothing(t *testing.T) {
	x := newDashFix(t, "")
	ctx := context.Background()
	if err := x.a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := x.a.CheckDashboard(ctx); rows != nil {
		t.Errorf("rows %v, want none", rows)
	}
	if c := x.f.calls(); len(c) != 0 {
		t.Errorf("calls %q, want none", c)
	}
	for _, p := range []string{x.d.KeyDir(), x.d.DashDir(), x.d.DataDir(), x.d.GatewayDash(), x.d.GatewayStudioTLS()} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists (%v)", p, err)
		}
	}
	// Control: the same node with the domain makes them.
	x.a.cfg.StudioDomain = "studio.test"
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{x.d.KeyDir(), x.d.DataDir(), x.d.GatewayDash()} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("control: %v", err)
		}
	}
}

func TestEnsureDashboard_ConfigRefused_DoesNothingAndReports(t *testing.T) {
	for _, c := range []struct {
		name, why string
		edit      func(*nodecfg.Config)
	}{
		{"address collision", "gateway_ip", func(c *nodecfg.Config) {
			ad := dashcfg.Static(*c)
			c.GatewayIP = ad.Studio.String()
		}},
		{"uid range over a platform uid", "65527", func(c *nodecfg.Config) { c.UIDBase, c.UIDCount = 65000, 1000 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newDashFix(t, "studio.test")
			c.edit(&x.a.cfg)
			ctx := context.Background()
			if err := x.a.EnsureDashboardFiles(ctx); err != nil {
				t.Fatal(err)
			}
			if err := x.a.EnsureDashboard(ctx); err != nil {
				t.Fatal(err)
			}
			if calls := x.f.calls(); len(calls) != 0 {
				t.Errorf("calls %q, want none", calls)
			}
			if _, err := os.Lstat(x.d.KeyDir()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("key directory made (%v)", err)
			}
			rows := x.a.CheckDashboard(ctx)
			if len(rows) != 1 || rows[0].Name != rowDashConfig || rows[0].OK || !strings.Contains(rows[0].Detail, c.why) {
				t.Errorf("rows %+v, want one failing %s naming %s", rows, rowDashConfig, c.why)
			}
		})
	}
	// Control: the default node's row passes.
	x := newDashFix(t, "studio.test")
	if rows := x.a.CheckDashboard(context.Background()); len(rows) == 0 || rows[0].Name != rowDashConfig || !rows[0].OK {
		t.Errorf("control rows %+v", rows)
	}
}

// ───────── keys ─────────

func TestKeys_ModesOwners_NeverReplaced(t *testing.T) {
	x := newDashFix(t, "studio.test")
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	ctx := context.Background()
	if err := x.a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	kd := x.d.KeyDir()
	if got := ownerMode(t, x, kd); got != dashRoot+" 0700" {
		t.Errorf("%s: %s", kd, got)
	}
	read := func(dir, n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, n := range []string{keyAssert, keyAssertPub, keyCache, keyCrypto} {
		if got := ownerMode(t, x, filepath.Join(kd, n)); got != dashRoot+" 0600" {
			t.Errorf("%s: %s, want root 0600", n, got)
		}
	}
	keyLine := regexp.MustCompile(`^[A-Za-z0-9_-]{43}\n$`)
	for _, n := range []string{keyAssert, keyAssertPub, keyCache} {
		if b := read(kd, n); !keyLine.Match(b) {
			t.Errorf("%s = %q: not 43 base64url characters and one line end", n, b)
		}
	}
	priv, err := dashtok.ParsePrivate(read(kd, keyAssert))
	if err != nil {
		t.Fatal(err)
	}
	// Studio's copies: dashtok reads them, the public half matches the key.
	pub, err := dashtok.ParsePublic(read(x.d.StudioKeys(), keyAssertPub))
	if err != nil || !bytes.Equal(pub, priv[32:]) {
		t.Errorf("Studio's assert.pub: %v", err)
	}
	if k, err := dashtok.ParsePublic(read(x.d.StudioKeys(), keyCache)); err != nil || len(k) != 32 {
		t.Errorf("Studio's cache.key: %v", err)
	}
	crypto := read(kd, keyCrypto)
	if b, err := base64.RawURLEncoding.Strict().DecodeString(string(crypto)); err != nil || len(b) != 48 || len(crypto) != 64 {
		t.Errorf("crypto.key = %q: want 64 base64url characters of 48 bytes, no line end", crypto)
	}
	for n, want := range map[string]string{keyAssertPub: dashRoot + " 0444",
		keyCache: fmt.Sprintf("%d:%d 0400", dashcfg.StudioUID, dashcfg.StudioUID), keyCrypto: fmt.Sprintf("%d:%d 0400", dashcfg.StudioUID, dashcfg.StudioUID)} {
		if got := ownerMode(t, x, filepath.Join(x.d.StudioKeys(), n)); got != want {
			t.Errorf("Studio's %s: %s, want %s", n, got, want)
		}
		if !bytes.Equal(read(x.d.StudioKeys(), n), read(kd, n)) {
			t.Errorf("Studio's %s differs from the node's", n)
		}
	}
	if got := ownerMode(t, x, x.d.StudioKeys()); got != dashRoot+" 0755" {
		t.Errorf("StudioKeys: %s", got)
	}

	// Never replaced: a second run writes nothing of KeyDir; a key the
	// operator put there stays, and Studio's copy follows it.
	texts := x.keyTexts(t)
	mine := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + "\n")
	if err := os.WriteFile(filepath.Join(kd, keyCache), mine, 0o600); err != nil {
		t.Fatal(err)
	}
	x.f.resetLog()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	for _, w := range x.writes() {
		if strings.Contains(w, kd+"/") {
			t.Errorf("KeyDir written again: %s", w)
		}
	}
	if !bytes.Equal(read(kd, keyCache), mine) || !bytes.Equal(read(x.d.StudioKeys(), keyCache), mine) {
		t.Error("the operator's cache key was replaced, or Studio's copy did not follow it")
	}
	if got := x.keyTexts(t); got[0] != texts[0] || got[1] != texts[1] || got[3] != texts[3] {
		t.Error("a key changed")
	}

	// A key alone gets its public half; a public half alone is refused and
	// left; a malformed key is refused and left.
	os.Remove(filepath.Join(kd, keyAssertPub))
	if err := x.a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read(kd, keyAssertPub), []byte(base64.RawURLEncoding.EncodeToString(priv[32:])+"\n")) {
		t.Error("assert.pub not derived from assert.key")
	}
	os.Remove(filepath.Join(kd, keyAssert))
	if err := x.a.EnsureDashboardFiles(ctx); err == nil {
		t.Error("a public half without its key accepted")
	}
	if _, err := os.Lstat(filepath.Join(kd, keyAssert)); err == nil {
		t.Error("a key was made beside a lone public half")
	}
	if err := os.WriteFile(filepath.Join(kd, keyAssert), []byte(texts[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kd, keyCache), []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := x.a.EnsureDashboardFiles(ctx); err == nil || !strings.Contains(err.Error(), keyCache) {
		t.Errorf("a malformed cache key: %v", err)
	}
	if string(read(kd, keyCache)) != "short\n" {
		t.Error("a malformed cache key was replaced")
	}
	for _, k := range texts {
		if strings.Contains(logs.String(), k) {
			t.Error("a key was logged")
		}
	}
}

// ───────── the files, then the containers ─────────

func TestEnsureDashboardFiles_KeysAndGatewayFiles_NoContainer(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if m := x.f.mutations(); len(m) != 0 {
		t.Errorf("docker calls %q, want none", m)
	}
	for _, c := range x.f.calls() {
		if strings.HasPrefix(c, "docker ") {
			t.Errorf("docker call %q", c)
		}
	}
	for _, p := range []string{filepath.Join(x.d.KeyDir(), keyAssert), filepath.Join(x.d.StudioKeys(), keyCache),
		filepath.Join(x.d.GatewayDash(), "domain"), filepath.Join(x.d.GatewayDash(), keyAssert),
		filepath.Join(x.d.GatewayStudioTLS(), "cert.pem"), filepath.Join(x.d.GatewayStudioTLS(), "key.pem")} {
		if _, err := os.Lstat(p); err != nil {
			t.Error(err)
		}
	}
	if got := ownerMode(t, x, x.d.SocketDir()); got != fmt.Sprintf("0:%d 0750", dashcfg.StudioUID) {
		t.Errorf("SocketDir: %s", got)
	}
	if got := ownerMode(t, x, x.d.DashDir()); got != dashRoot+" 0755" {
		t.Errorf("DashDir: %s", got)
	}

	// EnsureDashboard: the three containers, no file written again.
	x.f.resetLog()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if got := x.creates(); !slices.Equal(got, []string{dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgMeta1Name}) {
		t.Errorf("created %q", got)
	}
	for _, n := range []string{dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgMeta1Name} {
		if len(x.f.argv("start", "--", n)) != 1 {
			t.Errorf("%s not started once", n)
		}
	}
	if w := x.writes(); len(w) != 0 {
		t.Errorf("files written again: %q", w)
	}
	// A second round adopts all three.
	x.f.resetLog()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if m := x.f.mutations(); len(m) != 0 {
		t.Errorf("second round: %q", m)
	}

	// With a configuration dashcfg.For refuses: nothing written.
	y := newDashFix(t, "studio.test")
	y.a.cfg.UIDBase, y.a.cfg.UIDCount = 65000, 1000
	if err := y.a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if c := y.f.calls(); len(c) != 0 {
		t.Errorf("refused configuration: %q", c)
	}
}

func TestGatewayFiles_ModesOwners(t *testing.T) {
	x := newDashFix(t, "studio.test")
	if err := x.a.EnsureDashboardFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	gw := fmt.Sprintf("%d:%d", gatewayUID, gatewayUID)
	for p, want := range map[string]string{
		x.d.GatewayDash(): dashRoot + " 0755",
		filepath.Join(x.d.GatewayDash(), keyAssert):       gw + " 0400",
		filepath.Join(x.d.GatewayDash(), "domain"):        dashRoot + " 0444",
		x.d.GatewayStudioTLS():                            dashRoot + " 0755",
		filepath.Join(x.d.GatewayStudioTLS(), "cert.pem"): dashRoot + " 0444",
		filepath.Join(x.d.GatewayStudioTLS(), "key.pem"):  gw + " 0400",
	} {
		if got := ownerMode(t, x, p); got != want {
			t.Errorf("%s: %s, want %s", p, got, want)
		}
	}
	same := func(a, b string) {
		x, _ := os.ReadFile(a)
		y, _ := os.ReadFile(b)
		if len(x) == 0 || !bytes.Equal(x, y) {
			t.Errorf("%s is not %s", a, b)
		}
	}
	same(filepath.Join(x.d.GatewayDash(), keyAssert), filepath.Join(x.d.KeyDir(), keyAssert))
	same(filepath.Join(x.d.GatewayStudioTLS(), "cert.pem"), filepath.Join(x.d.StudioTLS(), "cert.pem"))
	same(filepath.Join(x.d.GatewayStudioTLS(), "key.pem"), filepath.Join(x.d.StudioTLS(), "key.pem"))
	if b, _ := os.ReadFile(filepath.Join(x.d.GatewayDash(), "domain")); string(b) != "studio.test\n" {
		t.Errorf("domain = %q", b)
	}
	// A renewed pair is copied at the next call; a missing pair is an error.
	os.WriteFile(filepath.Join(x.d.StudioTLS(), "cert.pem"), []byte("renewed\n"), 0o600)
	if err := x.a.EnsureDashboardFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	same(filepath.Join(x.d.GatewayStudioTLS(), "cert.pem"), filepath.Join(x.d.StudioTLS(), "cert.pem"))
	os.Remove(filepath.Join(x.d.StudioTLS(), "key.pem"))
	if err := x.a.EnsureDashboardFiles(context.Background()); err == nil {
		t.Error("no studio key: accepted")
	}
}

// ───────── Studio's container ─────────

// hardening asserts the flags every dashboard container carries.
func hardening(t *testing.T, a *Agent, args []string) {
	t.Helper()
	for _, pair := range [][2]string{{"--cap-drop", "ALL"}, {"--security-opt", "no-new-privileges"},
		{"--security-opt", "seccomp=" + a.seccompFile()}, {"--ulimit", "core=0"}, {"--restart", "unless-stopped"},
		{"--ipc", "private"}, {"--sysctl", "net.ipv4.ping_group_range=1 0"}, {"--sysctl", "net.ipv6.conf.all.disable_ipv6=1"}} {
		if !slices.Contains(flagValues(args, pair[0]), pair[1]) {
			t.Errorf("no %s %s", pair[0], pair[1])
		}
	}
	for _, f := range []string{"--read-only", "--no-healthcheck"} {
		if !slices.Contains(args[:slices.Index(args, "--")], f) {
			t.Errorf("no %s", f)
		}
	}
	for _, f := range []string{"--privileged", "--cap-add", "--device", "--pid", "--userns", "--group-add", "--mount", "--volumes-from"} {
		if slices.Contains(args, f) {
			t.Errorf("%s set", f)
		}
	}
	if n := flagValues(args, "--network"); len(n) != 1 || n[0] != platformNet {
		t.Errorf("networks %q, want platform alone", n)
	}
}

func noKeyIn(t *testing.T, x *dashFix, what string, s []string) {
	t.Helper()
	for _, k := range x.keyTexts(t) {
		for _, a := range s {
			if strings.Contains(a, k) {
				t.Errorf("%s holds key material", what)
			}
		}
	}
}

func TestStudioArgs_Recorded(t *testing.T) {
	x := newDashFix(t, "studio.test")
	if err := x.a.EnsureDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	args := x.create(t, dashcfg.StudioName)
	hardening(t, x.a, args)
	for flag, want := range map[string]string{"--user": fmt.Sprintf("%d:%d", dashcfg.StudioUID, dashcfg.StudioUID),
		"--ip": x.ad.Studio.String(), "--memory": "896m", "--memory-swap": "896m", "--pids-limit": "256", "--tmpfs": "/tmp"} {
		if got := flagValues(args, flag); len(got) != 1 || got[0] != want {
			t.Errorf("%s %q, want %s", flag, got, want)
		}
	}
	wantMounts := map[string]string{"/run/dash": x.d.SocketDir() + " ro", "/etc/dash": x.d.StudioKeys() + " ro",
		"/var/lib/dash": x.d.DataDir() + " rw"}
	if got := mounts(args); !maps.Equal(got, wantMounts) {
		t.Errorf("mounts %v, want %v", got, wantMounts)
	}
	want, err := dashcfg.StudioEnv(x.ad, x.a.cfg.NodeID, dashcfg.Limits, map[string]string{"PORT": "3000"})
	if err != nil {
		t.Fatal(err)
	}
	if got := flagValues(args, "-e"); !slices.Equal(got, want) {
		t.Errorf("environment %q, want %q", got, want)
	}
	if slices.Contains(args, "--env-file") || x.stdin[dashcfg.StudioName] != nil {
		t.Error("Studio is given an environment beside StudioEnv's")
	}
	c := x.f.ctrs[dashcfg.StudioName]
	if c.Labels[labelRole] != "studio" || len(c.Labels) != 2 {
		t.Errorf("labels %v", c.Labels)
	}
	if !slices.Equal(positional(args), []string{dashcfg.StudioImage}) {
		t.Errorf("image and command %q", positional(args))
	}
	noKeyIn(t, x, "Studio's arguments", args)
	noKeyIn(t, x, "Studio's labels", slices.Collect(maps.Values(c.Labels)))
}

// TestStudioEnv_EveryFixedNameSetAndEveryPathMounted: every name dashcfg's
// fixed list holds is set once on the container, whatever names that list
// gains; every value that is a path lies in one of the container's mounts,
// and the key directory holds the cache key in the form Studio reads.
func TestStudioEnv_EveryFixedNameSetAndEveryPathMounted(t *testing.T) {
	x := newDashFix(t, "studio.test")
	if err := x.a.EnsureDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	args := x.create(t, dashcfg.StudioName)
	set := map[string]int{}
	for _, kv := range flagValues(args, "-e") {
		n, _, _ := strings.Cut(kv, "=")
		set[n]++
	}
	names := dashcfg.FixedEnvNames()
	if len(names) == 0 {
		t.Fatal("dashcfg lists no fixed name")
	}
	for _, n := range names {
		if set[n] != 1 {
			t.Errorf("%s set %d times", n, set[n])
		}
	}
	ms := mounts(args)
	inMount := func(p string) (string, bool) {
		for dst, src := range ms {
			if p == dst || strings.HasPrefix(p, dst+"/") {
				s, _, _ := strings.Cut(src, " ")
				return filepath.Join(s, strings.TrimPrefix(p, dst)), true
			}
		}
		return "", false
	}
	env := envOf(args)
	paths := 0
	for n, v := range env {
		if !strings.HasPrefix(v, "/") {
			continue
		}
		paths++
		host, ok := inMount(v)
		if !ok || filepath.Clean(v) != v {
			t.Errorf("%s=%s: not a clean path in a mount", n, v)
			continue
		}
		if fi, err := os.Lstat(host); err == nil && !fi.IsDir() {
			t.Errorf("%s=%s: %s is not a directory", n, v, host)
		}
	}
	if paths < 3 {
		t.Errorf("%d path settings, want the socket, the keys and the data", paths)
	}
	keys, ok := inMount(env["SUPAPACE_DASH_KEYS"])
	if !ok {
		t.Fatal("SUPAPACE_DASH_KEYS not mounted")
	}
	b, err := os.ReadFile(filepath.Join(keys, "cache.key"))
	if err != nil || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}=?\n?$`).Match(b) {
		t.Errorf("cache.key in the mounted key directory: %v", err)
	}
	if _, ok := inMount(env["SUPAPACE_DASH_SOCKET"]); !ok || filepath.Base(env["SUPAPACE_DASH_SOCKET"]) != "dash.sock" {
		t.Error("the socket is not in the socket directory's mount")
	}
	if ms["/var/lib/dash"] != x.d.DataDir()+" rw" || env["SUPAPACE_DASH_DATA"] != "/var/lib/dash" {
		t.Error("the data directory is not mounted writable where Studio looks")
	}
	// The postgres-meta addresses name the two containers this round made, at
	// the port each was told to listen on.
	var metas []string
	for _, n := range []string{dashcfg.PgMeta0Name, dashcfg.PgMeta1Name} {
		a := x.create(t, n)
		metas = append(metas, "http://"+flagValue(a, "--ip")+":"+envOf(a)["PG_META_PORT"])
	}
	if got := env["SUPAPACE_PGMETA"]; got != strings.Join(metas, ",") {
		t.Errorf("SUPAPACE_PGMETA=%s, want the two containers %q", got, metas)
	}
	if env["SUPAPACE_NODE_ID"] != x.a.cfg.NodeID || x.a.cfg.NodeID == "" {
		t.Errorf("SUPAPACE_NODE_ID=%q", env["SUPAPACE_NODE_ID"])
	}
	if want := fmt.Sprintf("%s:%d:%d", x.ad.Pgcap, x.ad.MetaPortLo, x.ad.MetaPortHi); env["SUPAPACE_PGCAP"] != want {
		t.Errorf("SUPAPACE_PGCAP=%s, want %s", env["SUPAPACE_PGCAP"], want)
	}
	if !json.Valid([]byte(env["SUPAPACE_LIMITS"])) || env["SUPAPACE_LIMITS"] != dashcfg.Limits.StudioJSON() {
		t.Errorf("SUPAPACE_LIMITS=%s", env["SUPAPACE_LIMITS"])
	}
}

// TestStudioEnv_OnlyNamesTheForkSets: every name Studio's process gets — the
// created container's, the image's own ENV, Docker's two — is a row the
// fork's environment table classes "set"; none is one it classes "unset"
// (upstream's own connection and postgres-meta settings among them) and the
// prerender switches are never set.
func TestStudioEnv_OnlyNamesTheForkSets(t *testing.T) {
	b, err := os.ReadFile("../../studio/env.tsv")
	if err != nil {
		t.Fatal(err)
	}
	class := map[string]string{} // "set" or "unset"; a name may also have rows "dynamic"
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Split(l, "\t"); len(f) >= 2 && !strings.HasPrefix(l, "#") {
			if f[1] != "dynamic" {
				class[f[0]] = f[1]
			}
		}
	}
	unset := 0
	for _, c := range class {
		if c == "unset" {
			unset++
		}
	}
	if unset == 0 || class["SUPAPACE_PGMETA"] != "set" {
		t.Fatalf("the table is not as read here: %d rows, %d unset", len(class), unset)
	}
	x := newDashFix(t, "studio.test")
	if err := x.a.EnsureDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	args := x.create(t, dashcfg.StudioName)
	for _, kv := range slices.Concat(flagValues(args, "-e"), x.images[dashcfg.StudioImage].env, []string{"HOSTNAME=x", "HOME=/"}) {
		n, _, _ := strings.Cut(kv, "=")
		if class[n] != "set" || strings.HasPrefix(n, "TSS_") {
			t.Errorf("%s reaches Studio, classed %q", n, class[n])
		}
	}
}

func TestStudio_EnvFromTheImageLabel(t *testing.T) {
	x := newDashFix(t, "studio.test")
	x.image(dashcfg.StudioImage, dashImage{"sha256:" + strings.Repeat("2", 64), nil,
		map[string]string{labelStudioEnv: `{"PORT":"3000","ENABLED_FEATURES_LOGS":"false"}`}})
	if err := x.a.EnsureDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	env := envOf(x.create(t, dashcfg.StudioName))
	if env["PORT"] != "3000" || env["ENABLED_FEATURES_LOGS"] != "false" {
		t.Errorf("label's names missing: %v", env)
	}
	for name, im := range map[string]dashImage{
		"a name the label may not set": {"sha256:" + strings.Repeat("4", 64), nil, map[string]string{labelStudioEnv: `{"NODE_OPTIONS":"--inspect"}`}},
		"a feature switched on":        {"sha256:" + strings.Repeat("4", 64), nil, map[string]string{labelStudioEnv: `{"ENABLED_FEATURES_LOGS":"true"}`}},
		"not an object of strings":     {"sha256:" + strings.Repeat("4", 64), nil, map[string]string{labelStudioEnv: `{"PORT":3000}`}},
		"trailing data":                {"sha256:" + strings.Repeat("4", 64), nil, map[string]string{labelStudioEnv: `{} {}`}},
		"no label":                     {"sha256:" + strings.Repeat("4", 64), nil, map[string]string{"other": "x"}},
		"a listener name in its ENV":   {"sha256:" + strings.Repeat("4", 64), []string{"HOST=0.0.0.0"}, map[string]string{labelStudioEnv: `{}`}},
		"a fixed name in its ENV":      {"sha256:" + strings.Repeat("4", 64), []string{"SUPAPACE_PGMETA=x"}, map[string]string{labelStudioEnv: `{}`}},
	} {
		t.Run(name, func(t *testing.T) {
			y := newDashFix(t, "studio.test")
			y.image(dashcfg.StudioImage, im)
			err := y.a.EnsureDashboard(context.Background())
			if err == nil || !strings.Contains(err.Error(), dashcfg.StudioImage) {
				t.Errorf("EnsureDashboard: %v, want a refusal naming the image", err)
			}
			if slices.Contains(y.creates(), dashcfg.StudioName) {
				t.Error("Studio created")
			}
		})
	}
}

// TestStudio_EnvOutsideTheList_IsOnlyDockersAndTheImages: the agent gives
// Studio no environment but StudioEnv's list (no file, no standard input),
// so what its process sees beyond the list is Docker's HOSTNAME and HOME and
// the image's own ENV — none of which the listener reads, and the agent
// refuses an image whose ENV holds such a name.
func TestStudio_EnvOutsideTheList_IsOnlyDockersAndTheImages(t *testing.T) {
	x := newDashFix(t, "studio.test")
	if err := x.a.EnsureDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	args := x.create(t, dashcfg.StudioName)
	for _, f := range []string{"--env-file", "--env", "-i", "--interactive"} {
		if slices.Contains(args[:slices.Index(args, "--")], f) {
			t.Errorf("%s given", f)
		}
	}
	list, _ := dashcfg.StudioEnv(x.ad, x.a.cfg.NodeID, dashcfg.Limits, map[string]string{"PORT": "3000"})
	seen := slices.Concat(flagValues(args, "-e"), x.images[dashcfg.StudioImage].env, []string{"HOSTNAME=x", "HOME=/"})
	for _, kv := range seen {
		if slices.Contains(list, kv) {
			continue
		}
		n, _, _ := strings.Cut(kv, "=")
		if slices.Contains(dashcfg.ListenerNames, n) || strings.HasPrefix(n, "SUPAPACE_") || strings.HasPrefix(n, "ENABLED_FEATURES_") {
			t.Errorf("%s reaches Studio outside the list", n)
		}
	}
}

func TestStudioLabel_CoversTheThreeKeys(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	labels := func() [3]string {
		t.Helper()
		if err := x.a.EnsureDashboardFiles(ctx); err != nil {
			t.Fatal(err)
		}
		var l [3]string
		for i, n := range []string{dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgMeta1Name} {
			_, _, conf, err := x.a.dashConfig(ctx, x.ad, n)
			if err != nil {
				t.Fatal(err)
			}
			l[i] = conf
		}
		return l
	}
	kd := x.d.KeyDir()
	replace := map[string]func(){
		"the assertion pair": func() {
			priv, pub, _ := dashtok.GenerateKey()
			os.WriteFile(filepath.Join(kd, keyAssert), priv, 0o600)
			os.WriteFile(filepath.Join(kd, keyAssertPub), pub, 0o600)
		},
		"cache.key": func() {
			os.WriteFile(filepath.Join(kd, keyCache), []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))+"\n"), 0o600)
		},
		"crypto.key": func() {
			os.WriteFile(filepath.Join(kd, keyCrypto), []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 48))), 0o600)
		},
	}
	for _, name := range []string{"the assertion pair", "cache.key", "crypto.key"} {
		before := labels()
		replace[name]()
		after := labels()
		if before[0] == after[0] {
			t.Errorf("%s replaced: Studio's label unchanged", name)
		}
		pgmetaChanged := before[1] != after[1] && before[2] != after[2]
		if name == "crypto.key" != pgmetaChanged || (before[1] == after[1]) != (before[2] == after[2]) {
			t.Errorf("%s replaced: postgres-meta's labels changed %v (want %v)", name, pgmetaChanged, name == "crypto.key")
		}
	}
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgMeta1Name} {
		c := x.f.ctrs[n]
		if len(c.Labels) != 2 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.Labels[labelConfig]) {
			t.Errorf("%s labels %v: want the role and a hash", n, c.Labels)
		}
		noKeyIn(t, x, n+"'s labels", slices.Collect(maps.Values(c.Labels)))
	}
}

// ───────── postgres-meta ─────────

func TestPgMetaArgs_Recorded(t *testing.T) {
	x := newDashFix(t, "studio.test")
	if err := x.a.EnsureDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	crypto, _ := os.ReadFile(filepath.Join(x.d.KeyDir(), keyCrypto))
	keys := pgmetaKeysDir(x.d)
	l := dashcfg.Limits
	for i, n := range []string{dashcfg.PgMeta0Name, dashcfg.PgMeta1Name} {
		args := x.create(t, n)
		hardening(t, x.a, args)
		ip := []string{x.ad.PgMeta0.String(), x.ad.PgMeta1.String()}[i]
		for flag, want := range map[string]string{"--user": fmt.Sprintf("%d:%d", dashcfg.PgMetaUID, dashcfg.PgMetaUID), "--ip": ip,
			"--memory": "768m", "--memory-swap": "768m", "--cpus": "1", "--pids-limit": "128", "--tmpfs": "/tmp"} {
			if got := flagValues(args, flag); len(got) != 1 || got[0] != want {
				t.Errorf("%s: %s %q, want %s", n, flag, got, want)
			}
		}
		// The key reaches it by one read-only directory mount, never by its
		// environment or standard input.
		if got := mounts(args); !maps.Equal(got, map[string]string{"/etc/pgmeta": keys + " ro"}) {
			t.Errorf("%s: mounts %v", n, got)
		}
		if slices.Contains(args, "--env-file") || x.stdin[n] != nil {
			t.Errorf("%s: an environment file or standard input given", n)
		}
		if got := flagValues(args, "-e"); !slices.Equal(got, append(dashcfg.PgMetaEnv(l), "CRYPTO_KEY_FILE=/etc/pgmeta/crypto.key")) {
			t.Errorf("%s: -e %q", n, got)
		}
		want := map[string]string{"PG_META_PORT": "8080", "PG_META_DB_URL": "postgresql://none:none@127.0.0.1:9/none",
			"PG_META_MAX_RESULT_SIZE_MB": fmt.Sprint(l.MetaResultMB), "PG_CONN_TIMEOUT_SECS": fmt.Sprint(l.MetaConnSecs),
			"PG_QUERY_TIMEOUT_SECS": fmt.Sprint(l.MetaQuerySecs), "PG_META_MAX_BODY_LIMIT_MB": fmt.Sprint(l.MetaBodyMB),
			"PG_META_FORMAT_IN_WORKER": "true", "CRYPTO_KEY_FILE": "/etc/pgmeta/crypto.key"}
		if env := envOf(args); !maps.Equal(env, want) {
			t.Errorf("%s: the eight names %v, want %v", n, env, want)
		}
		if !slices.Equal(positional(args), []string{x.pgmeta}) {
			t.Errorf("%s: image and command %q, want the lock's %s", n, positional(args), x.pgmeta)
		}
		if x.f.ctrs[n].Labels[labelRole] != "pgmeta" {
			t.Errorf("%s: role %q", n, x.f.ctrs[n].Labels[labelRole])
		}
		noKeyIn(t, x, n+"'s arguments", args)
	}
	// The mounted copy: postgres-meta's uid, 0400, the key byte for byte, in a
	// root 0755 directory.
	if got := ownerMode(t, x, keys); got != dashRoot+" 0755" {
		t.Errorf("%s: %s", keys, got)
	}
	p := filepath.Join(keys, keyCrypto)
	if got := ownerMode(t, x, p); got != fmt.Sprintf("%d:%d 0400", dashcfg.PgMetaUID, dashcfg.PgMetaUID) {
		t.Errorf("%s: %s", p, got)
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, crypto) || len(b) != 64 {
		t.Errorf("%s is not crypto.key", p)
	}
	if !strings.HasPrefix(x.pgmeta, "public.ecr.aws/supabase/postgres-meta@sha256:145325b7e39f") {
		t.Errorf("PgMetaImage() = %s", x.pgmeta)
	}
}

// TestPgMeta_KeyCopyCheckedBeforeCreate: the image falls back to a built-in
// key when its key file is missing or empty, so postgres-meta is never
// rendered while its copy is not the key in place — absent, empty, another
// key, another owner or mode — and the files row reports each; EnsureDashboard
// writes it back before it creates anything.
func TestPgMeta_KeyCopyCheckedBeforeCreate(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(pgmetaKeysDir(x.d), keyCrypto)
	if _, _, _, err := x.a.dashConfig(ctx, x.ad, dashcfg.PgMeta0Name); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, spoil := range map[string]func(){
		"absent":      func() { os.Remove(p) },
		"empty":       func() { rewrite(t, p, nil) },
		"another key": func() { rewrite(t, p, []byte(strings.Repeat("b", 64))) },
		"other owner": func() { x.mu.Lock(); x.owners[p] = [2]int{0, 0}; x.mu.Unlock() },
		"other mode":  func() { os.Chmod(p, 0o444) },
	} {
		spoil()
		if _, _, _, err := x.a.dashConfig(ctx, x.ad, dashcfg.PgMeta0Name); err == nil {
			t.Errorf("%s: postgres-meta rendered", name)
		}
		if err := x.a.checkDashFiles(); err == nil {
			t.Errorf("%s: the files row passed", name)
		}
		x.f.resetLog()
		if err := x.a.EnsureDashboard(ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		w, c := slices.IndexFunc(x.f.calls(), func(s string) bool { return strings.HasPrefix(s, "write "+p+" ") }),
			slices.IndexFunc(x.f.calls(), func(s string) bool { return strings.HasPrefix(s, "docker create") })
		if w < 0 || (c >= 0 && c < w) {
			t.Errorf("%s: the copy is not written back before a create (%d, %d)", name, w, c)
		}
		if err := x.a.checkDashFiles(); err != nil {
			t.Errorf("%s: after the repair: %v", name, err)
		}
	}
}

func TestPgMeta_NoLibpqNameInItsWholeEnvironment(t *testing.T) {
	x := newDashFix(t, "studio.test")
	if err := x.a.EnsureDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{dashcfg.PgMeta0Name, dashcfg.PgMeta1Name} {
		whole := slices.Concat(x.images[x.pgmeta].env, flagValues(x.create(t, n), "-e"), strings.Split(strings.TrimSpace(string(x.stdin[n])), "\n"))
		for _, kv := range whole {
			if regexp.MustCompile(`^PG[A-Z]`).MatchString(kv) {
				t.Errorf("%s: %s", n, kv)
			}
		}
	}
	for _, bad := range []string{"PGHOST=db", "PGPASSWORD=x", "PGSSLMODE=disable", "PGOPTIONS=-c x=1", "PGAPPNAME=a", "CRYPTO_KEY=x", "CRYPTO_KEY_FILE=/x"} {
		y := newDashFix(t, "studio.test")
		y.image(y.pgmeta, dashImage{"sha256:" + strings.Repeat("5", 64), []string{"PATH=/usr/bin", bad}, nil})
		err := y.a.EnsureDashboard(context.Background())
		name, _, _ := strings.Cut(bad, "=")
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("image ENV %s: %v", name, err)
		}
		if c := y.creates(); slices.Contains(c, dashcfg.PgMeta0Name) || slices.Contains(c, dashcfg.PgMeta1Name) {
			t.Errorf("image ENV %s: postgres-meta created", name)
		}
	}
}

// TestPgMeta_ShortKey_Refused: crypto.key is taken only in the one form both
// readers use alike — 64 base64url characters and nothing else (Studio uses
// the file as it holds it, a line end included; postgres-meta gets the value
// of one environment line, which cannot hold one). Every other form, a key
// below 32 bytes first, creates no postgres-meta and is left as it is.
func TestPgMeta_ShortKey_Refused(t *testing.T) {
	a64 := strings.Repeat("a", 64)
	for _, c := range []struct {
		key string
		ok  bool
	}{{strings.Repeat("a", 31), false}, {strings.Repeat("a", 32), false}, {strings.Repeat("a", 63), false}, {a64, true},
		{a64 + "a", false}, {a64 + "\n", false}, {strings.Repeat("a", 63) + "+", false}, {strings.Repeat("a", 63) + "=", false}} {
		x := newDashFix(t, "studio.test")
		if err := os.Mkdir(x.d.KeyDir(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(x.d.KeyDir(), keyCrypto), []byte(c.key), 0o600); err != nil {
			t.Fatal(err)
		}
		err := x.a.EnsureDashboard(context.Background())
		made := slices.Contains(x.creates(), dashcfg.PgMeta0Name)
		if (err == nil) != c.ok || made != c.ok {
			t.Errorf("crypto.key %q: %v, created %v", c.key, err, made)
		}
		if b, _ := os.ReadFile(filepath.Join(x.d.KeyDir(), keyCrypto)); string(b) != c.key {
			t.Errorf("crypto.key %q replaced", c.key)
		}
	}
}

// ───────── the gateway's label ─────────

func gatewayLabel(t *testing.T, a *Agent) string {
	t.Helper()
	_, _, conf, err := a.gatewayConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

func gatewayReady(t *testing.T, a *Agent) {
	t.Helper()
	tls := filepath.Join(a.p.GatewayDir(), "tls")
	if err := os.MkdirAll(tls, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tls, "cert.pem"), []byte("base certificate\n"), 0o444); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayLabel_CoversKeyDomainAndStudioCertificate(t *testing.T) {
	x := newDashFix(t, "studio.test")
	gatewayReady(t, x.a)
	absent := gatewayLabel(t, x.a)
	if err := x.a.EnsureDashboardFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	l := gatewayLabel(t, x.a)
	if l == absent {
		t.Error("the files' arrival did not change the label")
	}
	for _, c := range []struct {
		path    string
		changes bool
	}{
		{filepath.Join(x.d.GatewayDash(), "domain"), true},
		{filepath.Join(x.d.KeyDir(), keyAssertPub), true},
		{filepath.Join(x.d.GatewayStudioTLS(), "cert.pem"), true},
		{filepath.Join(x.d.GatewayStudioTLS(), "key.pem"), false}, // the key is never in the label
		{filepath.Join(x.d.GatewayDash(), keyAssert), false},
	} {
		old, _ := os.ReadFile(c.path)
		rewrite(t, c.path, append(slices.Clone(old), 'x'))
		if got := gatewayLabel(t, x.a); (got != l) != c.changes {
			t.Errorf("%s changed: label changed %v, want %v", c.path, got != l, c.changes)
		}
		rewrite(t, c.path, old)
	}
	if gatewayLabel(t, x.a) != l {
		t.Error("label not restored")
	}
}

func TestGatewayLabel_UnchangedWithoutStudioDomain(t *testing.T) {
	x := newDashFix(t, "")
	gatewayReady(t, x.a)
	opts, cmd, conf, err := x.a.gatewayConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The label as built before the dashboard: the certificate, the profile,
	// the image id, nothing else.
	extra, err := fileDigests(filepath.Join(x.a.p.GatewayDir(), "tls", "cert.pem"), x.a.seccompFile())
	if err != nil {
		t.Fatal(err)
	}
	want := configHash(opts, cmd, append(extra, "image id="+x.f.images[nodecfg.GatewayImage])...)
	if conf != want {
		t.Error("the gateway's label differs from the one built before the dashboard")
	}
	// Dashboard files left on disk change nothing without the domain.
	os.MkdirAll(x.d.GatewayDash(), 0o755)
	os.WriteFile(filepath.Join(x.d.GatewayDash(), "domain"), []byte("studio.test\n"), 0o444)
	if gatewayLabel(t, x.a) != want {
		t.Error("a stale domain file changed the label")
	}
	// Control: the same node with the domain has another label.
	x.a.cfg.StudioDomain = "studio.test"
	if gatewayLabel(t, x.a) == want {
		t.Error("control: the studio domain changed nothing")
	}
}

// ───────── the data volume ─────────

func TestDataDir_QuotaForTheStudioUid(t *testing.T) {
	x := newDashFix(t, "studio.test")
	if err := x.a.EnsureDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%s %d %d", x.a.p.ProjectsDir(), dashcfg.StudioUID, dashcfg.Limits.StudioVolumeMB)
	if !slices.Equal(x.quotas, []string{want}) || dashcfg.Limits.StudioVolumeMB != 4096 {
		t.Errorf("quotas %q, want %q", x.quotas, want)
	}
	if got := ownerMode(t, x, x.d.DataDir()); got != fmt.Sprintf("%d:%d 0700", dashcfg.StudioUID, dashcfg.StudioUID) {
		t.Errorf("DataDir: %s", got)
	}
	calls := x.f.calls()
	q := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "quota ") })
	ch := slices.Index(calls, fmt.Sprintf("chown %s %d:%d", x.d.DataDir(), dashcfg.StudioUID, dashcfg.StudioUID))
	if q < 0 || ch < 0 || q > ch {
		t.Errorf("the quota (%d) is not set before the directory is handed over (%d)", q, ch)
	}
	// A failing quota: no data directory, no container.
	y := newDashFix(t, "studio.test")
	t.Cleanup(swap(&repoSetQuota, func(string, int, int) error { return errors.New("user quota is not enforced") }))
	if err := y.a.EnsureDashboard(context.Background()); err == nil {
		t.Error("a failing quota: accepted")
	}
	if _, err := os.Lstat(y.d.DataDir()); err == nil || len(y.creates()) != 0 {
		t.Error("a failing quota: the directory or a container was made")
	}
	// nodefs takes Studio's uid as a quota id, and still refuses its neighbours.
	if err := nodefs.SetQuotaAt(t.TempDir(), dashcfg.StudioUID, 16); err == nil || strings.Contains(err.Error(), "invalid quota id") {
		t.Errorf("SetQuotaAt(Studio's uid) on a non-XFS directory: %v, want the filesystem's refusal", err)
	}
	for _, id := range []int{dashcfg.StudioUID - 1, dashcfg.PgMetaUID} {
		if err := nodefs.SetQuotaAt(t.TempDir(), id, 16); err == nil || !strings.Contains(err.Error(), "invalid quota id") {
			t.Errorf("SetQuotaAt(%d): %v", id, err)
		}
		if _, _, err := nodefs.QuotaUsage(context.Background(), t.TempDir(), id); err == nil || !strings.Contains(err.Error(), "invalid quota id") {
			t.Errorf("QuotaUsage(%d): %v", id, err)
		}
	}
	if _, _, err := nodefs.QuotaUsage(context.Background(), "relative", dashcfg.StudioUID); err == nil || strings.Contains(err.Error(), "invalid quota id") {
		t.Errorf("QuotaUsage(Studio's uid): %v", err)
	}
}

// TestProjectsDirReaders_IgnoreTheDataDir: the data directory's name is no
// ref, so no project path can name it: every entry point of the package that
// takes a ref refuses it before touching anything.
func TestProjectsDirReaders_IgnoreTheDataDir(t *testing.T) {
	x := newDashFix(t, "studio.test")
	name := filepath.Base(x.d.DataDir())
	if filepath.Dir(x.d.DataDir()) != x.a.p.ProjectsDir() || refRE.MatchString(name) {
		t.Fatalf("data directory %s", x.d.DataDir())
	}
	ctx := context.Background()
	s := Spec{Ref: name, UID: 700001, GID: 700001, DiskQuotaMB: 1, SubnetIndex: 1}
	for what, err := range map[string]error{
		"EnsureDir": x.a.EnsureDir(ctx, s), "SetQuota": x.a.SetQuota(ctx, s), "RemoveRender": x.a.RemoveRender(ctx, name),
		"StopPostgREST": x.a.StopPostgREST(ctx, name), "EnsureRepoDir": x.a.EnsureRepoDir(ctx, s),
	} {
		if err == nil || !strings.Contains(err.Error(), "invalid ref") {
			t.Errorf("%s(%q): %v", what, name, err)
		}
	}
	if _, err := x.a.HostState(ctx, s); err == nil {
		t.Error("HostState accepted the data directory's name")
	}
	if _, err := x.a.DiskUsage(ctx, s); err == nil {
		t.Error("DiskUsage accepted the data directory's name")
	}
	if c := x.f.calls(); len(c) != 0 {
		t.Errorf("calls %q", c)
	}
}

// ───────── the node check ─────────

func TestCheckDashboard_Rows(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	names := func(rows []nodecfg.CheckResult) (n []string, failing []string) {
		for _, r := range rows {
			n = append(n, r.Name)
			if !r.OK {
				failing = append(failing, r.Name)
			}
		}
		return
	}
	n, bad := names(x.a.CheckDashboard(ctx))
	want := []string{rowDashConfig, rowDashFiles, dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgMeta1Name}
	if !slices.Equal(n, want) || !slices.Equal(bad, want[1:]) {
		t.Errorf("before the ensure: rows %q failing %q", n, bad)
	}
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if n, bad = names(x.a.CheckDashboard(ctx)); !slices.Equal(n, want) || len(bad) != 0 {
		t.Errorf("after: rows %q failing %q (%+v)", n, bad, x.a.CheckDashboard(ctx))
	}
	x.f.ctrs[dashcfg.PgMeta1Name].Running = false
	if _, bad = names(x.a.CheckDashboard(ctx)); !slices.Equal(bad, []string{dashcfg.PgMeta1Name}) {
		t.Errorf("a stopped postgres-meta: failing %q", bad)
	}
	x.f.ctrs[dashcfg.PgMeta1Name].Running = true
	rewrite(t, filepath.Join(x.d.StudioKeys(), keyCache), []byte("other\n"))
	if _, bad = names(x.a.CheckDashboard(ctx)); !slices.Equal(bad, []string{rowDashFiles, dashcfg.StudioName}) {
		t.Errorf("a changed copy: failing %q", bad)
	}
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if _, bad = names(x.a.CheckDashboard(ctx)); len(bad) != 0 {
		t.Errorf("repaired: failing %q", bad)
	}
	os.Chmod(x.d.DataDir(), 0o755)
	if _, bad = names(x.a.CheckDashboard(ctx)); !slices.Equal(bad, []string{rowDashFiles}) {
		t.Errorf("a data directory of another mode: failing %q", bad)
	}
	os.Chmod(x.d.DataDir(), 0o700)
	x.mu.Lock()
	x.owners[x.d.DataDir()] = [2]int{dashcfg.PgMetaUID, dashcfg.PgMetaUID}
	x.mu.Unlock()
	if _, bad = names(x.a.CheckDashboard(ctx)); !slices.Equal(bad, []string{rowDashFiles}) {
		t.Errorf("a data directory of another owner: failing %q", bad)
	}
}

// TestCheckDashboard_RestartLoopNamesItsLogLine: a container Docker is
// restarting — Studio exits at start when a setting its start check reads is
// missing, and Docker still reports it running — fails its row, and the row
// carries the container's last log line, bounded.
func TestCheckDashboard_RestartLoopNamesItsLogLine(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	row := func(name string) nodecfg.CheckResult {
		for _, r := range x.a.CheckDashboard(ctx) {
			if r.Name == name {
				return r
			}
		}
		t.Fatalf("no row %s", name)
		return nodecfg.CheckResult{}
	}
	if r := row(dashcfg.StudioName); !r.OK {
		t.Fatalf("control: %+v", r)
	}
	x.mu.Lock()
	x.restarting[dashcfg.StudioName] = true
	x.logs[dashcfg.StudioName] = "supapace: SUPAPACE_LIMITS is not set\n"
	x.mu.Unlock()
	if r := row(dashcfg.StudioName); r.OK || !strings.Contains(r.Detail, "restarting") || !strings.Contains(r.Detail, "supapace: SUPAPACE_LIMITS is not set") {
		t.Errorf("a restart loop: %+v", r)
	}
	if r := row(dashcfg.PgMeta0Name); !r.OK {
		t.Errorf("another container's row: %+v", r)
	}
	x.mu.Lock()
	x.logs[dashcfg.StudioName] = strings.Repeat("y", 100_000)
	x.mu.Unlock()
	if r := row(dashcfg.StudioName); r.OK || len(r.Detail) > 600 {
		t.Errorf("a long log line: OK %v, detail of %d bytes", r.OK, len(r.Detail))
	}
	x.mu.Lock()
	x.logs[dashcfg.StudioName] = strings.Repeat("y", 255) + "é" // the cut falls inside the character
	x.mu.Unlock()
	if r := row(dashcfg.StudioName); !utf8.ValidString(r.Detail) || strings.Contains(r.Detail, `\x`) {
		t.Errorf("the cut splits a character: %s", r.Detail)
	}
	// Between two restarts Docker reports it running and not restarting: a
	// restart within the last minute still fails the row; one an hour ago,
	// or none, does not.
	x.mu.Lock()
	x.restarting[dashcfg.StudioName] = false
	x.restarts[dashcfg.StudioName] = 3
	x.started[dashcfg.StudioName] = time.Now().Add(-2 * time.Second)
	x.logs[dashcfg.StudioName] = "supapace: the header key file cannot be read\n"
	x.mu.Unlock()
	if r := row(dashcfg.StudioName); r.OK || !strings.Contains(r.Detail, "restarted 3 times") || !strings.Contains(r.Detail, "header key file") {
		t.Errorf("up between restarts: %+v", r)
	}
	x.mu.Lock()
	x.started[dashcfg.StudioName] = time.Now().Add(-time.Hour)
	x.mu.Unlock()
	if r := row(dashcfg.StudioName); !r.OK {
		t.Errorf("restarted an hour ago, up since: %+v", r)
	}
	// A container just made has restarted never: it passes from its start.
	x.mu.Lock()
	x.restarts[dashcfg.StudioName] = 0
	x.started[dashcfg.StudioName] = time.Now().Add(-2 * time.Second)
	x.mu.Unlock()
	if r := row(dashcfg.StudioName); !r.OK {
		t.Errorf("just started, never restarted: %+v", r)
	}
}

// TestDashKeys_OwnerAndModeChecked: a key file of KeyDir that is not the
// daemon's own 0600 is refused — nothing is rendered from it and the files
// row names it — and left as it is.
func TestDashKeys_OwnerAndModeChecked(t *testing.T) {
	for _, k := range []string{keyAssert, keyAssertPub, keyCache, keyCrypto} {
		for name, spoil := range map[string]func(x *dashFix, p string){
			"mode 0644": func(x *dashFix, p string) { os.Chmod(p, 0o644) },
			"owner": func(x *dashFix, p string) {
				x.mu.Lock()
				x.owners[p] = [2]int{dashcfg.StudioUID, dashcfg.StudioUID}
				x.mu.Unlock()
			},
		} {
			x := newDashFix(t, "studio.test")
			ctx := context.Background()
			if err := x.a.EnsureDashboard(ctx); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(x.d.KeyDir(), k)
			spoil(x, p)
			x.f.resetLog()
			if err := x.a.EnsureDashboard(ctx); err == nil || !strings.Contains(err.Error(), p) {
				t.Errorf("%s, %s: %v", k, name, err)
			}
			if c := x.creates(); len(c) != 0 {
				t.Errorf("%s, %s: created %q", k, name, c)
			}
			for _, r := range x.a.CheckDashboard(ctx) {
				if r.Name == rowDashFiles && (r.OK || !strings.Contains(r.Detail, p)) {
					t.Errorf("%s, %s: files row %+v", k, name, r)
				}
			}
			for _, w := range x.writes() {
				if strings.Contains(w, p+" ") {
					t.Errorf("%s, %s: rewritten", k, name)
				}
			}
		}
	}
}

// rewrite replaces path's content, keeping its mode (the file may be
// read-only to its owner).
func rewrite(t *testing.T, path string, data []byte) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, fi.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
}

// TestEnsureDashboard_RecreatesOnLabelOrNetwork: a container is adopted only
// at its label, alone on platform at its address; otherwise it is removed and
// made again. A stopped one with its label is started.
func TestEnsureDashboard_RecreatesOnLabelOrNetwork(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		edit func(*fakeCtr)
		want string // "create", "start" or ""
	}{
		{"another label", func(c *fakeCtr) { c.Labels[labelConfig] = "other" }, "create"},
		{"a second network", func(c *fakeCtr) { c.Nets["bridge"] = "10.213.0.9" }, "create"},
		{"another address", func(c *fakeCtr) { c.Nets[platformNet] = "10.212.0.99" }, "create"},
		{"stopped", func(c *fakeCtr) { c.Running = false }, "start"},
		{"as made", func(c *fakeCtr) {}, ""},
	} {
		for _, n := range []string{dashcfg.StudioName, dashcfg.PgMeta1Name} {
			c.edit(x.f.ctrs[n])
			x.f.resetLog()
			if err := x.a.EnsureDashboard(ctx); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, m := range x.f.mutations() {
				got = append(got, strings.Fields(strings.TrimPrefix(m, "docker "))[0])
			}
			want := map[string][]string{"create": {"rm", "create", "start"}, "start": {"start"}, "": nil}[c.want]
			if !slices.Equal(got, want) {
				t.Errorf("%s, %s: %q, want %q", c.name, n, got, want)
			}
		}
	}
}

// TestDashboard_RefusesLimitsThatFailTheirCheck: a bounds table that fails
// its nesting renders no container.
func TestDashboard_RefusesLimitsThatFailTheirCheck(t *testing.T) {
	x := newDashFix(t, "studio.test")
	saved := dashcfg.Limits
	t.Cleanup(func() { dashcfg.Limits = saved })
	dashcfg.Limits.MetaQuerySecs = dashcfg.Limits.ProxyWallMS / 1000 // row 9 + row 7 < row 6 fails
	if err := x.a.EnsureDashboardFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := x.a.dashConfig(context.Background(), x.ad, dashcfg.PgMeta0Name); err == nil {
		t.Error("postgres-meta rendered from a failing table")
	}
	if err := x.a.EnsureDashboard(context.Background()); err == nil || len(x.creates()) != 0 {
		t.Errorf("EnsureDashboard: %v, created %q", err, x.creates())
	}
}

// TestDashFiles_OwnerAndPairChecked: a copy at another owner is not in place
// (reported, then written again); a public half that is not the key's is
// refused.
func TestDashFiles_OwnerAndPairChecked(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(x.d.StudioKeys(), keyCache)
	x.mu.Lock()
	x.owners[p] = [2]int{dashcfg.PgMetaUID, dashcfg.PgMetaUID}
	x.mu.Unlock()
	f := dashFile{x.d.StudioKeys(), keyCache, nil, 0o400, dashcfg.StudioUID, dashcfg.StudioUID}
	if err := f.inPlace(); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Errorf("inPlace: %v", err)
	}
	if err := x.a.checkDashFiles(); err == nil {
		t.Error("check: a copy at another owner passed")
	}
	x.f.resetLog()
	if err := x.a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if w := x.writes(); len(w) != 1 || !strings.Contains(w[0], p+" ") {
		t.Errorf("writes %q, want the copy alone", w)
	}
	x.mu.Lock()
	delete(x.owners, p)
	x.mu.Unlock()
	_, other, _ := dashtok.GenerateKey()
	os.WriteFile(filepath.Join(x.d.KeyDir(), keyAssertPub), other, 0o600)
	if err := x.a.EnsureDashboardFiles(ctx); err == nil || !strings.Contains(err.Error(), "public half") {
		t.Errorf("a public half of another key: %v", err)
	}
}

// TestDashFiles_ModeLinkAndKeyDirChecked: a copy of a key at a wider mode is
// not in place (the row fails, the next call writes it again at its mode); a
// key of KeyDir that is a link is refused, not followed; KeyDir at another
// mode fails the row.
func TestDashFiles_ModeLinkAndKeyDirChecked(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	filesRow := func() nodecfg.CheckResult {
		for _, r := range x.a.CheckDashboard(ctx) {
			if r.Name == rowDashFiles {
				return r
			}
		}
		t.Fatal("no files row")
		return nodecfg.CheckResult{}
	}
	if r := filesRow(); !r.OK {
		t.Fatalf("control: %+v", r)
	}
	copyPath := filepath.Join(x.d.StudioKeys(), keyCrypto)
	if err := os.Chmod(copyPath, 0o444); err != nil {
		t.Fatal(err)
	}
	if r := filesRow(); r.OK {
		t.Error("a world-readable copy of crypto.key passes the files row")
	}
	x.f.resetLog()
	if err := x.a.EnsureDashboardFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if w := x.writes(); len(w) != 1 || !strings.Contains(w[0], copyPath+" ") {
		t.Errorf("writes %q, want the copy alone", w)
	}
	if got := ownerMode(t, x, copyPath); !strings.HasSuffix(got, " 0400") {
		t.Errorf("the copy after the repair: %s", got)
	}

	if err := os.Chmod(x.d.KeyDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := filesRow(); r.OK {
		t.Error("a key directory of mode 0755 passes the files row")
	}
	if err := os.Chmod(x.d.KeyDir(), 0o700); err != nil {
		t.Fatal(err)
	}

	kd := x.d.KeyDir()
	key, err := os.ReadFile(filepath.Join(kd, keyCrypto))
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(elsewhere, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(kd, keyCrypto)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(kd, keyCrypto)); err != nil {
		t.Fatal(err)
	}
	if err := x.a.EnsureDashboardFiles(ctx); err == nil {
		t.Error("crypto.key as a link: accepted")
	}
	if fi, err := os.Lstat(filepath.Join(kd, keyCrypto)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced (%v)", err)
	}
}

// TestCheckDashboard_RestartCountSinceTheLastCheck: Docker spaces a crashing
// container's restarts up to a minute apart and reports it running in
// between, so a crash loop that slow passes the one-minute rule. Each
// container row also fails when its restart count grew since the last check.
func TestCheckDashboard_RestartCountSinceTheLastCheck(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	failing := func() (bad []string, detail string) {
		for _, r := range x.a.CheckDashboard(ctx) {
			if !r.OK {
				bad = append(bad, r.Name)
				detail += r.Detail
			}
		}
		return
	}
	set := func(name string, n int) {
		x.mu.Lock()
		x.restarts[name] = n
		x.logs[name] = "the server's last line\n"
		x.mu.Unlock()
	}
	names := []string{dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgMeta1Name}
	// Restarts of before this daemon's first check are not news (every start
	// in this test is an hour old).
	for _, name := range names {
		set(name, 4)
	}
	if bad, d := failing(); len(bad) != 0 {
		t.Fatalf("the first check: failing %q: %s", bad, d)
	}
	for _, name := range names {
		set(name, 6)
		if bad, d := failing(); !slices.Equal(bad, []string{name}) || !strings.Contains(d, "restarted 2 times since the last check") ||
			!strings.Contains(d, "the server's last line") {
			t.Errorf("%s restarted twice since: failing %q: %s", name, bad, d)
		}
		if bad, d := failing(); len(bad) != 0 {
			t.Errorf("%s, no restart since: failing %q: %s", name, bad, d)
		}
		// Made again since the last check, it counts from nought, not from six.
		x.f.mu.Lock()
		x.f.ctrs[name].Labels[labelConfig] = "other"
		x.f.mu.Unlock()
		if err := x.a.EnsureDashboard(ctx); err != nil {
			t.Fatal(err)
		}
		set(name, 1)
		if bad, d := failing(); !slices.Equal(bad, []string{name}) || !strings.Contains(d, "restarted 1 times since the last check") {
			t.Errorf("%s made again and restarted once: failing %q: %s", name, bad, d)
		}
		set(name, 0)
		x.f.mu.Lock()
		x.f.ctrs[name].Labels[labelConfig] = "other"
		x.f.mu.Unlock()
		if err := x.a.EnsureDashboard(ctx); err != nil {
			t.Fatal(err)
		}
		if bad, d := failing(); len(bad) != 0 {
			t.Errorf("%s made again, never restarted: failing %q: %s", name, bad, d)
		}
	}
}

// TestRemoveDashboard_OnlyWhereTheDashboardIsNotConfigured: a node that has
// lost its dashboard configuration keeps none of the dashboard's containers —
// left there, the node check's member rows fail at the next daemon start and
// every project is stopped. They are removed by exact name and role label;
// nothing else is touched, and a configured node is left alone.
func TestRemoveDashboard_OnlyWhereTheDashboardIsNotConfigured(t *testing.T) {
	for _, c := range []struct {
		name string
		lose func(*Agent)
	}{
		{"no studio domain", func(a *Agent) { a.cfg.StudioDomain = "" }},
		{"a configuration that cannot host one", func(a *Agent) { a.cfg.UIDBase, a.cfg.UIDCount = 65000, 1000 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newProxyFix(t, "studio.test")
			ctx := context.Background()
			s := x.project(14)
			healthy(x.a, x.f, s)
			tenants(x.a, x.f, s)
			if err := x.a.EnsureDashboard(ctx); err != nil {
				t.Fatal(err)
			}
			if err := x.a.AttachProxy(ctx, s); err != nil {
				t.Fatal(err)
			}
			keys := x.keyTexts(t)
			// Configured: nothing is read, nothing removed.
			x.f.resetLog()
			if err := x.a.RemoveDashboard(ctx); err != nil || len(x.f.calls()) != 0 {
				t.Fatalf("on a configured node: %v, calls %q", err, x.f.calls())
			}
			if err := x.a.CheckContainment(ctx, s); err != nil {
				t.Fatalf("control: the project starts on the configured node: %v", err)
			}
			c.lose(x.a)
			// What an operator would see without the removal.
			if err := x.a.checkPlatformMembers(ctx); err == nil || !strings.Contains(err.Error(), "foreign member") {
				t.Fatalf("control: platform-members with the containers left: %v", err)
			}
			if err := x.a.CheckContainment(ctx, s); err == nil || !strings.Contains(err.Error(), "member rule") {
				t.Fatalf("control: a start with the proxy left on the project network: %v", err)
			}
			// Not the platform's: the same name under another role label, and the
			// role label under another name.
			x.f.mu.Lock()
			x.f.ctrs[dashcfg.PgMeta1Name].Labels[labelRole] = "studio" // not its own
			x.f.mu.Unlock()
			x.f.ctr(fakeCtr{Name: dashcfg.StudioName + "-old", Running: true, CapDrop: []string{"ALL"}, Labels: map[string]string{labelRole: "studio"}})
			x.f.ctr(fakeCtr{Name: dashcfg.PgcapName + "2", Running: true, CapDrop: []string{"ALL"}, Labels: map[string]string{labelRole: "pgcap"}})
			// Each is removed by the id that was inspected, never by its name: a
			// container put under that name in between is not the one judged.
			ids := map[string]string{}
			x.f.mu.Lock()
			for name, c := range x.f.ctrs {
				ids[c.ID] = name
			}
			x.f.mu.Unlock()
			x.f.resetLog()
			if err := x.a.RemoveDashboard(ctx); err != nil {
				t.Fatal(err)
			}
			var removed []string
			for _, a := range x.f.argv("rm") {
				if !slices.Equal(a[:len(a)-1], []string{"rm", "-f", "--"}) || ids[a[len(a)-1]] == "" {
					t.Errorf("removal %q, want one by the container's id", a)
				}
				removed = append(removed, ids[a[len(a)-1]])
			}
			if want := []string{dashcfg.StudioName, dashcfg.PgMeta0Name, dashcfg.PgcapName}; !slices.Equal(removed, want) {
				t.Errorf("removed %q, want %q", removed, want)
			}
			if m := x.f.mutations(); len(m) != 3 {
				t.Errorf("Docker calls that change something: %q, want the three removals", m)
			}
			x.f.mu.Lock()
			var left []string
			for n := range x.f.ctrs {
				left = append(left, n)
			}
			x.f.mu.Unlock()
			slices.Sort(left)
			if want := []string{"pg-" + s.Ref, "postgrest-" + s.Ref, "sp-gateway", dashcfg.PgcapName + "2", dashcfg.PgMeta1Name, dashcfg.StudioName + "-old"}; !slices.Equal(left, want) {
				t.Errorf("containers left %q, want %q", left, want)
			}
			// The proxy's table goes with it: a node given a dashboard again
			// starts from no slice. The keys stay.
			if _, err := os.Lstat(x.path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the proxy's table is still there (%v)", err)
			}
			if !slices.Equal(x.keyTexts(t), keys) {
				t.Error("the keys changed")
			}
			// Again: nothing left to do.
			x.f.resetLog()
			if err := x.a.RemoveDashboard(ctx); err != nil || len(x.f.mutations()) != 0 {
				t.Errorf("again: %v, %q", err, x.f.mutations())
			}
			// With the strangers gone too (an operator's work), neither the
			// member rows nor a start is refused.
			x.f.mu.Lock()
			for _, n := range []string{dashcfg.PgMeta1Name, dashcfg.StudioName + "-old", dashcfg.PgcapName + "2"} {
				delete(x.f.ctrs, n)
			}
			x.f.mu.Unlock()
			if err := x.a.checkPlatformMembers(ctx); err != nil {
				t.Errorf("platform-members after the removal: %v", err)
			}
			nets, err := dockerNetworks(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := x.a.checkProjectAddresses(ctx, nets); err != nil {
				t.Errorf("project-addresses after the removal: %v", err)
			}
			if err := x.a.CheckContainment(ctx, s); err != nil {
				t.Errorf("a start after the removal: %v", err)
			}
			// A removal that fails is reported, and the others still happen.
			x.a.cfg = nodecfg.Default("sp.test")
			x.a.cfg.Uplinks, x.a.cfg.StudioDomain = []string{"eth0"}, "studio.test"
			if err := x.a.EnsureDashboard(ctx); err != nil {
				t.Fatal(err)
			}
			c.lose(x.a)
			boom := errors.New("docker: daemon busy")
			x.f.failInspect[dashcfg.StudioName] = boom
			if err := x.a.RemoveDashboard(ctx); !errors.Is(err, boom) {
				t.Errorf("a container that cannot be inspected: %v", err)
			}
			x.f.mu.Lock()
			_, studio := x.f.ctrs[dashcfg.StudioName]
			_, meta := x.f.ctrs[dashcfg.PgMeta0Name]
			x.f.mu.Unlock()
			if !studio || meta {
				t.Errorf("after the failed inspection: Studio there %v, postgres-meta there %v", studio, meta)
			}
		})
	}
}

// A fake without a dashboard fixture answers the restart reading for any
// container it has: never restarted, started an hour ago.
func init() {
	fakeVerbs[restartFormat] = func(f *fakeHost, args []string, _ []byte) (string, error) {
		c, ok := f.resolve(positional(args)[0])
		if !ok {
			return "", errors.New("docker: no such container")
		}
		return fmt.Sprintf("%s false 0 %s\n", c.ID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)), nil
	}
}
