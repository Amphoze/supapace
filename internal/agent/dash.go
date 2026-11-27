package agent

// The dashboard's node side: its keys, the files the gateway reads, Studio's
// data volume and the containers sp-studio, sp-pgmeta-0 and sp-pgmeta-1. On a
// node without a studio domain nothing here acts: no directory, no file, no
// image, no Docker call.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// The rows of CheckDashboard besides the three containers' (named after them).
const (
	rowDashConfig = "dashboard-config"
	rowDashFiles  = "dashboard-files"
)

// Where Studio sees its three mounts; dashcfg's fixed environment names the
// same paths (SUPAPACE_DASH_SOCKET is in the first, SUPAPACE_DASH_KEYS the
// second, SUPAPACE_DASH_DATA the third).
const (
	studioSockMount = "/run/dash"
	studioKeysMount = "/etc/dash"
	studioDataMount = "/var/lib/dash"
)

// labelStudioEnv is the Studio image's label that declares what it needs of
// its environment (a JSON object; dashcfg.StudioEnv decides what it may hold).
const labelStudioEnv = "supapace.studio.env"

// The key files of KeyDir: the assertion pair, the cache key (32 random
// bytes) and the header-encryption key (48 random bytes: 64 base64url
// characters, the one form it is taken in).
const (
	keyAssert, keyAssertPub, keyCache, keyCrypto = "assert.key", "assert.pub", "cache.key", "crypto.key"
	cacheKeyBytes, cryptoKeyBytes                = 32, 48
)

// Seams (tests replace them): the owner of a file as the filesystem reports
// it, and the pinned postgres-meta image.
var (
	fileOwner = func(path string, fi os.FileInfo) (uid, gid int) {
		st := fi.Sys().(*syscall.Stat_t)
		return int(st.Uid), int(st.Gid)
	}
	pgMetaImage = nodecfg.PgMetaImage
)

// dashAddrs is the node's dashboard addresses. ok is false on a node without
// a studio domain (err nil) and on one whose configuration dashcfg.For
// refuses (err its reason).
func (a *Agent) dashAddrs() (ad dashcfg.Addrs, ok bool, err error) {
	if a.cfg.StudioDomain == "" {
		return dashcfg.Addrs{}, false, nil
	}
	ad, err = dashcfg.For(a.cfg)
	return ad, err == nil, err
}

// EnsureDashboardFiles makes the keys (once), the dashboard's directories and
// the files the gateway reads: dash/domain, the assertion key and the studio
// pair, plus Studio's copies of its keys. It creates and starts no container.
// Without a studio domain, or when dashcfg.For refuses the node's
// configuration, it does nothing and returns nil (CheckDashboard reports the
// refusal).
func (a *Agent) EnsureDashboardFiles(ctx context.Context) error {
	if _, ok, _ := a.dashAddrs(); !ok {
		return nil
	}
	return a.ensureDashFiles()
}

// EnsureDashboard is EnsureDashboardFiles, then Studio's quota and data
// directory, then sp-studio, sp-pgmeta-0 and sp-pgmeta-1, each adopted when
// it carries this daemon's configuration label at its address and re-created
// otherwise. Like EnsureDashboardFiles it does nothing without a studio domain
// or on a refused configuration. EnsureImageFiles (the seccomp profile) and
// EnsurePlatformNetworks come first.
func (a *Agent) EnsureDashboard(ctx context.Context) error {
	ad, ok, _ := a.dashAddrs()
	if !ok {
		return nil
	}
	if err := a.ensureDashFiles(); err != nil {
		return err
	}
	// The quota first: a filesystem without enforced quotas stops here,
	// before the directory is handed to Studio's uid.
	d := dashcfg.PathsFor(a.p)
	if err := repoSetQuota(a.p.ProjectsDir(), dashcfg.StudioUID, dashcfg.Limits.StudioVolumeMB); err != nil {
		return fmt.Errorf("agent: Studio's quota on the projects filesystem: %w", err)
	}
	if err := ensureDir(d.DataDir(), 0o700, dashcfg.StudioUID, dashcfg.StudioUID); err != nil {
		return err
	}
	for _, c := range dashContainers(ad) {
		opts, cmd, conf, err := a.dashConfig(ctx, ad, c.name)
		if err != nil {
			return err
		}
		if err := a.ensureDashContainer(ctx, c.name, c.ip, opts, cmd, conf); err != nil {
			return err
		}
	}
	return nil
}

// CheckDashboard reports the dashboard's node side: nothing without a studio
// domain; the row dashboard-config alone when dashcfg.For refuses the
// configuration (its reason as the detail); else that row, dashboard-files
// (every key and copy in its form, mode and owner; the data directory) and one
// row per container.
func (a *Agent) CheckDashboard(ctx context.Context) []nodecfg.CheckResult {
	ad, ok, err := a.dashAddrs()
	if !ok && err == nil {
		return nil
	}
	var rows []nodecfg.CheckResult
	add := func(name string, err error) {
		r := nodecfg.CheckResult{Name: name, OK: err == nil}
		if err != nil {
			r.Detail = err.Error()
		}
		rows = append(rows, r)
	}
	add(rowDashConfig, err)
	if err != nil {
		return rows
	}
	add(rowDashFiles, a.checkDashFiles())
	for _, c := range dashContainers(ad) {
		if err := dashRestarting(ctx, c.name); err != nil {
			add(c.name, err)
			continue
		}
		add(c.name, a.checkPlatformContainer(ctx, c.name, map[string]string{platformNet: c.ip}, func() (string, error) {
			_, _, conf, err := a.dashConfig(ctx, ad, c.name)
			return conf, err
		}))
	}
	return rows
}

// restartFormat reads whether Docker is restarting a container, how often it
// has restarted it and when its process last started.
const restartFormat = "{{.State.Restarting}} {{.RestartCount}} {{.State.StartedAt}}"

// dashRestarting fails a container Docker is restarting, or has restarted and
// started again within the last minute — Docker reports it running in both
// cases, and a process that dies a few seconds after each start is up most of
// the time — with its last log line, at most 256 bytes: Studio exits at
// start, with one line, when a setting its start check reads is missing or
// invalid. A re-created container counts from 0. nil when none of this holds
// or it cannot be inspected (checkPlatformContainer then reports what it
// finds).
func dashRestarting(ctx context.Context, name string) error {
	out, err := dockerRun(ctx, "container", "inspect", "--format", restartFormat, "--", name)
	f := strings.Fields(out)
	if err != nil || len(f) != 3 {
		return nil
	}
	n, _ := strconv.Atoi(f[1])
	started, terr := time.Parse(time.RFC3339Nano, f[2])
	var why string
	switch {
	case f[0] == "true":
		why = "is restarting"
	case n > 0 && terr == nil && time.Since(started) < time.Minute:
		why = fmt.Sprintf("restarted %d times, the last start %s ago", n, time.Since(started).Round(time.Second))
	default:
		return nil
	}
	so, se, _ := dockerRunOutput(ctx, "logs", "--tail", "1", "--", name)
	line := strings.TrimSpace(se + so)
	if len(line) > 256 {
		line = strings.ToValidUTF8(line[:256], "") + "…"
	}
	return fmt.Errorf("%s %s; its last log line: %q", name, why, line)
}

type dashCtr struct{ name, ip string }

func dashContainers(ad dashcfg.Addrs) []dashCtr {
	return []dashCtr{{dashcfg.StudioName, ad.Studio.String()}, {dashcfg.PgMeta0Name, ad.PgMeta0.String()},
		{dashcfg.PgMeta1Name, ad.PgMeta1.String()}}
}

// ───────── keys and files ─────────

// ensureDashFiles: KeyDir and its keys, the directories, then each file that
// is not in place in content, mode and owner (a file in place is not written
// again).
func (a *Agent) ensureDashFiles() error {
	d := dashcfg.PathsFor(a.p)
	if err := ensureDir(d.KeyDir(), 0o700, -1, -1); err != nil {
		return err
	}
	if err := a.createKeys(d.KeyDir()); err != nil {
		return err
	}
	files, err := a.dashFiles()
	if err != nil {
		return err
	}
	if err := a.ensurePlatformDir(); err != nil {
		return err
	}
	for _, dir := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{
		{d.DashDir(), 0o755, -1, -1},
		{d.SocketDir(), 0o750, 0, dashcfg.StudioUID}, // as dashsock.Listen makes it
		{d.StudioKeys(), 0o755, -1, -1},
		{pgmetaKeysDir(d), 0o755, -1, -1},
		{a.p.GatewayDir(), 0o755, -1, -1},
		{d.GatewayDash(), 0o755, -1, -1},
		{d.GatewayStudioTLS(), 0o755, -1, -1},
	} {
		if err := ensureDir(dir.path, dir.mode, dir.uid, dir.gid); err != nil {
			return err
		}
	}
	for _, f := range files {
		if f.inPlace() == nil {
			continue
		}
		if err := writeFile(a.p, f.dir, f.name, f.data, f.mode, f.uid, f.gid); err != nil {
			return err
		}
	}
	return nil
}

// createKeys writes each key file of dir that is absent, root 0600, and never
// replaces one that exists. The assertion key is written before its public
// half: a public half alone is refused, a key alone gets its public half.
func (a *Agent) createKeys(dir string) error {
	has := func(name string) (bool, error) { return present(filepath.Join(dir, name)) }
	write := func(name string, data []byte) error {
		return writeFile(a.p, dir, name, data, 0o600, os.Geteuid(), os.Getegid())
	}
	key, err := has(keyAssert)
	if err != nil {
		return err
	}
	pub, err := has(keyAssertPub)
	if err != nil {
		return err
	}
	switch {
	case !key && pub:
		return fmt.Errorf("agent: %s exists without %s; neither is replaced", filepath.Join(dir, keyAssertPub), keyAssert)
	case !key:
		priv, pubFile, err := dashtok.GenerateKey()
		if err != nil {
			return err
		}
		if err := write(keyAssert, priv); err != nil {
			return err
		}
		if err := write(keyAssertPub, pubFile); err != nil {
			return err
		}
	case !pub:
		b, err := readRegularFile(filepath.Join(dir, keyAssert))
		if err != nil {
			return err
		}
		k, err := dashtok.ParsePrivate(b)
		if err != nil {
			return fmt.Errorf("agent: %s: %w", filepath.Join(dir, keyAssert), err)
		}
		if err := write(keyAssertPub, []byte(base64.RawURLEncoding.EncodeToString(k[32:])+"\n")); err != nil {
			return err
		}
	}
	for _, k := range []struct {
		name  string
		bytes int
		eol   string
	}{{keyCache, cacheKeyBytes, "\n"}, {keyCrypto, cryptoKeyBytes, ""}} {
		ok, err := has(k.name)
		if err != nil || ok {
			if err != nil {
				return err
			}
			continue
		}
		b := make([]byte, k.bytes)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		if err := write(k.name, []byte(base64.RawURLEncoding.EncodeToString(b)+k.eol)); err != nil {
			return err
		}
	}
	return nil
}

// dashKeys are KeyDir's four files as read and checked.
type dashKeys struct{ priv, pub, cache, crypto []byte }

// readDashKeys reads KeyDir's files, each a regular file of mode 0600 owned
// by the daemon (root), and refuses any not so or not in its form: the assertion pair as dashtok reads it and matching; cache.key
// as dashtok reads a key file (43 base64url characters and at most one line
// end: what Studio's reader accepts); crypto.key exactly 64 base64url
// characters and nothing else — Studio uses the file as it holds it, a line
// end included, and postgres-meta reads its copy as it is too, so this
// is the one form both readers take alike.
func readDashKeys(dir string) (dashKeys, error) {
	var k dashKeys
	for _, f := range []struct {
		name string
		dst  *[]byte
	}{{keyAssert, &k.priv}, {keyAssertPub, &k.pub}, {keyCache, &k.cache}, {keyCrypto, &k.crypto}} {
		p := filepath.Join(dir, f.name)
		fi, err := os.Lstat(p)
		if err != nil {
			return dashKeys{}, err
		}
		if uid, gid := fileOwner(p, fi); !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || uid != os.Geteuid() || gid != os.Getegid() {
			return dashKeys{}, fmt.Errorf("agent: %s is not a regular file of mode 0600 owned by %d:%d", p, os.Geteuid(), os.Getegid())
		}
		b, err := readRegularFile(p)
		if err != nil {
			return dashKeys{}, err
		}
		*f.dst = b
	}
	bad := func(name string) error { return fmt.Errorf("agent: %s is not in its form", filepath.Join(dir, name)) }
	priv, err := dashtok.ParsePrivate(k.priv)
	if err != nil {
		return dashKeys{}, bad(keyAssert)
	}
	pub, err := dashtok.ParsePublic(k.pub)
	if err != nil {
		return dashKeys{}, bad(keyAssertPub)
	}
	if !bytes.Equal(pub, priv[32:]) {
		return dashKeys{}, fmt.Errorf("agent: %s is not the public half of %s", filepath.Join(dir, keyAssertPub), keyAssert)
	}
	if _, err := dashtok.ParsePublic(k.cache); err != nil {
		return dashKeys{}, bad(keyCache)
	}
	if n := base64.RawURLEncoding.EncodedLen(cryptoKeyBytes); len(k.crypto) != n || !base64URLChars(k.crypto) {
		return dashKeys{}, fmt.Errorf("agent: %s does not hold %d base64url characters and nothing else", filepath.Join(dir, keyCrypto), n)
	}
	return k, nil
}

func base64URLChars(b []byte) bool {
	for _, c := range b {
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// dashFile is one file the dashboard's node side keeps in place.
type dashFile struct {
	dir, name string
	data      []byte
	mode      os.FileMode
	uid, gid  int
}

// inPlace is nil when the file holds data with exactly mode and owner.
func (f dashFile) inPlace() error {
	p := filepath.Join(f.dir, f.name)
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	uid, gid := fileOwner(p, fi)
	switch {
	case !fi.Mode().IsRegular() || fi.Mode().Perm() != f.mode:
		return fmt.Errorf("%s: not a regular file of mode %04o", p, f.mode)
	case uid != f.uid || gid != f.gid:
		return fmt.Errorf("%s: owned by %d:%d, want %d:%d", p, uid, gid, f.uid, f.gid)
	}
	b, err := readRegularFile(p)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, f.data) {
		return fmt.Errorf("%s differs", p)
	}
	return nil
}

// dashFiles is every file the dashboard's node side writes from KeyDir and
// StudioTLS, with its mode and owner: Studio's copies of its three keys and
// the gateway's domain file, assertion key and studio pair.
func (a *Agent) dashFiles() ([]dashFile, error) {
	d := dashcfg.PathsFor(a.p)
	k, err := readDashKeys(d.KeyDir())
	if err != nil {
		return nil, err
	}
	cert, err := readRegularFile(filepath.Join(d.StudioTLS(), "cert.pem"))
	if err != nil {
		return nil, fmt.Errorf("agent: the studio certificate: %w", err)
	}
	key, err := readRegularFile(filepath.Join(d.StudioTLS(), "key.pem"))
	if err != nil {
		return nil, fmt.Errorf("agent: the studio key: %w", err)
	}
	root, rootG, st, gw := os.Geteuid(), os.Getegid(), dashcfg.StudioUID, gatewayUID
	return []dashFile{
		{d.StudioKeys(), keyAssertPub, k.pub, 0o444, root, rootG},
		{d.StudioKeys(), keyCache, k.cache, 0o400, st, st},
		{d.StudioKeys(), keyCrypto, k.crypto, 0o400, st, st},
		{pgmetaKeysDir(d), keyCrypto, k.crypto, 0o400, dashcfg.PgMetaUID, dashcfg.PgMetaUID},
		{d.GatewayDash(), keyAssert, k.priv, 0o400, gw, gw},
		{d.GatewayDash(), "domain", []byte(a.cfg.StudioDomain + "\n"), 0o444, root, rootG},
		{d.GatewayStudioTLS(), "key.pem", key, 0o400, gw, gw},
		{d.GatewayStudioTLS(), "cert.pem", cert, 0o444, root, rootG},
	}, nil
}

// checkDashFiles: every file of dashFiles in place, KeyDir root 0700, the data
// directory Studio's 0700.
func (a *Agent) checkDashFiles() error {
	d := dashcfg.PathsFor(a.p)
	for _, dir := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{{d.KeyDir(), 0o700, os.Geteuid(), os.Getegid()}, {d.DataDir(), 0o700, dashcfg.StudioUID, dashcfg.StudioUID}} {
		fi, err := os.Lstat(dir.path)
		if err != nil {
			return err
		}
		if uid, gid := fileOwner(dir.path, fi); !fi.IsDir() || fi.Mode().Perm() != dir.mode || uid != dir.uid || gid != dir.gid {
			return fmt.Errorf("%s: not a directory of mode %04o owned by %d:%d", dir.path, dir.mode, dir.uid, dir.gid)
		}
	}
	files, err := a.dashFiles()
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range files {
		errs = append(errs, f.inPlace())
	}
	return errors.Join(errs...)
}

// readRegularFile reads path, never through a link, refusing anything but a
// regular file of at most 1 MiB (a FIFO does not block).
func readRegularFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := readRegular(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// gatewayDashDigests is what the gateway's configuration label adds on a node
// with a studio domain: the digests of its domain file, of the node's public
// assertion key and of its studio certificate — a file not yet written counts
// as absent, so the label changes once it is. Nothing without a studio
// domain.
func (a *Agent) gatewayDashDigests() ([]string, error) {
	if a.cfg.StudioDomain == "" {
		return nil, nil
	}
	d := dashcfg.PathsFor(a.p)
	var out []string
	for _, p := range []string{filepath.Join(d.GatewayDash(), "domain"), filepath.Join(d.KeyDir(), keyAssertPub),
		filepath.Join(d.GatewayStudioTLS(), "cert.pem")} {
		dg, err := fileDigests(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			dg = []string{filepath.Base(p) + " absent"}
		case err != nil:
			return nil, err
		}
		out = append(out, "studio "+dg[0])
	}
	return out, nil
}

// ───────── the containers ─────────

// dashHardening is what every dashboard container is created with.
func (a *Agent) dashHardening() []string {
	return []string{"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--ulimit", "core=0", "--no-healthcheck", "--restart", "unless-stopped", "--ipc", "private",
		"--sysctl", "net.ipv4.ping_group_range=1 0", "--sysctl", "net.ipv6.conf.all.disable_ipv6=1"}
}

// dashConfig is name's create options, command (image first) and its
// configuration label: options, command, image id, the seccomp profile and
// the keys the container reads once, as digests.
func (a *Agent) dashConfig(ctx context.Context, ad dashcfg.Addrs, name string) (opts, cmd []string, conf string, err error) {
	if err := dashcfg.Limits.Check(); err != nil {
		return nil, nil, "", err
	}
	d := dashcfg.PathsFor(a.p)
	l := dashcfg.Limits
	if name == dashcfg.StudioName {
		id, imgEnv, labels, err := imageConfig(ctx, dashcfg.StudioImage)
		if err != nil {
			return nil, nil, "", err
		}
		env, err := studioEnv(ad, a.cfg.NodeID, imgEnv, labels)
		if err != nil {
			return nil, nil, "", err
		}
		mem := strconv.Itoa(l.StudioMemMB) + "m"
		opts = slices.Concat([]string{"create", "--name", name, "--user", fmt.Sprintf("%d:%d", dashcfg.StudioUID, dashcfg.StudioUID)},
			a.dashHardening(), []string{"--memory", mem, "--memory-swap", mem, "--pids-limit", "256", "--tmpfs", "/tmp",
				"--network", platformNet, "--ip", ad.Studio.String(),
				"-v", d.SocketDir() + ":" + studioSockMount + ":ro", "-v", d.StudioKeys() + ":" + studioKeysMount + ":ro",
				"-v", d.DataDir() + ":" + studioDataMount, "--label", labelRole + "=studio"})
		for _, e := range env {
			opts = append(opts, "-e", e)
		}
		cmd = []string{dashcfg.StudioImage}
		extra, err := fileDigests(a.seccompFile(), filepath.Join(d.StudioKeys(), keyAssertPub),
			filepath.Join(d.StudioKeys(), keyCache), filepath.Join(d.StudioKeys(), keyCrypto))
		if err != nil {
			return nil, nil, "", err
		}
		return opts, cmd, configHash(opts, cmd, append(extra, "image id="+id)...), nil
	}
	ip := ad.PgMeta0
	if name == dashcfg.PgMeta1Name {
		ip = ad.PgMeta1
	}
	ref, err := pgMetaImage()
	if err != nil {
		return nil, nil, "", err
	}
	k, err := readDashKeys(d.KeyDir())
	if err != nil {
		return nil, nil, "", err
	}
	id, imgEnv, _, err := imageConfig(ctx, ref)
	if err != nil {
		return nil, nil, "", err
	}
	// The image falls back to a built-in key when its key file is missing or
	// empty: it is rendered only while the copy it reads is the key in place.
	if err := (dashFile{pgmetaKeysDir(d), keyCrypto, k.crypto, 0o400, dashcfg.PgMetaUID, dashcfg.PgMetaUID}).inPlace(); err != nil {
		return nil, nil, "", fmt.Errorf("agent: postgres-meta's key: %w", err)
	}
	env := append(dashcfg.PgMetaEnv(l), "CRYPTO_KEY_FILE="+pgmetaKeysMount+"/"+keyCrypto)
	if err := refuseLibpqNames(slices.Concat(imgEnv, env)); err != nil {
		return nil, nil, "", fmt.Errorf("agent: %s: %w", ref, err)
	}
	// The image takes CRYPTO_KEY before the file: its own ENV may name neither.
	for _, kv := range imgEnv {
		if n, _, _ := strings.Cut(kv, "="); n == "CRYPTO_KEY" || n == "CRYPTO_KEY_FILE" {
			return nil, nil, "", fmt.Errorf("agent: %s sets %s in its own ENV", ref, n)
		}
	}
	mem := strconv.Itoa(l.PgMetaMemMB) + "m"
	opts = slices.Concat([]string{"create", "--name", name, "--user", fmt.Sprintf("%d:%d", dashcfg.PgMetaUID, dashcfg.PgMetaUID)},
		a.dashHardening(), []string{"--memory", mem, "--memory-swap", mem, "--cpus", "1", "--pids-limit", "128", "--tmpfs", "/tmp",
			"--network", platformNet, "--ip", ip.String(), "-v", pgmetaKeysDir(d) + ":" + pgmetaKeysMount + ":ro",
			"--label", labelRole + "=pgmeta"})
	for _, e := range env {
		opts = append(opts, "-e", e)
	}
	cmd = []string{ref}
	extra, err := fileDigests(a.seccompFile(), filepath.Join(d.KeyDir(), keyCrypto))
	if err != nil {
		return nil, nil, "", err
	}
	return opts, cmd, configHash(opts, cmd, append(extra, "image id="+id)...), nil
}

// studioEnv is dashcfg.StudioEnv with the image's label, after the image's own
// ENV is checked: it names nothing Studio's listener reads, no fixed name and
// no feature, which the label and the fixed list alone may set.
func studioEnv(ad dashcfg.Addrs, node string, imgEnv []string, labels map[string]string) ([]string, error) {
	raw, ok := labels[labelStudioEnv]
	if !ok {
		return nil, fmt.Errorf("agent: %s has no label %s", dashcfg.StudioImage, labelStudioEnv)
	}
	var declared map[string]string
	dec := json.NewDecoder(strings.NewReader(raw))
	if err := dec.Decode(&declared); err != nil || declared == nil || dec.More() {
		return nil, fmt.Errorf("agent: %s: the label %s is not a JSON object of strings", dashcfg.StudioImage, labelStudioEnv)
	}
	for _, kv := range imgEnv {
		n, _, _ := strings.Cut(kv, "=")
		if slices.Contains(dashcfg.ListenerNames, n) || slices.Contains(dashcfg.FixedEnvNames(), n) || strings.HasPrefix(n, "ENABLED_FEATURES_") {
			return nil, fmt.Errorf("agent: %s sets %s in its own ENV", dashcfg.StudioImage, n)
		}
	}
	env, err := dashcfg.StudioEnv(ad, node, dashcfg.Limits, declared)
	if err != nil {
		return nil, fmt.Errorf("agent: %s: %w", dashcfg.StudioImage, err)
	}
	return env, nil
}

// refuseLibpqNames refuses a name of libpq's family in env (NAME=value):
// "PG" followed by a capital letter (PGHOST, PGPASSWORD, PGSSLMODE, ...).
// node-postgres takes them as defaults of every connection; postgres-meta's
// own names are PG_….
func refuseLibpqNames(env []string) error {
	for _, kv := range env {
		n, _, _ := strings.Cut(kv, "=")
		if len(n) > 2 && strings.HasPrefix(n, "PG") && n[2] != '_' {
			return fmt.Errorf("the environment holds %s", n)
		}
	}
	return nil
}

// imageConfFormat reads an image's id and configuration in one call (the
// configuration whole: an image without labels has no Labels member, which
// a template naming it refuses).
const imageConfFormat = `{"id":{{json .Id}},"config":{{json .Config}}}`

// imageConfig is the id, own ENV and labels of the image ref names now.
func imageConfig(ctx context.Context, ref string) (id string, env []string, labels map[string]string, err error) {
	out, err := dockerRun(ctx, "image", "inspect", "--format", imageConfFormat, "--", ref)
	if err != nil {
		return "", nil, nil, err
	}
	var c struct {
		ID     string `json:"id"`
		Config struct {
			Env    []string
			Labels map[string]string
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &c); err != nil || !imageIDRE.MatchString(c.ID) {
		return "", nil, nil, fmt.Errorf("docker image inspect %s: not an image configuration", ref)
	}
	return c.ID, c.Config.Env, c.Config.Labels, nil
}

// ensureDashContainer adopts name when it carries conf and sits on platform
// alone at ip (started when stopped), and otherwise (re-)creates and starts
// it.
func (a *Agent) ensureDashContainer(ctx context.Context, name, ip string, opts, cmd []string, conf string) error {
	confs, err := a.existing(ctx, name)
	if err != nil {
		return err
	}
	if len(confs) == 1 {
		c := confs[0]
		at, on := c.addr(platformNet)
		if c.Labels[labelConfig] == conf && on && at == ip && len(c.Networks) == 1 {
			if !c.Running {
				_, err = dockerRun(ctx, "start", "--", name)
			}
			return err
		}
		logRecreate(name, "its configuration changed", c.Running)
		if _, err := dockerRun(ctx, "rm", "-f", "--", name); err != nil {
			return err
		}
	}
	args := slices.Concat(opts, []string{"--label", labelConfig + "=" + conf, "--"}, cmd)
	if _, err := dockerRun(ctx, args...); err != nil {
		return err
	}
	_, err = dockerRun(ctx, "start", "--", name)
	return err
}

// pgmetaKeysDir is the directory postgres-meta's key copy is in (root 0755;
// crypto.key PgMetaUID 0400), mounted read-only at pgmetaKeysMount: the image
// reads the key from the file CRYPTO_KEY_FILE names, so the key is in no
// container's configuration.
func pgmetaKeysDir(d dashcfg.Paths) string { return filepath.Join(d.DashDir(), "pgmeta") }

const pgmetaKeysMount = "/etc/pgmeta"
