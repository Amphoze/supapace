package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/jackc/pgx/v5"
)

// seccompProfile is Docker's default seccomp profile, passed explicitly to
// every container the daemon starts so that it does not depend on the
// daemon's built-in default. The file is seccomp/default.json of the
// github.com/moby/profiles module exactly as vendored by Docker 29.10.0 (the
// release the node image pins), unmodified, under the Apache License 2.0;
// seccomp/NOTICE gives its source and attribution. Replace both, unmodified,
// when that pin moves.
//
//go:embed seccomp/default.json
var seccompProfile []byte

// Ids of the platform's own containers.
const (
	cpUID      = nodecfg.ControlPlaneUID // the control-plane image's postgres user
	gatewayUID = 65531                   // the gateway image's user; nothing else runs as it
)

// EnsurePlatformNetworks creates `platform` (internal, isolated: no host
// address, no routed path; Docker allocates only from platform_ip_range) and
// `ingress`, both with IPv6 off. A network of either name with other options
// is ErrContainment.
func (a *Agent) EnsurePlatformNetworks(ctx context.Context) error {
	c := a.cfg
	plat, err := dockerInspectNetwork(ctx, platformNet)
	if err != nil {
		return err
	}
	if plat == nil {
		if _, err := dockerRun(ctx, "network", "create", "--internal", "--ipv6=false", "--subnet", c.PlatformSubnet,
			"--ip-range", c.PlatformIPRange, "-o", optBridgeName+"="+nodecfg.PlatformBridge,
			"-o", optGatewayMode+"=isolated", "--", platformNet); err != nil {
			return err
		}
	} else if why, err := a.platformMismatch(ctx, plat); err != nil {
		return err
	} else if why != "" {
		return refuse(nil, "%s exists: %s", platformNet, why)
	} else if err := refuseIPv6(ctx, platformNet); err != nil {
		return err
	}
	ing, err := dockerInspectNetwork(ctx, ingressNet)
	if err != nil {
		return err
	}
	if ing == nil {
		_, err := dockerRun(ctx, "network", "create", "--ipv6=false", "--subnet", c.IngressSubnet,
			"-o", optBridgeName+"="+nodecfg.IngressBridge, "--", ingressNet)
		return err
	}
	switch {
	case ing.Internal:
		return refuse(nil, "%s exists: internal", ingressNet)
	case ing.BridgeName != nodecfg.IngressBridge:
		return refuse(nil, "%s exists: bridge %q", ingressNet, ing.BridgeName)
	case !samePrefix(ing.Subnet, netPrefix(c.IngressSubnet)):
		return refuse(nil, "%s exists: subnet %q", ingressNet, ing.Subnet)
	}
	return refuseIPv6(ctx, ingressNet)
}

// platformMismatch says why an existing platform network is not ours, or "".
func (a *Agent) platformMismatch(ctx context.Context, n *dockerx.Network) (string, error) {
	if why := platformNetMismatch(n); why != "" {
		return why, nil
	}
	if !samePrefix(n.Subnet, netPrefix(a.cfg.PlatformSubnet)) {
		return fmt.Sprintf("subnet %q", n.Subnet), nil
	}
	// The IPAM gateway reads "invalid IP" in isolated mode; it is not read.
	out, err := dockerRun(ctx, "network", "inspect", "--format", "{{json .IPAM.Config}}", "--", platformNet)
	if err != nil {
		return "", err
	}
	var ipam []struct{ IPRange string }
	if err := json.Unmarshal([]byte(out), &ipam); err != nil {
		return "", fmt.Errorf("docker network inspect: parse: %w", err)
	}
	if len(ipam) != 1 || !samePrefix(ipam[0].IPRange, netPrefix(a.cfg.PlatformIPRange)) {
		return "ip range differs", nil
	}
	return "", nil
}

// EnsureControlPlaneDB starts sp-cp-db: no network, uid 70, peer
// authentication over the mounted socket only, read-only root, archiving
// into its spool, its quotas set at every call. It refuses while a restore
// is marked, and moves a database still at an older build's data path first
// (moveCPData).
func (a *Agent) EnsureControlPlaneDB(ctx context.Context) error {
	if err := a.refuseWhileCPRestoring(); err != nil {
		return err
	}
	if err := a.ensureCPRoot(); err != nil {
		return err
	}
	if err := a.ensureCPQuotas(); err != nil {
		return err
	}
	if err := a.moveCPData(ctx); err != nil {
		return err
	}
	if err := a.ensureCPTrees(); err != nil {
		return err
	}
	if err := a.ensureCPArchBinary(); err != nil {
		return err
	}
	// On an unstamped node the first start initialises the data directory
	// with the initdb password; once the server answers, the node is stamped
	// and the container made again without the password (the stamp is in
	// its label), and the ensure returns only when that container answers.
	// So a fresh node's boot starts the database twice, and no container
	// keeps the password once a database exists. On a stamped node with its
	// container in place nothing waits.
	for pass := range 2 {
		// A running sp-cp-db on an unstamped node may still initialise (a
		// daemon that died during the first start): the first pass adopts
		// it and waits for its answer; the second pass stamps.
		mayStamp := pass > 0
		if !mayStamp {
			c, err := dockerInspectContainer(ctx, cpName)
			if err != nil {
				return err
			}
			mayStamp = c == nil || !c.Running
		}
		stamped, wrote, err := a.checkCPStamp(mayStamp)
		if err != nil {
			return err
		}
		if err := a.startCP(ctx, stamped); err != nil {
			return err
		}
		if stamped && !wrote {
			return nil
		}
		if err := waitCPAnswers(ctx, filepath.Join(a.p.CPDir(), "sock")); err != nil {
			return err
		}
		if stamped {
			return nil
		}
	}
	return fmt.Errorf("agent: %s answered but %s holds no database", cpName, filepath.Join(a.p.CPProjectDir(), "data"))
}

// startCP adopts, starts or (with other arguments) re-creates sp-cp-db; the
// initdb password only while the node is unstamped.
func (a *Agent) startCP(ctx context.Context, stamped bool) error {
	opts, cmd, conf, err := a.cpConfig()
	if err != nil {
		return err
	}
	c, err := dockerInspectContainer(ctx, cpName)
	if err != nil {
		return err
	}
	if c != nil {
		if c.Labels[labelConfig] == conf {
			if !c.Running {
				_, err = dockerRun(ctx, "start", "--", cpName)
			}
			return err
		}
		// Created with other arguments (or not by this daemon): its data
		// stays in the mounted directory.
		logRecreate(cpName, "its configuration changed", c.Running)
		if err := removeControlPlaneDB(ctx, cpName, c.Running); err != nil {
			return err
		}
	}
	// initdb needs a password; peer authentication never uses it, and it is
	// not part of the configuration hash. Only an unstamped node gets one:
	// without it the image's entrypoint refuses to initialise an empty data
	// directory, so neither this start nor Docker's own restart of the
	// container can create a new database on a node that had one.
	var pwEnv []string
	if !stamped {
		pw := make([]byte, 32)
		if _, err := rand.Read(pw); err != nil {
			return err
		}
		pwEnv = []string{"-e", "POSTGRES_PASSWORD=" + hex.EncodeToString(pw)}
	}
	_, err = dockerRun(ctx, slices.Concat(opts, pwEnv, []string{"--label", labelConfig + "=" + conf, "--"}, cmd)...)
	return err
}

// cpAnswerWait bounds the wait for the control-plane database to answer
// (a first start initialises its directory); cpPoll is the interval.
var (
	cpAnswerWait = 3 * time.Minute
	cpPoll       = time.Second
)

// waitCPAnswers waits until a session over the socket in sock opens, while
// sp-cp-db runs; it exiting, or the bound, is an error.
func waitCPAnswers(ctx context.Context, sock string) error {
	ctx, cancel := context.WithTimeout(ctx, cpAnswerWait)
	defer cancel()
	for {
		c, err := dockerInspectContainer(ctx, cpName)
		switch {
		case err != nil:
			return err
		case c == nil || !c.Running:
			return fmt.Errorf("agent: %s stopped before it answered", cpName)
		}
		_, _, err = cpSession(ctx, sock)
		switch {
		case err == nil:
			return nil
		case !errors.Is(err, errCPNotUp):
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("agent: %s did not answer within %v: %w", cpName, cpAnswerWait, err)
		case <-time.After(cpPoll):
		}
	}
}

// cpConfig is sp-cp-db's create options, command and configuration label,
// the label computed from the files as now on disk.
func (a *Agent) cpConfig() (opts, cmd []string, conf string, err error) {
	opts, cmd = a.cpArgs(cpName, "cp-db", true)
	etc := filepath.Join(a.p.CPDir(), "etc")
	// What the server reads at start, as now on disk: the profile, the two
	// access files and the archive binary its commands run.
	extra, err := fileDigests(a.seccompFile(), filepath.Join(etc, "pg_hba.conf"), filepath.Join(etc, "pg_ident.conf"),
		filepath.Join(a.p.ToolsDir(), archBinary))
	if err != nil {
		return nil, nil, "", err
	}
	// Whether the node is stamped decides whether the container may
	// initialise its data directory (EnsureControlPlaneDB): a container made
	// before the stamp is made again once, without the initdb password.
	stamped, err := present(a.cpStampPath())
	if err != nil {
		return nil, nil, "", err
	}
	return opts, cmd, configHash(opts, cmd, append(extra, "stamped="+strconv.FormatBool(stamped))...), nil
}

// removeControlPlaneDB removes the control-plane container name. A running
// one is first stopped with the server's own grace period, so it shuts down
// cleanly; when the stop fails and it is still there and running, the error
// is returned and nothing is removed.
func removeControlPlaneDB(ctx context.Context, name string, running bool) error {
	if !running {
		_, err := dockerRun(ctx, "rm", "-f", "--", name)
		return err
	}
	if _, err := dockerRun(ctx, "stop", "-t", "30", "--", name); err != nil {
		now, ierr := dockerInspectContainer(ctx, name)
		switch {
		case ierr != nil || now != nil && now.Running:
			return err
		case now == nil:
			return nil
		}
	}
	_, err := dockerRun(ctx, "rm", "--", name)
	return err
}

// fileDigests returns "<base name> sha256=<hex>" for each file as now on disk.
func fileDigests(paths ...string) ([]string, error) {
	var out []string
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("agent: %w", err)
		}
		sum := sha256.Sum256(b)
		out = append(out, filepath.Base(p)+" sha256="+hex.EncodeToString(sum[:]))
	}
	return out, nil
}

var imageIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// imageID is the id the image reference ref resolves to now.
func imageID(ctx context.Context, ref string) (string, error) {
	out, err := dockerRun(ctx, "image", "inspect", "--format", "{{json .Id}}", "--", ref)
	if err != nil {
		return "", err
	}
	var id string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &id); err != nil || !imageIDRE.MatchString(id) {
		return "", fmt.Errorf("docker image inspect %s: not an image id", ref)
	}
	return id, nil
}

// labelConfig carries the configuration hash of a platform container.
const labelConfig = "supapace.config"

// configHash is the lower-case hex SHA-256 over the options and command a
// platform container is created with, then extra (facts the container reads
// once at start, such as a file's digest), each followed by a NUL, in the
// order given. Callers leave every secret out.
func configHash(opts, cmd []string, extra ...string) string {
	h := sha256.New()
	for _, s := range slices.Concat(opts, []string{"--"}, cmd, extra) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EnsureGateway copies the node's TLS files into the gateway's mounted
// directory (the key readable by the gateway's uid only; the dev CA is never
// copied) and runs sp-gateway on ingress and platform at their fixed
// addresses.
func (a *Agent) EnsureGateway(ctx context.Context) error {
	cert, err := os.ReadFile(filepath.Join(a.p.TLSDir(), "cert.pem"))
	if err != nil {
		return fmt.Errorf("agent: gateway certificate: %w", err)
	}
	key, err := os.ReadFile(filepath.Join(a.p.TLSDir(), "key.pem"))
	if err != nil {
		return fmt.Errorf("agent: gateway key: %w", err)
	}
	gw := a.p.GatewayDir()
	tlsDir := filepath.Join(gw, "tls")
	if err := a.ensurePlatformDir(); err != nil {
		return err
	}
	for _, d := range []string{gw, tlsDir} {
		if err := ensureDir(d, 0o755, -1, -1); err != nil {
			return err
		}
	}
	if err := writeFile(a.p, tlsDir, "cert.pem", cert, 0o444, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	if err := writeFile(a.p, tlsDir, "key.pem", key, 0o400, gatewayUID, gatewayUID); err != nil {
		return err
	}
	opts, cmd, conf, err := a.gatewayConfig(ctx)
	if err != nil {
		return err
	}
	confs, err := a.existing(ctx, gatewayName)
	if err != nil {
		return err
	}
	if len(confs) == 1 {
		c := confs[0]
		ing, onIng := c.addr(ingressNet)
		plat, onPlat := c.addr(platformNet)
		if c.Labels[labelConfig] == conf && onIng && ing == a.cfg.GatewayIngressIP && (!onPlat || plat == a.cfg.GatewayIP) {
			if !onPlat { // interrupted between create and connect
				if _, err := dockerRun(ctx, "network", "connect", "--ip", a.cfg.GatewayIP, "--", platformNet, gatewayName); err != nil {
					return err
				}
			}
			if !c.Running {
				_, err = dockerRun(ctx, "start", "--", gatewayName)
			}
			return err
		}
		// At other addresses or created with other arguments.
		why := "its configuration changed"
		if c.Labels[labelConfig] == conf {
			why = "its addresses changed"
		}
		logRecreate(gatewayName, why, c.Running)
		if _, err := dockerRun(ctx, "rm", "-f", "--", gatewayName); err != nil {
			return err
		}
	}
	if _, err := dockerRun(ctx, slices.Concat(opts, []string{"--label", labelConfig + "=" + conf, "--"}, cmd)...); err != nil {
		return err
	}
	if _, err := dockerRun(ctx, "network", "connect", "--ip", a.cfg.GatewayIP, "--", platformNet, gatewayName); err != nil {
		return err
	}
	_, err = dockerRun(ctx, "start", "--", gatewayName)
	return err
}

// gatewayConfig is sp-gateway's create options, command and configuration
// label: what the gateway takes at create and start, as now on disk and in
// the image store — its certificate (never the key), the profile, and the
// image the tag names (a rebuilt image under the same tag re-creates it);
// with a studio domain also its domain file, the node's public assertion key
// and its studio certificate (gatewayDashDigests).
func (a *Agent) gatewayConfig(ctx context.Context) (opts, cmd []string, conf string, err error) {
	gw := a.p.GatewayDir()
	opts = []string{"create", "--name", gatewayName, "--user", fmt.Sprintf("%d:%d", gatewayUID, gatewayUID),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--memory", "768m", "--memory-swap", "768m", "--pids-limit", "256", "--ulimit", "core=0",
		"--stop-timeout", "15", "--restart", "unless-stopped", "--label", labelRole + "=gateway",
		"--network", ingressNet, "--ip", a.cfg.GatewayIngressIP, "-p", "0.0.0.0:443:8443", "-p", "0.0.0.0:80:8080",
		"-v", gw + ":/etc/supapace/gateway:ro"}
	cmd = []string{a.cfg.Images.Gateway}
	extra, err := fileDigests(filepath.Join(gw, "tls", "cert.pem"), a.seccompFile())
	if err != nil {
		return nil, nil, "", err
	}
	dash, err := a.gatewayDashDigests()
	if err != nil {
		return nil, nil, "", err
	}
	img, err := imageID(ctx, a.cfg.Images.Gateway)
	if err != nil {
		return nil, nil, "", err
	}
	return opts, cmd, configHash(opts, cmd, slices.Concat(extra, dash, []string{"image id=" + img})...), nil
}

// ensurePlatformDir makes /var/lib/supapace (root 0700) and its platform tree
// (root 0755: containers read it through mounts, no tenant writes it).
func (a *Agent) ensurePlatformDir() error {
	if err := ensureDir(filepath.Dir(a.p.PlatformDir()), 0o700, -1, -1); err != nil {
		return err
	}
	return ensureDir(a.p.PlatformDir(), 0o755, -1, -1)
}

// existing returns the configuration of name, or nothing when it does not exist.
func (a *Agent) existing(ctx context.Context, name string) ([]ctrConf, error) {
	c, err := dockerInspectContainer(ctx, name)
	if err != nil || c == nil {
		return nil, err
	}
	return readConfs(ctx, []string{c.ID})
}

// The files EnsureImageFiles takes out of the cluster image, in the order
// written: postgresql.conf last, so its presence means the set is complete.
var imageFiles = []struct{ src, dst string }{
	{"/etc/passwd", "passwd"},
	{"/etc/group", "group"},
	{"/etc/postgresql-custom/supautils.conf", "supautils.conf"},
	{"/etc/postgresql-custom/conf.d/.", "conf.d"}, // a link in the image; "/." copies what it names
	{"/etc/postgresql/postgresql.conf", "postgresql.conf"},
}

// EnsureImageFiles writes the seccomp profile (every call), and extracts the
// cluster image's passwd, group, supautils.conf, conf.d and postgresql.conf
// into image/<digest12>/ once per digest, through a container that is
// created, never started. Only regular files are accepted from the image.
func (a *Agent) EnsureImageFiles(ctx context.Context) error {
	plat := a.p.PlatformDir()
	if err := a.ensurePlatformDir(); err != nil {
		return err
	}
	if err := writeFile(a.p, plat, "seccomp.json", seccompProfile, 0o444, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	dir := a.p.ImageDir(a.cfg.Images.Postgres)
	if fi, err := os.Lstat(filepath.Join(dir, "postgresql.conf")); err == nil && fi.Mode().IsRegular() {
		return nil
	}
	for _, d := range []string{filepath.Dir(dir), dir, filepath.Join(dir, "conf.d")} {
		if err := ensureDir(d, 0o755, -1, -1); err != nil {
			return err
		}
	}
	name := "sp-extract-" + filepath.Base(dir)
	if _, err := dockerRun(ctx, "rm", "-f", "--", name); err != nil { // left by a crashed run
		return err
	}
	if _, err := dockerRun(ctx, "create", "--name", name, "--network", "none", "--label", labelRole+"=task",
		"--", a.cfg.Images.Postgres); err != nil {
		return err
	}
	err := a.extract(ctx, name, dir)
	if _, rmErr := dockerRun(context.WithoutCancel(ctx), "rm", "-f", "--", name); err == nil {
		err = rmErr
	}
	return err
}

func (a *Agent) extract(ctx context.Context, ctr, dir string) error {
	for _, f := range imageFiles {
		out, err := dockerRun(ctx, "cp", ctr+":"+f.src, "-")
		if err != nil {
			return err
		}
		isDir := f.dst == "conf.d"
		files, err := regularFiles(out, isDir)
		if err != nil {
			return fmt.Errorf("agent: %s in the image: %w", f.src, err)
		}
		to := filepath.Join(dir, f.dst)
		if !isDir {
			data, ok := files[path.Base(f.src)]
			if !ok || len(files) != 1 {
				return fmt.Errorf("agent: %s in the image: not one regular file", f.src)
			}
			files, to = map[string][]byte{f.dst: data}, dir
		}
		for name, data := range files {
			if err := writeFile(a.p, to, name, data, 0o444, os.Geteuid(), os.Getegid()); err != nil {
				return err
			}
		}
	}
	return nil
}

// regularFiles reads a `docker cp … -` archive. For a directory (dir) it
// accepts the "./" entry and regular files directly below it; otherwise one
// regular file. Links, devices, subdirectories and odd names are refused.
func regularFiles(archive string, dir bool) (map[string][]byte, error) {
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader([]byte(archive)))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		name := h.Name
		if dir {
			if name == "./" && h.Typeflag == tar.TypeDir {
				continue
			}
			rest, ok := strings.CutPrefix(name, "./")
			if !ok {
				return nil, fmt.Errorf("unexpected entry %q", name)
			}
			name = rest
		}
		if h.Typeflag != tar.TypeReg || name == "" || name == "." || name == ".." || path.Base(name) != name {
			return nil, fmt.Errorf("entry %q is not a plain regular file", h.Name)
		}
		b, err := io.ReadAll(io.LimitReader(tr, 1<<20+1))
		if err != nil {
			return nil, err
		}
		if len(b) > 1<<20 {
			return nil, fmt.Errorf("entry %q is larger than 1 MiB", name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("entry %q appears twice", name)
		}
		out[name] = b
	}
}

// logRecreate says, before a platform container is re-created, why: in
// neutral words, never its arguments.
func logRecreate(name, why string, running bool) {
	state := "stopped"
	if running {
		state = "running"
	}
	slog.Info("re-creating "+name+": "+why, "was", state)
}

// ───────── the control-plane database's host side, its move and its restore ─────────

// cpRecoveryName is the control plane's recovery start: the database's own
// arguments without a restart policy, plus the recovery settings.
const cpRecoveryName = "sp-cp-recovery"

// Seams of the move and of the session over the control plane's socket
// (tests replace them).
var (
	cpRename  = os.Rename
	cpSession = cpRecoverySession
)

var (
	errCPRestoring = errors.New("agent: a control-plane restore is marked: the database is not started")
	// errCPNotUp: no session could be opened over the socket (the server is
	// still starting or replaying, or gone).
	errCPNotUp = errors.New("agent: the control-plane database does not answer")
)

// refuseWhileCPRestoring refuses while the restore marker exists, whatever
// it is; a marker that cannot be read is an error too.
func (a *Agent) refuseWhileCPRestoring() error {
	_, err := os.Lstat(a.p.CPRestoring())
	switch {
	case err == nil:
		return errCPRestoring
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return fmt.Errorf("agent: restore marker: %w", err)
}

// ensureCPRoot makes the control plane's directory where it is built: the
// socket directory (70:70) and the two access files (root 0444).
func (a *Agent) ensureCPRoot() error {
	cp := a.p.CPDir()
	for _, d := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{
		{filepath.Dir(cp), 0o700, -1, -1},
		{cp, 0o700, -1, -1},
		{filepath.Join(cp, "sock"), 0o700, cpUID, cpUID},
		{filepath.Join(cp, "etc"), 0o755, -1, -1},
	} {
		if err := ensureDir(d.path, d.mode, d.uid, d.gid); err != nil {
			return err
		}
	}
	etc := filepath.Join(cp, "etc")
	if err := writeFile(a.p, etc, "pg_hba.conf", []byte("local all supapaced peer map=cp\nlocal all all reject\n"), 0o444, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	return writeFile(a.p, etc, "pg_ident.conf", []byte("cp root supapaced\ncp postgres supapaced\n"), 0o444, os.Geteuid(), os.Getegid())
}

// ensureCPQuotas sets uid 70's two quotas (nodecfg.CPQuotas): on the
// projects filesystem, and on the repository filesystem through its
// repository directory; then makes its directory on the projects
// filesystem (root 0700). The quotas come first: a filesystem without
// enforced quotas stops here, before anything is written to it.
func (a *Agent) ensureCPQuotas() error {
	disk, repo := nodecfg.CPQuotas(a.cfg, a.p)
	if err := repoSetQuota(a.p.ProjectsDir(), cpUID, disk); err != nil {
		return fmt.Errorf("agent: control-plane quota on the projects filesystem: %w", err)
	}
	if err := ensureRepoDir(a.p, nodecfg.ControlPlaneSubject, cpUID, cpUID, repo); err != nil {
		return fmt.Errorf("agent: control-plane repository directory: %w", err)
	}
	return ensureDir(a.p.CPProjectDir(), 0o700, -1, -1)
}

// ensureCPTrees makes data, spool and rspool/{req,out} on the projects
// filesystem, 70:70 0700. An existing data directory is left as it is.
func (a *Agent) ensureCPTrees() error {
	pd := a.p.CPProjectDir()
	for _, d := range []string{"data", "spool", "rspool", "rspool/req", "rspool/out"} {
		if err := ensureDir(filepath.Join(pd, d), 0o700, cpUID, cpUID); err != nil {
			return err
		}
	}
	return nil
}

// ensureCPArchBinary copies the archive binary from beside the daemon's
// executable to ToolsDir (root 0555, temporary name and rename) when it
// differs. Unlike a project's copy, the control plane's configuration label
// covers it.
func (a *Agent) ensureCPArchBinary() error {
	exe, err := daemonExe()
	if err != nil {
		return fmt.Errorf("agent: own executable: %w", err)
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(exe), archBinary))
	if err != nil {
		return fmt.Errorf("agent: archive binary: %w", err)
	}
	if err := a.ensurePlatformDir(); err != nil {
		return err
	}
	tools := a.p.ToolsDir()
	if err := ensureDir(tools, 0o755, -1, -1); err != nil {
		return err
	}
	if have, err := os.ReadFile(filepath.Join(tools, archBinary)); err == nil && bytes.Equal(have, src) {
		return nil
	}
	return writeFile(a.p, tools, archBinary, src, 0o555, os.Geteuid(), os.Getegid())
}

// cpArgs is the create options and command of a control-plane container:
// sp-cp-db (role cp-db, restart unless-stopped) or its recovery start. The
// archive settings are the projects' constants; the archive command keeps
// its marker word, without which a backup is refused.
func (a *Agent) cpArgs(name, role string, restart bool) (opts, cmd []string) {
	cp, pd := a.p.CPDir(), a.p.CPProjectDir()
	opts = []string{"run", "-d", "--name", name, "--network", "none", "--user", fmt.Sprintf("%d:%d", cpUID, cpUID),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--tmpfs", "/tmp", "--memory", "256m", "--pids-limit", "128", "--ulimit", "core=0"}
	if restart {
		opts = append(opts, "--restart", "unless-stopped")
	}
	opts = append(opts, "--label", labelRole+"="+role,
		"-e", "POSTGRES_USER=supapaced", "-e", "POSTGRES_DB=supapaced", "-e", "POSTGRES_INITDB_ARGS=--data-checksums",
		"-v", filepath.Join(pd, "data")+":/var/lib/postgresql/data", "-v", filepath.Join(cp, "sock")+":/var/run/postgresql",
		"-v", filepath.Join(cp, "etc")+":/etc/sp:ro",
		"-v", filepath.Join(pd, "spool")+":/opt/supapace/spool", "-v", filepath.Join(pd, "rspool")+":/opt/supapace/rspool",
		"-v", a.p.ToolsDir()+":/opt/supapace/tools:ro")
	cmd = []string{a.cfg.Images.ControlPlane,
		"postgres", "-c", "listen_addresses=", "-c", "hba_file=/etc/sp/pg_hba.conf", "-c", "ident_file=/etc/sp/pg_ident.conf",
		"-c", "archive_mode=on", "-c", "archive_command=" + pgconf.ArchiveCommand, "-c", "restore_command=" + pgconf.RestoreCommand,
		"-c", "archive_timeout=300"}
	return opts, cmd
}

// moveCPData moves a database still at an older build's data path,
// CPDir()/data, to the projects filesystem, once, in an order where each
// interrupted state has one resume action:
//  1. the old tree checked (directories and regular files only), then
//     sp-cp-db stopped and removed;
//  2. the old tree copied to data.part (a leftover data.part is removed and
//     copied again), then the projects filesystem synced (syncfs; a reported
//     write error stops the move here);
//  3. CPDir()/data renamed to data.moved;
//  4. data.part renamed to data.
//
// data.moved with data.part: finish 4. data.moved with data: done. The old
// and the new data with no data.moved: refused (nothing here makes that
// state). data.moved stays until the daemon removes it.
func (a *Agent) moveCPData(ctx context.Context) error {
	old := filepath.Join(a.p.CPDir(), "data")
	moved := old + ".moved"
	pd := a.p.CPProjectDir()
	part, data := filepath.Join(pd, "data.part"), filepath.Join(pd, "data")
	var has [4]bool
	for i, p := range []string{old, moved, part, data} {
		var err error
		if has[i], err = present(p); err != nil {
			return err
		}
	}
	hOld, hMoved, hPart, hData := has[0], has[1], has[2], has[3]
	switch {
	case hMoved && hData:
		return nil
	case hMoved && hPart:
		slog.Info("finishing the move of the control-plane database to the projects filesystem")
		if err := a.removeCPForMove(ctx); err != nil {
			return err
		}
		return renameSynced(part, data)
	case hMoved:
		return fmt.Errorf("agent: %s exists without %s or %s: the control-plane database is not started", moved, data, part)
	case !hOld:
		return nil
	case hData:
		return fmt.Errorf("agent: both %s and %s exist and %s does not: the control-plane database is not started", old, data, moved)
	}
	// A tree the copy cannot carry is refused while the database still runs.
	if err := walkTree(old, func(string, os.FileInfo) error { return nil }); err != nil {
		return fmt.Errorf("agent: the control-plane database cannot be moved: %w", err)
	}
	slog.Info("moving the control-plane database to the projects filesystem")
	start := time.Now()
	if err := a.removeCPForMove(ctx); err != nil {
		return err
	}
	if err := os.RemoveAll(part); err != nil {
		return err
	}
	// Opened before the copy: syncfs reports a write error of the
	// filesystem since its descriptor was opened.
	fsDir, err := os.Open(pd)
	if err != nil {
		return err
	}
	defer fsDir.Close()
	if err := copyTree(old, part); err != nil {
		return fmt.Errorf("agent: copying the control-plane database: %w", err)
	}
	// The rename of the old tree is the commit point: from then on the copy
	// is the database. One syncfs of the projects filesystem before it
	// makes every file, owner, mode and directory entry of the copy durable
	// first — the same guarantee as a sync of each entry, in one call. Each
	// rename's directory is synced after it. A write error stops the move here,
	// before the old tree is renamed aside.
	if err := cpSyncfs(int(fsDir.Fd())); err != nil {
		return fmt.Errorf("agent: syncing the copy of the control-plane database: %w", err)
	}
	if err := renameSynced(old, moved); err != nil {
		return err
	}
	if err := renameSynced(part, data); err != nil {
		return err
	}
	slog.Info("moved the control-plane database", "seconds", int(time.Since(start).Seconds()))
	return nil
}

// removeCPForMove stops and removes sp-cp-db, if it exists, before its
// directory is moved.
func (a *Agent) removeCPForMove(ctx context.Context) error {
	c, err := dockerInspectContainer(ctx, cpName)
	if err != nil || c == nil {
		return err
	}
	return removeControlPlaneDB(ctx, cpName, c.Running)
}

// renameSynced renames from to to and syncs to's directory.
func renameSynced(from, to string) error {
	if err := cpRename(from, to); err != nil {
		return err
	}
	return syncPath(filepath.Dir(to))
}

// walkTree calls fn for every entry of the directory src (src first), not
// following links; an entry that is neither a directory nor a regular file
// is an error: the platform's database holds none.
func walkTree(src string, fn func(p string, fi os.FileInfo) error) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			return fmt.Errorf("%s: neither a directory nor a regular file", p)
		}
		return fn(p, fi)
	})
}

// copyTree copies the directory src to dst, which must not exist:
// directories and regular files only, each with its permissions and owner.
// Nothing is synced here: the caller syncs the filesystem once.
func copyTree(src, dst string) error {
	return walkTree(src, func(p string, fi os.FileInfo) error {
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if fi.IsDir() {
			err = os.Mkdir(to, 0o700)
		} else {
			err = copyFile(p, to)
		}
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: no owner", p)
		}
		if err := os.Chmod(to, fi.Mode().Perm()); err != nil {
			return err
		}
		return chown(to, int(st.Uid), int(st.Gid))
	})
}

// copyFile copies the regular file from (never through a link) to a new
// file to.
func copyFile(from, to string) error {
	in, err := os.OpenFile(from, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncPath fsyncs a directory (or file) by path.
func syncPath(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// cpSyncfs is syncfs(2) of the filesystem that holds the open descriptor
// fd; it reports a write error since fd was opened (a seam: tests make it fail).
var cpSyncfs = func(fd int) error {
	if _, _, e := syscall.Syscall(sysSyncfs, uintptr(fd), 0, 0); e != 0 {
		return e
	}
	return nil
}

// emptyDir removes everything below dir (never following a link), keeping
// dir itself; an absent dir is empty.
func emptyDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// EnsureControlPlaneRecovery starts sp-cp-recovery: sp-cp-db's arguments
// without a restart policy and without an initdb password (an empty data
// directory then stops the image's entrypoint instead of creating a new
// database), the recovery settings of t last. It starts nothing unless the
// restore marker exists, or while sp-cp-db exists; an earlier recovery start
// is removed first.
func (a *Agent) EnsureControlPlaneRecovery(ctx context.Context, t pgconf.RecoveryTarget) error {
	pins, err := pgconf.RecoveryPins(t)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(a.p.CPRestoring()); err != nil {
		return fmt.Errorf("agent: no control-plane restore is marked: %w", err)
	}
	c, err := dockerInspectContainer(ctx, cpName)
	if err != nil {
		return err
	}
	if c != nil {
		return fmt.Errorf("agent: %s exists: no recovery start beside it", cpName)
	}
	if err := a.ensureCPArchBinary(); err != nil {
		return err
	}
	if err := a.StopControlPlaneRecovery(ctx); err != nil {
		return err
	}
	opts, cmd := a.cpArgs(cpRecoveryName, "cp-recovery", false)
	_, err = dockerRun(ctx, slices.Concat(opts, []string{"--"}, cmd, pins)...)
	return err
}

// StopControlPlaneRecovery stops sp-cp-recovery with the server's grace
// period and removes it; absent, it is done.
func (a *Agent) StopControlPlaneRecovery(ctx context.Context) error {
	c, err := dockerInspectContainer(ctx, cpRecoveryName)
	if err != nil || c == nil {
		return err
	}
	return removeControlPlaneDB(ctx, cpRecoveryName, c.Running)
}

// PrepareControlPlaneRestore readies the control plane's trees for a
// restore without starting anything. It refuses while sp-cp-db exists, and
// when a database is still at an older build's data path (a restore beside
// it would leave two). A first preparation (no marker yet) also refuses a
// data directory or a repository that holds anything: either may be the
// node's newest copy. It stops an earlier recovery start, writes the restore
// marker (root 0600, empty) before any tree is touched, makes the
// directories with their quotas and empties spool and rspool/{req,out}. A
// re-run (the marker was there) also empties data, empties repo/ and
// removes fetch/, so that it starts from nothing.
func (a *Agent) PrepareControlPlaneRestore(ctx context.Context) error {
	c, err := dockerInspectContainer(ctx, cpName)
	if err != nil {
		return err
	}
	if c != nil {
		return fmt.Errorf("agent: %s exists: remove it before a restore", cpName)
	}
	if err := a.StopControlPlaneRecovery(ctx); err != nil {
		return err
	}
	if err := a.ensureCPRoot(); err != nil {
		return err
	}
	old := filepath.Join(a.p.CPDir(), "data")
	switch has, err := present(old); {
	case err != nil:
		return err
	case has:
		return fmt.Errorf("agent: a database is still at %s: no restore beside it", old)
	}
	pd := a.p.CPProjectDir()
	data := filepath.Join(pd, "data")
	repo := filepath.Join(a.p.RepoDir(nodecfg.ControlPlaneSubject), "repo")
	rerun := false
	switch err := a.refuseWhileCPRestoring(); {
	case errors.Is(err, errCPRestoring):
		rerun = true
	case err != nil:
		return err
	default:
		for _, d := range []string{data, repo} {
			ents, err := os.ReadDir(d)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if len(ents) > 0 {
				return fmt.Errorf("agent: %s is not empty and no restore is marked: it may hold the node's newest copy", d)
			}
		}
	}
	if err := writeFile(a.p, a.p.CPDir(), filepath.Base(a.p.CPRestoring()), nil, 0o600, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	if err := a.ensureCPQuotas(); err != nil {
		return err
	}
	if err := a.ensureCPTrees(); err != nil {
		return err
	}
	// data, spool and rspool: below the root 0700 directory, written only by
	// the platform's own server, which is not running.
	trees := []string{filepath.Join(pd, "spool"), filepath.Join(pd, "rspool", "req"), filepath.Join(pd, "rspool", "out")}
	if rerun {
		trees = append(trees, data)
	}
	for _, d := range trees {
		if err := emptyDir(d); err != nil {
			return err
		}
	}
	if !rerun {
		return nil
	}
	if _, err := a.cpPurgeRepoDir(ctx, "repo", cpUID); err != nil {
		return err
	}
	return a.removeCPFetch(ctx)
}

// cpPurgeRepoDir empties <repo>/cp/<dir> by the tree-removal helper as a
// task at uid (and the control plane's gid) on the control-plane image —
// root never walks a tree another id wrote; launched is false when the
// directory is absent.
func (a *Agent) cpPurgeRepoDir(ctx context.Context, dir string, uid int) (launched bool, err error) {
	rd := a.p.RepoDir(nodecfg.ControlPlaneSubject)
	if present, err := dirPresent(filepath.Join(rd, dir)); err != nil || !present {
		return false, err
	}
	flags, err := helperMount()
	if err != nil {
		return false, err
	}
	s := Spec{Ref: nodecfg.ControlPlaneSubject, UID: uid, GID: cpUID}
	kind := "purge-" + dir
	code, out, err := a.runTaskImage(ctx, s, a.cfg.Images.ControlPlane, kind, append(flags, "-v", rd+":/r"),
		"/supapaced", "rmtree", "--keep-root", "/r/"+dir)
	if err != nil {
		return true, err
	}
	if code != 0 {
		return true, taskFailed(kind, s, code, out)
	}
	return true, nil
}

// removeCPFetch empties fetch/ at the replicator's uid, then removes it by
// descriptor; absent, it is done.
func (a *Agent) removeCPFetch(ctx context.Context) error {
	launched, err := a.cpPurgeRepoDir(ctx, "fetch", nodecfg.ReplicatorUID)
	if err != nil || !launched {
		return err
	}
	return removeEmptyFetchDir(a.p, nodecfg.ControlPlaneSubject)
}

// ControlPlaneRecoveryState reports whether sp-cp-recovery has exited (from
// Docker; absent counts as exited, and no session is opened then) and, from
// one session as root by peer over the socket, whether it has promoted and,
// once it has, the database system identifier as the decimal of its
// unsigned 64-bit value. A server that does not answer yet is not promoted.
func (a *Agent) ControlPlaneRecoveryState(ctx context.Context) (promoted, exited bool, systemID string, err error) {
	c, err := dockerInspectContainer(ctx, cpRecoveryName)
	if err != nil {
		return false, false, "", err
	}
	if c == nil || !c.Running {
		return false, true, "", nil
	}
	in, id, err := cpSession(ctx, filepath.Join(a.p.CPDir(), "sock"))
	switch {
	case errors.Is(err, errCPNotUp):
		return false, false, "", nil
	case err != nil:
		return false, false, "", err
	case in:
		return false, false, "", nil
	}
	return true, false, strconv.FormatUint(uint64(id), 10), nil
}

// cpRecoverySession opens one session as the daemon's database user over
// the socket in sock (peer authentication: root maps to it) and reads
// pg_is_in_recovery() and the system identifier, as the server reports it
// (a signed 64-bit value), within 10 s. A failed connection wraps
// errCPNotUp.
func cpRecoverySession(ctx context.Context, sock string) (inRecovery bool, systemID int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return false, 0, err
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = sock, 5432, "supapaced", "supapaced", ""
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return false, 0, fmt.Errorf("%w: %w", errCPNotUp, err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	err = conn.QueryRow(ctx, "select pg_catalog.pg_is_in_recovery(), (select system_identifier from pg_catalog.pg_control_system())").Scan(&inRecovery, &systemID)
	return inRecovery, systemID, err
}

// FinishControlPlaneRestore stops the recovery start, then removes fetch/
// (emptied by a task at the replicator's uid) and, last, the restore marker.
func (a *Agent) FinishControlPlaneRestore(ctx context.Context) error {
	if err := a.StopControlPlaneRecovery(ctx); err != nil {
		return err
	}
	if err := a.removeCPFetch(ctx); err != nil {
		return err
	}
	if err := os.Remove(a.p.CPRestoring()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// cpStampPath is the stamp of a node that has had a control-plane database:
// root 0444 in the root 0700 control-plane directory, which the database's
// uid cannot reach.
func (a *Agent) cpStampPath() string { return filepath.Join(a.p.CPDir(), "initialised") }

// checkCPStamp stamps the node once its data directory holds a database
// (after the move, or once the first start has initialised it), and refuses
// when the node is stamped and the data directory holds none: the projects
// filesystem is not the one the database was on, or the data is gone, and a
// new database there would silently replace every project's record.
// Without mayStamp it does not stamp (a start that may still initialise).
func (a *Agent) checkCPStamp(mayStamp bool) (stamped, wrote bool, err error) {
	data := filepath.Join(a.p.CPProjectDir(), "data")
	hasDB, err := present(filepath.Join(data, "PG_VERSION"))
	if err != nil {
		return false, false, err
	}
	stamp := a.cpStampPath()
	if stamped, err = present(stamp); err != nil {
		return false, false, err
	}
	switch {
	case hasDB && !stamped && mayStamp:
		if err := writeFile(a.p, a.p.CPDir(), filepath.Base(stamp), nil, 0o444, os.Geteuid(), os.Getegid()); err != nil {
			return false, false, err
		}
		return true, true, nil
	case !hasDB && stamped:
		return true, false, fmt.Errorf("agent: %s holds no database although this node had one (%s exists): "+
			"check that the projects filesystem the database was on is mounted at %s, or recover the control plane; "+
			"nothing is started", data, stamp, a.p.ProjectsDir())
	}
	return stamped, false, nil
}

// present reports whether path exists (not following a link).
func present(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}
