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
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
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
	cpUID      = 70    // the control-plane image's postgres user
	gatewayUID = 65531 // the gateway image's user; nothing else runs as it
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
// authentication over the mounted socket only, read-only root.
func (a *Agent) EnsureControlPlaneDB(ctx context.Context) error {
	cp := a.p.CPDir()
	for _, d := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{
		{filepath.Dir(cp), 0o700, -1, -1},
		{cp, 0o700, -1, -1},
		{filepath.Join(cp, "data"), 0o700, cpUID, cpUID},
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
	if err := writeFile(a.p, etc, "pg_ident.conf", []byte("cp root supapaced\ncp postgres supapaced\n"), 0o444, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	opts := []string{"run", "-d", "--name", cpName, "--network", "none", "--user", fmt.Sprintf("%d:%d", cpUID, cpUID),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--tmpfs", "/tmp", "--memory", "256m", "--pids-limit", "128", "--ulimit", "core=0",
		"--restart", "unless-stopped", "--label", labelRole + "=cp-db",
		"-e", "POSTGRES_USER=supapaced", "-e", "POSTGRES_DB=supapaced",
		"-v", filepath.Join(cp, "data") + ":/var/lib/postgresql/data", "-v", filepath.Join(cp, "sock") + ":/var/run/postgresql",
		"-v", etc + ":/etc/sp:ro"}
	cmd := []string{a.cfg.Images.ControlPlane,
		"postgres", "-c", "listen_addresses=", "-c", "hba_file=/etc/sp/pg_hba.conf", "-c", "ident_file=/etc/sp/pg_ident.conf"}
	// What the server reads at start, as now on disk: the profile and the
	// two access files.
	extra, err := fileDigests(a.seccompFile(), filepath.Join(etc, "pg_hba.conf"), filepath.Join(etc, "pg_ident.conf"))
	if err != nil {
		return err
	}
	conf := configHash(opts, cmd, extra...)
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
		if err := removeControlPlaneDB(ctx, c.Running); err != nil {
			return err
		}
	}
	// initdb needs a password; peer authentication never uses it, and it is
	// not part of the configuration hash.
	pw := make([]byte, 32)
	if _, err := rand.Read(pw); err != nil {
		return err
	}
	_, err = dockerRun(ctx, slices.Concat(opts, []string{"-e", "POSTGRES_PASSWORD=" + hex.EncodeToString(pw),
		"--label", labelConfig + "=" + conf, "--"}, cmd)...)
	return err
}

// removeControlPlaneDB removes sp-cp-db. A running one is first stopped
// with the server's own grace period, so it shuts down cleanly; when the
// stop fails and it is still there and running, the error is returned and
// nothing is removed.
func removeControlPlaneDB(ctx context.Context, running bool) error {
	if !running {
		_, err := dockerRun(ctx, "rm", "-f", "--", cpName)
		return err
	}
	if _, err := dockerRun(ctx, "stop", "-t", "30", "--", cpName); err != nil {
		now, ierr := dockerInspectContainer(ctx, cpName)
		switch {
		case ierr != nil || now != nil && now.Running:
			return err
		case now == nil:
			return nil
		}
	}
	_, err := dockerRun(ctx, "rm", "--", cpName)
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

	opts := []string{"create", "--name", gatewayName, "--user", fmt.Sprintf("%d:%d", gatewayUID, gatewayUID),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--memory", "768m", "--memory-swap", "768m", "--pids-limit", "256", "--ulimit", "core=0",
		"--stop-timeout", "15", "--restart", "unless-stopped", "--label", labelRole + "=gateway",
		"--network", ingressNet, "--ip", a.cfg.GatewayIngressIP, "-p", "0.0.0.0:443:8443", "-p", "0.0.0.0:80:8080",
		"-v", gw + ":/etc/supapace/gateway:ro"}
	cmd := []string{a.cfg.Images.Gateway}
	// What the gateway takes at create and start, as now on disk and in the
	// image store: its certificate (never the key), the profile, and the image
	// the tag names (a rebuilt image under the same tag re-creates it).
	extra, err := fileDigests(filepath.Join(tlsDir, "cert.pem"), a.seccompFile())
	if err != nil {
		return err
	}
	img, err := imageID(ctx, a.cfg.Images.Gateway)
	if err != nil {
		return err
	}
	conf := configHash(opts, cmd, append(extra, "image id="+img)...)
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
