package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/pgconf"
)

const (
	postgrestUID  = 65532 // the PostgREST image's user
	postgrestConf = "postgrest.conf"
	postgrestKeys = "jwks.json"

	labelRef        = "supapace.ref"
	labelGeneration = "supapace.generation"
	labelEpoch      = "supapace.epoch"
	labelImage      = "supapace.image"
)

// marshalJWKS is a seam: the tests substitute a serialiser that produces
// sets the parse-back must refuse.
var marshalJWKS = jwtx.MarshalJWKS

func (a *Agent) postgrestDir(ref string) string {
	return filepath.Join(a.p.RenderDir(ref), "postgrest")
}

// EnsurePostgREST renders postgrest.conf and jwks.json, then makes
// postgrest-<ref> run on proj-<ref> at base+3 and on platform at
// PlatformAddr(SubnetIndex) — an address computed from the subnet index,
// never learned from Docker. A running container with the desired labels
// (generation, epoch, image, configuration hash of postgrest.conf as on
// disk) at both addresses is adopted after CheckAdopted: a refusal stops
// it; a check that could not be completed (ErrCheckIncomplete) is returned
// and leaves it running. Any other postgrest-<ref> is removed, and a new
// one created, connected, passed through the start gate and started. It has
// no restart policy, and no secret is in its argv or environment.
func (a *Agent) EnsurePostgREST(ctx context.Context, s Spec) error {
	if err := s.valid(a.cfg); err != nil {
		return err
	}
	fileHash, err := a.renderPostgREST(s)
	if err != nil {
		return err
	}
	name := postgrestName(s.Ref)
	i := s.SubnetIndex
	flags, tail := a.postgrestArgs(s)
	label, err := a.configLabel(fileHash, slices.Concat(flags, tail))
	if err != nil {
		return err
	}

	confs, err := a.existing(ctx, name)
	if err != nil {
		return err
	}
	if len(confs) == 1 {
		if a.adoptable(confs[0], s, label) {
			if err := a.CheckAdopted(ctx, s); err != nil {
				if errors.Is(err, ErrCheckIncomplete) && !a.ContainmentFailed() {
					return err // not a finding: the running container is left as it is
				}
				return errors.Join(err, a.StopPostgREST(context.WithoutCancel(ctx), s.Ref))
			}
			return nil
		}
		if _, err := dockerRun(ctx, "rm", "-f", "--", name); err != nil {
			return err
		}
	}
	if _, err := dockerRun(ctx, slices.Concat(flags, []string{"--label", labelConfig + "=" + label}, tail)...); err != nil {
		return err
	}
	if _, err := dockerRun(ctx, "network", "connect", "--ip", a.cfg.PlatformAddr(i).String(), "--", platformNet, name); err != nil {
		return err
	}
	if err := a.CheckContainment(ctx, s); err != nil {
		return a.removeRefused(ctx, name, err)
	}
	if _, err := dockerRun(ctx, "start", "--", name); err != nil {
		// Docker frees a stopped member's address; someone else holding it is
		// a containment fault, never a transient one.
		if strings.Contains(err.Error(), "Address already in use") {
			return a.removeRefused(ctx, name, refuse(err, "start %s", name))
		}
		return err
	}
	return nil
}

// postgrestArgs is postgrest-<ref>'s create options (without its
// configuration label) and, from "--" on, image and command.
func (a *Agent) postgrestArgs(s Spec) (flags, tail []string) {
	name := postgrestName(s.Ref)
	i := s.SubnetIndex
	flags = []string{"create", "--name", name, "--user", fmt.Sprintf("%d:%d", postgrestUID, postgrestUID),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--memory", "256m", "--memory-swap", "256m", "--pids-limit", "64",
		"--ulimit", "core=0", "--ulimit", "nofile=65536:65536", "--no-healthcheck", "--ipc", "private",
		"--sysctl", "net.ipv4.ping_group_range=1 0", "--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
		"-e", "GHCRTS=-N2",
		"--network", networkName(s.Ref), "--ip", a.cfg.PostgRESTAddr(i).String(),
		"-v", a.postgrestDir(s.Ref) + ":/etc/postgrest:ro",
		"--label", labelRole + "=postgrest", "--label", labelRef + "=" + s.Ref,
		"--label", labelGeneration + "=" + strconv.FormatInt(s.Generation, 10), "--label", labelEpoch + "=" + strconv.FormatInt(s.Epoch, 10),
		"--label", labelImage + "=" + a.cfg.Images.PostgREST}
	tail = []string{"--", a.cfg.Images.PostgREST, "/bin/postgrest", "/etc/postgrest/" + postgrestConf}
	return flags, tail
}

// removeRefused removes a container that was created and connected but
// refused at its start, so that nothing stays attached to the project's and
// the platform's networks. Best effort, on a fresh bounded context; a
// removal error is joined to refusal, which stays matchable.
func (a *Agent) removeRefused(ctx context.Context, name string, refusal error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	if _, err := dockerRun(ctx, "rm", "-f", "--", name); err != nil {
		return errors.Join(refusal, err)
	}
	return refusal
}

// configLabel is the supapace.config label, in the form the platform
// containers use (configHash): the create arguments (the label itself
// excluded; args holds the options, "--", then image and command) and the
// hash of postgrest.conf as written, then the digest of the seccomp profile
// as now on disk. A container created with other arguments, another
// configuration or another profile is therefore not adopted; an unreadable
// profile is an error. No secret enters it: the file contributes its hash,
// the arguments hold none.
func (a *Agent) configLabel(fileHash string, args []string) (string, error) {
	profile, err := fileDigests(a.seccompFile())
	if err != nil {
		return "", err
	}
	i := slices.Index(args, "--")
	return configHash(args[:i], args[i+1:], append([]string{postgrestConf + " sha256=" + fileHash}, profile...)...), nil
}

// adoptable: running, our labels at the desired values, attached to exactly
// its project network and platform, at both computed addresses.
func (a *Agent) adoptable(c ctrConf, s Spec, label string) bool {
	want := map[string]string{
		labelRole: "postgrest", labelRef: s.Ref,
		labelGeneration: strconv.FormatInt(s.Generation, 10), labelEpoch: strconv.FormatInt(s.Epoch, 10),
		labelImage: a.cfg.Images.PostgREST, labelConfig: label,
	}
	for k, v := range want {
		if c.Labels[k] != v {
			return false
		}
	}
	plat, onPlat := c.addr(platformNet)
	proj, onProj := c.addr(networkName(s.Ref))
	return c.Running && len(c.Networks) == 2 && onPlat && plat == a.cfg.PlatformAddr(s.SubnetIndex).String() &&
		onProj && proj == a.cfg.PostgRESTAddr(s.SubnetIndex).String()
}

// renderPostgREST writes jwks.json (root 0444) and postgrest.conf (0400,
// PostgREST's uid), each complete when renamed into place, and returns the
// configuration hash of postgrest.conf as read back from disk. Everything is
// checked before the first write: the key set is built only from keys the
// token package accepts and is parsed back before it is written.
func (a *Agent) renderPostgREST(s Spec) (string, error) {
	jwks, err := renderJWKS(s.Keys)
	if err != nil {
		return "", err
	}
	conf, err := pgconf.PostgREST(pgconf.PostgRESTConfig{ClusterAddr: a.cfg.ClusterAddr(s.SubnetIndex),
		AuthenticatorPassword: s.Secrets.AuthenticatorPassword})
	if err != nil {
		return "", err
	}
	// The OpenAPI root advertises the project's public URL (the ref and the
	// domain are validated names), not the listen address.
	conf = fmt.Appendf(conf, "openapi-server-proxy-uri = \"https://%s.%s/rest/v1\"\n", s.Ref, a.cfg.Domain)
	if err := a.ensurePlatformDir(); err != nil {
		return "", err
	}
	dir := a.postgrestDir(s.Ref)
	for _, d := range []string{filepath.Dir(a.p.RenderDir(s.Ref)), a.p.RenderDir(s.Ref), dir} {
		if err := ensureDir(d, 0o755, -1, -1); err != nil {
			return "", err
		}
	}
	// The key set first: the configuration names it.
	if err := writeFile(a.p, dir, postgrestKeys, jwks, 0o444, os.Geteuid(), os.Getegid()); err != nil {
		return "", err
	}
	if err := writeFile(a.p, dir, postgrestConf, conf, 0o400, postgrestUID, postgrestUID); err != nil {
		return "", err
	}
	return renderedHash(dir, postgrestConf)
}

// renderJWKS serialises keys as a public key set after each has passed
// jwtx.KeyFromJWK, and parses the result back: the set must hold exactly
// those keys. PostgREST reads a file that is not a valid key set as a shared
// secret, so nothing else may ever be written.
func renderJWKS(keys []jwtx.Key) ([]byte, error) {
	for _, k := range keys {
		if k.Pub == nil || k.Pub.N == nil {
			return nil, fmt.Errorf("agent: key %q: %w", k.KID, jwtx.ErrKey)
		}
		n, e := jwkMembers(k)
		if _, err := jwtx.KeyFromJWK(k.KID, k.Class, n, e); err != nil {
			return nil, fmt.Errorf("agent: key %q: %w", k.KID, err)
		}
	}
	b, err := marshalJWKS(keys)
	if err != nil {
		return nil, err
	}
	back, err := jwtx.ParseJWKS(b, "issuer")
	if err != nil {
		return nil, fmt.Errorf("agent: rendered key set does not parse: %w", err)
	}
	if len(back) != len(keys) {
		return nil, fmt.Errorf("agent: rendered key set holds %d keys, want %d", len(back), len(keys))
	}
	for i, k := range back {
		if k.KID != keys[i].KID || k.Pub.N.Cmp(keys[i].Pub.N) != 0 || k.Pub.E != keys[i].Pub.E {
			return nil, fmt.Errorf("agent: rendered key set differs at key %d", i)
		}
	}
	// ParseJWKS skips entries it does not use (another kty, use or alg); the
	// bytes must hold nothing but the keys it returned.
	if canon, err := jwtx.MarshalJWKS(back); err != nil || !bytes.Equal(canon, b) {
		return nil, errors.New("agent: rendered key set holds entries other than its keys")
	}
	return b, nil
}

// renderedHash is the lower-case hex SHA-256 over each named file of dir as
// on disk: its base name, a NUL, its content, a NUL.
func renderedHash(dir string, names ...string) (string, error) {
	h := sha256.New()
	for _, n := range names {
		f, err := os.OpenFile(filepath.Join(dir, n), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", err
		}
		b, err := readRegular(f)
		f.Close()
		if err != nil {
			return "", fmt.Errorf("agent: %s/%s: %w", dir, n, err)
		}
		h.Write([]byte(n + "\x00"))
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readRegular(f *os.File) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return nil, errors.New("not a regular file of at most 1 MiB")
	}
	b := make([]byte, fi.Size())
	_, err = f.ReadAt(b, 0)
	return b, err
}

// StopPostgREST stops postgrest-<ref> (10 s grace) and removes it; nil when
// absent.
func (a *Agent) StopPostgREST(ctx context.Context, ref string) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	name := postgrestName(ref)
	c, err := dockerInspectContainer(ctx, name)
	if err != nil || c == nil {
		return err
	}
	if _, err := dockerRun(ctx, "stop", "-t", "10", "--", name); err != nil {
		return a.goneOr(ctx, name, err)
	}
	if _, err := dockerRun(ctx, "rm", "--", name); err != nil {
		return a.goneOr(ctx, name, err)
	}
	return nil
}

// goneOr is nil when name no longer exists (removed in between), else err.
func (a *Agent) goneOr(ctx context.Context, name string, err error) error {
	if c, ierr := dockerInspectContainer(ctx, name); ierr == nil && c == nil {
		return nil
	}
	return err
}
