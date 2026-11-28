package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/poolcfg"
	"github.com/Amphoze/supapace/internal/secrets"
)

func init() { commands["init"] = initCmd }

// rootOnly makes init refuse to run as anyone but root; tests clear it.
var rootOnly = true

// now is the clock for certificate validity; tests move it.
var now = time.Now

// escrowWord is what the operator types once the key is stored offline.
const escrowWord = "escrowed"

// daemonKeysDropped are daemon.json keys init never writes and drops from the
// merge it proposes: the userland proxy stays on (with it off, Docker loads
// br_netfilter and turns bridge-nf-call-iptables back on), inter-container
// traffic is the ruleset's business, and live-restore stays off.
var daemonKeysDropped = []string{"userland-proxy", "icc", "live-restore"}

type initOpts struct {
	domain, tlsCert, tlsKey       string
	studio, studioCert, studioKey string
	label, poolerCert, poolerKey  string
	publicAddrs                   []string
	dev, noSystemd, ack           bool
}

// initCmd writes a node's configuration before Docker runs: node.json, the
// ruleset file, Docker's daemon.json, the systemd units, the TLS files (a
// development CA with --dev; with a studio domain, also its pair in
// tls-studio), and the key-encryption key with its one-time
// escrow display. It touches neither Docker nor the database, and a second
// run changes nothing.
func initCmd(args []string) int {
	fl := flag.NewFlagSet("init", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var o initOpts
	fl.StringVar(&o.domain, "domain", "", "base domain; project hosts are <ref>.<domain> (required)")
	fl.BoolVar(&o.dev, "dev", false, "development node: issue a CA and a server certificate, write the dev-mode marker")
	fl.BoolVar(&o.noSystemd, "no-systemd", false, "do not install the systemd units")
	fl.BoolVar(&o.ack, "ack-escrow", false, "show the key escrow without waiting for the typed acknowledgement")
	fl.StringVar(&o.tlsCert, "tls-cert", "", "server certificate (PEM) valid for *.<domain>")
	fl.StringVar(&o.tlsKey, "tls-key", "", "the certificate's private key (PEM)")
	fl.StringVar(&o.studio, "studio-domain", "", "the dashboard's domain; its hosts are <label>.<studio domain> (set once)")
	fl.StringVar(&o.studioCert, "studio-tls-cert", "", "certificate chain (PEM) naming the studio domain and *.<studio domain>")
	fl.StringVar(&o.studioKey, "studio-tls-key", "", "the studio certificate's private key (PEM)")
	fl.StringVar(&o.label, "pooler-label", "", "the pooler's zone label; its hosts are <ref>.<label>.<domain> (set once)")
	fl.StringVar(&o.poolerCert, "pooler-tls-cert", "", "certificate (PEM) naming *.<label>.<domain> and nothing else")
	fl.StringVar(&o.poolerKey, "pooler-tls-key", "", "the pooler certificate's private key (PEM)")
	fl.Func("public-addr", "an IPv4 address under which the outside sees this node, repeated for each: every address the node's names resolve to, and every source address the provider gives the node's outbound traffic. A node whose outbound address cannot be named (a pool that changes, or one shared with other customers) declares none, and offers no network restrictions. The flags given replace the stored list; a run without the flag keeps it. To return to declaring none, remove public_addrs from the node file", func(s string) error {
		o.publicAddrs = append(o.publicAddrs, s)
		return nil
	})
	if err := fl.Parse(args); err != nil {
		return 2
	}
	usage := ""
	switch {
	case fl.NArg() != 0:
		usage = "unexpected argument " + fl.Arg(0)
	case o.domain == "":
		usage = "--domain is required"
	case (o.tlsCert == "") != (o.tlsKey == ""):
		usage = "--tls-cert and --tls-key go together"
	case (o.studioCert == "") != (o.studioKey == ""):
		usage = "--studio-tls-cert and --studio-tls-key go together"
	case o.studioCert != "" && o.studio == "":
		usage = "--studio-tls-cert and --studio-tls-key need --studio-domain"
	case (o.poolerCert == "") != (o.poolerKey == ""):
		usage = "--pooler-tls-cert and --pooler-tls-key go together"
	case o.poolerCert != "" && o.label == "":
		usage = "--pooler-tls-cert and --pooler-tls-key need --pooler-label"
	case o.dev && (o.tlsCert != "" || o.studioCert != "" || o.poolerCert != ""):
		usage = "--dev issues its own certificates and takes no --tls-cert, --tls-key, --studio-tls-cert, --studio-tls-key, --pooler-tls-cert or --pooler-tls-key"
	case !o.dev && o.tlsCert == "" && !exists(filepath.Join(paths.TLSDir(), "cert.pem")):
		usage = "--tls-cert and --tls-key are required without --dev"
	case !o.dev && o.studio != "" && o.studioCert == "" && !exists(filepath.Join(dashcfg.PathsFor(paths).StudioTLS(), "cert.pem")):
		usage = "--studio-tls-cert and --studio-tls-key are required with --studio-domain without --dev"
	case !o.dev && o.label != "" && o.poolerCert == "" && !exists(filepath.Join(paths.PoolerTLS(), "cert.pem")):
		usage = "--pooler-tls-cert and --pooler-tls-key are required with --pooler-label without --dev"
	}
	if usage != "" {
		fmt.Fprintf(stderr, "supapaced init: %s\n", usage)
		fl.Usage()
		return 2
	}
	if rootOnly && os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "supapaced init: must run as root")
		return 1
	}
	if err := initNode(o); err != nil {
		fmt.Fprintf(stderr, "supapaced init: %v\n", err)
		return 1
	}
	return 0
}

// initNode checks every input and refuses before writing anything, then
// writes what is missing or differs. The key comes last: it is the step that
// may wait for the operator.
func initNode(o initOpts) error {
	if !nodecfg.ValidDomain(o.domain) {
		return fmt.Errorf("--domain %q is not a lowercase domain name", o.domain)
	}
	var certPEM, keyPEM []byte
	if o.tlsCert != "" {
		var err error
		if certPEM, keyPEM, err = readServerPair(o.tlsCert, o.tlsKey, o.domain); err != nil {
			return err
		}
	}
	etc := filepath.Dir(paths.NodeJSON())
	devMarker := filepath.Join(etc, "dev-mode")
	// Development mode, like the domain, is fixed at the first init: the
	// marker makes host-global node checks informational.
	switch {
	case !o.dev && exists(devMarker):
		return errors.New("this node was initialised with --dev; run init with --dev")
	case o.dev && exists(paths.NodeJSON()) && !exists(devMarker):
		return errors.New("this node was initialised without --dev; --dev cannot be added later")
	}
	c, err := nodeConfig(o.domain)
	if err != nil {
		return err
	}
	if err := studioDomain(&c, o.studio); err != nil {
		return err
	}
	var studioCertPEM, studioKeyPEM []byte
	if o.studioCert != "" {
		if studioCertPEM, studioKeyPEM, err = readStudioPair(o.studioCert, o.studioKey, c.StudioDomain); err != nil {
			return err
		}
	}
	if !o.dev && c.StudioDomain != "" && studioCertPEM == nil && !exists(filepath.Join(dashcfg.PathsFor(paths).StudioTLS(), "cert.pem")) {
		return fmt.Errorf("%s holds studio domain %q and no studio certificate is stored; pass --studio-tls-cert and --studio-tls-key", paths.NodeJSON(), c.StudioDomain)
	}
	if err := poolerLabel(&c, o.label); err != nil {
		return err
	}
	var poolerCertPEM, poolerKeyPEM []byte
	if o.poolerCert != "" {
		if poolerCertPEM, poolerKeyPEM, err = readPoolerPair(o.poolerCert, o.poolerKey, poolcfg.Zone(c.Domain, c.PoolerLabel)); err != nil {
			return err
		}
	}
	if !o.dev && c.PoolerLabel != "" && poolerCertPEM == nil && !exists(filepath.Join(paths.PoolerTLS(), "cert.pem")) {
		return fmt.Errorf("%s holds pooler label %q and no pooler certificate is stored; pass --pooler-tls-cert and --pooler-tls-key", paths.NodeJSON(), c.PoolerLabel)
	}
	// The declared addresses are replaced as a whole: a provider can re-address a node.
	if o.publicAddrs != nil {
		c.PublicAddrs = o.publicAddrs
		if err := c.Validate(); err != nil {
			return fmt.Errorf("--public-addr: %w", err)
		}
	}
	if !o.dev {
		for _, f := range []struct {
			name string
			v    int
		}{{"offsite_window_s", c.OffsiteWindowS}, {"rekey_settle_s", c.RekeySettleS}} {
			if f.v != 0 {
				return fmt.Errorf("%s holds %s, which only a development node (init --dev) may carry; remove it", paths.NodeJSON(), f.name)
			}
		}
	}
	caPath := filepath.Join(paths.CADir(), "ca.pem")
	if o.dev && c.StudioDomain != "" && exists(caPath) {
		ca, _, err := loadCA(caPath, filepath.Join(paths.CADir(), "ca.key"))
		if err != nil {
			return err
		}
		if !slices.Contains(ca.PermittedDNSDomains, c.StudioDomain) {
			return fmt.Errorf("the development CA cannot vouch for the studio domain; re-initialise this development node to add a studio domain: remove %s and %s and run init --dev --studio-domain %s again (projects are kept; clients must trust the new %s)",
				paths.CADir(), paths.TLSDir(), c.StudioDomain, caPath)
		}
	}
	if err := checkRange(c); err != nil {
		return err
	}
	daemonPath := filepath.Join(paths.Root, "/etc/docker/daemon.json")
	daemon, err := daemonJSON(daemonPath, c)
	if err != nil {
		return err
	}
	var units map[string][]byte
	if !o.noSystemd {
		units = nft.Units()
		for name := range units {
			if fi, err := os.Lstat(unitPath(name)); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
				return fmt.Errorf("%s is a link (a masked unit); unmask it (systemctl unmask %s) and run init again", unitPath(name), filepath.Base(unitPath(name)))
			}
		}
	}
	nodeJSON, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	w := &writer{uid: os.Geteuid(), gid: os.Getegid()}
	w.dir(etc)
	// Leftovers of interrupted writes: every ".<name>.tmp-*" in init's own
	// directories (nodefs.WriteFile, secrets.GenerateKEK), and in the system
	// directories only the exact names of writeAtomic's temporary files.
	leftovers := []string{daemonPath}
	for name := range nft.Units() {
		leftovers = append(leftovers, unitPath(name))
	}
	for i, p := range leftovers {
		leftovers[i] = filepath.Join(filepath.Dir(p), "."+filepath.Base(p)+".tmp-*")
	}
	studioDir := dashcfg.PathsFor(paths).StudioTLS()
	for _, d := range []string{etc, paths.TLSDir(), paths.CADir(), studioDir, paths.PoolerTLS()} {
		leftovers = append(leftovers, filepath.Join(d, ".*.tmp-*"))
	}
	w.removeLeftovers(leftovers...)
	if o.dev {
		// Before node.json: a first run that stops after node.json is still
		// recognised as a development node.
		w.etcFile(devMarker, nil, 0o600)
	}
	w.etcFile(paths.NodeJSON(), append(nodeJSON, '\n'), 0o600)
	w.ruleset(c)
	if daemon != nil {
		w.file(daemonPath, daemon, 0o644)
	}
	if units != nil {
		names := make([]string, 0, len(units))
		for name := range units {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			w.file(unitPath(name), units[name], 0o644)
		}
	}
	w.dir(paths.TLSDir())
	if certPEM != nil {
		w.etcFile(filepath.Join(paths.TLSDir(), "key.pem"), keyPEM, 0o600)
		w.etcFile(filepath.Join(paths.TLSDir(), "cert.pem"), certPEM, 0o600)
	}
	// Without a studio domain nothing of the dashboard is written.
	if c.StudioDomain != "" {
		w.dir(studioDir)
		if studioCertPEM != nil {
			w.etcFile(filepath.Join(studioDir, "key.pem"), studioKeyPEM, 0o600)
			w.etcFile(filepath.Join(studioDir, "cert.pem"), studioCertPEM, 0o600)
		}
	}
	// Without a pooler label nothing of the pooler is written.
	if c.PoolerLabel != "" {
		w.dir(paths.PoolerTLS())
		if poolerCertPEM != nil {
			w.etcFile(filepath.Join(paths.PoolerTLS(), "key.pem"), poolerKeyPEM, 0o600)
			w.etcFile(filepath.Join(paths.PoolerTLS(), "cert.pem"), poolerCertPEM, 0o600)
		}
	}
	if o.dev && w.err == nil {
		// A CA issued now vouches for no pair in place: every pair is issued again.
		newCA := !exists(caPath)
		base := newCA || devCertDue(paths.TLSDir())
		studio := c.StudioDomain != "" && (newCA || devCertDue(studioDir))
		pooler := c.PoolerLabel != "" && (newCA || devCertDue(paths.PoolerTLS()))
		if base || studio || pooler {
			w.devTLS(c, base, studio, pooler)
		}
	}
	if w.err != nil {
		return w.err
	}
	shown, k, err := ensureKEK(etc, o.ack)
	if err != nil {
		return err
	}
	if err := w.cpPass(k); err != nil {
		return err
	}
	if len(w.wrote) == 0 && !shown {
		fmt.Fprintln(stdout, "supapaced init: nothing to change")
	}
	return nil
}

// nodeConfig returns the node.json in place, or the defaults for domain when
// there is none. An existing file that does not load, or names another
// domain, is refused and never overwritten.
func nodeConfig(domain string) (nodecfg.Config, error) {
	if _, err := os.Lstat(paths.NodeJSON()); errors.Is(err, fs.ErrNotExist) {
		c := nodecfg.Default(domain)
		if err := c.Validate(); err != nil {
			return nodecfg.Config{}, fmt.Errorf("computed node configuration: %w", err)
		}
		return c, nil
	}
	c, err := nodecfg.Load(paths.NodeJSON())
	if err != nil {
		return nodecfg.Config{}, fmt.Errorf("existing node configuration (left as it is): %w", err)
	}
	if c.Domain != domain {
		return nodecfg.Config{}, fmt.Errorf("%s holds domain %q; init does not change it", paths.NodeJSON(), c.Domain)
	}
	return c, nil
}

// studioDomain sets the studio domain of c from the flag, or keeps the one in
// place: it is set once and never changed. A node with a studio domain must
// be one dashcfg.For accepts, or the dashboard could not run on it; that is
// refused here, before anything is written.
func studioDomain(c *nodecfg.Config, studio string) error {
	if studio != "" {
		if slices.Contains(strings.Split(studio, "."), dashcfg.SignInLabel) {
			return fmt.Errorf("--studio-domain %q holds the reserved label %q", studio, dashcfg.SignInLabel)
		}
		if c.StudioDomain != "" && c.StudioDomain != studio {
			return fmt.Errorf("%s holds studio domain %q; init does not change it, and there is no supported way to change or remove it", paths.NodeJSON(), c.StudioDomain)
		}
		c.StudioDomain = studio
		if err := c.Validate(); err != nil {
			return fmt.Errorf("--studio-domain: %w", err)
		}
	}
	if c.StudioDomain == "" {
		return nil
	}
	if _, err := dashcfg.For(*c); err != nil {
		return fmt.Errorf("this node cannot have a studio domain: %w", err)
	}
	return nil
}

// poolerLabel sets the pooler label of c from the flag, or keeps the one in
// place: it is set once, at a first init or on a node that has none, and never
// changed. A node with a label must be one poolcfg.For accepts (addresses,
// ports, uids), or the pooler could not run on it; that is refused here,
// before anything is written.
func poolerLabel(c *nodecfg.Config, label string) error {
	if label != "" {
		if c.PoolerLabel != "" && c.PoolerLabel != label {
			return fmt.Errorf("%s holds pooler label %q; init does not change it", paths.NodeJSON(), c.PoolerLabel)
		}
		c.PoolerLabel = label
		if err := c.Validate(); err != nil {
			return fmt.Errorf("--pooler-label: %w", err)
		}
	}
	if c.PoolerLabel == "" {
		return nil
	}
	if _, err := poolcfg.For(*c); err != nil {
		return fmt.Errorf("this node cannot have a pooler: %w", err)
	}
	return nil
}

// readPoolerPair reads the pooler zone's certificate and key and requires
// them to match, to cover a pooler host of zone, and to name the zone's
// wildcard and nothing else.
func readPoolerPair(certFile, keyFile, zone string) (certPEM, keyPEM []byte, err error) {
	if certPEM, err = readRegular(certFile); err != nil {
		return nil, nil, err
	}
	if keyPEM, err = readRegular(keyFile); err != nil {
		return nil, nil, err
	}
	if err := checkPair(certPEM, keyPEM, "--pooler-tls", strings.Repeat("a", 20)+"."+zone); err != nil {
		return nil, nil, err
	}
	pair, _ := tls.X509KeyPair(certPEM, keyPEM) // checked by checkPair
	l := pair.Leaf
	if !slices.Equal(l.DNSNames, []string{"*." + zone}) || len(l.IPAddresses)+len(l.EmailAddresses)+len(l.URIs) != 0 {
		return nil, nil, fmt.Errorf("--pooler-tls-cert must name *.%s and nothing else", zone)
	}
	return certPEM, keyPEM, nil
}

// checkRange refuses a node whose passwd, group, subuid or subgid already use
// an id of the reserved project range.
func checkRange(c nodecfg.Config) error {
	var r [4]io.Reader
	for i, name := range []string{"passwd", "group", "subuid", "subgid"} {
		b, err := os.ReadFile(filepath.Join(paths.Root, "/etc", name))
		switch {
		case err == nil:
			r[i] = bytes.NewReader(b)
		case i >= 2 && errors.Is(err, fs.ErrNotExist):
		default:
			return err
		}
	}
	return nodefs.CheckRange(c.UIDBase, c.UIDCount, r[0], r[1], r[2], r[3])
}

// daemonJSON returns the daemon.json to write, or nil when the file in place
// already says exactly that. A file holding any other key or value is refused
// with the merged document it needs, which init never writes itself.
func daemonJSON(path string, c nodecfg.Config) ([]byte, error) {
	want := map[string]any{
		"default-address-pools": []any{map[string]any{"base": c.DockerPool, "size": c.DockerPoolSize}},
		"ipv6":                  false,
		"log-driver":            "local",
		"log-opts":              map[string]any{"max-size": "10m", "max-file": "3"},
	}
	data, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return data, nil
	}
	if err != nil {
		return nil, err
	}
	have, err := decodeObject(b)
	if err != nil {
		return nil, fmt.Errorf("%s is not a JSON object; replace it with:\n%s", path, data)
	}
	want, _ = decodeObject(data) // the same value types as the parsed file
	foreign := false
	for k, v := range have {
		if w, ok := want[k]; !ok || !reflect.DeepEqual(v, w) {
			foreign = true
		}
	}
	if !foreign {
		// Only a root-owned 0644 file counts as in place: whoever can write
		// daemon.json controls Docker.
		if len(have) == len(want) && same(path, b, 0o644, os.Geteuid()) {
			return nil, nil
		}
		return data, nil
	}
	for _, k := range daemonKeysDropped {
		delete(have, k)
	}
	for k, v := range want {
		have[k] = v
	}
	merged, _ := json.MarshalIndent(have, "", "  ")
	return nil, fmt.Errorf("%s holds settings init does not own; merge it by hand into this and run init again:\n%s", path, merged)
}

// unitPath is where a file of nft.Units() goes: the docker-* file is a drop-in
// of docker.service, the others are units.
func unitPath(name string) string {
	dir := filepath.Join(paths.Root, "/etc/systemd/system")
	if rest, ok := strings.CutPrefix(name, "docker-"); ok {
		return filepath.Join(dir, "docker.service.d", rest)
	}
	return filepath.Join(dir, name)
}

// readServerPair reads the operator's certificate and key and requires them
// to match and to cover a project host of domain.
func readServerPair(certFile, keyFile, domain string) (certPEM, keyPEM []byte, err error) {
	if certPEM, err = readRegular(certFile); err != nil {
		return nil, nil, err
	}
	if keyPEM, err = readRegular(keyFile); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, checkPair(certPEM, keyPEM, "--tls", strings.Repeat("a", 20)+"."+domain)
}

// readStudioPair reads the studio certificate and key and requires them to
// match, to cover the studio domain, the sign-in host and a dashboard host,
// and to name the studio domain and its wildcard literally, as the gateway's
// loader requires.
func readStudioPair(certFile, keyFile, studio string) (certPEM, keyPEM []byte, err error) {
	if certPEM, err = readRegular(certFile); err != nil {
		return nil, nil, err
	}
	if keyPEM, err = readRegular(keyFile); err != nil {
		return nil, nil, err
	}
	if err := checkPair(certPEM, keyPEM, "--studio-tls", studio, dashcfg.SignInLabel+"."+studio, strings.Repeat("a", 20)+"."+studio); err != nil {
		return nil, nil, err
	}
	if pair, _ := tls.X509KeyPair(certPEM, keyPEM); !slices.Contains(pair.Leaf.DNSNames, studio) || !slices.Contains(pair.Leaf.DNSNames, "*."+studio) {
		return nil, nil, fmt.Errorf("--studio-tls-cert must name both %s and *.%s among its DNS names", studio, studio)
	}
	return certPEM, keyPEM, nil
}

// maxPairFile bounds what init reads of a certificate or key file.
const maxPairFile = 1 << 20

// readRegular reads a regular file of at most maxPairFile bytes. A link is
// followed (the path is the operator's own); what it opens must be a regular
// file, so a FIFO or a device is refused without being blocked on.
func readRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPairFile+1))
	if err == nil && len(b) > maxPairFile {
		err = fmt.Errorf("%s is larger than %d bytes", path, maxPairFile)
	}
	return b, err
}

// checkPair requires the certificate to match the key, to cover every host,
// to be valid now and to allow server authentication. flag names the pair's
// flags in errors.
func checkPair(certPEM, keyPEM []byte, flag string, hosts ...string) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("%s-cert/%s-key: %w", flag, flag, err)
	}
	for _, h := range hosts {
		if err := pair.Leaf.VerifyHostname(h); err != nil {
			return fmt.Errorf("%s-cert does not cover %s: %w", flag, h, err)
		}
	}
	switch t, leaf := now(), pair.Leaf; {
	case t.After(leaf.NotAfter):
		return fmt.Errorf("%s-cert expired on %s", flag, leaf.NotAfter.UTC().Format(time.RFC3339))
	case t.Before(leaf.NotBefore):
		return fmt.Errorf("%s-cert is not valid before %s", flag, leaf.NotBefore.UTC().Format(time.RFC3339))
	case len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny):
		return fmt.Errorf("%s-cert has an extended key usage without serverAuth", flag)
	}
	return nil
}

// writer applies init's writes in order and stops at the first error. Every
// write is atomic and skipped when the file already holds the same bytes with
// the same mode and owner.
type writer struct {
	uid, gid int
	wrote    []string
	err      error
}

func (w *writer) done(path string) {
	w.wrote = append(w.wrote, path)
	fmt.Fprintf(stdout, "supapaced init: wrote %s\n", path)
}

// dir creates a root-only directory and refuses an existing one that is
// anything else.
func (w *writer) dir(path string) {
	if w.err != nil {
		return
	}
	err := os.Mkdir(path, 0o700)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		w.err = err
		return
	}
	created := err == nil
	fi, err := os.Lstat(path)
	if err != nil {
		w.err = err
		return
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 || owner(fi) != w.uid {
		w.err = fmt.Errorf("%s must be a directory owned by uid %d with mode 0700", path, w.uid)
		return
	}
	if created {
		w.done(path)
	}
}

// etcFile writes a file below the node configuration directory through
// nodefs.WriteFile: created under a temporary name with its final mode and
// owner, then renamed into place.
func (w *writer) etcFile(path string, data []byte, mode os.FileMode) {
	if w.err != nil || same(path, data, mode, w.uid) {
		return
	}
	if w.err = nodefs.WriteFile(paths, filepath.Dir(path), filepath.Base(path), data, mode, w.uid, w.gid); w.err == nil {
		w.done(path)
	}
}

// ruleset writes the ruleset file through nft.EnsureRules (rendered from the
// saved off-site set, written only when it differs; nothing is loaded).
func (w *writer) ruleset(c nodecfg.Config) {
	if w.err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	changed, err := nft.EnsureRules(ctx, paths, c, false)
	if w.err = err; err == nil && changed {
		w.done(paths.NftFile())
	}
}

// file writes a system file outside the node configuration directory
// (daemon.json, units), creating its directory 0755 when missing.
func (w *writer) file(path string, data []byte, mode os.FileMode) {
	if w.err != nil || same(path, data, mode, w.uid) {
		return
	}
	if w.err = writeAtomic(path, data, mode); w.err == nil {
		w.done(path)
	}
}

// devTLS issues the development CA (unless one is in place), constrained to
// the node's domain and its studio domain, and with it the server pair for
// *.<domain> when base is set and the studio pair for the studio domain and
// its wildcard when studio is set, and the pooler pair for the pooler zone's
// wildcard (under the node's domain) when pooler is set. Each key is written
// before its certificate, so a certificate on disk always has its key.
func (w *writer) devTLS(c nodecfg.Config, base, studio, pooler bool) {
	w.dir(paths.CADir())
	if w.err != nil {
		return
	}
	caPEMPath, caKeyPath := filepath.Join(paths.CADir(), "ca.pem"), filepath.Join(paths.CADir(), "ca.key")
	names := []string{c.Domain}
	if c.StudioDomain != "" {
		names = append(names, c.StudioDomain)
	}
	var ca *x509.Certificate
	var caKey crypto.Signer
	if exists(caPEMPath) {
		ca, caKey, w.err = loadCA(caPEMPath, caKeyPath)
	} else {
		var certPEM, keyPEM []byte
		if certPEM, keyPEM, ca, caKey, w.err = issue(&x509.Certificate{
			Subject:               pkix.Name{CommonName: "supapace development CA"},
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLenZero:        true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			// It can vouch for the node's own names only.
			PermittedDNSDomainsCritical: true,
			PermittedDNSDomains:         names,
			PermittedIPRanges:           []*net.IPNet{{IP: net.ParseIP(c.GatewayIngressIP).To4(), Mask: net.CIDRMask(32, 32)}},
		}, caDays, nil, nil); w.err == nil {
			w.etcFile(caKeyPath, keyPEM, 0o400)
			w.etcFile(caPEMPath, certPEM, 0o644)
		}
	}
	if w.err != nil {
		return
	}
	if base {
		// The agent reaches the gateway at its ingress address, hence the IP name.
		w.devPair(paths.TLSDir(), ca, caKey, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "*." + c.Domain},
			DNSNames:    []string{"*." + c.Domain},
			IPAddresses: []net.IP{net.ParseIP(c.GatewayIngressIP)},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
	}
	if studio {
		w.devPair(dashcfg.PathsFor(paths).StudioTLS(), ca, caKey, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "*." + c.StudioDomain},
			DNSNames:    []string{c.StudioDomain, "*." + c.StudioDomain},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
	}
	if pooler {
		zone := poolcfg.Zone(c.Domain, c.PoolerLabel)
		w.devPair(paths.PoolerTLS(), ca, caKey, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "*." + zone},
			DNSNames:    []string{"*." + zone},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
	}
}

// devPair issues a server pair from tmpl, signed by the development CA, into
// dir: the key first, then the certificate.
func (w *writer) devPair(dir string, ca *x509.Certificate, caKey crypto.Signer, tmpl *x509.Certificate) {
	if w.err != nil {
		return
	}
	certPEM, keyPEM, _, _, err := issue(tmpl, serverDays, ca, caKey)
	if w.err = err; err == nil {
		w.etcFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600)
		w.etcFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600)
	}
}

// Validity of the development certificates, in days. Many clients refuse a
// server certificate valid for longer than 825 days, even under a local root.
const (
	caDays        = 3650
	serverDays    = 825
	renewWithin   = 30 * 24 * time.Hour
	kekEscrowName = "kek.escrowed"
)

// devCertDue reports whether the development pair in dir cannot be loaded
// (a file missing or unreadable, a key that does not match) or the
// certificate expires within renewWithin.
func devCertDue(dir string) bool {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	return err != nil || now().Add(renewWithin).After(pair.Leaf.NotAfter)
}

// issue creates a P-256 key and a certificate from tmpl valid for days,
// signed by parent (self-signed when parent is nil).
func issue(tmpl *x509.Certificate, days int, parent *x509.Certificate, parentKey crypto.Signer) (certPEM, keyPEM []byte, cert *x509.Certificate, key crypto.Signer, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if tmpl.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)); err != nil {
		return nil, nil, nil, nil, err
	}
	t := now()
	tmpl.NotBefore, tmpl.NotAfter = t.Add(-time.Hour), t.AddDate(0, 0, days)
	if parent == nil {
		parent, parentKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, k.Public(), parentKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if cert, err = x509.ParseCertificate(der); err != nil {
		return nil, nil, nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), cert, k, nil
}

// loadCA reads the development CA written by an earlier run.
func loadCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("development CA: %w", err)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || !pair.Leaf.IsCA {
		return nil, nil, fmt.Errorf("development CA in %s is not a CA key pair", filepath.Dir(certPath))
	}
	return pair.Leaf, signer, nil
}

// ensureKEK generates the key-encryption key, or takes the one in place, and
// shows its escrow text until the operator has acknowledged it once. Whether
// to show is decided by the acknowledgement marker, never by the key file: a
// power loss can leave a complete key that was never shown. It reports
// whether the key was shown and, when it read or generated it, the key.
func ensureKEK(etc string, ack bool) (bool, *secrets.KEK, error) {
	marker := filepath.Join(etc, kekEscrowName)
	if exists(marker) {
		if problem := kekProblem(paths.KEK()); problem != "" {
			return false, nil, fmt.Errorf("the key escrow was acknowledged but %s %s: restore the escrowed key; init will not make a new one", paths.KEK(), problem)
		}
		return false, nil, nil
	}
	// The flag asserts the operator saw the key; a display that provably went
	// nowhere cannot be acknowledged. A closed standard output is reopened on
	// the null device by the Go runtime, so this covers that case too.
	if ack && toNullDevice(stdout) {
		return false, nil, fmt.Errorf("--ack-escrow needs the key escrow shown somewhere: standard output is %s; run init with standard output on a terminal or a file", os.DevNull)
	}
	var k secrets.KEK
	var err error
	if _, serr := os.Lstat(paths.KEK()); errors.Is(serr, fs.ErrNotExist) {
		k, err = secrets.GenerateKEK(paths.KEK())
	} else {
		k, err = secrets.LoadKEK(paths.KEK())
	}
	if err != nil {
		return false, nil, err
	}
	_, werr := fmt.Fprintf(stdout, "\nKey-encryption key of this node. Store it offline now; it is shown until acknowledged, then never again:\n\n%s\n\n", secrets.EscrowText(k))
	if werr != nil {
		clear(k[:])
		// Never acknowledged unless shown: the next run shows it again.
		return false, nil, fmt.Errorf("the key escrow could not be shown: %w", werr)
	}
	if ack {
		fmt.Fprintln(stdout, "supapaced init: escrow acknowledged by --ack-escrow")
	} else {
		fmt.Fprintf(stdout, "Type %q once it is stored: ", escrowWord)
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(line) != escrowWord {
			clear(k[:])
			return true, nil, errors.New("key escrow not acknowledged; run init again to see the key")
		}
	}
	if err := nodefs.WriteFile(paths, etc, filepath.Base(marker), nil, 0o600, os.Geteuid(), os.Getegid()); err != nil {
		clear(k[:])
		return true, nil, err
	}
	fmt.Fprintf(stdout, "supapaced init: wrote %s\n", marker)
	return true, &k, nil
}

// cpPass creates the control plane's sealed cipher passphrase when it is
// absent; a file in place is never touched. k is the key ensureKEK read or
// generated (cleared here), or nil: then the key file is loaded.
func (w *writer) cpPass(k *secrets.KEK) error {
	if k != nil {
		defer clear(k[:])
	}
	if exists(paths.CPStanzaSealed()) {
		return nil
	}
	if k == nil {
		key, err := secrets.LoadKEK(paths.KEK())
		if err != nil {
			return err
		}
		defer clear(key[:])
		k = &key
	}
	if _, err := offsite.EnsureControlPlanePass(paths, *k); err != nil {
		return err
	}
	w.done(paths.CPStanzaSealed())
	return nil
}

// same reports whether path is a regular file owned by uid with exactly mode
// and data.
func same(path string, data []byte, mode os.FileMode, uid int) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != mode || owner(fi) != uid {
		return false
	}
	b, err := os.ReadFile(path)
	return err == nil && bytes.Equal(b, data)
}

func owner(fi os.FileInfo) int { return int(fi.Sys().(*syscall.Stat_t).Uid) }

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// toNullDevice reports whether w is a file that is the null device.
func toNullDevice(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	null, nerr := os.Stat(os.DevNull)
	return err == nil && nerr == nil && os.SameFile(fi, null)
}

// kekProblem describes what makes the key file unusable, or returns "": it
// must be a regular file (not a link), mode 0400, 32 bytes, owned by the
// effective uid.
func kekProblem(path string) string {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "is missing"
	case err != nil:
		return "cannot be examined: " + err.Error()
	case !fi.Mode().IsRegular():
		return "is not a regular file"
	case fi.Mode() != 0o400:
		return fmt.Sprintf("has mode %v, want 0400", fi.Mode())
	case fi.Size() != int64(len(secrets.KEK{})):
		return fmt.Sprintf("has size %d, want %d", fi.Size(), len(secrets.KEK{}))
	case owner(fi) != os.Geteuid():
		return fmt.Sprintf("is owned by uid %d, want %d", owner(fi), os.Geteuid())
	}
	return ""
}

// removeLeftovers removes what interrupted writes left behind, given as glob
// patterns whose directory part is literal. A directory that is absent or not
// a real directory is skipped (the writes that follow refuse it); a match is
// unlinked, never followed.
func (w *writer) removeLeftovers(globs ...string) {
	for _, g := range globs {
		if fi, err := os.Lstat(filepath.Dir(g)); w.err != nil || err != nil || !fi.IsDir() {
			continue
		}
		left, _ := filepath.Glob(g)
		for _, f := range left {
			if err := os.Remove(f); err != nil {
				w.err = err
				return
			}
		}
	}
}

// writeAtomic replaces path with data: a temporary file in the same
// directory, given its mode before anything is written to it, synced, renamed
// over path, and the directory synced.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	err = f.Chmod(mode)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
		return fmt.Errorf("writing %s: %w", path, err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// decodeObject parses one JSON object with numbers kept as written, so that
// 26 and 26.0 differ (Docker refuses the second where it wants an integer).
// Trailing data is an error.
func decodeObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return m, nil
}
