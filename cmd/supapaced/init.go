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

	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/offsite"
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
	domain, tlsCert, tlsKey string
	dev, noSystemd, ack     bool
}

// initCmd writes a node's configuration before Docker runs: node.json, the
// ruleset file, Docker's daemon.json, the systemd units, the TLS files (a
// development CA with --dev), and the key-encryption key with its one-time
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
	case o.dev && o.tlsCert != "":
		usage = "--dev issues its own certificate and takes no --tls-cert or --tls-key"
	case !o.dev && o.tlsCert == "" && !exists(filepath.Join(paths.TLSDir(), "cert.pem")):
		usage = "--tls-cert and --tls-key are required without --dev"
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
	for _, d := range []string{etc, paths.TLSDir(), paths.CADir()} {
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
	switch {
	case certPEM != nil:
		w.etcFile(filepath.Join(paths.TLSDir(), "key.pem"), keyPEM, 0o600)
		w.etcFile(filepath.Join(paths.TLSDir(), "cert.pem"), certPEM, 0o600)
	case o.dev && w.err == nil && devCertDue():
		w.devTLS(c)
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
	if certPEM, err = os.ReadFile(certFile); err != nil {
		return nil, nil, err
	}
	if keyPEM, err = os.ReadFile(keyFile); err != nil {
		return nil, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("--tls-cert/--tls-key: %w", err)
	}
	if err := pair.Leaf.VerifyHostname(strings.Repeat("a", 20) + "." + domain); err != nil {
		return nil, nil, fmt.Errorf("--tls-cert does not cover project hosts of %s: %w", domain, err)
	}
	switch t, leaf := now(), pair.Leaf; {
	case t.After(leaf.NotAfter):
		return nil, nil, fmt.Errorf("--tls-cert expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	case t.Before(leaf.NotBefore):
		return nil, nil, fmt.Errorf("--tls-cert is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny):
		return nil, nil, errors.New("--tls-cert has an extended key usage without serverAuth")
	}
	return certPEM, keyPEM, nil
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

// devTLS issues the development CA (unless one is in place) and a server
// certificate for *.<domain> signed by it. Each key is written before its
// certificate, so a certificate on disk always has its key.
func (w *writer) devTLS(c nodecfg.Config) {
	w.dir(paths.CADir())
	if w.err != nil {
		return
	}
	caPEMPath, caKeyPath := filepath.Join(paths.CADir(), "ca.pem"), filepath.Join(paths.CADir(), "ca.key")
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
			PermittedDNSDomains:         []string{c.Domain},
			PermittedIPRanges:           []*net.IPNet{{IP: net.ParseIP(c.GatewayIngressIP).To4(), Mask: net.CIDRMask(32, 32)}},
		}, caDays, nil, nil); w.err == nil {
			w.etcFile(caKeyPath, keyPEM, 0o400)
			w.etcFile(caPEMPath, certPEM, 0o644)
		}
	}
	if w.err != nil {
		return
	}
	// The agent reaches the gateway at its ingress address, hence the IP name.
	certPEM, keyPEM, _, _, err := issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "*." + c.Domain},
		DNSNames:    []string{"*." + c.Domain},
		IPAddresses: []net.IP{net.ParseIP(c.GatewayIngressIP)},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, serverDays, ca, caKey)
	if w.err = err; err == nil {
		w.etcFile(filepath.Join(paths.TLSDir(), "key.pem"), keyPEM, 0o600)
		w.etcFile(filepath.Join(paths.TLSDir(), "cert.pem"), certPEM, 0o600)
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

// devCertDue reports whether the development server pair cannot be loaded
// (a file missing or unreadable, a key that does not match) or the
// certificate expires within renewWithin.
func devCertDue() bool {
	pair, err := tls.LoadX509KeyPair(filepath.Join(paths.TLSDir(), "cert.pem"), filepath.Join(paths.TLSDir(), "key.pem"))
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
