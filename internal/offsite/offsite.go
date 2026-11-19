// Package offsite holds the node's object-store declaration (the endpoint, the
// two buckets and their credentials) sealed under the KEK, the control plane's
// cipher passphrase, the resolution of the endpoint to the addresses replication
// jobs may reach, and the escrow document from which the control plane is
// recovered.
//
// No value of a credential, a passphrase or the key appears in an error, and
// the types that hold one print and marshal redacted.
package offsite

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/secrets"
)

// Credential is one access key pair. It prints and marshals redacted.
type Credential struct{ AccessKey, SecretKey string }

const redacted = "[redacted]"

func (Credential) String() string               { return "offsite.Credential{" + redacted + "}" }
func (c Credential) GoString() string           { return c.String() }
func (c Credential) Format(f fmt.State, _ rune) { io.WriteString(f, c.String()) }
func (Credential) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

func (c Credential) present() bool { return c.AccessKey != "" && c.SecretKey != "" }

// Bucket is one bucket of the endpoint, the prefix every key of it starts
// with, and its write and read-only credentials.
type Bucket struct {
	Name, Prefix string
	Write, Read  Credential
}

// Declaration is the node's off-site object store.
type Declaration struct {
	Endpoint, Region       string
	PathStyle              bool
	CAPEM                  string
	Projects, ControlPlane Bucket
}

// State is how much of a declaration the node holds.
type State string

const (
	StateUndeclared State = "undeclared" // no declaration file
	StatePartial    State = "partial"    // a file without both buckets or all four credentials
	StateDeclared   State = "declared"   // both buckets named, all four credentials present
)

// Names the sealed files are bound to (secrets.SealNode).
const (
	offsiteName = "offsite"
	cpPassName  = "cp-stanza"
	maxPrefix   = 256     // bytes; keeps every object key the platform derives under the store's key limit
	maxSegment  = 255     // bytes between two "/": the pinned stand-in store refuses a longer segment
	maxSealed   = 1 << 20 // the declaration file, a CA bundle included
)

// wireBucket and wireDecl are the sealed file's JSON; Credential marshals
// redacted, so the declaration is never marshalled directly.
type wireBucket struct {
	Name           string `json:"name"`
	Prefix         string `json:"prefix"`
	WriteAccessKey string `json:"write_access_key"`
	WriteSecretKey string `json:"write_secret_key"`
	ReadAccessKey  string `json:"read_access_key"`
	ReadSecretKey  string `json:"read_secret_key"`
}

type wireDecl struct {
	Endpoint     string     `json:"endpoint"`
	Region       string     `json:"region"`
	PathStyle    bool       `json:"path_style"`
	CAPEM        string     `json:"ca_pem"`
	Projects     wireBucket `json:"projects"`
	ControlPlane wireBucket `json:"control_plane"`
}

func toWire(b Bucket) wireBucket {
	return wireBucket{b.Name, b.Prefix, b.Write.AccessKey, b.Write.SecretKey, b.Read.AccessKey, b.Read.SecretKey}
}

func fromWire(w wireBucket) Bucket {
	return Bucket{w.Name, w.Prefix, Credential{w.WriteAccessKey, w.WriteSecretKey}, Credential{w.ReadAccessKey, w.ReadSecretKey}}
}

// Load reads the declaration. No file is StateUndeclared with a zero
// declaration and no error.
func Load(p nodecfg.Paths, k secrets.KEK) (d Declaration, st State, err error) {
	b, err := readFile(p.OffsiteSealed(), maxSealed)
	if errors.Is(err, fs.ErrNotExist) {
		return Declaration{}, StateUndeclared, nil
	}
	if err != nil {
		return Declaration{}, "", err
	}
	plain, err := secrets.OpenNode(k, offsiteName, b)
	if err != nil {
		return Declaration{}, "", fmt.Errorf("offsite: %s: %w", p.OffsiteSealed(), err)
	}
	defer clear(plain)
	var w wireDecl
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || dec.More() {
		return Declaration{}, "", fmt.Errorf("offsite: %s does not hold a declaration", p.OffsiteSealed())
	}
	d = Declaration{w.Endpoint, w.Region, w.PathStyle, w.CAPEM, fromWire(w.Projects), fromWire(w.ControlPlane)}
	if err := check(d); err != nil {
		return Declaration{}, "", err
	}
	st = StatePartial
	if d.Projects.Name != "" && d.ControlPlane.Name != "" && d.Projects.Write.present() && d.Projects.Read.present() &&
		d.ControlPlane.Write.present() && d.ControlPlane.Read.present() {
		st = StateDeclared
	}
	return d, st, nil
}

// Save checks d and replaces the declaration file atomically: written under a
// temporary name with mode 0600, then renamed into place.
func Save(p nodecfg.Paths, k secrets.KEK, d Declaration) error {
	if err := check(d); err != nil {
		return err
	}
	plain, err := json.Marshal(wireDecl{d.Endpoint, d.Region, d.PathStyle, d.CAPEM, toWire(d.Projects), toWire(d.ControlPlane)})
	if err != nil {
		return err
	}
	sealed, err := secrets.SealNode(k, offsiteName, plain)
	clear(plain)
	if err != nil {
		return err
	}
	path := p.OffsiteSealed()
	return nodefs.WriteFile(p, filepath.Dir(path), filepath.Base(path), sealed, 0o600, os.Geteuid(), os.Getegid())
}

// EnsureControlPlanePass returns the control plane's cipher passphrase,
// creating it (32 random bytes, base64url) when its sealed file is absent. An
// existing file is never replaced: one that does not open is an error.
func EnsureControlPlanePass(p nodecfg.Paths, k secrets.KEK) (string, error) {
	path := p.CPStanzaSealed()
	for range 2 { // a lost race to create reads the winner's file
		b, err := readFile(path, 4096)
		if err == nil {
			plain, err := secrets.OpenNode(k, cpPassName, b)
			if err != nil {
				return "", fmt.Errorf("offsite: %s: %w", path, err)
			}
			if raw, derr := base64.RawURLEncoding.DecodeString(string(plain)); derr != nil || len(raw) != 32 {
				return "", fmt.Errorf("offsite: %s does not hold a passphrase", path)
			}
			return string(plain), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		pass := base64.RawURLEncoding.EncodeToString(raw[:])
		sealed, err := secrets.SealNode(k, cpPassName, []byte(pass))
		if err != nil {
			return "", err
		}
		err = createOnce(path, sealed)
		if err == nil {
			return pass, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("offsite: %s appeared and vanished", path)
}

// createOnce writes data to a temporary file of mode 0600 beside path and
// links it to path: the link fails (fs.ErrExist) when path exists, so an
// existing file is never changed, and path never holds a partial file.
func createOnce(path string, data []byte) error {
	dir := filepath.Dir(path)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || owner(fi) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("offsite: %s is not a directory owned by uid %d and writable only by it", dir, os.Geteuid())
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(suffix[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("offsite: create %s: %w", tmp, err)
	}
	defer os.Remove(tmp)
	err = f.Chmod(0o600) // exact, whatever the umask
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("offsite: write %s: %w", tmp, err)
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return err
		}
		return fmt.Errorf("offsite: install %s: %w", path, err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// readFile reads a regular file of at most max bytes, refusing a link in the
// last component and never blocking on a FIFO. A missing file is
// fs.ErrNotExist.
func readFile(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("offsite: open %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("offsite: %s is not a regular file of at most %d bytes", path, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("offsite: %s grew while reading", path)
	}
	return b, err
}

// check refuses a declaration the store or the key rule would not take: an
// endpoint that is not https://host[:port], a prefix that breaks the key rule
// or is longer than 256 bytes, and one bucket for both uses with overlapping
// prefixes.
func check(d Declaration) error {
	if _, _, err := hostPort(d.Endpoint); err != nil {
		return err
	}
	for _, b := range []Bucket{d.Projects, d.ControlPlane} {
		if err := checkPrefix(b.Prefix); err != nil {
			return err
		}
	}
	if d.Projects.Name != "" && d.Projects.Name == d.ControlPlane.Name && overlap(d.Projects.Prefix, d.ControlPlane.Prefix) {
		return fmt.Errorf("offsite: the projects and control-plane prefixes %q and %q of bucket %q overlap", d.Projects.Prefix, d.ControlPlane.Prefix, d.Projects.Name)
	}
	return nil
}

// hostPort splits an endpoint https://host[:port]; the port defaults to 443.
func hostPort(endpoint string) (string, uint16, error) {
	u, err := url.Parse(endpoint)
	bad := err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.Hostname() == "" ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(endpoint, "#?")
	port := uint64(443)
	if !bad && u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
		bad = err != nil || port == 0
	}
	if bad || strings.HasSuffix(u.Host, ":") {
		return "", 0, errors.New("offsite: the endpoint is not https://host[:port]")
	}
	return u.Hostname(), uint16(port), nil
}

// checkPrefix applies the store's key rule to a bucket prefix: empty, or at
// most 256 bytes with no leading or trailing "/", no empty, "." or ".."
// segment, no segment over 255 bytes, and no control byte.
func checkPrefix(p string) error {
	if p == "" {
		return nil
	}
	bad := len(p) > maxPrefix
	for _, seg := range strings.Split(p, "/") {
		bad = bad || seg == "" || seg == "." || seg == ".." || len(seg) > maxSegment
	}
	for i := 0; i < len(p); i++ {
		bad = bad || p[i] < 0x20 || p[i] == 0x7f
	}
	if bad {
		return fmt.Errorf("offsite: prefix %q: at most %d bytes, no leading or trailing \"/\", no empty, \".\" or \"..\" segment, no segment over %d bytes", p, maxPrefix, maxSegment)
	}
	return nil
}

// overlap reports whether one prefix lies below the other (or both are one):
// an empty prefix overlaps every other.
func overlap(a, b string) bool {
	return a == "" || b == "" || a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func owner(fi os.FileInfo) int {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(st.Uid)
}
