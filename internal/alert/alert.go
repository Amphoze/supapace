// Package alert delivers the node's alerts: one JSON document per alert row
// to the HTTPS endpoint the operator declares, and the dead-man ping of a
// stanza to the operator's dead-man address.
//
// A document holds only what the daemon computed: the node's id, a subject
// (node, cp or a project's ref), a code from a fixed list, a severity, a
// count, two times and named integers. No text a cluster, a repository, a
// job or a log supplied can reach it; what a destination answers is read for
// its status code alone. The declared addresses may carry a token in their
// path or query: they are never printed, logged or put in an error except
// as scheme and host.
package alert

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/secrets"
)

// Declaration is the node's alert destination, its CA bundle (empty: the
// system's roots) and the dead-man address template, which holds {stanza}.
// It prints and marshals with both addresses cut to scheme and host.
type Declaration struct {
	URL, CAPEM, DeadmanURL string

	dev    bool // loaded on a node with the development marker: plain http to 127.0.0.1 allowed
	tested bool // a test document was delivered to this declaration
}

func (d Declaration) String() string {
	dm := "none"
	if d.DeadmanURL != "" {
		dm = Redact(d.DeadmanURL)
	}
	return fmt.Sprintf("alert.Declaration{url: %s, own CA: %t, dead-man: %s}", Redact(d.URL), d.CAPEM != "", dm)
}
func (d Declaration) Format(f fmt.State, _ rune) { io.WriteString(f, d.String()) }
func (d Declaration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// NotReady is the reason the node may not yet hold real data as far as
// alerts go, or "" when a destination and a dead-man address are declared
// and a test document was delivered to them as they now stand.
func (d Declaration) NotReady() string {
	switch {
	case d.URL == "":
		return "alert destination not declared"
	case d.DeadmanURL == "":
		return "dead-man address not declared"
	case !d.tested:
		return "no test alert delivered to the declared destination"
	}
	return ""
}

// Redact cuts an address to its scheme and host (with the port); anything
// that does not parse is "[address]".
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || !printable(u.Scheme+u.Host) {
		return "[address]"
	}
	return u.Scheme + "://" + u.Host
}

const (
	sealedName = "alert"   // the name the sealed file is bound to (secrets.SealNode)
	maxSealed  = 1 << 20   // the file, a CA bundle included
	maxCA      = 512 << 10 // bytes of a CA bundle
	maxURL     = 2048
	stanzaVar  = "{stanza}"
)

type wireDecl struct {
	URL        string `json:"url"`
	CAPEM      string `json:"ca_pem"`
	DeadmanURL string `json:"deadman_url"`
	Tested     bool   `json:"tested"`
}

// devNode reports whether the development marker, a regular file beside
// node.json, exists.
func devNode(p nodecfg.Paths) bool {
	fi, err := os.Lstat(filepath.Join(filepath.Dir(p.NodeJSON()), "dev-mode"))
	return err == nil && fi.Mode().IsRegular()
}

// Load reads the declaration from Paths.AlertSealed(). No file is a zero
// declaration, false and no error.
func Load(p nodecfg.Paths, k secrets.KEK) (Declaration, bool, error) {
	b, fi, err := readFile(p.AlertSealed(), maxSealed)
	if errors.Is(err, fs.ErrNotExist) {
		return Declaration{}, false, nil
	}
	if err != nil {
		return Declaration{}, false, err
	}
	if fi.Mode().Perm()&^0o600 != 0 {
		return Declaration{}, false, fmt.Errorf("alert: %s has mode %#o; it must be 0600 or narrower", p.AlertSealed(), fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != fileOwner() {
		return Declaration{}, false, fmt.Errorf("alert: %s is not owned by uid %d", p.AlertSealed(), fileOwner())
	}
	plain, err := secrets.OpenNode(k, sealedName, b)
	if err != nil {
		return Declaration{}, false, fmt.Errorf("alert: %s: %w", p.AlertSealed(), err)
	}
	defer clear(plain)
	var w wireDecl
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || dec.More() {
		return Declaration{}, false, fmt.Errorf("alert: %s does not hold a declaration", p.AlertSealed())
	}
	d := Declaration{URL: w.URL, CAPEM: w.CAPEM, DeadmanURL: w.DeadmanURL, dev: devNode(p), tested: w.Tested}
	if err := check(d); err != nil {
		return Declaration{}, false, err
	}
	return d, true, nil
}

// Save checks d and replaces the declaration file atomically (mode 0600). A
// saved declaration has had no test delivered.
func Save(p nodecfg.Paths, k secrets.KEK, d Declaration) error {
	d.dev = devNode(p)
	if err := check(d); err != nil {
		return err
	}
	return write(p, k, wireDecl{d.URL, d.CAPEM, d.DeadmanURL, false})
}

// MarkTested records that a test document was delivered to d. It refuses
// when the file no longer holds d: a declaration saved during the test has
// had none.
func MarkTested(p nodecfg.Paths, k secrets.KEK, d Declaration) error {
	cur, ok, err := Load(p, k)
	if err != nil {
		return err
	}
	if !ok || cur.URL != d.URL || cur.CAPEM != d.CAPEM || cur.DeadmanURL != d.DeadmanURL {
		return errors.New("alert: the declaration changed while it was tested")
	}
	// ponytail: no lock against a concurrent set between the read and the
	// write; both are root's commands, run by hand. Add a flock if a daemon
	// ever writes the file.
	return write(p, k, wireDecl{d.URL, d.CAPEM, d.DeadmanURL, true})
}

func write(p nodecfg.Paths, k secrets.KEK, w wireDecl) error {
	plain, err := json.Marshal(w)
	if err != nil {
		return err
	}
	sealed, err := secrets.SealNode(k, sealedName, plain)
	clear(plain)
	if err != nil {
		return err
	}
	path := p.AlertSealed()
	return nodefs.WriteFile(p, filepath.Dir(path), filepath.Base(path), sealed, 0o600, os.Geteuid(), os.Getegid())
}

// readFile reads a regular file of at most max bytes, refusing a link in the
// last component and never blocking on a FIFO.
func readFile(path string, max int) ([]byte, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, fmt.Errorf("alert: %s is a link; give the file itself", path)
		}
		return nil, nil, fmt.Errorf("alert: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > int64(max) {
		return nil, nil, fmt.Errorf("alert: %s is not a regular file of at most %d bytes", path, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err == nil && len(b) > max {
		err = fmt.Errorf("alert: %s grew while reading", path)
	}
	return b, fi, err
}

// check refuses a declaration whose destination is not a valid address, a
// dead-man template that is not one or lacks {stanza}, and a CA bundle that
// holds no certificate. No refusal quotes an address.
func check(d Declaration) error {
	if err := checkURL(d.URL, d.dev); err != nil {
		return fmt.Errorf("alert: the destination %w", err)
	}
	if d.DeadmanURL != "" {
		if !strings.Contains(d.DeadmanURL, stanzaVar) {
			return errors.New("alert: the dead-man address holds no " + stanzaVar)
		}
		if err := checkURL(strings.ReplaceAll(d.DeadmanURL, stanzaVar, "x"), d.dev); err != nil {
			return fmt.Errorf("alert: the dead-man address %w", err)
		}
	}
	if d.CAPEM != "" {
		if len(d.CAPEM) > maxCA || !x509.NewCertPool().AppendCertsFromPEM([]byte(d.CAPEM)) {
			return fmt.Errorf("alert: the CA bundle is not at most %d bytes of PEM certificates", maxCA)
		}
	}
	return nil
}

// checkURL accepts https://host[:port][/path][?query] — or, on a
// development node, http://127.0.0.1:port[/path][?query] — of printable
// ASCII, at most 2,048 bytes, with no user information and no fragment.
func checkURL(raw string, dev bool) error {
	u, err := url.Parse(raw)
	switch {
	case raw == "":
		return errors.New("is not declared")
	case len(raw) > maxURL || !printable(raw) || err != nil:
		return fmt.Errorf("is not an address of at most %d printable bytes", maxURL)
	case u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || u.Hostname() == "":
		return errors.New("is not scheme://host[:port][/path][?query] without user information or fragment")
	}
	if p := u.Port(); p != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.ParseUint(p, 10, 16); err != nil || n == 0 {
			return errors.New("has an invalid port")
		}
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && dev && u.Hostname() == "127.0.0.1" && u.Port() != "":
		return nil
	case u.Scheme == "http":
		return errors.New("is plain http, which only a development node allows, and only to 127.0.0.1:port")
	}
	return errors.New("is not https")
}

// printable: ASCII 0x21 to 0x7e only.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// Document is what one delivery carries. Every string member is checked
// against a fixed form before it is sent (checkDoc).
type Document struct {
	Node     string           `json:"node"`
	Subject  string           `json:"subject"`
	Code     string           `json:"code"`
	Severity string           `json:"severity"`
	Count    int64            `json:"count"`
	FirstAt  time.Time        `json:"first_at"`
	LastAt   time.Time        `json:"last_at"`
	Figures  map[string]int64 `json:"figures"`
}

var (
	subjectRE = regexp.MustCompile(`^([a-z0-9]{20}|cp|node)$`)
	figureRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	stanzaRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

const (
	maxFigures = 16
	maxNode    = 255
)

// checkDoc refuses a document a fixed form does not hold: the node's id (1
// to 255 bytes of UTF-8 without a control or line-separator character, as
// node.json allows it), the subject, a code of the list, the severity, at
// most 16 figures with names of [a-z][a-z0-9_]. A refusal quotes nothing of
// the document.
func checkDoc(doc Document) error {
	if _, known := Severity(doc.Code); !known {
		return errors.New("alert: the code is not on the list")
	}
	if !subjectRE.MatchString(doc.Subject) {
		return errors.New("alert: the subject is not node, cp or a project's ref")
	}
	if doc.Severity != "warn" && doc.Severity != "page" {
		return errors.New("alert: the severity is not warn or page")
	}
	if len(doc.Node) == 0 || len(doc.Node) > maxNode || !utf8.ValidString(doc.Node) {
		return errors.New("alert: the node id is not 1 to 255 bytes of UTF-8")
	}
	for _, r := range doc.Node {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
			return errors.New("alert: the node id holds a control character")
		}
	}
	if len(doc.Figures) > maxFigures {
		return fmt.Errorf("alert: more than %d figures", maxFigures)
	}
	for k := range doc.Figures {
		if !figureRE.MatchString(k) {
			return errors.New("alert: a figure's name is not [a-z][a-z0-9_]{0,31}")
		}
	}
	return nil
}

// severities: every code a document may carry, with the severity Severity
// answers. The backup notices pass through by code, as warnings.
var severities = map[string]string{
	"test": "warn", "schedule-failed": "page", "schedule-stale-list": "warn", "schedule-set-mismatch": "warn",
	"disk-half": "warn", "disk-soft": "warn", "pusher-lag": "warn", "replication-lag": "warn",
	"fleet-pusher-lag": "page", "spool-dropped": "page", "full-failing": "page", "expire-held": "warn",
	"repository-damaged": "page", "canary-failed": "warn", "clock-jump": "page",
	"offsite-expire-undeclared": "warn", "offsite-expire-failed": "warn", "offsite-marker-unexpected": "page",
	"offsite-unrecorded": "warn", "offsite-retention-exceeded": "warn", "offsite-purge-pending": "warn",
	"offsite-purge-refused": "page", "rekey-pending": "page", "pooler-memory": "page", "pooler-ended": "page",
	"orphan-container": "warn", "orphan-network": "warn", "orphan-directory": "warn", "orphan-tenant": "page",
	"orphan-route": "warn", "orphan-slice": "warn", "tenant-row-drift": "page", "allow-list-node-address": "page",
	"rendered-file-drift": "warn", "proxy-table-drift": "warn", "route-drift": "warn", "host-check-failed": "warn",
	// the backup notices
	"unlisted-entry": "warn", "history-rewritten": "warn", "offsite-differs": "warn", "walk-truncated": "warn",
	"unreadable-entry": "warn", "segment-without-history": "warn", "budget-exceeded": "warn",
	"record-not-in-store": "warn", "restore-shortfall": "warn", "timeline-mismatch": "warn", "quarantine": "warn",
	"backup-failed": "warn", "offsite-undeclared": "warn", "cp-quota-half": "warn", "repo-space-low": "warn",
	"repo-quota-full": "warn", "fetch-too-large": "warn",
	// the fixed form of a row no document can carry
	"unlisted-code": "page",
}

// Severity returns a code's severity and whether the code is on the list.
// clock-jump answers page; its raiser lowers it to warn where the
// provider's clock agreed.
func Severity(code string) (severity string, known bool) {
	s, ok := severities[code]
	return s, ok
}

// ReadAddressFile reads an address from a file, so that a token in it never
// stands on a command line: one line of printable ASCII, a final newline
// allowed, at most 2,048 bytes, from a regular file not reached through a
// link. The error never quotes the file's content.
func ReadAddressFile(path string) (string, error) {
	b, _, err := readFile(path, maxURL+1)
	if err != nil {
		return "", err
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" || !printable(s) {
		return "", fmt.Errorf("alert: %s does not hold one address of printable characters on one line", path)
	}
	return s, nil
}

// fileOwner is the uid the sealed file must belong to: the process's own,
// root on a node (every command that reads it runs as root). Tests
// substitute another.
var fileOwner = os.Geteuid
