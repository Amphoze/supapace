package offsite

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/secrets"
)

// EscrowControlPlane is what the escrow document records of the control plane.
// It prints and marshals redacted (it holds the cipher passphrase).
type EscrowControlPlane struct {
	Stanza, Incarnation, CipherPass, Image string
	SchemaVersion                          int
}

// EscrowWorkerImage is the worker image the document records.
type EscrowWorkerImage struct{ Reference, ID, Archive string }

// EscrowOffsite is the document's "offsite" member: the control-plane bucket's
// location and its read-only credential.
type EscrowOffsite struct {
	Endpoint, Region string
	PathStyle        bool
	CAPEM            string // "" is null in the document
	Bucket, Prefix   string
	ReadOnly         bool
	Read             Credential
}

// Escrow is the escrow document, joined from its parts. It prints and
// marshals redacted.
type Escrow struct {
	Version          int
	CreatedAt        time.Time
	KEK              secrets.KEK
	KEKID            string
	ControlPlane     EscrowControlPlane
	Offsite          EscrowOffsite
	WorkerImage      EscrowWorkerImage
	SupapacedVersion string
}

func (EscrowControlPlane) String() string               { return "offsite.EscrowControlPlane{" + redacted + "}" }
func (c EscrowControlPlane) GoString() string           { return c.String() }
func (c EscrowControlPlane) Format(f fmt.State, _ rune) { io.WriteString(f, c.String()) }
func (EscrowControlPlane) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Escrow) String() string                           { return "offsite.Escrow{" + redacted + "}" }
func (e Escrow) GoString() string                       { return e.String() }
func (e Escrow) Format(f fmt.State, _ rune)             { io.WriteString(f, e.String()) }
func (Escrow) MarshalJSON() ([]byte, error)             { return []byte(`"` + redacted + `"`), nil }

const (
	escrowVersion = 1
	maxEscrowPart = 1 << 20
	maxDepth      = 4 // the deepest member is two objects down
)

// The document's JSON, member order as printed. One shape serves the three
// parts: "all" carries every member, "kek" version, part and kek, "rest" every
// member but kek. EscrowRestHash marshals it without created_at.
type wireEscrow struct {
	Version          int          `json:"version"`
	Part             string       `json:"part"`
	CreatedAt        string       `json:"created_at,omitempty"`
	KEK              string       `json:"kek,omitempty"`
	KEKID            string       `json:"kek_id,omitempty"`
	ControlPlane     *wireCP      `json:"control_plane,omitempty"`
	Offsite          *wireOffsite `json:"offsite,omitempty"`
	WorkerImage      *wireWorker  `json:"worker_image,omitempty"`
	SupapacedVersion string       `json:"supapaced_version,omitempty"`
}

type wireCP struct {
	Stanza        string `json:"stanza"`
	Incarnation   string `json:"incarnation"`
	CipherPass    string `json:"cipher_pass"`
	Image         string `json:"image"`
	SchemaVersion int    `json:"schema_version"`
}

type wireOffsite struct {
	Endpoint      string  `json:"endpoint"`
	Region        string  `json:"region"`
	PathStyle     bool    `json:"path_style"`
	CAPEM         *string `json:"ca_pem"`
	Bucket        string  `json:"bucket"`
	Prefix        string  `json:"prefix"`
	ReadOnly      bool    `json:"read_only"`
	ReadAccessKey string  `json:"read_access_key"`
	ReadSecretKey string  `json:"read_secret_key"`
}

type wireWorker struct {
	Reference string `json:"reference"`
	ID        string `json:"id"`
	Archive   string `json:"archive"`
}

// The top-level members of each part.
var partMembers = map[string][]string{
	"all":  {"version", "part", "created_at", "kek", "kek_id", "control_plane", "offsite", "worker_image", "supapaced_version"},
	"kek":  {"version", "part", "kek"},
	"rest": {"version", "part", "created_at", "kek_id", "control_plane", "offsite", "worker_image", "supapaced_version"},
}

// KEKID names a key without revealing it: the first 16 hex digits of
// SHA-256("supapace-kek-id" || 0x00 || key).
func KEKID(k secrets.KEK) string {
	sum := sha256.Sum256(append([]byte("supapace-kek-id\x00"), k[:]...))
	return hex.EncodeToString(sum[:8])
}

// BuildEscrow prints the escrow document from its arguments alone: the whole
// document and its "kek" and "rest" parts. Of the declaration it takes the
// control-plane bucket's location and read-only credential, never a write
// credential. What it prints parses with ParseEscrow, or nothing is returned.
func BuildEscrow(k secrets.KEK, d Declaration, cp EscrowControlPlane, worker EscrowWorkerImage, version string, now time.Time) (all, kek, rest []byte, err error) {
	b := d.ControlPlane
	var ca *string
	if d.CAPEM != "" {
		ca = &d.CAPEM
	}
	w := wireEscrow{
		Version: escrowVersion, Part: "all", CreatedAt: now.UTC().Format(time.RFC3339),
		KEK: base64.StdEncoding.EncodeToString(k[:]), KEKID: KEKID(k),
		ControlPlane: &wireCP{cp.Stanza, cp.Incarnation, cp.CipherPass, cp.Image, cp.SchemaVersion},
		Offsite: &wireOffsite{d.Endpoint, d.Region, d.PathStyle, ca, b.Name, b.Prefix, b.Read != b.Write,
			b.Read.AccessKey, b.Read.SecretKey},
		WorkerImage:      &wireWorker{worker.Reference, worker.ID, worker.Archive},
		SupapacedVersion: version,
	}
	r := w
	r.Part, r.KEK = "rest", ""
	if all, err = printDoc(w); err == nil {
		if kek, err = printDoc(wireEscrow{Version: escrowVersion, Part: "kek", KEK: w.KEK}); err == nil {
			rest, err = printDoc(r)
		}
	}
	if err == nil {
		_, err = ParseEscrow(all)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("offsite: escrow document not built: %w", err)
	}
	return all, kek, rest, nil
}

func printDoc(w wireEscrow) ([]byte, error) {
	b, err := json.MarshalIndent(w, "", "  ")
	return append(b, '\n'), err
}

// ParseEscrow reads one "all" part, or one "kek" part and one "rest" part in
// either order. It refuses unknown, duplicate and missing members, a version
// other than 1, a key whose KEKID is not the document's kek_id, and a stanza
// that is not "cp-" followed by the incarnation, a decimal string.
func ParseEscrow(parts ...[]byte) (Escrow, error) {
	var w wireEscrow
	switch len(parts) {
	case 1:
		var err error
		if w, err = parsePart(parts[0]); err != nil {
			return Escrow{}, err
		}
		if w.Part != "all" {
			return Escrow{}, fmt.Errorf("offsite: a %q part alone is not an escrow document", w.Part)
		}
	case 2:
		a, err := parsePart(parts[0])
		if err != nil {
			return Escrow{}, err
		}
		b, err := parsePart(parts[1])
		if err != nil {
			return Escrow{}, err
		}
		if a.Part == "rest" {
			a, b = b, a
		}
		if a.Part != "kek" || b.Part != "rest" {
			return Escrow{}, fmt.Errorf("offsite: two parts must be one \"kek\" and one \"rest\", not %q and %q", a.Part, b.Part)
		}
		w = b
		w.KEK = a.KEK
	default:
		return Escrow{}, fmt.Errorf("offsite: an escrow document is one or two parts, not %d", len(parts))
	}
	e, err := fromRest(w)
	if err != nil {
		return Escrow{}, err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(w.KEK)
	if err != nil || len(raw) != len(e.KEK) {
		clear(raw)
		return Escrow{}, errors.New("offsite: escrow member kek is not 32 bytes in base64")
	}
	copy(e.KEK[:], raw)
	clear(raw)
	if subtle.ConstantTimeCompare([]byte(KEKID(e.KEK)), []byte(e.KEKID)) != 1 {
		return Escrow{}, errors.New("offsite: the escrowed key does not match kek_id: the parts are of different documents")
	}
	return e, nil
}

// EscrowRestHash is the hex SHA-256 of a "rest" part without created_at, its
// members in the printed order: two prints of the same state hash alike.
func EscrowRestHash(rest []byte) (string, error) {
	w, err := parsePart(rest)
	if err != nil {
		return "", err
	}
	if w.Part != "rest" {
		return "", fmt.Errorf("offsite: only a \"rest\" part is hashed, not %q", w.Part)
	}
	if _, err := fromRest(w); err != nil {
		return "", err
	}
	w.CreatedAt = ""
	b, err := json.Marshal(w)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// parsePart decodes one part strictly: its member names, by path, must be
// exactly those the part's shape prints — no unknown, duplicate,
// differently cased or missing member — and nothing may follow it.
func parsePart(b []byte) (wireEscrow, error) {
	if len(b) > maxEscrowPart {
		return wireEscrow{}, fmt.Errorf("offsite: escrow part over %d bytes", maxEscrowPart)
	}
	var v struct{ Version int }
	if json.Unmarshal(b, &v) == nil && v.Version > escrowVersion {
		return wireEscrow{}, fmt.Errorf("offsite: escrow document version %d is newer than this build reads (%d)", v.Version, escrowVersion)
	}
	have := map[string]bool{}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := memberPaths(dec, "", have, 0); err != nil {
		return wireEscrow{}, malformed(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return wireEscrow{}, errors.New("offsite: escrow part: data after the document")
	}
	var w wireEscrow
	dec = json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return wireEscrow{}, malformed(err)
	}
	top, ok := partMembers[w.Part]
	if !ok {
		return wireEscrow{}, fmt.Errorf("offsite: escrow part %.20q is none of all, kek, rest", w.Part)
	}
	if w.Version != escrowVersion {
		return wireEscrow{}, fmt.Errorf("offsite: escrow document version %d, want %d", w.Version, escrowVersion)
	}
	back, err := json.Marshal(w)
	if err != nil {
		return wireEscrow{}, err
	}
	// Wanted: the part's top-level members (one printed empty is still
	// required) and what the shape prints below them.
	printed, want := map[string]bool{}, map[string]bool{}
	memberPaths(json.NewDecoder(bytes.NewReader(back)), "", printed, 0)
	for _, m := range top {
		want["/"+m] = true
		for p := range printed {
			if strings.HasPrefix(p, "/"+m+"/") {
				want[p] = true
			}
		}
	}
	if !maps.Equal(have, want) {
		var odd []string
		for p := range have {
			if !want[p] {
				odd = append(odd, "unknown "+p)
			}
		}
		for p := range want {
			if !have[p] {
				odd = append(odd, "missing "+p)
			}
		}
		slices.Sort(odd)
		return wireEscrow{}, fmt.Errorf("offsite: escrow %s part: %.200q", w.Part, odd)
	}
	return w, nil
}

// malformed describes a JSON error by its position only: the text around it
// may be a secret.
func malformed(err error) error {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("offsite: escrow part is not valid JSON at byte %d", se.Offset)
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Errorf("offsite: escrow member %.60q has the wrong type", te.Field)
	}
	return errors.New("offsite: escrow part is not one JSON object of the escrow shape")
}

// memberPaths records the path of every member of the value dec is at
// ("/control_plane/stanza") and refuses a duplicate and nesting deeper than
// maxDepth.
func memberPaths(dec *json.Decoder, path string, out map[string]bool, depth int) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t == nil && path != "/offsite/ca_pem" {
		return fmt.Errorf("null member %.60q", path)
	}
	d, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxDepth {
		return errors.New("nested too deep")
	}
	for i := 0; dec.More(); i++ {
		p := path + "/" + strconv.Itoa(i)
		if d == '{' {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			if p = path + "/" + k.(string); out[p] {
				return fmt.Errorf("duplicate member %.60q", p)
			}
			out[p] = true
		}
		if err := memberPaths(dec, p, out, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// fromRest checks every member but kek and converts the document.
func fromRest(w wireEscrow) (Escrow, error) {
	at, err := time.Parse(time.RFC3339, w.CreatedAt)
	if err != nil {
		return Escrow{}, errors.New("offsite: escrow member created_at is not an RFC 3339 time")
	}
	cp, o, wk := w.ControlPlane, w.Offsite, w.WorkerImage
	if cp == nil || o == nil || wk == nil {
		return Escrow{}, errors.New("offsite: escrow control_plane, offsite and worker_image must be objects")
	}
	if n, err := strconv.ParseUint(cp.Incarnation, 10, 64); err != nil || strconv.FormatUint(n, 10) != cp.Incarnation {
		return Escrow{}, fmt.Errorf("offsite: escrow incarnation %.30q is not a decimal string", cp.Incarnation)
	}
	if cp.Stanza != "cp-"+cp.Incarnation {
		return Escrow{}, fmt.Errorf("offsite: escrow stanza %.40q is not named after its incarnation %s", cp.Stanza, cp.Incarnation)
	}
	if len(w.KEKID) != 16 || !isLowerHex(w.KEKID) {
		return Escrow{}, errors.New("offsite: escrow member kek_id is not 16 lower-case hex digits")
	}
	if cp.CipherPass == "" || cp.Image == "" || cp.SchemaVersion < 1 {
		return Escrow{}, errors.New("offsite: escrow control_plane lacks the passphrase, the image or the schema version")
	}
	if _, _, err := hostPort(o.Endpoint); err != nil {
		return Escrow{}, err
	}
	if err := checkPrefix(o.Prefix); err != nil {
		return Escrow{}, err
	}
	if o.Region == "" || o.Bucket == "" || o.ReadAccessKey == "" || o.ReadSecretKey == "" {
		return Escrow{}, errors.New("offsite: escrow offsite lacks the region, the bucket or the read-only credential")
	}
	if wk.Reference == "" || wk.ID == "" || wk.Archive == "" || w.SupapacedVersion == "" {
		return Escrow{}, errors.New("offsite: escrow worker_image or supapaced_version is empty")
	}
	e := Escrow{
		Version: w.Version, CreatedAt: at, KEKID: w.KEKID,
		ControlPlane: EscrowControlPlane{cp.Stanza, cp.Incarnation, cp.CipherPass, cp.Image, cp.SchemaVersion},
		Offsite: EscrowOffsite{o.Endpoint, o.Region, o.PathStyle, "", o.Bucket, o.Prefix, o.ReadOnly,
			Credential{o.ReadAccessKey, o.ReadSecretKey}},
		WorkerImage:      EscrowWorkerImage{wk.Reference, wk.ID, wk.Archive},
		SupapacedVersion: w.SupapacedVersion,
	}
	if o.CAPEM != nil {
		e.Offsite.CAPEM = *o.CAPEM
	}
	return e, nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
