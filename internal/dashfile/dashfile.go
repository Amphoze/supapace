// Package dashfile is the gateway's dashboard file: the node's sign-in issuer,
// the revocations still in force and every live project's members. One writer
// renders it whole; the gateway reads it with Parse, which is strict — every
// member exactly once and in its exact spelling, nothing unknown, nothing
// trailing — and enforces every cap while it reads, before it builds the value.
package dashfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

type File struct {
	Generation   int64              `json:"generation"`
	Node         string             `json:"node"`
	StudioDomain string             `json:"studio_domain"`
	Studio       string             `json:"studio"`
	Issuer       *Issuer            `json:"issuer"`
	Revoked      []Revocation       `json:"revoked"`
	Projects     map[string]Project `json:"projects"`
}

type Issuer struct {
	Iss            string      `json:"iss"`
	ClientID       string      `json:"client_id"`
	AuthorizeURL   string      `json:"authorize_url"`
	EndSessionURL  string      `json:"end_session_url"`
	SessionSeconds int64       `json:"session_seconds"`
	Keys           []IssuerKey `json:"keys"`
}

// IssuerKey is one RSA key of the issuer, every one a dashboard key. The gateway
// converts each when it loads the table; this package takes nothing of the
// token code.
type IssuerKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Revocation refuses every session of the principal issued before NotBefore
// (whole seconds, rounded up from the stored time).
type Revocation struct {
	Iss       string `json:"iss"`
	Sub       string `json:"sub"`
	NotBefore int64  `json:"not_before"`
}

type Project struct {
	Name    string   `json:"name"`
	Members []Member `json:"members"`
}

type Member struct {
	Iss  string `json:"iss"`
	Sub  string `json:"sub"`
	Role string `json:"role"`
}

// The caps: rows, then string lengths in bytes before encoding (an issuer or
// a subject is 1 to 255 bytes). With every string at its cap and every byte of
// it written as six, the largest file they allow is under MaxBytes, the bound
// of Parse's input, of Marshal's output and of the gateway's read.
const MaxProjects, MaxMembers, MaxRevocations, MaxKeys = 4096, 256, 4096, 16
const MaxMemberRows = 16384 // the whole file
const MaxBytes = 64 << 20
const MaxClientIDBytes, MaxURLBytes, MaxKidBytes, MaxNBytes, MaxEBytes, MaxNameBytes, MaxNodeBytes = 255, 2048, 255, 1400, 16, 64, 255

// maxSessionSeconds is the longest session an issuer row may set (8 h).
const maxSessionSeconds = 8 * 3600

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// Parse reads the file strictly and validates it.
func Parse(b []byte) (File, error) {
	if len(b) > MaxBytes {
		return File{}, fmt.Errorf("dashfile: %d bytes, more than %d", len(b), MaxBytes)
	}
	if !utf8.Valid(b) {
		return File{}, errors.New("dashfile: not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walk(dec, fileShape); err != nil {
		return File{}, fmt.Errorf("dashfile: %w", err)
	}
	var f File // Unmarshal refuses trailing data
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("dashfile: %w", err)
	}
	if err := f.validate(); err != nil {
		return File{}, err
	}
	return f, nil
}

// Marshal validates f and writes its one form: members in declaration order,
// projects sorted by ref, empty collections as [] and {}. It refuses an output
// of more than MaxBytes.
func (f File) Marshal() ([]byte, error) { return f.marshal(MaxBytes) }

func (f File) marshal(max int) ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	if f.Revoked == nil {
		f.Revoked = []Revocation{}
	}
	ps := make(map[string]Project, len(f.Projects))
	for ref, p := range f.Projects {
		if p.Members == nil {
			p.Members = []Member{}
		}
		ps[ref] = p
	}
	f.Projects = ps
	if f.Issuer != nil && f.Issuer.Keys == nil {
		iss := *f.Issuer
		iss.Keys = []IssuerKey{}
		f.Issuer = &iss
	}
	b, err := json.Marshal(f)
	if err == nil && len(b) > max {
		return nil, fmt.Errorf("dashfile: %d bytes, more than %d", len(b), max)
	}
	return b, err
}

// within: at most max bytes, and at least one when required.
func within(s string, required bool, max int) bool { return len(s) <= max && (s != "" || !required) }

// principal: 1 to 255 bytes of printable ASCII, as an issuer and a subject are.
func principal(s string) bool {
	if len(s) < 1 || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func validRole(r string) bool {
	return r == dashcfg.RoleOwner || r == dashcfg.RoleDeveloper || r == dashcfg.RoleReadOnly
}

// validStudio: exactly http://<IPv4>:<StudioPort> (ParseAddr takes dotted decimal alone, no leading zero).
func validStudio(s string) bool {
	host, ok := strings.CutPrefix(s, "http://")
	if !ok {
		return false
	}
	host, ok = strings.CutSuffix(host, ":"+strconv.Itoa(dashcfg.StudioPort))
	if !ok {
		return false
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Is4()
}

func (f File) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("dashfile: "+format, a...)) }
	if f.Generation < 1 {
		bad("generation %d below 1", f.Generation)
	}
	if !within(f.Node, true, MaxNodeBytes) {
		bad("node: empty or more than %d bytes", MaxNodeBytes)
	}
	if !nodecfg.ValidDomain(f.StudioDomain) {
		bad("studio_domain %q is not a domain name", f.StudioDomain)
	}
	if !validStudio(f.Studio) {
		bad("studio %q is not http://<IPv4>:%d", f.Studio, dashcfg.StudioPort)
	}
	if is := f.Issuer; is != nil {
		if !principal(is.Iss) || !within(is.ClientID, true, MaxClientIDBytes) ||
			!within(is.AuthorizeURL, true, MaxURLBytes) || !within(is.EndSessionURL, false, MaxURLBytes) {
			bad("issuer: iss, client_id and authorize_url are required; iss and client_id at most 255 bytes, each URL at most %d", MaxURLBytes)
		}
		if is.SessionSeconds < 1 || is.SessionSeconds > maxSessionSeconds {
			bad("issuer: session_seconds %d outside 1 to %d", is.SessionSeconds, maxSessionSeconds)
		}
		if len(is.Keys) > MaxKeys {
			bad("issuer: %d keys, more than %d", len(is.Keys), MaxKeys)
		}
		for _, k := range is.Keys {
			if !within(k.Kid, true, MaxKidBytes) || k.Kty != "RSA" || !within(k.N, true, MaxNBytes) || !within(k.E, true, MaxEBytes) {
				bad("issuer: key %.64q is not an RSA key with kid, n and e within their caps", k.Kid)
			}
		}
	}
	if len(f.Revoked) > MaxRevocations {
		bad("%d revocations, more than %d", len(f.Revoked), MaxRevocations)
	}
	for _, r := range f.Revoked {
		if !principal(r.Iss) || !principal(r.Sub) || r.NotBefore < 0 {
			bad("revocation of %q: bad principal or not_before", r.Sub)
		}
	}
	if len(f.Projects) > MaxProjects {
		bad("%d projects, more than %d", len(f.Projects), MaxProjects)
	}
	rows := 0
	for ref, p := range f.Projects {
		rows += len(p.Members)
		if len(p.Name) > MaxNameBytes {
			bad("project %s: name of more than %d bytes", ref, MaxNameBytes)
		}
		if !refRE.MatchString(ref) {
			bad("project %q is not a ref", ref)
		}
		if len(p.Members) > MaxMembers {
			bad("project %s: %d members, more than %d", ref, len(p.Members), MaxMembers)
		}
		seen := make(map[[2]string]bool, len(p.Members))
		for _, m := range p.Members {
			k := [2]string{m.Iss, m.Sub}
			switch {
			case !principal(m.Iss) || !principal(m.Sub):
				bad("project %s: bad principal %q", ref, m.Sub)
			case !validRole(m.Role):
				bad("project %s: role %q", ref, m.Role)
			case seen[k]:
				bad("project %s: duplicate principal %q", ref, m.Sub)
			}
			seen[k] = true
		}
	}
	if rows > MaxMemberRows {
		bad("%d member rows, more than %d", rows, MaxMemberRows)
	}
	return errors.Join(errs...)
}

// The file's shape, for the strict first pass.
type shape struct {
	kind     byte // 's' string, 'n' number, 'o' object, 'a' array, 'm' map by ref
	fields   []string
	sub      []*shape // per field (o) or the element (a, m: sub[0])
	max      int      // a, m
	nullable bool     // o
}

var (
	str, num  = &shape{kind: 's'}, &shape{kind: 'n'}
	keyShape  = &shape{kind: 'o', fields: []string{"kid", "kty", "n", "e"}, sub: []*shape{str, str, str, str}}
	issShape  = &shape{kind: 'o', nullable: true, fields: []string{"iss", "client_id", "authorize_url", "end_session_url", "session_seconds", "keys"}, sub: []*shape{str, str, str, str, num, {kind: 'a', max: MaxKeys, sub: []*shape{keyShape}}}}
	revShape  = &shape{kind: 'o', fields: []string{"iss", "sub", "not_before"}, sub: []*shape{str, str, num}}
	memShape  = &shape{kind: 'o', fields: []string{"iss", "sub", "role"}, sub: []*shape{str, str, str}}
	projShape = &shape{kind: 'o', fields: []string{"name", "members"}, sub: []*shape{str, {kind: 'a', max: MaxMembers, sub: []*shape{memShape}}}}
	fileShape = &shape{kind: 'o', fields: []string{"generation", "node", "studio_domain", "studio", "issuer", "revoked", "projects"},
		sub: []*shape{num, str, str, str, issShape, {kind: 'a', max: MaxRevocations, sub: []*shape{revShape}}, {kind: 'm', max: MaxProjects, sub: []*shape{projShape}}}}
)

// walk reads one value of shape s from dec: exact member names, each once and
// all present, no null but where allowed, and every array and map within its
// cap. Nesting is bounded by the shape.
func walk(dec *json.Decoder, s *shape) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch s.kind {
	case 's':
		if _, ok := tok.(string); !ok {
			return fmt.Errorf("%v where a string belongs", tok)
		}
		return nil
	case 'n':
		if _, ok := tok.(json.Number); !ok {
			return fmt.Errorf("%v where a number belongs", tok)
		}
		return nil
	case 'a':
		if tok != json.Delim('[') {
			return fmt.Errorf("%v where an array belongs", tok)
		}
		for n := 1; dec.More(); n++ {
			if n > s.max {
				return fmt.Errorf("more than %d elements", s.max)
			}
			if err := walk(dec, s.sub[0]); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	if tok == nil && s.nullable {
		return nil
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("%v where an object belongs", tok)
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key := t.(string) // an object's key is always a string
		if seen[key] {
			return fmt.Errorf("duplicate member %q", key)
		}
		seen[key] = true
		var sub *shape
		if s.kind == 'm' {
			if len(seen) > s.max {
				return fmt.Errorf("more than %d projects", s.max)
			}
			if !refRE.MatchString(key) {
				return fmt.Errorf("project %q is not a ref", key)
			}
			sub = s.sub[0]
		} else {
			for i, f := range s.fields {
				if f == key {
					sub = s.sub[i]
				}
			}
			if sub == nil {
				return fmt.Errorf("unknown member %q", key)
			}
		}
		if err := walk(dec, sub); err != nil {
			return err
		}
	}
	if s.kind == 'o' && len(seen) != len(s.fields) {
		return fmt.Errorf("missing a member of %v", s.fields)
	}
	_, err = dec.Token()
	return err
}
