// Package routes is the gateway route file: the table of projects the gateway
// serves, written by the agent and read by the gateway.
package routes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

type File struct {
	Generation int64              `json:"generation"`
	Domain     string             `json:"domain"`
	Projects   map[string]Project `json:"projects"`
}

type Project struct {
	State     string   `json:"state"` // "active" | "draining"
	Rest      string   `json:"rest"`  // "http://<ipv4>:3000"
	UserRoles []string `json:"user_roles"`
	Keys      []Key    `json:"keys"`
}

type Key struct {
	KID   string `json:"kid"`
	Class string `json:"class"` // "anon" | "service_role" | "issuer"
	Kty   string `json:"kty"`   // "RSA"
	N     string `json:"n"`
	E     string `json:"e"`
}

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// Parse decodes a route file strictly: trailing data, unknown fields, a
// generation below 1, a domain that is not lowercase DNS labels, a malformed ref,
// an unknown state, a rest URL other than http://<ipv4>:3000, or a project
// without both an anon and a service_role key are errors. A table with no
// projects is valid.
func Parse(b []byte) (File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return File{}, fmt.Errorf("routes: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return File{}, errors.New("routes: trailing data")
	}
	if err := f.validate(); err != nil {
		return File{}, err
	}
	return f, nil
}

// Marshal encodes the file; it refuses a file Parse would reject, so a writer
// never installs a table the gateway would ignore.
func (f File) Marshal() ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(f)
}

func (f File) validate() error {
	if f.Generation < 1 || !nodecfg.ValidDomain(f.Domain) {
		return fmt.Errorf("routes: generation %d or domain %q: not a valid table", f.Generation, f.Domain)
	}
	for ref, p := range f.Projects {
		if !refRE.MatchString(ref) {
			return fmt.Errorf("routes: bad ref %q", ref)
		}
		if p.State != "active" && p.State != "draining" {
			return fmt.Errorf("routes: %s: bad state %q", ref, p.State)
		}
		host, ok := strings.CutPrefix(p.Rest, "http://")
		if ok {
			host, ok = strings.CutSuffix(host, ":3000")
		}
		if a, err := netip.ParseAddr(host); !ok || err != nil || !a.Is4() {
			return fmt.Errorf("routes: %s: rest %q is not http://<ipv4>:3000", ref, p.Rest)
		}
		var anon, service bool
		for _, k := range p.Keys {
			switch k.Class {
			case "anon":
				anon = true
			case "service_role":
				service = true
			case "issuer":
			default:
				return fmt.Errorf("routes: %s: key %q: bad class %q", ref, k.KID, k.Class)
			}
			if k.KID == "" || k.Kty != "RSA" {
				return fmt.Errorf("routes: %s: key %q: kid empty or kty not RSA", ref, k.KID)
			}
		}
		if !anon || !service {
			return fmt.Errorf("routes: %s: an anon and a service_role key are required", ref)
		}
	}
	return nil
}
