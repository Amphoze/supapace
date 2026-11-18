package bootstrap

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// Baseline is what a fresh, unbootstrapped cluster of the pinned image holds:
// its roles (every role not starting pg_), the distinct (member, role) pairs
// involving one of them, role settings, the four platform schemas, event
// triggers, the paths of the image's files, the settings a fresh cluster
// already takes from postgresql.auto.conf, and the size of a fresh data
// directory.
type Baseline struct {
	Image          string         `json:"image"`
	Digest         string         `json:"digest"`
	PGVersion      string         `json:"pg_version"`
	Roles          []Role         `json:"roles"`
	Memberships    []Membership   `json:"memberships"`
	RoleSettings   []RoleSetting  `json:"role_settings"`
	Schemas        []Schema       `json:"schemas"`
	EventTriggers  []EventTrigger `json:"event_triggers"`
	Files          Files          `json:"files"`
	AutoConf       []string       `json:"auto_conf"`
	FreshClusterMB int            `json:"fresh_cluster_mb"`
}

// Role holds the seven compared attributes of a role.
type Role struct {
	Name        string `json:"name"`
	Super       bool   `json:"super"`
	CreateRole  bool   `json:"createrole"`
	CreateDB    bool   `json:"createdb"`
	Replication bool   `json:"replication"`
	BypassRLS   bool   `json:"bypassrls"`
	Login       bool   `json:"login"`
	ConnLimit   int    `json:"connlimit"`
}

type Membership struct {
	Member string `json:"member"`
	Role   string `json:"role"`
}

type RoleSetting struct {
	Role     string   `json:"role"`
	Settings []string `json:"settings"`
}

type Schema struct {
	Name  string   `json:"name"`
	Owner string   `json:"owner"`
	ACL   []string `json:"acl"`
}

type EventTrigger struct {
	Name     string `json:"name"`
	Event    string `json:"event"`
	Owner    string `json:"owner"`
	Function string `json:"function"` // schema.name
}

// Files are paths inside the cluster image.
type Files struct {
	IncludeDir    string `json:"include_dir"`
	HBAFile       string `json:"hba_file"`
	IdentFile     string `json:"ident_file"`
	SupautilsConf string `json:"supautils_conf"`
	PgsodiumKey   string `json:"pgsodium_key"`
}

//go:embed baseline_17.6.1.166.json
var baselineJSON []byte

// LoadBaseline parses the embedded baseline of the pinned image.
func LoadBaseline() (Baseline, error) { return parseBaseline(baselineJSON) }

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	nameRE   = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	pathRE   = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)
)

func parseBaseline(b []byte) (Baseline, error) {
	var bl Baseline
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&bl); err != nil {
		return Baseline{}, fmt.Errorf("bootstrap: baseline: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return Baseline{}, errors.New("bootstrap: baseline: trailing data")
	}
	if err := bl.validate(); err != nil {
		return Baseline{}, fmt.Errorf("bootstrap: baseline: %w", err)
	}
	return bl, nil
}

func (bl Baseline) validate() error {
	if bl.Image == "" || !digestRE.MatchString(bl.Digest) || bl.PGVersion == "" || bl.FreshClusterMB <= 0 {
		return errors.New("image, digest, pg_version or fresh_cluster_mb missing or malformed")
	}
	if len(bl.Roles) == 0 {
		return errors.New("no roles")
	}
	roles := map[string]bool{}
	for _, r := range bl.Roles {
		if !nameRE.MatchString(r.Name) || strings.HasPrefix(r.Name, "pg_") || roles[r.Name] {
			return fmt.Errorf("role %q", r.Name)
		}
		roles[r.Name] = true
	}
	for _, m := range bl.Memberships {
		if !nameRE.MatchString(m.Member) || !nameRE.MatchString(m.Role) || !roles[m.Member] && !roles[m.Role] {
			return fmt.Errorf("membership %q in %q", m.Member, m.Role)
		}
	}
	for _, s := range bl.RoleSettings {
		if !roles[s.Role] {
			return fmt.Errorf("role setting of %q", s.Role)
		}
	}
	var schemas []string
	for _, s := range bl.Schemas {
		if !nameRE.MatchString(s.Owner) {
			return fmt.Errorf("schema %q owner", s.Name)
		}
		schemas = append(schemas, s.Name)
	}
	slices.Sort(schemas)
	if !slices.Equal(schemas, []string{"auth", "extensions", "realtime", "storage"}) {
		return fmt.Errorf("schemas %q", schemas)
	}
	for _, e := range bl.EventTriggers {
		if !nameRE.MatchString(e.Name) || !nameRE.MatchString(e.Owner) || e.Event == "" || strings.Count(e.Function, ".") != 1 {
			return fmt.Errorf("event trigger %q", e.Name)
		}
	}
	f := bl.Files
	for _, p := range []string{f.IncludeDir, f.HBAFile, f.IdentFile, f.SupautilsConf, f.PgsodiumKey} {
		if !pathRE.MatchString(p) {
			return fmt.Errorf("file path %q", p)
		}
	}
	return nil
}
