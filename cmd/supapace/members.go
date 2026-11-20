package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Amphoze/supapace/internal/pgsock"
)

// The dashboard's commands: members of projects, the sign-in issuer,
// revocations, the service-key rotation and the audit read. Each prints the
// answer on stdout as every command does; what the operator must know about
// it — a rotated key, a key left valid, a change not yet in force — goes to
// stderr, cleaned of control characters.

const revokeHint = "if this principal was removed in the last eight hours, a session cookie it kept is valid again; " +
	"'supapace dashboard revoke ISSUER SUBJECT' ends it"

// say prints one line to stderr; text the daemon sent is cleaned first.
func say(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, "supapace: %s\n", pgsock.Sanitize(fmt.Sprintf(format, args...), 2048))
}

// dashCall registers the flags of a dashboard command on fs and returns the
// function that builds its call from the positional arguments; nil for any
// other command.
func dashCall(verb string, fs *flag.FlagSet) func(pos []string, project string) (call, error) {
	var subject, role string
	var issuer *string
	var keep, rotate bool
	nonEmpty := func(name string, p *string) {
		fs.Func(name, "", func(s string) error {
			if s == "" {
				return errors.New("empty value")
			}
			*p = s
			return nil
		})
	}
	principal := func() {
		nonEmpty("subject", &subject)
		fs.Func("issuer", "", func(s string) error {
			if s == "" {
				return errors.New("empty issuer; leave the flag out to mean the dashboard issuer")
			}
			issuer = &s
			return nil
		})
	}
	serviceKey := func() {
		fs.BoolVar(&keep, "keep-service-key", false, "")
		fs.BoolVar(&rotate, "rotate-service-key", false, "")
	}
	// sk is the request's service_key; "" is the default.
	sk := func() (string, error) {
		switch {
		case keep && rotate:
			return "", usagef("%s: --keep-service-key and --rotate-service-key exclude each other", verb)
		case keep:
			return "keep", nil
		case rotate:
			return "rotate", nil
		}
		return "", nil
	}
	type memberBody struct {
		Issuer     *string `json:"issuer,omitempty"`
		Subject    string  `json:"subject"`
		Role       string  `json:"role,omitempty"`
		ServiceKey string  `json:"service_key,omitempty"`
	}
	switch verb {
	case "member add":
		principal()
		nonEmpty("role", &role)
		return func(pos []string, project string) (call, error) {
			if subject == "" || role == "" {
				return call{}, usagef("member add: --subject and --role are required")
			}
			return call{method: "POST", path: project + "/members", body: memberBody{Issuer: issuer, Subject: subject, Role: role},
				look: "'supapace member list " + pos[0] + "' and 'supapace dashboard show'", notes: memberNotes(verb, pos[0])}, nil
		}
	case "member set-role", "member remove":
		principal()
		serviceKey()
		if verb == "member set-role" {
			nonEmpty("role", &role)
		}
		return func(pos []string, project string) (call, error) {
			if subject == "" || verb == "member set-role" && role == "" {
				if verb == "member remove" {
					return call{}, usagef("member remove: --subject is required")
				}
				return call{}, usagef("member set-role: --subject and --role are required")
			}
			s, err := sk()
			if err != nil {
				return call{}, err
			}
			path := project + "/members/remove"
			if verb == "member set-role" {
				path = project + "/members/role"
			}
			return call{method: "POST", path: path, body: memberBody{Issuer: issuer, Subject: subject, Role: role, ServiceKey: s},
				look: "'supapace member list " + pos[0] + "' and 'supapace dashboard show'", before: endingNote(verb, s), notes: memberNotes(verb, pos[0])}, nil
		}
	case "member list":
		return func(pos []string, project string) (call, error) {
			return call{method: "GET", path: project + "/members", notes: memberNotes(verb, pos[0])}, nil
		}
	case "member clean-jobs":
		return func(pos []string, project string) (call, error) {
			return call{method: "POST", path: project + "/members/clean-jobs", look: "'supapace dashboard show'",
				notes: memberNotes(verb, pos[0])}, nil
		}
	case "project rotate-key":
		var service bool
		fs.BoolVar(&service, "service", false, "")
		return func(pos []string, project string) (call, error) {
			if !service {
				return call{}, usagef("project rotate-key: --service is required: the service_role key is the only key it rotates")
			}
			return call{method: "POST", path: project + "/service-key/rotate", look: "'supapace project keys " + pos[0] + "'",
				before: "rotating the project's service_role key; this cannot be undone",
				notes:  memberNotes(verb, pos[0])}, nil
		}
	case "project audit":
		var tail *int
		fs.Func("tail", "", func(s string) error {
			n, err := strconv.Atoi(s)
			if err != nil {
				return errors.New("want an integer")
			}
			tail = &n
			return nil
		})
		return func(pos []string, project string) (call, error) {
			if tail == nil {
				return call{method: "GET", path: project + "/audit"}, nil
			}
			return call{method: "GET", path: project + "/audit?" + url.Values{"tail": {strconv.Itoa(*tail)}}.Encode()}, nil
		}
	case "dashboard issuer set":
		var iss, client, authorize, end, jwks string
		var hours *int
		nonEmpty("issuer", &iss)
		nonEmpty("client-id", &client)
		nonEmpty("authorize-url", &authorize)
		nonEmpty("jwks", &jwks)
		nonEmpty("end-session-url", &end)
		fs.Func("session-hours", "", func(s string) error {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > 8 {
				return errors.New("want 1 to 8 (hours)")
			}
			hours = &n
			return nil
		})
		return func([]string, string) (call, error) {
			if iss == "" || client == "" || authorize == "" || jwks == "" {
				return call{}, usagef("dashboard issuer set: --issuer, --client-id, --authorize-url and --jwks are required")
			}
			set, err := readJWKS(jwks)
			if err != nil {
				return call{}, err
			}
			body := struct {
				Issuer         string          `json:"issuer"`
				ClientID       string          `json:"client_id"`
				AuthorizeURL   string          `json:"authorize_url"`
				EndSessionURL  string          `json:"end_session_url,omitempty"`
				SessionSeconds *int            `json:"session_seconds,omitempty"`
				JWKS           json.RawMessage `json:"jwks"`
			}{Issuer: iss, ClientID: client, AuthorizeURL: authorize, EndSessionURL: end, JWKS: set}
			if hours != nil {
				s := *hours * 3600
				body.SessionSeconds = &s
			}
			var entries struct{ Keys []json.RawMessage }
			json.Unmarshal(set, &entries)
			return call{method: "PUT", path: "/v1/dashboard/issuer", body: body, look: "'supapace dashboard issuer show' and 'supapace dashboard show'",
				notes: issuerNotes(len(entries.Keys))}, nil
		}
	case "dashboard issuer show":
		return func([]string, string) (call, error) { return call{method: "GET", path: "/v1/dashboard/issuer"}, nil }
	case "dashboard revoke":
		return func(pos []string, _ string) (call, error) {
			body := struct {
				Issuer  string `json:"issuer"`
				Subject string `json:"subject"`
			}{pos[0], pos[1]}
			return call{method: "POST", path: "/v1/dashboard/revocations", body: body, look: "'supapace dashboard show'",
				notes: revokeNotes}, nil
		}
	case "dashboard show":
		return func([]string, string) (call, error) {
			return call{method: "GET", path: "/v1/dashboard", notes: showNotes}, nil
		}
	}
	return nil
}

// endingNote says, before the request, what ending a membership does by
// default.
func endingNote(verb, sk string) string {
	what := "removing a member"
	if verb == "member set-role" {
		what = "changing a member's role"
	}
	key := "if it is an owner who stops being one, the project's service_role key is rotated (--keep-service-key keeps it)"
	switch sk {
	case "keep":
		key = "the project's service_role key is kept"
	case "rotate":
		key = "the project's service_role key is rotated"
	}
	return what + ": " + key + "; if it is read_only and stops being so, the read-only role's sessions are ended and its " +
		"scheduled jobs deleted, the other read-only members' included"
}

// nif is the stderr of an answer not_in_force: the message, and how the
// change comes into force.
func nif(w io.Writer, message string, jobs *string) {
	say(w, "%s", message)
	if jobs != nil && (strings.HasPrefix(*jobs, "failed: ") || strings.HasPrefix(*jobs, "not run: ")) {
		say(w, "the read-only role's sessions and scheduled jobs are not yet cleaned; the daemon retries")
	}
	if !strings.HasPrefix(message, "committed;") {
		return
	}
	switch {
	case strings.Contains(message, "dashboard file: "):
		say(w, "the gateway still applies the previous member, issuer and revocation table: until the daemon writes the file, "+
			"a removed or revoked principal is still admitted and an added one is not; the daemon retries in each round, "+
			"and 'supapace dashboard show' exits 0 once it is in force")
	case strings.Contains(message, "containment is not verified"):
		say(w, "the daemon runs the clean-up once 'supapace node check' reports the node's containment verified")
	case strings.Contains(message, "read-only clean-up: "):
		say(w, "the daemon retries; 'supapace dashboard show' tells when it is")
	}
	if strings.Contains(message, "service-key rotation: ") {
		say(w, "the new service_role key is stored, but the rotation is not complete: until the daemon's next rounds "+
			"finish it, the gateway or the REST service may still accept the old key")
	}
}

// exit is a command's status from its answer: 0 for a 2xx.
func exit(status int) int {
	if status/100 == 2 {
		return 0
	}
	return 1
}

func memberNotes(verb, ref string) func(io.Writer, int, []byte) int {
	return func(w io.Writer, status int, body []byte) int {
		var d struct {
			Code       string  `json:"code"`
			Message    string  `json:"message"`
			Ref        string  `json:"ref"`
			Role       *string `json:"role"`
			Previous   string  `json:"previous_role"`
			ServiceKey string  `json:"service_key"`
			StillValid *string `json:"still_valid"`
			Jobs       *string `json:"jobs"`
			Rotation   *struct {
				Rest string `json:"rest"`
			} `json:"rotation"`
			Members []struct {
				Issuer  string `json:"issuer"`
				Subject string `json:"subject"`
				Role    string `json:"role"`
				AddedAt string `json:"added_at"`
			} `json:"members"`
		}
		if json.Unmarshal(body, &d) != nil {
			return 1
		}
		committed := status/100 == 2 || d.Code == "not_in_force"
		if !committed {
			return 1
		}
		switch verb {
		case "member add":
			say(w, revokeHint)
		case "member list":
			if len(d.Members) == 0 {
				say(w, "project %s has no members; add one with 'supapace member add %s --subject SUB --role ROLE'", ref, ref)
			} else {
				say(w, "project %s has %d members:", ref, len(d.Members))
			}
			for _, m := range d.Members {
				fmt.Fprintf(w, "  %-9s  %s  (%s) since %s\n", pgsock.Sanitize(m.Role, 16), pgsock.Sanitize(m.Subject, 255),
					pgsock.Sanitize(m.Issuer, 255), pgsock.Sanitize(m.AddedAt, 32))
			}
		case "member clean-jobs":
			if d.Code == "" {
				say(w, "the read-only role's sessions were ended and its scheduled jobs deleted")
			}
		}
		switch d.ServiceKey {
		case "rotated":
			say(w, "the service_role key of project %s was rotated: the project's own server-side clients must take the new key "+
				"('supapace project keys %s')", ref, ref)
			if d.Rotation != nil && strings.HasPrefix(d.Rotation.Rest, "owed") {
				say(w, "the gateway refuses the old key; the REST service reloads the new one in a later round of the daemon")
			}
		case "kept":
			if d.StillValid != nil {
				say(w, "%s", *d.StillValid)
			}
		case "unchanged":
			// A developer whose membership ends or is lowered may hold the key.
			if d.Previous == "developer" && (d.Role == nil || *d.Role == "read_only") {
				say(w, "the service_role key of project %s was not rotated; a developer may have captured it from the "+
					"project's traffic: 'supapace project rotate-key %s --service' rotates it", ref, ref)
			}
		}
		if d.Code == "not_in_force" {
			nif(w, d.Message, d.Jobs)
			switch {
			case verb != "member clean-jobs" || d.Jobs == nil:
			case strings.HasPrefix(*d.Jobs, "not run: "):
				say(w, "run 'supapace member clean-jobs %s' again once 'supapace dashboard show' says the file is in force", ref)
			default:
				say(w, "run 'supapace member clean-jobs %s' again; a clean-up owed by a membership change is also retried by the daemon", ref)
			}
		}
		return exit(status)
	}
}

func issuerNotes(entries int) func(io.Writer, int, []byte) int {
	return func(w io.Writer, status int, body []byte) int {
		var d struct {
			Code    string   `json:"code"`
			Message string   `json:"message"`
			Kids    []string `json:"kids"`
		}
		if json.Unmarshal(body, &d) != nil {
			return 1
		}
		if status/100 == 2 || d.Code == "not_in_force" {
			say(w, "dashboard sign-in trusts %d key(s) of the issuer: %s", len(d.Kids), strings.Join(d.Kids, ", "))
			if entries > len(d.Kids) {
				say(w, "%d of the %d entries of the key set are not RS256 signing keys (another key type, or a key for "+
					"encryption) and are not used for sign-in", entries-len(d.Kids), entries)
			}
		}
		if d.Code == "not_in_force" {
			nif(w, d.Message, nil)
		}
		return exit(status)
	}
}

func revokeNotes(w io.Writer, status int, body []byte) int {
	var d struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		NotBefore string `json:"not_before"`
	}
	if json.Unmarshal(body, &d) != nil {
		return 1
	}
	if status == http.StatusOK {
		say(w, "every session of this principal issued before %s is refused on every project of this node; it can sign in "+
			"again where it is still a member ('supapace member remove' ends that)", d.NotBefore)
	}
	if d.Code == "not_in_force" {
		nif(w, d.Message, nil)
	}
	return exit(status)
}

// showNotes: dashboard show exits 0 only while the gateway reads the file
// the store renders.
func showNotes(w io.Writer, status int, body []byte) int {
	var d struct {
		InForce    bool   `json:"in_force"`
		Generation *int64 `json:"dashboard_generation"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &d) != nil {
		return 1
	}
	if !d.InForce {
		say(w, "the dashboard file is not in force: the gateway does not yet apply the latest member, issuer and "+
			"revocation changes; the daemon writes it again in each round")
		return 1
	}
	return 0
}
