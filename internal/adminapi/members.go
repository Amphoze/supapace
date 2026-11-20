package adminapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

// The dashboard's authorization table: members of projects, the sign-in
// issuer and revocations. A write is committed by the store and then brought
// into force by the daemon's capabilities, asserted at use on Ops (an Ops
// without one runs as before): a committed write that is not yet in force
// answers 503 not_in_force with its document, and the daemon's next round
// repairs it. The principal (issuer, subject) travels in the body only.

// RotationOutcome is what a committed service-key rotation did at the
// gateway's route entry and at the REST service's key set: "done", "owed:
// signal follows", "skipped: no running service" or the failed step's error.
// Err is set when a step failed after the commit.
type RotationOutcome struct {
	Gateway, Rest string
	Err           error
}

// The capabilities, implemented by the daemon.
type (
	studioDomainer  interface{ StudioDomain() string }
	dashboardPusher interface {
		PushDashboard(context.Context) (generation int64, err error)
		DashboardInForce(context.Context) (generation int64, inForce bool, err error)
	}
	memberRotator interface {
		ChangeMemberRotating(ctx context.Context, ref, issuer, subject, fromRole, toRole string) (RotationOutcome, error)
	}
	keyRotator interface {
		RotateServiceKey(ctx context.Context, ref string) (RotationOutcome, error)
	}
	jobsDropper interface {
		DropReadOnlyJobs(ctx context.Context, ref string) error
	}
)

// jobsWait bounds the read-only clean-up a request waits for: the run's own
// deadline is 15 s.
const jobsWait = 20 * time.Second

const (
	notRun             = "not run: dashboard not in force"
	rotationNotHere    = "service-key rotation is not available in this daemon"
	jobsNotHere        = "this daemon cannot end the read-only role's sessions and delete its scheduled jobs, which ending a read_only membership requires; nothing was changed"
	pusherNotHere      = "this daemon cannot bring a dashboard change into force (it has no dashboard file writer); nothing was changed"
	noStudioDomain     = "this node has no studio domain, so it serves no dashboard; give it one with 'supapaced init --studio-domain DOMAIN' (see 'supapaced init --help')"
	maxPrincipal       = 255
	maxIssuerURL       = dashfile.MaxURLBytes
	stillValidSentence = "the service_role key of project %s, which this owner could read, stays valid: it passes the gateway " +
		"and bypasses row-level security until it is rotated ('supapace project rotate-key %s --service')"
)

type rotationJSON struct {
	Gateway string `json:"gateway"`
	Rest    string `json:"rest"`
}

type memberJSON struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Role    string `json:"role"`
	AddedAt string `json:"added_at"`
}

type memberDocJSON struct {
	Ref          string        `json:"ref"`
	Issuer       string        `json:"issuer"`
	Subject      string        `json:"subject"`
	Role         *string       `json:"role"`
	PreviousRole *string       `json:"previous_role"`
	ServiceKey   string        `json:"service_key"`
	Rotation     *rotationJSON `json:"rotation"`
	StillValid   *string       `json:"still_valid"`
	Jobs         *string       `json:"jobs"`
	Generation   *int64        `json:"dashboard_generation"`
}

type issuerJSON struct {
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	AuthorizeURL   string   `json:"authorize_url"`
	EndSessionURL  string   `json:"end_session_url"`
	SessionSeconds int      `json:"session_seconds"`
	Kids           []string `json:"kids"`
	UpdatedAt      string   `json:"updated_at"`
}

type issuerSetJSON struct {
	issuerJSON
	Generation *int64 `json:"dashboard_generation"`
}

type revocationJSON struct {
	Issuer     string `json:"issuer"`
	Subject    string `json:"subject"`
	NotBefore  string `json:"not_before"`
	Generation *int64 `json:"dashboard_generation"`
}

type dashShowJSON struct {
	StudioDomain string `json:"studio_domain"`
	InForce      bool   `json:"in_force"`
	Generation   *int64 `json:"dashboard_generation"`
	Members      int    `json:"members"`
	Revocations  int    `json:"revocations"`
}

type jobsJSON struct {
	Ref  string `json:"ref"`
	Jobs string `json:"jobs"`
}

type rotateJSON struct {
	Ref        string        `json:"ref"`
	ServiceKey string        `json:"service_key"`
	Rotation   *rotationJSON `json:"rotation"`
}

// notInForceError is the 503 answer: the code, the message and the document.
type notInForceError struct{ body json.RawMessage }

func (e *notInForceError) Error() string { return "not_in_force" }

func notInForce(msg string, doc any) error {
	head, err := json.Marshal(errorJSON{"not_in_force", msg})
	if err != nil {
		return err
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return &notInForceError{append(append(head[:len(head)-1], ','), b[1:]...)}
}

// cause is an error's text as an answer carries it: cleaned and capped.
func cause(err error) string { return clean(err.Error(), maxMessage, "error") }

// principalOK: 1 to 255 bytes of printable ASCII, as the dashboard file
// holds an issuer and a subject.
func principalOK(s string) bool {
	if len(s) < 1 || len(s) > maxPrincipal {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func roleOK(r string) bool { return r == "owner" || r == "developer" || r == "read_only" }

// rank orders the roles by what they grant; a removal ("") grants nothing.
var rank = map[string]int{"read_only": 1, "developer": 2, "owner": 3}

// grant refuses a change that widens access (an add, a raised role) while the
// node's containment is not verified; a change that narrows it is a cut-off
// and is always served.
func (a *api) grant() error {
	if a.ops.ContainmentOK() {
		return nil
	}
	return &apiError{http.StatusServiceUnavailable, "containment_failed", "the node's containment is not verified; " +
		"adding a member or raising a role is refused until it is (see 'supapace node check'); removals, lowered roles, " +
		"revocations, the issuer and rotations are served"}
}

// studio refuses a route of the dashboard on a node without a studio domain.
func (a *api) studio() (string, error) {
	if s, ok := a.ops.(studioDomainer); ok {
		if d := s.StudioDomain(); d != "" {
			return d, nil
		}
	}
	return "", conflict(noStudioDomain)
}

// writer is the dashboard pusher a write needs, after the studio check: a
// write nothing could bring into force is not accepted.
func (a *api) writer() (dashboardPusher, error) {
	if _, err := a.studio(); err != nil {
		return nil, err
	}
	if p, ok := a.ops.(dashboardPusher); ok {
		return p, nil
	}
	return nil, conflict(pusherNotHere)
}

// principal checks a request's principal; an omitted issuer is the
// configured dashboard issuer.
func (a *api) principal(ctx context.Context, issuer *string, subject string) (string, error) {
	if !principalOK(subject) {
		return "", badRequest("subject must be 1 to 255 bytes of printable ASCII: the principal's sub claim at its issuer")
	}
	if issuer != nil {
		if !principalOK(*issuer) {
			return "", badRequest("issuer must be 1 to 255 bytes of printable ASCII; leave it out to mean the dashboard issuer")
		}
		return *issuer, nil
	}
	d, err := a.st.GetDashboardIssuer(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return "", conflict("no dashboard issuer is set, so the principal's issuer cannot be left out; " +
			"set one with 'supapace dashboard issuer set', or name the issuer (--issuer)")
	}
	return d.Issuer, err
}

// notMember is the answer for a principal that holds no membership.
func (a *api) notMember(ctx context.Context, ref string) error {
	if _, err := a.st.GetProject(ctx, ref); err != nil {
		return err
	}
	return notFound("the principal is not a member of project " + ref + "; see 'supapace member list " + ref + "'")
}

// ───────── members ─────────

func (a *api) listMembers(r *http.Request) (any, error) {
	if _, err := a.studio(); err != nil {
		return nil, err
	}
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	ms, err := a.st.ListMembers(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	out := struct {
		Ref     string       `json:"ref"`
		Members []memberJSON `json:"members"`
	}{ref, []memberJSON{}}
	for _, m := range ms {
		out.Members = append(out.Members, memberJSON{pgsock.Sanitize(m.Issuer, maxPrincipal), pgsock.Sanitize(m.Subject, maxPrincipal),
			pgsock.Sanitize(m.Role, maxName), stamp(m.AddedAt)})
	}
	return out, nil
}

func (a *api) addMember(r *http.Request) (any, error) {
	p, err := a.writer()
	if err != nil {
		return nil, err
	}
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	var req struct {
		Issuer  *string `json:"issuer"`
		Subject string  `json:"subject"`
		Role    string  `json:"role"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if !roleOK(req.Role) {
		return nil, badRequest("role must be owner, developer or read_only")
	}
	if err := a.grant(); err != nil {
		return nil, err
	}
	ctx := r.Context()
	iss, err := a.principal(ctx, req.Issuer, req.Subject)
	if err != nil {
		return nil, err
	}
	if err := a.st.AddMember(ctx, store.Member{Ref: ref, Issuer: iss, Subject: req.Subject, Role: req.Role}); err != nil {
		return nil, err
	}
	doc := memberDocJSON{Ref: ref, Issuer: iss, Subject: req.Subject, Role: &req.Role, ServiceKey: "unchanged"}
	return a.inForce(ctx, p, &doc, nil, false)
}

func (a *api) setRole(r *http.Request) (any, error) {
	var req struct {
		Issuer     *string `json:"issuer"`
		Subject    string  `json:"subject"`
		Role       string  `json:"role"`
		ServiceKey string  `json:"service_key"`
	}
	return a.changeMember(r, &req, &req.Issuer, &req.Subject, &req.Role, &req.ServiceKey)
}

func (a *api) removeMember(r *http.Request) (any, error) {
	var req struct {
		Issuer     *string `json:"issuer"`
		Subject    string  `json:"subject"`
		ServiceKey string  `json:"service_key"`
	}
	return a.changeMember(r, &req, &req.Issuer, &req.Subject, nil, &req.ServiceKey)
}

// changeMember changes a member's role (to "" removes it). An owner whose
// membership ends rotates the project's service key unless the request
// keeps it; any change rotates it when the request asks, but an owner who
// stays an owner never does. A read_only membership that ends cleans the
// read-only role once the change is in force.
func (a *api) changeMember(r *http.Request, req any, issuer **string, subject, to, serviceKey *string) (any, error) {
	p, err := a.writer()
	if err != nil {
		return nil, err
	}
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	if err := decode(r, req); err != nil {
		return nil, err
	}
	var toRole string // "" removes the member
	if to != nil {
		if toRole = *to; !roleOK(toRole) {
			return nil, badRequest("role must be owner, developer or read_only")
		}
	}
	sk := *serviceKey
	switch sk {
	case "":
		sk = "default"
	case "default", "keep", "rotate":
	default:
		return nil, badRequest("service_key must be default, keep or rotate")
	}
	ctx := r.Context()
	iss, err := a.principal(ctx, *issuer, *subject)
	if err != nil {
		return nil, err
	}
	from, err := a.st.MemberRole(ctx, ref, iss, *subject)
	if errors.Is(err, store.ErrNotFound) {
		return nil, a.notMember(ctx, ref)
	}
	if err != nil {
		return nil, err
	}
	ownerStays := from == "owner" && toRole == "owner"
	if ownerStays && sk == "rotate" {
		return nil, badRequest("an owner who stays an owner keeps the project's service key; rotate it on its own with "+
			"'supapace project rotate-key %s --service'", ref)
	}
	rotate := !ownerStays && (sk == "rotate" || from == "owner" && sk != "keep")
	jobs := from == "read_only" && toRole != "read_only"
	if rank[toRole] > rank[from] {
		if err := a.grant(); err != nil {
			return nil, err
		}
	}
	// Everything the change needs, before anything is changed.
	rot, hasRot := a.ops.(memberRotator)
	if rotate && !hasRot {
		return nil, conflict("%s; repeat with the service key kept (--keep-service-key)", rotationNotHere)
	}
	if _, ok := a.ops.(jobsDropper); jobs && !ok {
		return nil, conflict(jobsNotHere)
	}
	doc := memberDocJSON{Ref: ref, Issuer: iss, Subject: *subject, PreviousRole: &from, ServiceKey: "unchanged"}
	if to != nil {
		doc.Role = &toRole
	}
	var outcome *RotationOutcome
	if rotate {
		o, err := rot.ChangeMemberRotating(ctx, ref, iss, *subject, from, toRole)
		if errors.Is(err, store.ErrNotFound) {
			return nil, a.notMember(ctx, ref)
		}
		if err != nil {
			return nil, err
		}
		outcome, doc.ServiceKey = &o, "rotated"
	} else {
		err := a.st.ChangeMember(ctx, ref, iss, *subject, from, toRole)
		if errors.Is(err, store.ErrNotFound) {
			return nil, a.notMember(ctx, ref)
		}
		if err != nil {
			return nil, err
		}
		if from == "owner" && toRole != "owner" {
			sv := fmt.Sprintf(stillValidSentence, ref, ref)
			doc.ServiceKey, doc.StillValid = "kept", &sv
		}
	}
	return a.inForce(ctx, p, &doc, outcome, jobs)
}

// inForce brings a committed member change into force: the push, the
// rotation's outcome, and the read-only clean-up once the push is in force.
// Any step that is not done makes the answer 503 not_in_force.
func (a *api) inForce(ctx context.Context, p dashboardPusher, doc *memberDocJSON, rot *RotationOutcome, jobs bool) (any, error) {
	var failed []string
	gen, pushed := push(ctx, p, &failed)
	if pushed {
		doc.Generation = &gen
	}
	if rot != nil {
		doc.Rotation = &rotationJSON{pgsock.Sanitize(rot.Gateway, maxMessage), pgsock.Sanitize(rot.Rest, maxMessage)}
		if rot.Err != nil {
			failed = append(failed, "service-key rotation: "+cause(rot.Err))
		}
	}
	if jobs {
		s := notRun
		if pushed && !a.ops.ContainmentOK() {
			s = "not run: containment not verified"
			failed = append(failed, "read-only clean-up: not run: the node's containment is not verified; the daemon runs it from the owed record once it is")
		} else if pushed {
			if err := a.dropJobs(ctx, doc.Ref); err != nil {
				s = "failed: " + cause(err)
				failed = append(failed, "read-only clean-up: "+cause(err))
			} else {
				s = "ran"
			}
		}
		doc.Jobs = &s
	}
	if len(failed) > 0 {
		return nil, notInForce("committed; not yet in force: "+strings.Join(failed, "; "), doc)
	}
	return doc, nil
}

// push writes the dashboard file; a failure, or generation 0 (no file in
// force), is recorded in failed.
func push(ctx context.Context, p dashboardPusher, failed *[]string) (int64, bool) {
	gen, err := p.PushDashboard(ctx)
	switch {
	case err != nil:
		*failed = append(*failed, "dashboard file: "+cause(err))
	case gen <= 0:
		*failed = append(*failed, "dashboard file: no file is in force")
	default:
		return gen, true
	}
	return 0, false
}

func (a *api) dropJobs(ctx context.Context, ref string) error {
	ctx, cancel := context.WithTimeout(ctx, jobsWait)
	defer cancel()
	return a.ops.(jobsDropper).DropReadOnlyJobs(ctx, ref)
}

// cleanJobs runs the read-only role's clean-up now: it changes no member and
// no record, and does not run while the dashboard file is not in force.
func (a *api) cleanJobs(r *http.Request) (any, error) {
	if _, err := a.studio(); err != nil {
		return nil, err
	}
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	if err := noBody(r); err != nil {
		return nil, err
	}
	if _, ok := a.ops.(jobsDropper); !ok {
		return nil, conflict("this daemon cannot end the read-only role's sessions and delete its scheduled jobs")
	}
	p, ok := a.ops.(dashboardPusher)
	if !ok {
		return nil, conflict(pusherNotHere)
	}
	if !a.ops.ContainmentOK() {
		return nil, &apiError{http.StatusServiceUnavailable, "containment_failed", "the node's containment is not verified; the read-only clean-up runs once it is (see 'supapace node check')"}
	}
	ctx := r.Context()
	pr, err := a.st.GetProject(ctx, ref)
	if err != nil {
		return nil, err
	}
	if pr.State != "active" {
		return nil, conflict("project is %s; the read-only role is cleaned on an active project", pr.State)
	}
	gen, in, err := p.DashboardInForce(ctx)
	if err != nil {
		return nil, err
	}
	doc := jobsJSON{Ref: ref, Jobs: notRun}
	if !in || gen <= 0 {
		return nil, notInForce("the read-only clean-up did not run: dashboard not in force; "+
			"'supapace dashboard show' tells when it is", doc)
	}
	if err := a.dropJobs(ctx, ref); err != nil {
		doc.Jobs = "failed: " + cause(err)
		return nil, notInForce("the read-only clean-up failed: "+cause(err), doc)
	}
	doc.Jobs = "ran"
	return doc, nil
}

func (a *api) rotateKey(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	if err := noBody(r); err != nil {
		return nil, err
	}
	k, ok := a.ops.(keyRotator)
	if !ok {
		return nil, conflict("%s; nothing was changed", rotationNotHere)
	}
	o, err := k.RotateServiceKey(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	doc := rotateJSON{ref, "rotated", &rotationJSON{pgsock.Sanitize(o.Gateway, maxMessage), pgsock.Sanitize(o.Rest, maxMessage)}}
	if o.Err != nil {
		return nil, notInForce("committed; not yet in force: service-key rotation: "+cause(o.Err), doc)
	}
	return doc, nil
}

// ───────── issuer, revocations, state ─────────

func toIssuer(d store.DashboardIssuer) issuerJSON {
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	json.Unmarshal(d.JWKS, &set) // the store checked it at insert
	kids := []string{}
	for _, k := range set.Keys {
		kids = append(kids, pgsock.Sanitize(k.Kid, dashfile.MaxKidBytes))
	}
	return issuerJSON{pgsock.Sanitize(d.Issuer, maxPrincipal), pgsock.Sanitize(d.ClientID, maxPrincipal),
		pgsock.Sanitize(d.AuthorizeURL, maxIssuerURL), pgsock.Sanitize(d.EndSessionURL, maxIssuerURL), d.SessionSeconds, kids, stamp(d.UpdatedAt)}
}

func (a *api) showIssuer(r *http.Request) (any, error) {
	if _, err := a.studio(); err != nil {
		return nil, err
	}
	d, err := a.st.GetDashboardIssuer(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no dashboard issuer is set; set one with 'supapace dashboard issuer set'")
	}
	if err != nil {
		return nil, err
	}
	return toIssuer(d), nil
}

// httpsURL checks an issuer endpoint: an https URL with a host, no user
// information and no fragment, of printable ASCII without spaces.
func httpsURL(name, s string) error {
	bad := badRequest("%s must be an https URL with a host and without a fragment, at most %d bytes", name, maxIssuerURL)
	if len(s) > maxIssuerURL || strings.Contains(s, "#") {
		return bad
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] > 0x7e {
			return bad
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return bad
	}
	return nil
}

func (a *api) setIssuer(r *http.Request) (any, error) {
	p, err := a.writer()
	if err != nil {
		return nil, err
	}
	var req struct {
		Issuer         string          `json:"issuer"`
		ClientID       string          `json:"client_id"`
		AuthorizeURL   string          `json:"authorize_url"`
		EndSessionURL  string          `json:"end_session_url"`
		SessionSeconds *int            `json:"session_seconds"`
		JWKS           json.RawMessage `json:"jwks"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if !principalOK(req.Issuer) {
		return nil, badRequest("issuer must be 1 to 255 bytes of printable ASCII: the iss claim of the issuer's ID tokens, exactly")
	}
	if !principalOK(req.ClientID) {
		return nil, badRequest("client_id must be 1 to 255 bytes of printable ASCII")
	}
	if err := httpsURL("authorize_url", req.AuthorizeURL); err != nil {
		return nil, err
	}
	if req.EndSessionURL != "" {
		if err := httpsURL("end_session_url", req.EndSessionURL); err != nil {
			return nil, err
		}
	}
	secs := store.MaxSessionSeconds
	if req.SessionSeconds != nil {
		if secs = *req.SessionSeconds; secs < 300 || secs > store.MaxSessionSeconds {
			return nil, badRequest("session_seconds must be 300 to %d (5 minutes to 8 hours)", store.MaxSessionSeconds)
		}
	}
	// The keys the parser keeps — RSA, for signatures, RS256 — and only those
	// are stored, re-encoded: an encryption key or another key type the set
	// publishes beside them never becomes a sign-in key.
	keys, err := jwtx.ParseDashboardJWKS(req.JWKS)
	if err != nil {
		return nil, badRequest("jwks: %v; it must be a JSON Web Key Set holding 1 to %d RSA signing keys (RS256, 2048 to 4096 bits, "+
			"exponent 65537), each with a kid and none with a private member; keys of other types or for encryption are left out",
			err, dashfile.MaxKeys)
	}
	if len(keys) > dashfile.MaxKeys {
		return nil, badRequest("jwks: %d signing keys; at most %d", len(keys), dashfile.MaxKeys)
	}
	for _, k := range keys {
		if !principalOK(k.KID) {
			return nil, badRequest("jwks: a kid must be 1 to 255 bytes of printable ASCII")
		}
	}
	ctx := r.Context()
	if err := a.projectKey(ctx, keys); err != nil {
		return nil, err
	}
	set, err := jwtx.MarshalJWKS(keys)
	if err != nil {
		return nil, err
	}
	if err := a.st.SetDashboardIssuer(ctx, store.DashboardIssuer{Issuer: req.Issuer, ClientID: req.ClientID, AuthorizeURL: req.AuthorizeURL,
		EndSessionURL: req.EndSessionURL, SessionSeconds: secs, JWKS: set}); err != nil {
		return nil, err
	}
	d, err := a.st.GetDashboardIssuer(ctx)
	if err != nil {
		return nil, err
	}
	doc := issuerSetJSON{issuerJSON: toIssuer(d)}
	var failed []string
	if gen, ok := push(ctx, p, &failed); ok {
		doc.Generation = &gen
	}
	if len(failed) > 0 {
		return nil, notInForce("committed; not yet in force: "+strings.Join(failed, "; "), doc)
	}
	return doc, nil
}

// projectKey refuses a key that is also a key of a project: a project's keys
// are never accepted for dashboard sign-in.
func (a *api) projectKey(ctx context.Context, keys []jwtx.Key) error {
	ps, err := a.st.ListProjects(ctx)
	if err != nil {
		return err
	}
	for _, p := range ps {
		rows, err := a.st.ListKeys(ctx, p.Ref)
		if err != nil {
			return err
		}
		for _, row := range rows {
			var j struct {
				N string `json:"n"`
			}
			if json.Unmarshal(row.JWK, &j) != nil {
				continue
			}
			nb, err := base64.RawURLEncoding.DecodeString(j.N)
			if err != nil {
				continue
			}
			n := new(big.Int).SetBytes(nb)
			for _, k := range keys {
				if k.Pub.N.Cmp(n) == 0 {
					return badRequest("jwks: key %q is a key of project %s; a project's keys are never accepted for dashboard sign-in",
						pgsock.Sanitize(k.KID, 64), p.Ref)
				}
			}
		}
	}
	return nil
}

func (a *api) revoke(r *http.Request) (any, error) {
	p, err := a.writer()
	if err != nil {
		return nil, err
	}
	var req struct {
		Issuer  *string `json:"issuer"`
		Subject string  `json:"subject"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ctx := r.Context()
	iss, err := a.principal(ctx, req.Issuer, req.Subject)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if err := a.st.Revoke(ctx, iss, req.Subject, now); err != nil {
		return nil, err
	}
	// The file holds whole seconds, rounded up: the time it refuses from.
	nb := now.Truncate(time.Second)
	if nb.Before(now) {
		nb = nb.Add(time.Second)
	}
	doc := revocationJSON{Issuer: iss, Subject: req.Subject, NotBefore: stamp(nb)}
	var failed []string
	if gen, ok := push(ctx, p, &failed); ok {
		doc.Generation = &gen
	}
	if len(failed) > 0 {
		return nil, notInForce("committed; not yet in force: "+strings.Join(failed, "; "), doc)
	}
	return doc, nil
}

func (a *api) dashboard(r *http.Request) (any, error) {
	domain, err := a.studio()
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	out := dashShowJSON{StudioDomain: pgsock.Sanitize(domain, maxPrincipal)}
	p, ok := a.ops.(dashboardPusher)
	if !ok {
		return nil, conflict("this daemon cannot write the dashboard file, so no member, issuer or revocation change is in force")
	}
	gen, in, err := p.DashboardInForce(ctx)
	if err != nil {
		return nil, err
	}
	if gen > 0 {
		out.Generation = &gen
		out.InForce = in
	}
	t, err := a.st.DashboardTable(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range t.Projects {
		out.Members += len(p.Members)
	}
	out.Revocations = len(t.Revoked)
	return out, nil
}
