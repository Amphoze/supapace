// Package adminapi is the node's admin API: JSON over HTTP, served by the
// daemon on its root-only Unix socket (the daemon creates the listener). It
// owns ref generation and the output contract: every response body is one of
// the fixed JSON shapes below, and the CLI prints it unchanged.
//
// Requests are bounded (maxBody) and decoded strictly: unknown members,
// trailing data and bodies on routes that take none are refused. Text that
// reaches a response from elsewhere (store errors, operation errors, check
// results) passes through pgsock.Sanitize, is capped and loses the platform's
// package-name prefixes and repeated parts (tidy). An unexpected error
// answers "internal error"; its text goes to the log (log/slog), never to
// the response. A path that is not clean is not found, never redirected.
//
// Mutations answer 202 with {"ref","operation_id"} and are refused with
// containment_failed while the node's containment is not verified; reads are
// always served. A create the placement would refuse for room is refused at once
// with node_full; a restart to a disk quota below the project's usage plus
// store.QuotaHeadroomMB with quota_below_usage; a restore target outside the
// backups' window with out_of_window and the window. The backups document is
// read from the store alone. Projects and keys carry the project's URL and the
// path of the CA certificate that signed the gateway's (read from node.json
// and the node's TLS files at each request).
//
// A dashboard write (members, the sign-in issuer, revocations, a service-key
// rotation) answers 200 once in force and 503 not_in_force when it is
// committed and not yet in force (members.go). It is not refused while
// containment is unverified: a removal is a cut-off.
package adminapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

// Ops is what the API needs from the daemon beyond the store: the saga
// runner's submissions, the agent's checks and the containment flag.
type Ops interface {
	// Submit queues a restart, delete or restore. A restore's params are
	// {"to","timeline","from"}: to is latest, an RFC 3339 time or
	// lsn:<hex>/<hex>; timeline 0 and from "" when the request named none.
	// A target outside the window is a *store.WindowError.
	// For a restart, params is
	// {"base_generation": N, "config": {"disk_quota_mb","mem_mb","guc"}}: the
	// merged target configuration and the project generation it was merged
	// onto; Submit refuses with store.ErrConflict when the generation differs.
	Submit(ctx context.Context, kind, ref string, params json.RawMessage) (int64, error)
	Abort(ctx context.Context, ref string) (int64, error)
	// VerifyProject opens one session to the project's cluster. code is ""
	// when the operational facts hold, else peer, timeout or internal; drift
	// holds the assertion's findings.
	VerifyProject(ctx context.Context, ref string) (code, message string, drift []nodecfg.CheckResult)
	NodeCheck(ctx context.Context) []nodecfg.CheckResult
	ContainmentOK() bool
	// DiskUsage returns the bytes the user quota of uid charges on the
	// projects mount (the filesystem's accounting, never a cluster's figure).
	DiskUsage(ctx context.Context, uid int) (int64, error)
}

// restartParams is what a restart hands to Ops.Submit: the merged target
// configuration and the generation of the configuration it was merged onto.
type restartParams struct {
	BaseGeneration int64               `json:"base_generation"`
	Config         store.ProjectConfig `json:"config"`
}

// Drift is one finding of a project check.
type Drift struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

const (
	maxBody        = 128 << 10 // a request body; an issuer key set is at most 64 KiB
	maxIssuerKeys  = 16
	maxUserRoles   = 16
	minDiskQuotaMB = 1024
	maxDiskQuotaMB = 1 << 24 // 16 TiB
	defaultQuotaMB = 8192
	clusterMemMB   = 512 // the cluster container's memory limit
	maxMessage     = 1024
	maxDetail      = 256
	maxName        = 64 // a check or drift row's name
	maxDrift       = 64
	refAttempts    = 8
	refLen         = 20
	refAlphabet    = "abcdefghijklmnopqrstuvwxyz0123456789"
	refAcceptBelow = 252 // 7 × 36: bytes at or above are redrawn, so no symbol is favoured
)

var (
	refRE  = regexp.MustCompile(`^[a-z0-9]{20}$`)
	idRE   = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	roleRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
)

// NewRef returns a fresh project ref: 20 characters of [a-z0-9] from
// crypto/rand, by rejection sampling.
func NewRef() (string, error) {
	ref := make([]byte, 0, refLen)
	buf := make([]byte, 32)
	for len(ref) < refLen {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < refAcceptBelow && len(ref) < refLen {
				ref = append(ref, refAlphabet[b%36])
			}
		}
	}
	return string(ref), nil
}

// newRef is NewRef; tests replace it to force a collision.
var newRef = NewRef

// afterAdmission runs between a create's admission check and its insert;
// tests replace it to race a second create there.
var afterAdmission = func() {}

type api struct {
	st     *store.Store
	kek    secrets.KEK
	ops    Ops
	domain string        // the node's domain, as the daemon loaded it
	paths  nodecfg.Paths // the node CA and the gateway's certificate
	// create holds one token: admission pre-check and insert of a create.
	createSlot chan struct{}
}

// New returns the admin API. It inserts creates itself (store.CreateProject,
// generating the ref when none is given); restarts and deletes go through
// ops.Submit, aborts through ops.Abort. domain is the node's domain as the
// daemon loaded it; p locates the node CA and the gateway's certificate.
func New(st *store.Store, kek secrets.KEK, ops Ops, domain string, p nodecfg.Paths) http.Handler {
	a := &api{st: st, kek: kek, ops: ops, domain: domain, paths: p, createSlot: make(chan struct{}, 1)}
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/projects", a.mutation(a.create))
	m.HandleFunc("GET /v1/projects", read(a.listProjects))
	m.HandleFunc("GET /v1/projects/{ref}", read(a.showProject))
	m.HandleFunc("GET /v1/projects/{ref}/keys", read(a.keys))
	m.HandleFunc("POST /v1/projects/{ref}/check", read(a.check))
	m.HandleFunc("POST /v1/projects/{ref}/restart", a.mutation(a.restart))
	m.HandleFunc("GET /v1/projects/{ref}/backups", read(a.backups))
	m.HandleFunc("POST /v1/projects/{ref}/restore", a.mutation(a.restore))
	m.HandleFunc("DELETE /v1/projects/{ref}", a.mutation(a.delete))
	m.HandleFunc("POST /v1/projects/{ref}/purge", a.mutation(a.purge))
	m.HandleFunc("POST /v1/projects/{ref}/abort", a.mutation(a.abort))
	m.HandleFunc("GET /v1/operations", read(a.listOperations))
	m.HandleFunc("GET /v1/operations/{id}", read(a.showOperation))
	m.HandleFunc("POST /v1/operations/{id}/retry", a.mutation(a.retry))
	m.HandleFunc("GET /v1/node/check", read(a.nodeCheck))
	m.HandleFunc("GET /v1/projects/{ref}/logs", read(a.projectLogs))
	m.HandleFunc("GET /v1/node/logs", read(a.nodeLogs))
	// The dashboard's authorization table: writes answer 200 once in force.
	m.HandleFunc("GET /v1/projects/{ref}/members", read(a.listMembers))
	m.HandleFunc("POST /v1/projects/{ref}/members", read(a.addMember))
	m.HandleFunc("POST /v1/projects/{ref}/members/role", read(a.setRole))
	m.HandleFunc("POST /v1/projects/{ref}/members/remove", read(a.removeMember))
	m.HandleFunc("POST /v1/projects/{ref}/members/clean-jobs", read(a.cleanJobs))
	m.HandleFunc("POST /v1/projects/{ref}/service-key/rotate", read(a.rotateKey))
	m.HandleFunc("GET /v1/projects/{ref}/audit", read(a.audit))
	m.HandleFunc("GET /v1/dashboard", read(a.dashboard))
	m.HandleFunc("GET /v1/dashboard/issuer", read(a.showIssuer))
	m.HandleFunc("PUT /v1/dashboard/issuer", read(a.setIssuer))
	m.HandleFunc("POST /v1/dashboard/revocations", read(a.revoke))
	noRoute := read(func(*http.Request) (any, error) { return nil, notFound("no such route") })
	m.HandleFunc("/", noRoute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The router would redirect an unclean path, with an HTML body.
		if r.URL.Path != path.Clean(r.URL.Path) {
			noRoute(w, r)
			return
		}
		m.ServeHTTP(w, r)
	})
}

// ───────── responses ─────────

type apiError struct {
	status        int
	Code, Message string
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func badRequest(format string, args ...any) error {
	return &apiError{http.StatusBadRequest, "bad_request", fmt.Sprintf(format, args...)}
}

func notFound(msg string) error { return &apiError{http.StatusNotFound, "not_found", msg} }

func conflict(format string, args ...any) error {
	return &apiError{http.StatusConflict, "conflict", fmt.Sprintf(format, args...)}
}

// toError maps an error to its status and synchronous error body. An
// internal error answers with a fixed message; the error itself is logged.
func toError(r *http.Request, err error) (int, any) {
	var ae *apiError
	var nif *notInForceError
	var we *store.WindowError
	switch {
	case errors.As(err, &nif):
		return http.StatusServiceUnavailable, nif.body
	case errors.As(err, &we):
		var w windowJSON // a bound that is not known is null
		if !we.From.IsZero() {
			w.Earliest = optStamp(&we.From)
		}
		if !we.To.IsZero() {
			w.Latest = optStamp(&we.To)
		}
		msg := clean(we.Error(), maxMessage, "the target is outside the restorable window")
		if ref := r.PathValue("ref"); refRE.MatchString(ref) {
			msg += "; see 'supapace project backups " + ref + "'"
		}
		return http.StatusConflict, outOfWindowJSON{errorJSON{"out_of_window", msg}, w}
	case errors.As(err, &ae):
		return ae.status, errorJSON{ae.Code, clean(ae.Message, maxMessage, ae.Code)}
	case errors.Is(err, store.ErrBadRef):
		return http.StatusBadRequest, errorJSON{"bad_ref", "a ref is 20 characters of a-z and 0-9"}
	case errors.Is(err, store.ErrDestroyed):
		return http.StatusNotFound, errorJSON{"not_found", "the project's keys were destroyed when it was purged or aborted"}
	case errors.Is(err, store.ErrNotFound):
		if r.PathValue("id") != "" {
			return http.StatusNotFound, errorJSON{"not_found", "no such operation"}
		}
		return http.StatusNotFound, errorJSON{"not_found", "no such project"}
	case errors.Is(err, store.ErrConflict):
		msg := strings.TrimPrefix(err.Error(), store.ErrConflict.Error())
		msg = strings.TrimSpace(strings.TrimPrefix(msg, ":"))
		return http.StatusConflict, errorJSON{"conflict", clean(msg, maxMessage, "the project's state does not allow this")}
	}
	slog.Error("admin API: internal error", "method", r.Method, "route", r.Pattern,
		"error", pgsock.Sanitize(err.Error(), maxMessage))
	return http.StatusInternalServerError, errorJSON{"internal", "internal error"}
}

// clean sanitises outside text and tidies it; an empty result becomes
// fallback.
func clean(s string, max int, fallback string) string {
	if s = tidy(pgsock.Sanitize(s, max)); s == "" {
		return fallback
	}
	return s
}

// internalPrefixes are the platform's package names, which its error texts
// carry as prefixes.
var internalPrefixes = []string{"adminapi", "agent", "bootstrap", "dockerx", "jwtx", "nodecfg", "nodefs", "nft",
	"pgconf", "pgsock", "routes", "saga", "secrets", "store"}

// tidy drops the package-name parts of a "part: part: …" message and a part
// that repeats the one before it ("connect: connect: refused").
func tidy(s string) string {
	var out []string
	for _, p := range strings.Split(s, ": ") {
		if slices.Contains(internalPrefixes, p) || len(out) > 0 && out[len(out)-1] == p {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, ": ")
}

type handler func(r *http.Request) (any, error)

func read(h handler) http.HandlerFunc { return serve(http.StatusOK, h) }

func (a *api) mutation(h handler) http.HandlerFunc {
	return serve(http.StatusAccepted, func(r *http.Request) (any, error) {
		if !a.ops.ContainmentOK() {
			return nil, &apiError{http.StatusServiceUnavailable, "containment_failed",
				"the node's containment is not verified; mutations are refused until it is (see 'supapace node check')"}
		}
		return h(r)
	})
}

func serve(ok int, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := ok
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		v, err := h(r)
		if err != nil {
			status, v = toError(r, err)
		}
		b, err := json.Marshal(v)
		if err != nil {
			status, v = toError(r, err)
			b, _ = json.Marshal(v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(append(b, '\n'))
	}
}

// ───────── requests ─────────

// decode reads exactly one JSON object into v, refusing unknown members and
// trailing data.
func decode(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return bodyError(err)
	}
	if !bytes.HasPrefix(bytes.TrimLeft(b, " \t\r\n"), []byte("{")) {
		return badRequest("request body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return bodyError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err != nil {
			return bodyError(err)
		}
		return badRequest("request body: trailing data")
	}
	// After Decode: the body is one well-formed document of bounded depth.
	if err := uniqueMembers(json.NewDecoder(bytes.NewReader(b)), true); err != nil {
		return badRequest("request body: %v", err)
	}
	return nil
}

// uniqueMembers refuses a member named twice in one object and, at the top
// level, a member name that is not lower case (the decoder would match it
// case-insensitively, and keep the last of two). A syntax error is left to the
// decoder.
func uniqueMembers(dec *json.Decoder, top bool) error {
	t, err := dec.Token()
	if err != nil {
		return nil
	}
	d, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for dec.More() {
		if d == '{' {
			k, err := dec.Token()
			if err != nil {
				return nil
			}
			s, _ := k.(string)
			if seen[s] || top && s != strings.ToLower(s) {
				return fmt.Errorf("member %.64q is repeated or not in lower case", s)
			}
			seen[s] = true
		}
		if err := uniqueMembers(dec, false); err != nil {
			return err
		}
	}
	dec.Token() // the closing delimiter
	return nil
}

// noBody refuses a request that carries a body.
func noBody(r *http.Request) error {
	if n, err := r.Body.Read(make([]byte, 1)); n > 0 || err != nil && err != io.EOF {
		return badRequest("this request takes no body")
	}
	return nil
}

func bodyError(err error) error {
	var mb *http.MaxBytesError
	if errors.As(err, &mb) {
		return &apiError{http.StatusRequestEntityTooLarge, "bad_request", fmt.Sprintf("request body over %d bytes", maxBody)}
	}
	return badRequest("request body: %v", err)
}

func pathRef(r *http.Request) (string, error) {
	ref := r.PathValue("ref")
	if !refRE.MatchString(ref) {
		return "", store.ErrBadRef
	}
	return ref, nil
}

func pathID(r *http.Request) (int64, error) {
	s := r.PathValue("id")
	id, err := strconv.ParseInt(s, 10, 64)
	if !idRE.MatchString(s) || err != nil {
		return 0, badRequest("operation id must be a positive integer")
	}
	return id, nil
}

func diskQuota(v *int) (int, error) {
	if v == nil {
		return defaultQuotaMB, nil
	}
	if *v < minDiskQuotaMB || *v > maxDiskQuotaMB {
		return 0, badRequest("disk_quota_mb must be %d to %d", minDiskQuotaMB, maxDiskQuotaMB)
	}
	return *v, nil
}

// ───────── shapes ─────────

type errorJSON struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type mutationJSON struct {
	Ref         string `json:"ref"`
	OperationID int64  `json:"operation_id"`
}

type operationJSON struct {
	ID         int64  `json:"id"`
	Ref        string `json:"ref"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	Step       string `json:"step"`
	Attempts   int    `json:"attempts"`
	Epoch      int64  `json:"epoch"`
	Generation int64  `json:"generation"`
	LastError  string `json:"last_error"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Result     any    `json:"result"` // null until a step records one
}

// endpointJSON is where a client reaches a project: its URL and, when the
// node's development CA signed the gateway's certificate, that CA's
// certificate (null when the certificate is the operator's own).
type endpointJSON struct {
	URL    string  `json:"url"`
	CACert *string `json:"ca_cert"`
}

type projectJSON struct {
	Ref         string              `json:"ref"`
	Name        string              `json:"name"`
	State       string              `json:"state"`
	Generation  int64               `json:"generation"`
	AppliedGen  int64               `json:"applied_gen"`
	UID         *int                `json:"uid"`
	SubnetIndex *int                `json:"subnet_index"`
	Config      store.ProjectConfig `json:"config"`
	UserRoles   []string            `json:"user_roles"`
	CreatedAt   string              `json:"created_at"`
	DeletedAt   *string             `json:"deleted_at"`
	PurgeAfter  *string             `json:"purge_after"`
	endpointJSON
}

// showUsageWait bounds the usage read of `project show`.
const showUsageWait = 5 * time.Second

// showJSON is a project as `project show` answers it: the record plus the
// bytes its user quota charges, a host-side figure (null when it cannot be
// read or the project holds no directory: not placed yet, purged, aborted).
type showJSON struct {
	projectJSON
	DiskUsedBytes *int64 `json:"disk_used_bytes"`
}

type keysJSON struct {
	Ref              string `json:"ref"`
	AnonKey          string `json:"anon_key"`
	ServiceRoleKey   string `json:"service_role_key"`
	PostgresPassword string `json:"postgres_password"`
	endpointJSON
}

// caCert is the path of the node CA's certificate when that CA signed the
// gateway's certificate, else nil (the operator's own certificate).
func (a *api) caCert() *string {
	caPath := filepath.Join(a.paths.CADir(), "ca.pem")
	if signedBy(filepath.Join(a.paths.TLSDir(), "cert.pem"), caPath) {
		return &caPath
	}
	return nil
}

// signedBy reports whether the first certificate in certFile is signed by the
// first certificate in caFile.
func signedBy(certFile, caFile string) bool {
	first := func(name string) *x509.Certificate {
		b, err := os.ReadFile(name)
		if err != nil {
			return nil
		}
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "CERTIFICATE" {
			return nil
		}
		c, _ := x509.ParseCertificate(blk.Bytes)
		return c
	}
	leaf, ca := first(certFile), first(caFile)
	return leaf != nil && ca != nil && leaf.CheckSignatureFrom(ca) == nil
}

func endpoint(ref, domain string, ca *string) endpointJSON {
	return endpointJSON{URL: "https://" + ref + "." + domain, CACert: ca}
}

type checkJSON struct {
	OK      bool    `json:"ok"`
	Code    string  `json:"code,omitempty"`
	Message string  `json:"message,omitempty"`
	Drift   []Drift `json:"drift"`
}

type nodeCheckJSON struct {
	OK                bool                  `json:"ok"`
	ContainmentFailed bool                  `json:"containment_failed"`
	Checks            []nodecfg.CheckResult `json:"checks"`
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func optStamp(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := stamp(*t)
	return &s
}

func toOperation(o store.Operation) operationJSON {
	return operationJSON{ID: o.ID, Ref: o.Ref, Kind: o.Kind, State: o.State, Step: o.Step, Attempts: o.Attempts,
		Epoch: o.Epoch, Generation: o.Generation, LastError: tidy(pgsock.Sanitize(o.LastError, maxMessage)),
		CreatedAt: stamp(o.CreatedAt), UpdatedAt: stamp(o.UpdatedAt), Result: cleanResult(o.Result)}
}

func toProject(p store.Project, domain string, ca *string) projectJSON {
	cfg := p.Config
	if cfg.GUC == nil {
		cfg.GUC = map[string]string{}
	}
	roles := p.UserRoles
	if roles == nil {
		roles = []string{}
	}
	return projectJSON{Ref: p.Ref, Name: pgsock.Sanitize(p.Name, maxMessage), State: p.State, Generation: p.Generation,
		AppliedGen: p.AppliedGen, UID: p.UID, SubnetIndex: p.SubnetIndex, Config: cfg, UserRoles: roles,
		CreatedAt: stamp(p.CreatedAt), DeletedAt: optStamp(p.DeletedAt), PurgeAfter: optStamp(p.PurgeAfter),
		endpointJSON: endpoint(p.Ref, domain, ca)}
}

// ───────── projects ─────────

func (a *api) create(r *http.Request) (any, error) {
	var req struct {
		Name        string          `json:"name"`
		Ref         string          `json:"ref"`
		IssuerJWKS  json.RawMessage `json:"issuer_jwks"`
		UserRoles   []string        `json:"user_roles"`
		DiskQuotaMB *int            `json:"disk_quota_mb"`
		UploadMB    *int            `json:"upload_mb_per_day"`
		UploadObj   *int            `json:"upload_objects_per_day"`
		Layout      *int            `json:"layout"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	layout := DefaultLayout
	if req.Layout != nil {
		// The suite's fixture for a project without backups on a node whose
		// default has them.
		if *req.Layout != 1 || !a.devNode() {
			return nil, badRequest("layout: only 1 (a project without backups) is accepted, and only on a development node")
		}
		layout = 1
	}
	if err := uploadSettings(req.UploadMB, req.UploadObj); err != nil {
		return nil, err
	}
	if !nameRE.MatchString(req.Name) {
		return nil, badRequest("name must be 1 to 64 characters of letters, digits, space, '.', '_' or '-', starting with a letter or digit")
	}
	keys, err := jwtx.ParseJWKS(req.IssuerJWKS, "issuer")
	if err != nil {
		return nil, badRequest("issuer_jwks: %v; it must be a JSON Web Key Set of 1 to %d RSA signing keys "+
			"(RS256, 2048 to 4096 bits, exponent 65537), each with a kid and without private members", err, maxIssuerKeys)
	}
	if len(keys) > maxIssuerKeys {
		return nil, badRequest("issuer_jwks: %d usable keys; at most %d", len(keys), maxIssuerKeys)
	}
	if len(req.UserRoles) > maxUserRoles {
		return nil, badRequest("at most %d user roles", maxUserRoles)
	}
	for i, role := range req.UserRoles {
		switch {
		case !roleRE.MatchString(role):
			return nil, badRequest("user role %d is not a lower-case identifier of at most 63 characters "+
				"(a-z, 0-9 and '_', not starting with a digit)", i+1)
		case jwtx.ForbiddenUserRole(role):
			return nil, badRequest("user role %q is reserved: anon, service_role, the database image's own roles "+
				"and every name starting with pg_, supabase_ or supapace_ belong to the platform and no user token may claim them", role)
		case slices.Contains(req.UserRoles[:i], role):
			return nil, badRequest("user role %q is listed twice", role)
		}
	}
	quota, err := diskQuota(req.DiskQuotaMB)
	if err != nil {
		return nil, err
	}
	set, err := jwtx.MarshalJWKS(keys)
	if err != nil {
		return nil, err
	}
	params, err := json.Marshal(struct {
		IssuerJWKS json.RawMessage `json:"issuer_jwks"`
	}{set})
	if err != nil {
		return nil, err
	}
	np := store.NewProject{Ref: req.Ref, Name: req.Name, UserRoles: req.UserRoles, Params: params,
		Config: store.ProjectConfig{DiskQuotaMB: quota, MemMB: clusterMemMB, GUC: map[string]string{}, Layout: stored(layout),
			UploadMBPerDay: deref(req.UploadMB), UploadObjectsPerDay: deref(req.UploadObj)}}
	// A node just recovered holds only the control plane's read credential:
	// projects created now could not reach the off-site store.
	if a.offsite() == "partial" {
		return nil, conflict("off-site store partly declared; run 'supapaced offsite set' on this node to give the projects' bucket its credentials")
	}
	// The worker's placement decides; this refuses a create it would refuse
	// before a ref is burned. Creates through this API are serialised so two
	// cannot both pass on the same room.
	// ponytail: an in-process lock; the daemon holds the node's single admin socket.
	select {
	case a.createSlot <- struct{}{}:
		defer func() { <-a.createSlot }()
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	// A chosen ref that exists is refused as such, also on a full node.
	if req.Ref != "" {
		if !refRE.MatchString(req.Ref) {
			return nil, store.ErrBadRef
		}
		if _, err := a.st.GetProject(r.Context(), req.Ref); err == nil {
			return nil, refExists(req.Ref)
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	share, err := store.ProjectShare(np.Config)
	if err != nil {
		return nil, err
	}
	if err := a.st.CheckAdmission(r.Context(), clusterMemMB, share); errors.Is(err, store.ErrNodeFull) {
		return nil, &apiError{http.StatusConflict, "node_full", strings.TrimPrefix(err.Error(), store.ErrNodeFull.Error()+": ")}
	} else if err != nil {
		return nil, err
	}
	afterAdmission()
	for range refAttempts {
		if req.Ref == "" {
			if np.Ref, err = newRef(); err != nil {
				return nil, err
			}
		}
		id, err := a.st.CreateProject(r.Context(), np)
		if errors.Is(err, store.ErrRefExists) && req.Ref == "" {
			continue // a generated ref collided: draw again
		}
		if errors.Is(err, store.ErrRefExists) {
			return nil, refExists(np.Ref)
		}
		if err != nil {
			return nil, err
		}
		return mutationJSON{np.Ref, id}, nil
	}
	return nil, errors.New("no free ref after repeated draws")
}

var projectStates = []string{"provisioning", "active", "restarting", "restoring", "deleting", "deleted", "purged", "aborted"}

// refExists is the refusal for a ref that is, or once was, a project's.
func refExists(ref string) error {
	return &apiError{http.StatusConflict, "ref_exists", "ref " + ref + " exists or existed; refs are never reused"}
}

// listProjects lists every project, or with ?state= (repeatable) those in
// the states named.
func (a *api) listProjects(r *http.Request) (any, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, badRequest("query: %v", err)
	}
	for k, v := range q {
		if k != "state" {
			return nil, badRequest("the only query parameter is state")
		}
		for _, s := range v {
			if !slices.Contains(projectStates, s) {
				return nil, badRequest("state %q: want one of %s", s, strings.Join(projectStates, ", "))
			}
		}
	}
	ps, err := a.st.ListProjects(r.Context())
	if err != nil {
		return nil, err
	}
	ca := a.caCert()
	out := struct {
		Projects []projectJSON `json:"projects"`
	}{[]projectJSON{}}
	for _, p := range ps {
		if len(q["state"]) == 0 || slices.Contains(q["state"], p.State) {
			out.Projects = append(out.Projects, toProject(p, a.domain, ca))
		}
	}
	return out, nil
}

func (a *api) showProject(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	p, err := a.st.GetProject(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	out := showJSON{projectJSON: toProject(p, a.domain, a.caCert())}
	if p.UID != nil && p.State != "purged" && p.State != "aborted" {
		// A stalled quota tool must not hang the read: null after showUsageWait.
		ctx, cancel := context.WithTimeout(r.Context(), showUsageWait)
		used, err := a.ops.DiskUsage(ctx, *p.UID)
		cancel()
		if err == nil {
			out.DiskUsedBytes = &used
		}
	}
	return out, nil
}

// keys returns the project's own credentials, unsealed with its DEK.
func (a *api) keys(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	if _, err := a.st.GetProject(ctx, ref); err != nil {
		return nil, err
	}
	nonce, wrapped, err := a.st.GetDEK(ctx, ref)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("the project's credentials are not issued yet")
	}
	if err != nil {
		return nil, err
	}
	dek, err := secrets.UnwrapDEK(a.kek, ref, nonce, wrapped)
	if err != nil {
		return nil, err
	}
	var v [3]string
	for i, name := range []string{"token.anon", "token.service_role", "pg.postgres.password"} {
		n, ct, err := a.st.GetSecret(ctx, ref, name)
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("the project's credentials are not issued yet")
		}
		if err != nil {
			return nil, err
		}
		plain, err := secrets.Open(dek, ref, name, n, ct)
		if err != nil {
			return nil, err
		}
		v[i] = string(plain)
	}
	return keysJSON{ref, v[0], v[1], v[2], endpoint(ref, a.domain, a.caCert())}, nil
}

func (a *api) check(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	if err := noBody(r); err != nil {
		return nil, err
	}
	p, err := a.st.GetProject(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	if p.State != "active" && p.State != "restarting" {
		return nil, conflict("project is %s; a check needs an active or restarting project", p.State)
	}
	code, msg, drift := a.ops.VerifyProject(r.Context(), ref)
	out := checkJSON{OK: code == "", Drift: []Drift{}}
	if !out.OK {
		if code != "peer" && code != "timeout" {
			code = "internal"
		}
		out.Code, out.Message = code, clean(msg, maxMessage, code)
	}
	for _, d := range drift {
		if !d.OK && len(out.Drift) < maxDrift {
			out.Drift = append(out.Drift, Drift{pgsock.Sanitize(d.Name, maxName), pgsock.Sanitize(d.Detail, maxDetail)})
		}
	}
	return out, nil
}

func (a *api) restart(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	var req struct {
		Set         map[string]string `json:"set"`
		DiskQuotaMB *int              `json:"disk_quota_mb"`
		UploadMB    *int              `json:"upload_mb_per_day"`
		UploadObj   *int              `json:"upload_objects_per_day"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if err := uploadSettings(req.UploadMB, req.UploadObj); err != nil {
		return nil, err
	}
	p, err := a.st.GetProject(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	next := p.Config
	next.Layout = stored(max(layoutOf(p.Config), DefaultLayout))
	if req.UploadMB != nil {
		next.UploadMBPerDay = *req.UploadMB
	}
	if req.UploadObj != nil {
		next.UploadObjectsPerDay = *req.UploadObj
	}
	next.GUC = maps.Clone(p.Config.GUC)
	if next.GUC == nil {
		next.GUC = map[string]string{}
	}
	maps.Copy(next.GUC, req.Set)
	if req.DiskQuotaMB != nil {
		if next.DiskQuotaMB, err = diskQuota(req.DiskQuotaMB); err != nil {
			return nil, err
		}
	}
	// The merged result, against the cluster container's memory.
	if _, err := pgconf.Overrides(next.GUC, next.MemMB); err != nil {
		return nil, badRequest("%s", settingError(err, next.GUC))
	}
	// A changed quota must leave room above the usage for the cluster to
	// start; the restart's own R1 checks again under the ref lock. A project
	// in a state that takes no restart is left to Submit's state conflict.
	if next.DiskQuotaMB != p.Config.DiskQuotaMB && p.UID != nil && (p.State == "active" || p.State == "restarting") {
		used, err := a.ops.DiskUsage(r.Context(), *p.UID)
		if err != nil {
			return nil, err
		}
		if err := store.CheckQuota(next.DiskQuotaMB, used); err != nil {
			return nil, &apiError{http.StatusConflict, "quota_below_usage",
				strings.TrimPrefix(err.Error(), store.ErrQuotaBelowUsage.Error()+": ")}
		}
	}
	// The worker refuses the restart when the project's generation is no
	// longer the one this merge was based on.
	params, err := json.Marshal(restartParams{BaseGeneration: p.Generation, Config: next})
	if err != nil {
		return nil, err
	}
	id, err := a.ops.Submit(r.Context(), "restart", ref, params)
	if err != nil {
		return nil, err
	}
	return mutationJSON{ref, id}, nil
}

// settingError words a refused setting for the operator. A value refused for
// its form alone carries no reason from pgconf; the form is added here.
func settingError(err error, gucs map[string]string) string {
	msg := err.Error()
	if rest, ok := strings.CutPrefix(msg, pgconf.ErrGUCNotAllowed.Error()+": "); ok {
		return "setting " + rest + " cannot be set; see 'supapace project restart --help' for those that can"
	}
	rest, ok := strings.CutPrefix(msg, pgconf.ErrGUCValue.Error()+": ")
	if !ok {
		return msg
	}
	for name, v := range gucs {
		if rest == fmt.Sprintf("%s = %q", name, v) {
			return rest + ": a value is 1 to 64 letters, digits or '.', and does not start with 0 " +
				"followed by a digit or letter (Postgres would read that as octal or hex)"
		}
	}
	return rest
}

func (a *api) delete(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	if err := noBody(r); err != nil {
		return nil, err
	}
	id, err := a.ops.Submit(r.Context(), "delete", ref, nil)
	if err != nil {
		return nil, err
	}
	return mutationJSON{ref, id}, nil
}

func (a *api) purge(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	if err := noBody(r); err != nil {
		return nil, err
	}
	if err := a.st.SetPurgeNow(r.Context(), ref); err != nil {
		return nil, err
	}
	// ponytail: SetPurgeNow does not return the id; the ref has one purge, so read it back.
	ops, err := a.st.ListOperations(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	for _, o := range ops {
		if o.Kind == "purge" {
			return mutationJSON{ref, o.ID}, nil
		}
	}
	return nil, errors.New("purge operation not found after scheduling it")
}

func (a *api) abort(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	if err := noBody(r); err != nil {
		return nil, err
	}
	id, err := a.ops.Abort(r.Context(), ref)
	if errors.Is(err, store.ErrConflict) {
		if p, gerr := a.st.GetProject(r.Context(), ref); gerr == nil && p.State != "provisioning" {
			next := map[string]string{"active": "; an active project is removed with delete",
				"restarting": "; a project left restarting by a failed restart takes a new restart or a delete",
				"restoring":  "; a project left restoring by a failed restore takes a new restore or a delete",
				"deleted":    "; a deleted project is removed for good with purge"}[p.State]
			return nil, conflict("project is %s; abort applies only to a create in progress%s", p.State, next)
		}
	}
	if err != nil {
		return nil, err
	}
	return mutationJSON{ref, id}, nil
}

// ───────── operations and node ─────────

func (a *api) listOperations(r *http.Request) (any, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, badRequest("query: %v", err)
	}
	ref := ""
	for k, v := range q {
		if k != "ref" || len(v) != 1 {
			return nil, badRequest("the only query parameter is one ref")
		}
		ref = v[0]
	}
	if ref != "" && !refRE.MatchString(ref) {
		return nil, store.ErrBadRef
	}
	ops, err := a.st.ListOperations(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	out := struct {
		Operations []operationJSON `json:"operations"`
	}{[]operationJSON{}}
	for _, o := range ops {
		out.Operations = append(out.Operations, toOperation(o))
	}
	return out, nil
}

func (a *api) showOperation(r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	o, err := a.st.GetOperation(r.Context(), id)
	if err != nil {
		return nil, err
	}
	return toOperation(o), nil
}

func (a *api) retry(r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	if err := noBody(r); err != nil {
		return nil, err
	}
	o, err := a.st.GetOperation(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if err := a.st.RetryOperation(r.Context(), id); err != nil {
		return nil, err
	}
	return mutationJSON{o.Ref, id}, nil
}

func (a *api) nodeCheck(r *http.Request) (any, error) {
	out := nodeCheckJSON{OK: true, ContainmentFailed: !a.ops.ContainmentOK(), Checks: []nodecfg.CheckResult{}}
	for _, c := range a.ops.NodeCheck(r.Context()) {
		out.Checks = append(out.Checks, nodecfg.CheckResult{Name: pgsock.Sanitize(c.Name, maxName), OK: c.OK,
			Detail: pgsock.Sanitize(c.Detail, maxDetail)})
		out.OK = out.OK && c.OK
	}
	out.OK = out.OK && !out.ContainmentFailed && len(out.Checks) > 0
	return out, nil
}
