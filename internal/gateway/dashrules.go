package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashtok"
)

// sessionCookie is the dashboard's session cookie, host-only.
const sessionCookie = "__Host-sp-session"

// rules applies rules 2 to 10 to a request on a dashboard host, in order,
// and fills in dr's session, role and purpose. The first rule that fails
// answers; rules returns false then. raw is the path as sent.
func (d *Dashboard) rules(w http.ResponseWriter, r *http.Request, dt *dashTable, dr *dashRequest, raw string) bool {
	refuse := func(rule, status int, code string) bool {
		if rule <= 4 {
			d.count(dr.Ref, rule)
		}
		writeDash(w, status, code)
		return false
	}
	lp := dr.Lower
	// 2. Any segment shaped like a ref must be this host's.
	for _, s := range lp {
		if refRE.MatchString(s) && s != dr.Ref {
			return refuse(2, http.StatusNotFound, "not_found")
		}
	}
	// 3. The opt-in routes are not served.
	if apiPath(lp) && len(lp) >= 2 && (lp[1] == "mcp" || lp[1] == "ai") {
		return refuse(3, http.StatusNotFound, "not_found")
	}
	// 4. No service worker can be registered.
	for _, v := range r.Header.Values("Service-Worker") {
		if strings.EqualFold(strings.TrimSpace(v), "script") {
			return refuse(4, http.StatusNotFound, "not_found")
		}
	}
	// 5. A session of this ref, of the table's issuer, not revoked.
	s, ok := d.session(r, dt, dr.Ref, time.Now())
	if !ok {
		if r.Header.Get("Sec-Fetch-Mode") == "navigate" ||
			r.Method == http.MethodGet && strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
			h := w.Header()
			h.Set("Location", "/-/auth/login?return="+url.QueryEscape(r.RequestURI))
			h.Set("Cache-Control", "no-store")
			dashHeaders(h)
			w.WriteHeader(http.StatusFound)
			return false
		}
		return refuse(5, http.StatusUnauthorized, "login_required")
	}
	dr.Session = s
	// 6. The role, read from the table on every request.
	role := dt.roles[dr.Ref][principal{s.Iss, s.Sub}]
	if role == "" {
		return refuse(6, http.StatusForbidden, "not_a_member")
	}
	dr.Role = role
	// 7. Same origin, but for a top-level navigation to a page.
	api := apiPath(lp)
	for _, v := range r.Header.Values("Sec-Fetch-Site") {
		if v != "same-origin" && v != "none" && !(r.Method == http.MethodGet && !api &&
			r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document") {
			return refuse(7, http.StatusForbidden, "cross_origin")
		}
	}
	// 8. read_only writes nothing but its two statement paths, spelled exactly.
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		if role == dashcfg.RoleReadOnly && !(r.Method == http.MethodPost &&
			(raw == "/api/platform/pg-meta/"+dr.Ref+"/query" || raw == "/api/parse-query")) {
			return refuse(8, http.StatusForbidden, "read_only")
		}
	}
	// 9. The reveal purpose: an owner's GET of the project's keys, spelled exactly.
	_, query, _ := strings.Cut(r.RequestURI, "?")
	if keys, ok := strings.CutPrefix(raw, "/api/v1/projects/"+dr.Ref+"/api-keys"); ok && role == dashcfg.RoleOwner &&
		r.Method == http.MethodGet && query == "reveal=true" && (keys == "" || keys[0] == '/' && !strings.Contains(keys[1:], "/")) {
		dr.Purpose = "reveal"
	}
	// 10. No upgrade; the body within its cap.
	if len(headerValues(r.Header, "Upgrade")) > 0 {
		return refuse(10, http.StatusBadRequest, "upgrade_not_supported")
	}
	limit := int64(dashcfg.Limits.BodyBytes)
	if r.Method == http.MethodPost && apiPath(lp) && len(lp) == 2 && lp[1] == "parse-query" {
		limit = int64(dashcfg.Limits.ParseBodyBytes)
	}
	if r.ContentLength > limit {
		return refuse(10, http.StatusRequestEntityTooLarge, "body_too_large")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	return true
}

// session returns the request's session when it carries exactly one session
// cookie, signed by this gateway, for ref and the table's issuer, within the
// table's lifetime and issued no earlier than the principal's revocation.
func (d *Dashboard) session(r *http.Request, dt *dashTable, ref string, now time.Time) (dashtok.Session, bool) {
	cs := r.CookiesNamed(sessionCookie)
	is := dt.file.Issuer
	if len(cs) != 1 || is == nil {
		return dashtok.Session{}, false
	}
	s, err := dashtok.VerifySession(d.pub, cs[0].Value, is.SessionSeconds, now)
	if err != nil || s.Ref != ref || s.Iss != is.Iss || s.Iat < dt.notBefore[principal{s.Iss, s.Sub}] {
		return dashtok.Session{}, false
	}
	return s, true
}

// apiPath reports whether lp, the lower-cased segments, is an API path: /api
// itself or anything under /api/.
func apiPath(lp []string) bool { return len(lp) >= 1 && lp[0] == "api" }
