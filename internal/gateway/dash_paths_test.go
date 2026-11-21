package gateway

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
)

// pathVector is one line of studio/prove/paths.json: a raw request path and
// what the dashboard's own server made of it — the URL its parser left, the
// segments its router matched on, and the route the built route tree gave.
// The file is generated from the built server by studio/prove/paths.mjs and a
// build fails when it differs from the committed one.
type pathVector struct {
	Raw      string    `json:"raw"`
	Href     *string   `json:"href"`     // nil: the server refused the request unread
	Segments *[]string `json:"segments"` // nil: no router was asked
	Route    *string   `json:"route"`    // nil: no route matched
}

// TestDashPaths_ServerVectors sends every vector through the gateway's rules
// as the owner of project A and holds the gateway's reading of the path to
// the server's. A path the server routes anywhere while the gateway read
// another path fails one of the assertions:
//
//	(i)   the server refused the request, or resolved or rewrote its path (the
//	      path of href differs from raw in more than letter case): the gateway
//	      answered 400;
//	(ii)  a segment the router matched on is, lower-cased, another project's
//	      ref: the gateway refused;
//	(iii) the route is one that is not served (/api/mcp, under /api/ai): the
//	      gateway refused;
//	(iv)  the route is /api or under it: the gateway took the request for an
//	      API request — as a cross-site navigation it is refused;
//	(v)   raw holds a "#": the gateway answered 400;
//	(vi)  the gateway forwarded the request: the segments it read are the
//	      segments the router matched on (the router leaves a percent sign
//	      and the characters that delimit a URL encoded; decoded, they are
//	      the gateway's);
//	(vii) the path ends in an encoded space: the gateway answered 400. The
//	      server parses the decoded path as a URL once more, and a URL
//	      parser drops a space that ends it, so the server routes the path
//	      without it, behind a dot segment too.
func TestDashPaths_ServerVectors(t *testing.T) {
	b, err := os.ReadFile("../../studio/prove/paths.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []pathVector
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	e := newDashEnv(t, active(), true)

	pathOf := func(s string) string { return s[:len(s)-len(s[strings.IndexAny(s+"?", "?#"):])] }
	optIn := func(route string) bool {
		s := strings.Split(strings.Trim(strings.ToLower(route), "/"), "/")
		return len(s) >= 2 && s[0] == "api" && (s[1] == "ai" || s[1] == "mcp")
	}
	api := func(route string) bool {
		s := strings.Split(strings.Trim(strings.ToLower(route), "/"), "/")
		return s[0] == "api"
	}
	// send answers the status and what reached the forward seam; a request the
	// gateway answers itself (its sign-in paths) counts as refused to Studio.
	send := func(raw string, header map[string]string) (int, *dashRequest) {
		r := e.as(t, rawReq("GET", dhostA, raw), refA, subOwnerA)
		for k, v := range header {
			r.Header.Set(k, v)
		}
		e.resetSeams()
		w := e.do(r)
		if f, a := e.seams(); f == 1 {
			return w.Code, e.lastFwd(t)
		} else if a == 1 {
			return http.StatusNotFound, nil
		}
		return w.Code, nil
	}
	crossSite := map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}

	var n [8]int // vectors each assertion applied to; n[0]: forwarded
	for _, v := range vectors {
		status, fwd := send(v.Raw, nil)
		refused := fwd == nil && (status == 400 || status == 404)
		if fwd == nil && !refused {
			t.Errorf("%q: neither forwarded nor refused: %d", v.Raw, status)
		}
		rawPath, _, _ := strings.Cut(v.Raw, "?")
		if v.Href == nil || !strings.EqualFold(pathOf(*v.Href), rawPath) {
			n[1]++
			if status != 400 || fwd != nil {
				t.Errorf("(i) %q: the server made %v of it; the gateway answered %d", v.Raw, deref(v.Href), status)
			}
		}
		if v.Segments != nil && slices.ContainsFunc(*v.Segments, func(s string) bool {
			s = strings.ToLower(s)
			return refRE.MatchString(s) && s != refA
		}) {
			n[2]++
			if !refused {
				t.Errorf("(ii) %q: the router matched on %q, with another project's ref; the gateway answered %d", v.Raw, *v.Segments, status)
			}
		}
		if v.Route != nil && optIn(*v.Route) {
			n[3]++
			if !refused {
				t.Errorf("(iii) %q: routed to %s, which is not served; the gateway answered %d", v.Raw, *v.Route, status)
			}
		}
		if v.Route != nil && api(*v.Route) {
			n[4]++
			if s, f := send(v.Raw, crossSite); f != nil || fwd != nil && s != http.StatusForbidden {
				t.Errorf("(iv) %q: routed to %s; as a cross-site navigation the gateway answered %d", v.Raw, *v.Route, s)
			}
		}
		if strings.Contains(v.Raw, "#") {
			n[5]++
			if status != 400 || fwd != nil {
				t.Errorf("(v) %q: a fragment; the gateway answered %d", v.Raw, status)
			}
		}
		if strings.HasSuffix(rawPath, "%20") {
			n[7]++
			if status != 400 || fwd != nil {
				t.Errorf("(vii) %q: the path ends in an encoded space; the gateway answered %d", v.Raw, status)
			}
		}
		if fwd != nil {
			n[0]++
			n[6]++
			if v.Segments == nil || !slices.EqualFunc(fwd.Path, *v.Segments, func(gw, router string) bool {
				s, err := url.PathUnescape(router)
				return err == nil && s == gw
			}) {
				t.Errorf("(vi) %q: forwarded as %q; the router matched on %v", v.Raw, fwd.Path, v.Segments)
			}
		}
	}
	// Every assertion, and the control — a path that is forwarded — must
	// have had vectors: an emptied or reshaped file proves nothing.
	for i, min := range [8]int{200, 500, 500, 100, 200, 500, 200, 1000} {
		if n[i] < min {
			t.Errorf("assertion %d applied to %d vectors of %d, want at least %d", i, n[i], len(vectors), min)
		}
	}
	// A page of the project and one of its API routes are forwarded as sent;
	// as a cross-site navigation the page still is, the API route is not.
	for raw, wantCross := range map[string]int{"/project/" + refA: 200, "/api/platform/profile": 403} {
		if !slices.ContainsFunc(vectors, func(v pathVector) bool { return v.Raw == raw && v.Route != nil }) {
			t.Errorf("no vector for %s with a route", raw)
		}
		if s, f := send(raw, nil); f == nil {
			t.Errorf("control %s: not forwarded (%d)", raw, s)
		}
		if s, _ := send(raw, crossSite); s != wantCross {
			t.Errorf("control %s as a cross-site navigation: %d, want %d", raw, s, wantCross)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "a refusal"
	}
	return *s
}
