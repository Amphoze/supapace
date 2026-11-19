package gateway

import (
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
)

// dashSetNames are the headers the gateway sets on every dashboard answer
// (dashHeaders) and Cache-Control: a trailer of one of these names is
// dropped, so Studio can neither add a second value nor, by announcing it as
// a trailer, have the server leave the gateway's value out of the header.
var dashSetNames = func() []string {
	h := http.Header{"Cache-Control": nil}
	dashHeaders(h)
	return slices.Sorted(maps.Keys(h))
}()

// filterDash removes from what Studio sent what must not reach a browser on
// a studio host: the project API's list (Server, Set-Cookie2,
// Clear-Site-Data, every Set-Cookie with a Domain attribute), every
// Access-Control- header, and every Set-Cookie of a name the gateway's own
// cookies use (__Host-sp-, in any letter case).
func filterDash(h http.Header) {
	filterResponse(h)
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			delete(h, k)
		}
	}
	if vs, ok := h["Set-Cookie"]; ok {
		h["Set-Cookie"] = slices.DeleteFunc(vs, platformCookie)
	}
}

// platformCookie reports whether a Set-Cookie value sets a cookie whose name
// begins __Host-sp-, in any letter case.
func platformCookie(v string) bool {
	name, _, _ := strings.Cut(v, "=")
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "__host-sp-")
}

// filterDashResponse prepares Studio's final header: the filter, no-store on
// an API path or a status that is neither 2xx nor 304, then the gateway's
// headers, replacing whatever Studio sent.
func filterDashResponse(h http.Header, status int, api bool) {
	filterDash(h)
	if api || (status < 200 || status > 299) && status != http.StatusNotModified {
		h.Set("Cache-Control", "no-store")
	}
	dashHeaders(h)
}

// filterDashTrailer applies the filter to trailers and drops every name the
// gateway sets.
func filterDashTrailer(h http.Header) {
	filterDash(h)
	for _, k := range dashSetNames {
		delete(h, k)
	}
}

// dashTrailers filters Studio's trailers, which the transport has filled in
// by the time the body reports io.EOF.
type dashTrailers struct {
	io.ReadCloser
	resp *http.Response
}

func (t *dashTrailers) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if err == io.EOF {
		filterDashTrailer(t.resp.Trailer)
	}
	return n, err
}
