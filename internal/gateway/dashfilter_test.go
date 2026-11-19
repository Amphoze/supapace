package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"testing"
)

// setHeadersWrong reports what is wrong with the headers the gateway sets on
// a dashboard answer: each exactly once with its value, never the sandbox.
func setHeadersWrong(h http.Header) string {
	for k, v := range dashWant {
		if vs := h.Values(k); len(vs) != 1 || vs[0] != v {
			return k + ": " + strings.Join(vs, " | ")
		}
	}
	return ""
}

// TestDashFilter_DropsAndReplaces: on the final header, on a 1xx relayed over
// HTTP/1.1 and on trailers, Studio's Server, Clear-Site-Data, Set-Cookie2,
// Access-Control- headers and cookies with a Domain or a platform name never
// reach the client, and each header the gateway sets is there exactly once
// with its value (none in the trailers) — also when Studio sends its own
// values, twice, or announces one as a trailer. Other headers, cookies and
// trailers pass.
func TestDashFilter_DropsAndReplaces(t *testing.T) {
	e := newFwdEnv(t)
	hostile := "Server: up/1\r\nClear-Site-Data: \"*\"\r\nSet-Cookie2: z=1\r\nAccess-Control-Allow-Origin: *\r\n" +
		"access-control-allow-credentials: true\r\nACCESS-CONTROL-EXPOSE-HEADERS: x\r\n" +
		"Set-Cookie: d=1; Path=/; Domain=" + studioDom + "\r\nSet-Cookie: __Host-sp-session=forged; Path=/; Secure\r\n" +
		"Set-Cookie: __HOST-SP-login-AAAAAAAAAAA=1\r\nSet-Cookie:  __host-sp-x=1\r\nSet-Cookie: ok=1; Path=/\r\n" +
		"X-Content-Type-Options: sniff\r\nX-Content-Type-Options: other\r\nContent-Security-Policy: default-src *\r\n" +
		"Strict-Transport-Security: max-age=1; includeSubDomains\r\nReferrer-Policy: unsafe-url\r\n" +
		"Cross-Origin-Opener-Policy: unsafe-none\r\nCross-Origin-Resource-Policy: cross-origin\r\nX-Kept: 1\r\n"
	rawStudio(t, func(c net.Conn, _ *http.Request) {
		io.WriteString(c, "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n"+hostile+"\r\n"+
			"HTTP/1.1 200 OK\r\n"+hostile+"Trailer: Content-Security-Policy, X-Content-Type-Options, X-U, Server, Cache-Control\r\n"+
			"Transfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"+
			"Content-Security-Policy: x\r\nX-Content-Type-Options: y\r\nX-U: 1\r\nServer: up/1\r\nCache-Control: max-age=9\r\n"+
			"Strict-Transport-Security: max-age=0\r\nAccess-Control-Allow-Origin: *\r\nSet-Cookie: t=1; Domain="+studioDom+"\r\n"+
			"X-Undeclared: 1\r\n\r\n")
	})
	addr := serveDashTLS(t, e)
	clean := func(what string, h http.Header) {
		t.Helper()
		for k := range h {
			if l := strings.ToLower(k); l == "server" || l == "clear-site-data" || l == "set-cookie2" || strings.HasPrefix(l, "access-control-") {
				t.Errorf("%s: %s reached the client", what, k)
			}
		}
		if got := strings.Join(h.Values("Set-Cookie"), "|"); got != "ok=1; Path=/" {
			t.Errorf("%s: Set-Cookie %q", what, got)
		}
		if s := setHeadersWrong(h); s != "" || h.Get("X-Kept") != "1" {
			t.Errorf("%s: %s, X-Kept %q", what, s, h.Get("X-Kept"))
		}
	}
	for _, h2 := range []bool{false, true} {
		var hints []http.Header
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
				hints = append(hints, http.Header(h).Clone())
				return nil
			}})
		res, err := dashClient(t, addr, h2).Do(e.wireReq(t, ctx, "GET", "/x", nil))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || string(b) != "ok" || res.StatusCode != 200 {
			t.Fatalf("h2=%v: %d %q %v", h2, res.StatusCode, b, err)
		}
		what := fmt.Sprintf("h2=%v", h2)
		clean(what+" final", res.Header)
		if !h2 {
			if len(hints) != 1 {
				t.Fatalf("%d 1xx relayed over HTTP/1.1", len(hints))
			}
			clean(what+" 103", hints[0])
		}
		if res.Header.Get("Cache-Control") != "" {
			t.Errorf("%s: Cache-Control %q on a public page", what, res.Header.Values("Cache-Control"))
		}
		for k := range res.Trailer {
			if k != "X-U" && k != "X-Undeclared" {
				t.Errorf("%s: trailer %s: %q", what, k, res.Trailer.Values(k))
			}
		}
		if res.Trailer.Get("X-U") != "1" {
			t.Errorf("%s: trailers %v", what, res.Trailer)
		}
	}
}

// TestDashFilter_NoStore: no-store replaces Studio's Cache-Control on an API
// path in any spelling and on a status that is neither 2xx nor 304; a public
// file keeps its own, and so does a 304 outside the API.
func TestDashFilter_NoStore(t *testing.T) {
	e := newFwdEnv(t)
	recordStudio(t, func(w http.ResponseWriter, r *http.Request) {
		cc, status := "public, max-age=31536000, immutable", 200
		switch strings.ToLower(r.URL.Path) {
		case "/missing", "/api/missing":
			status = 404
		case "/err":
			status = 500
		case "/nm", "/api/nm":
			status = 304
		case "/moved":
			status = 302
		}
		w.Header().Add("Cache-Control", cc)
		w.Header().Add("Cache-Control", "max-age=60")
		w.WriteHeader(status)
	})
	for target, want := range map[string]string{
		"/api/x": "no-store", "/API/x": "no-store", "/api": "no-store", "/Api/nm": "no-store", "/api/missing": "no-store",
		"/missing": "no-store", "/err": "no-store", "/moved": "no-store",
		"/x.js": "public, max-age=31536000, immutable|max-age=60", "/nm": "public, max-age=31536000, immutable|max-age=60",
	} {
		w := e.do(e.owner(t, "GET", target))
		if got := strings.Join(w.Header().Values("Cache-Control"), "|"); got != want {
			t.Errorf("%s (%d): Cache-Control %q, want %q", target, w.Code, got, want)
		}
		if s := setHeadersWrong(w.Header()); s != "" {
			t.Errorf("%s: %s", target, s)
		}
	}
}
