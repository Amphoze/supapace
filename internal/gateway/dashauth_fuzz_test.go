package gateway

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// checkReturn fails unless r is a return path a sign-in may end on: a path of
// the origin itself, which a browser requests as written, and which the
// gateway then reads neither as one of its own endpoints nor as an API path.
func checkReturn(t *testing.T, in, r string) {
	t.Helper()
	if r != "/" && r != in {
		t.Fatalf("returnPath(%q) = %q: neither the path nor \"/\"", in, r)
	}
	if len(r) > maxReturn || !strings.HasPrefix(r, "/") || strings.Contains(r, "//") || strings.Contains(r, `\`) {
		t.Fatalf("returnPath(%q) = %q: not a path of this origin", in, r)
	}
	for i := 0; i < len(r); i++ {
		if r[i] <= 0x20 || r[i] == 0x7f {
			t.Fatalf("returnPath(%q) = %q: a byte a browser drops or cuts at", in, r)
		}
	}
	if again := returnPath(r); again != r {
		t.Fatalf("returnPath(%q) = %q, and of that %q", in, r, again)
	}
	path := r
	if i := strings.IndexAny(r, "?#"); i >= 0 {
		path = r[:i]
	}
	// As the request for it arrives: rule 0 passes it, and it is neither
	// under /-/ nor an API path.
	segs, ok := readPath(path)
	if !ok {
		t.Fatalf("returnPath(%q) = %q: its path does not pass the path rule", in, r)
	}
	if apiPath(lower(segs)) || len(segs) > 0 && lower(segs)[0] == "-" || path == "/-" || strings.HasPrefix(path, "/-/") {
		t.Fatalf("returnPath(%q) = %q: one of the gateway's endpoints or an API path", in, r)
	}
	// Resolved the way a link is, it stays on the origin and no segment of
	// its path is resolved away.
	base := &url.URL{Scheme: "https", Host: "origin.test", Path: "/-/auth/session"}
	if u, err := base.Parse(r); err == nil {
		if decoded, _ := url.PathUnescape(path); u.Scheme != "https" || u.Host != "origin.test" || u.User != nil || u.Path != decoded {
			t.Fatalf("returnPath(%q) = %q resolves to %q", in, r, u)
		}
	}
}

func FuzzReturnPath(f *testing.F) {
	for _, s := range []string{"/", "/project/x?a=b#c", "//evil.test/", `/\evil.test`, "/-/auth/logout", "/api/x", "/API", "/%61pi/x",
		"/%2D/auth/logout", "/a/../-/auth/logout", "/a/%2e%2e/api", "/api%20/x", "/-%20/auth/login", "/x?u=//evil.test", "/x#//evil.test",
		"/\t/evil.test", "/x y", "/x\x7f", "https://evil.test/", "/%zz", "/a%2fb", "/a%5cb", "/K", "/x?\xff", "", "/?", "/#", "/-", "/-?x",
		"/.", "/..", "/x/", "/x//y", "/;/evil", "/@evil.test", "/:evil", strings.Repeat("/a", 512), strings.Repeat("/a", 513)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) { checkReturn(t, in, returnPath(in)) })
}

var stateAlphabetRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// FuzzParseState: whatever is read as a state has the one form, names a
// target of a ref's shape or the sign-in host, carries a validated return
// path, and is the only spelling of what it says.
func FuzzParseState(f *testing.F) {
	enc := base64.RawURLEncoding.EncodeToString
	for _, s := range []string{"v1.abcdefghij0123456789.AAECAwQFBgc.0.Lw", "v1._.AAECAwQFBgc.1.Lw", "v1._.AAECAwQFBgc.0.", "v1._.AAECAwQFBgc.2.Lw",
		"v2._.AAECAwQFBgc.0.Lw", "v1._.AAECAwQFBgc.0.Lw.x", "v1._.AAECAwQFBgc.0.Lw\n", "v1._.AAECAwQFBgc.0.Lx", "v1._.AAECAwQFBgc.0.Lw==",
		"v1.ABCDEFGHIJ0123456789.AAECAwQFBgc.0.Lw", "v1.studio.test.AAECAwQFBgc.0.Lw", "", "v1....",
		"v1._.AAECAwQFBgc.0." + enc([]byte("//evil.test/")), "v1._.AAECAwQFBgc.0." + enc([]byte("/-/auth/logout")),
		"v1._.AAECAwQFBgc.0." + enc([]byte(strings.Repeat("/a", 512))), "v1._.AAECAwQFBgc.0." + enc([]byte(strings.Repeat("/a", 600)))} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		at, ok := parseState(s)
		if !ok {
			if at != (attempt{}) {
				t.Fatalf("parseState(%q) refused it and returned %+v", s, at)
			}
			return
		}
		p := strings.Split(s, ".")
		if len(s) > maxState || !stateAlphabetRE.MatchString(s) || len(p) != 5 || p[0] != "v1" {
			t.Fatalf("parseState(%q) took it", s)
		}
		if at.target != p[1] || at.target != "_" && !refRE.MatchString(at.target) || at.a != p[2] || len(at.a) != 11 ||
			p[3] != "0" && p[3] != "1" || at.retry != (p[3] == "1") {
			t.Fatalf("parseState(%q) = %+v", s, at)
		}
		raw, err := base64.RawURLEncoding.DecodeString(p[4])
		if err != nil || len(raw) == 0 || enc(raw) != p[4] {
			t.Fatalf("parseState(%q): the path's encoding is not the one spelling of %q", s, raw)
		}
		checkReturn(t, string(raw), at.ret)
	})
}
