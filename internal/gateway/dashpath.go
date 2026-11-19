package gateway

import (
	"net/url"
	"slices"
	"strings"
)

// readPath applies rule 0 to a request target as sent (path and query) and
// returns the path's segments, each percent-decoded once ("/" has none). A
// raw "#" anywhere in the target is refused: a URL parser ends the path or the
// query there, so the rules would read what the server never sees ("%23"
// stays an ordinary character, in the path and in the query). The path is read two
// ways — split at "/" and each segment decoded, and decoded whole and then
// split — and refused (ok false) when, in either reading, it does not begin
// with "/", has an empty segment (a doubled slash, a trailing one on anything
// but "/"), a "." or ".." segment, a backslash, a byte below 0x20 or above
// 0x7e, or a "%" without two hexadecimal digits, or when the readings differ
// (an encoded slash). What passes has one reading
// that a URL parser resolves no further, and is ASCII, so lower-casing it
// means the same everywhere.
func readPath(target string) (segs []string, ok bool) {
	if strings.IndexByte(target, '#') >= 0 {
		return nil, false
	}
	raw, _, _ := strings.Cut(target, "?")
	if raw == "/" {
		return []string{}, true
	}
	if !strings.HasPrefix(raw, "/") {
		return nil, false
	}
	whole, err := url.PathUnescape(raw)
	if err != nil {
		return nil, false
	}
	parts := strings.Split(raw[1:], "/")
	segs = make([]string, len(parts))
	for i, p := range parts {
		if segs[i], err = url.PathUnescape(p); err != nil {
			return nil, false
		}
	}
	if !slices.Equal(segs, strings.Split(whole[1:], "/")) {
		return nil, false // an encoded slash: the readings differ
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return nil, false
		}
		for j := 0; j < len(s); j++ {
			if c := s[j]; c < 0x20 || c > 0x7e || c == '\\' {
				return nil, false
			}
		}
	}
	return segs, true
}

// lower is segs with each segment ASCII lower-cased; segs is ASCII (rule 0).
func lower(segs []string) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = strings.ToLower(s)
	}
	return out
}
