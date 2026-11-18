package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
)

// authenticate checks the request's credentials against p's keys and returns
// the bearer to forward, or the code of a 401 and its message.
//
// The apikey comes from one header or one query parameter (or both, equal)
// and must be a valid anon or service_role token of this project. A single
// "Authorization: Bearer" header, when present, is verified on its own and is
// what is forwarded; otherwise the apikey is.
func authenticate(h http.Header, queryKeys []string, p *project, now time.Time) (bearer, code, msg string) {
	hk := headerValues(h, "apikey")
	if len(hk) > 1 || len(queryKeys) > 1 {
		return "", "invalid_apikey", "more than one apikey"
	}
	var key string
	switch {
	case len(hk) == 0 && len(queryKeys) == 0:
		return "", "no_apikey", ""
	case len(hk) == 1 && len(queryKeys) == 1 && hk[0] != queryKeys[0]:
		return "", "invalid_apikey", "apikey header and query parameter differ"
	case len(hk) == 1:
		key = hk[0]
	default:
		key = queryKeys[0]
	}
	k, err := p.verify(key, now)
	if err != nil {
		return "", "invalid_apikey", tokenMessage(err)
	}
	if k.Class != "anon" && k.Class != "service_role" {
		return "", "invalid_apikey", "apikey is not an anon or service_role key"
	}
	az := headerValues(h, "Authorization")
	switch len(az) {
	case 0:
		return key, "", ""
	case 1:
		tok, ok := cutBearer(az[0])
		if !ok {
			return "", "invalid_token", "Authorization is not \"Bearer <token>\""
		}
		if _, err := p.verify(tok, now); err != nil {
			return "", "invalid_token", tokenMessage(err)
		}
		return tok, "", ""
	}
	return "", "invalid_token", "more than one Authorization header"
}

// tokenMessages names why a token was refused. The messages are constants:
// nothing of the token, the keys or the project is echoed.
var tokenMessages = map[error]string{
	jwtx.ErrMalformed:       "token is malformed",
	jwtx.ErrDuplicateMember: "token has a duplicate member name",
	jwtx.ErrAlg:             "token algorithm is not RS256",
	jwtx.ErrNoKID:           "token has no kid",
	jwtx.ErrUnknownKID:      "token kid is not a key of this project",
	jwtx.ErrSignature:       "token signature is invalid",
	jwtx.ErrExpired:         "token is expired or has no exp",
	jwtx.ErrNotYetValid:     "token is not yet valid",
	jwtx.ErrNoRole:          "token has no role",
	jwtx.ErrRole:            "token role is not allowed for its key",
}

func tokenMessage(err error) string {
	if m, ok := tokenMessages[err]; ok {
		return m
	}
	return "token is invalid"
}

// verify is the only way a token is accepted: signature and dates by
// jwtx.Verify, then the role bound to the signing key's class by
// jwtx.CheckRole.
func (p *project) verify(token string, now time.Time) (jwtx.Key, error) {
	k, c, err := jwtx.Verify(token, p.keys, now)
	if err != nil {
		return jwtx.Key{}, err
	}
	return k, jwtx.CheckRole(k, c, p.userRoles)
}

func cutBearer(s string) (string, bool) {
	if len(s) <= len("Bearer ") || !strings.EqualFold(s[:len("Bearer ")], "Bearer ") {
		return "", false
	}
	return s[len("Bearer "):], true
}

// headerValues collects the values of every header whose name equals name
// in any case, so a non-canonical key cannot hide a second value.
func headerValues(h http.Header, name string) []string {
	var v []string
	for k, vs := range h {
		if strings.EqualFold(k, name) {
			v = append(v, vs...)
		}
	}
	return v
}

// splitQuery takes every apikey parameter out of a raw query and returns
// their values and the remaining query, byte for byte. A parameter counts as
// apikey when its unescaped name is "apikey". A query using ';' as separator
// is refused: some servers split on it and some do not.
func splitQuery(raw string) (rest string, keys []string, ok bool) {
	if raw == "" {
		return "", nil, true
	}
	if strings.Contains(raw, ";") {
		return "", nil, false
	}
	var kept []string
	for _, part := range strings.Split(raw, "&") {
		name, val, _ := strings.Cut(part, "=")
		if n, err := url.QueryUnescape(name); err == nil && n == "apikey" {
			v, err := url.QueryUnescape(val)
			if err != nil {
				v = val // not a token: fails verification
			}
			keys = append(keys, v)
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "&"), keys, true
}
