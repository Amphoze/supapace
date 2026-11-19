package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

var errAudience = errors.New("gateway: token carries no audience the project lists")

// verifyBearer is verify, and then, for a token signed by an issuer key of a
// project with an audience list, the audience check: the token's aud, a
// string or a list, must hold one listed audience. Tokens of the anon and
// service_role keys are the platform's and are not checked.
func (p *project) verifyBearer(token string, now time.Time) error {
	k, err := p.verify(token, now)
	if err != nil || k.Class != "issuer" || len(p.aud) == 0 {
		return err
	}
	if !slices.ContainsFunc(audiences(token), func(a string) bool { return slices.Contains(p.aud, a) }) {
		return errAudience
	}
	return nil
}

// audiences returns the string values of the aud member of a token verify
// has accepted, so its payload is one strict JSON object without duplicate
// names. The name is matched exactly; values of other types count as none.
func audiences(token string) []string {
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return nil
	}
	switch a := c["aud"].(type) {
	case string:
		return []string{a}
	case []any:
		var out []string
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
