package gateway

import (
	"net/http"
	"regexp"
	"strings"
)

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// resolve maps a Host value to its project: an optional numeric port is
// dropped, and what remains must be exactly "<ref>.<domain>" in lower case
// with ref a project of the table. name is the host without its port.
func (tb *table) resolve(host string) (name, ref string, p *project) {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		port := host[i+1:]
		if port == "" || strings.Trim(port, "0123456789") != "" {
			return "", "", nil
		}
		host = host[:i]
	}
	ref, ok := strings.CutSuffix(host, "."+tb.domain)
	if !ok || !refRE.MatchString(ref) {
		return "", "", nil
	}
	if p = tb.projects[ref]; p == nil {
		return "", "", nil
	}
	return host, ref, p
}

// sniAgrees reports whether the TLS server name, when the client sent one,
// names the host the request resolved to.
func sniAgrees(r *http.Request, name string) bool {
	return r.TLS == nil || r.TLS.ServerName == "" || strings.EqualFold(r.TLS.ServerName, name)
}
