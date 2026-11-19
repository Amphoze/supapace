package gateway

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Amphoze/supapace/internal/dashtok"
)

// Log out is a chain of top-level navigations. The host it starts on holds
// the session, so it knows the principal: it clears its own cookies and
// redirects to the first of the principal's other project hosts with a
// signed ticket naming the hosts still to visit. Each hop needs no cookie —
// between sites a browser sends none — only the ticket: it clears its own
// session cookie and passes a ticket for the rest on, under the first
// ticket's times. The last hop redirects to the sign-in host's signed-out
// page, which clears that host's cookie. The sign-in host is never a hop.

const (
	maxHops       = 16 // project hosts one chain visits
	ticketSeconds = 60
)

// logout: GET /-/auth/logout, with the ticket t on a hop.
func (s *signIn) logout(query string) {
	q, err := url.ParseQuery(query)
	ts, hop := q["t"]
	// A query that does not parse may have meant a ticket; a ticket is one
	// parameter, and the sign-in host takes none.
	if err != nil || hop && (len(ts) != 1 || s.ref == "_") {
		s.refusal(http.StatusBadRequest, textBadTicket, "")
		return
	}
	signedOut := s.origin("_") + "/-/auth/signed-out"
	var t dashtok.Ticket
	if hop {
		// This host must be the ticket's next ref, and every ref it names a
		// ref of the table: the redirect below names no other host.
		t, err = dashtok.VerifyTicket(s.d.pub, ts[0], s.now)
		if err != nil || t.Refs[0] != s.ref || !s.allHosted(t.Refs) {
			s.refusal(http.StatusBadRequest, textBadTicket, "")
			return
		}
		s.clearSession() // without needing one in the request
		t.Refs = t.Refs[1:]
	} else if sess, ok := s.d.session(s.r, s.dt, s.ref, s.now); ok {
		s.clearSession()
		now := s.now.Unix()
		t = dashtok.Ticket{Iss: sess.Iss, Sub: sess.Sub, Refs: s.projects(principal{sess.Iss, sess.Sub}, s.ref),
			Iat: now, Exp: now + ticketSeconds}
		if len(t.Refs) > maxHops {
			t.Refs, t.More = t.Refs[:maxHops], true
		}
	} else {
		// No session of this host was shown, so none is ended and no chain is
		// built: never an error, and no cookie cleared that was not shown.
		if len(s.r.CookiesNamed(sessionCookie)) > 0 {
			s.clearSession()
		}
		s.clearShownLogins()
		s.redirect(signedOut + "?ended=0")
		return
	}
	s.clearShownLogins()
	if len(t.Refs) == 0 {
		if t.More {
			signedOut += "?more=1"
		}
		s.redirect(signedOut)
		return
	}
	tok, err := dashtok.SignTicket(s.d.priv, t)
	if err != nil {
		s.refuse(http.StatusServiceUnavailable, "unavailable")
		return
	}
	s.redirect(s.origin(t.Refs[0]) + "/-/auth/logout?t=" + tok)
}

func (s *signIn) allHosted(refs []string) bool {
	for _, ref := range refs {
		if _, ok := s.dt.file.Projects[ref]; !ok {
			return false
		}
	}
	return true
}

// signedOut is the sign-in host's page a chain ends on. It clears that
// host's session cookie and the login cookies it is shown on every visit,
// whoever asks and whatever the query. Two parameters, each written exactly
// so and once — more=1 and ended=0 — select a fixed sentence each; nothing
// of the query is rendered.
func (s *signIn) signedOut(query string) {
	s.clearSession()
	s.clearShownLogins()
	count, written := map[string]int{}, map[string]bool{}
	for _, kv := range strings.Split(query, "&") {
		k, _, _ := strings.Cut(kv, "=")
		count[k]++
		written[kv] = true
	}
	data := struct {
		Ended, More bool
		EndSession  string
	}{Ended: count["ended"] == 1 && written["ended=0"], More: count["more"] == 1 && written["more=1"]}
	if u := s.is.EndSessionURL; strings.HasPrefix(u, "https://") {
		data.EndSession = u
	}
	s.page(http.StatusOK, "signedout", data, "'none'", "'none'")
}
