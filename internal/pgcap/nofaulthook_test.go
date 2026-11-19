//go:build !faulthook

package pgcap

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

// The product build has no fault hook: the type that a build with the tag
// faulthook panics on is a message type like any other the relay does not know
// — relayed after authentication-ok, a breach (not a fault) before it.
func TestFaultHook_AbsentFromTheProductBuild(t *testing.T) {
	marker := ms4('!', "x")
	run, ch := script(t, login, marker)
	p := relayTo(t, metaClass(), run)
	if got := p.read(t, len(login)+len(marker)); !bytes.Equal(got, cat(login, marker)) {
		t.Fatalf("got %q", got[len(login):])
	}
	p.open(t, <-ch)
	q := relayTo(t, metaClass(), func(s net.Conn) { write(s, marker) })
	if err := q.closed(t, nil); !strings.Contains(err.Error(), "before authentication-ok") {
		t.Fatalf("relay: %v", err)
	}
}
