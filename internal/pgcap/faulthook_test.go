//go:build faulthook

package pgcap

import (
	"net"
	"strings"
	"testing"
)

// In the build with the tag faulthook the marker message panics its
// connection's handler, which the relay recovers: that connection alone ends.
func TestFaultHookBuild_MarkerEndsItsConnection(t *testing.T) {
	a := relayTo(t, metaClass(), func(s net.Conn) { write(s, login, ms4(FaultMarker, "x")) })
	if err := a.closed(t, login); !strings.Contains(err.Error(), "fault") {
		t.Fatalf("relay: %v", err)
	}
	run, ch := script(t, login, ms4('D', "\x00\x00"))
	b := relayTo(t, metaClass(), run)
	b.read(t, len(login)+7)
	<-ch
}
