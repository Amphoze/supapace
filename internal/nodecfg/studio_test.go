package nodecfg

import (
	"strings"
	"testing"
)

// nameOf returns a valid domain name of exactly n bytes ending in ".test".
func nameOf(n int) string {
	s := "test"
	for len(s) < n {
		l := min(63, n-len(s)-1)
		if l < 1 {
			s = "a" + s[1:] // cannot happen for the lengths used here
			break
		}
		s = strings.Repeat("a", l) + "." + s
	}
	return s
}

// Every host of the studio domain — the sign-in host and a 20-letter project
// label under it — must itself be a name of at most 253 bytes.
func TestConfig_StudioDomainLeavesRoomForItsHosts(t *testing.T) {
	ok, long := nameOf(253-21), nameOf(253-20)
	if len(ok) != 232 || len(long) != 233 || !ValidDomain(long) {
		t.Fatalf("lengths %d %d", len(ok), len(long))
	}
	if err := studioCfg("example.org.test", ok).Validate(); err != nil {
		t.Errorf("%d bytes: %v", len(ok), err)
	}
	if err := studioCfg("example.org.test", long).Validate(); err == nil || !strings.Contains(err.Error(), "studio_domain") {
		t.Errorf("%d bytes: Validate = %v, want a studio_domain refusal", len(long), err)
	}
}

// Spellings of an address and other near-names.
func TestConfig_StudioDomainNotAnAddress(t *testing.T) {
	for _, s := range []string{"192.0.2.1", "studio.0x", "studio.0xff", "studio.010", "a.4294967295", "::1", "[::1]",
		"*.studio.test", "studio_x.test", "studio..test", ".studio.test", "-a.test", "a-.test", "stüdio.test"} {
		if err := studioCfg("example.test", s).Validate(); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	// Punycode labels are LDH and accepted, as is a hex-looking label that is
	// not a number.
	for _, s := range []string{"xn--stdio-kva.test", "studio.0x1g", "0x10.test"} {
		if err := studioCfg("example.test", s).Validate(); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}
