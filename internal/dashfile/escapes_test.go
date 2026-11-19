package dashfile

import (
	"reflect"
	"strings"
	"testing"
)

// The first pass and the decoder read member names alike: an escape names the
// member it decodes to, so it neither hides a duplicate nor makes an unknown
// member known; a byte order mark and a DEL are refused.
func TestDashfile_EscapedNamesAndEdgeBytes(t *testing.T) {
	sub := func(old, new string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	for name, s := range map[string]string{
		"escaped duplicate member": sub(`"generation":7,`, `"generation":7,"generation":8,`),
		"escaped duplicate ref":    sub(`,"`+ref2+`":`, `,"abcdefghij0123456789":{"name":"","members":[]},"`+ref2+`":`),
		"escaped case variant":     sub(`"generation":7`, `"Generation":7`),
		"escaped upper-case ref":   sub(`"`+ref2+`"`, `"Bcdefghij0123456789a"`),
		"byte order mark":          "\xef\xbb\xbf" + good,
		"DEL in a subject":         sub(`"sub":"user-1"`, `"sub":"user\u007f1"`),
		"DEL in an issuer":         sub(`"iss":"https://issuer.test","client_id"`, `"iss":"https://issuer.test\u007f","client_id"`),
		"leading zero":             sub(`"generation":7`, `"generation":07`),
	} {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Control: an escaped exact name is the same member.
	want, _ := Parse([]byte(good))
	got, err := Parse([]byte(sub(`"node":`, `"node":`)))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("escaped exact name: %v", err)
	}
}
