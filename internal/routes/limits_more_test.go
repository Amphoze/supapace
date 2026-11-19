package routes

import "testing"

// The printable range is 0x20 to 0x7e at both ends.
func TestRoutes_AudiencePrintableEdges(t *testing.T) {
	for aud, ok := range map[string]bool{" ": true, "~": true, "\x1f": false, "\x7f": false} {
		f := sample()
		p := f.Projects[refA]
		p.Aud = []string{aud}
		f.Projects[refA] = p
		if _, err := f.Marshal(); (err == nil) != ok {
			t.Errorf("%q: err %v, want ok %v", aud, err, ok)
		}
	}
}
