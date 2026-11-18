package s3x

import "testing"

// The version listing, which rebuild and the fetch use, refuses a prefix a
// store would rewrite before any request, as the current listing does.
func TestListVersions_RewrittenPrefixRefused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	for _, p := range []string{"/", "/p", "p//", "./", "p/../"} {
		if _, _, _, err := c.ListVersions(bg, p, "", ""); err == nil {
			t.Errorf("prefix %q accepted", p)
		}
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d requests sent for refused prefixes", n)
	}
	for _, p := range []string{"", "p/", "p/q/"} {
		if _, _, _, err := c.ListVersions(bg, p, "", ""); err != nil {
			t.Errorf("prefix %q: %v", p, err)
		}
	}
}
