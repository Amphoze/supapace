package poolcfg

import (
	"strings"
	"testing"
)

// The label's rule is written twice — here and in the node file's validation,
// which cannot import this package. The two must accept the same labels.
func TestValidLabel_AgreesWithTheNodeFile(t *testing.T) {
	for _, l := range []string{
		"db", "a", "0", "pool-1", "a--b", "xn--db", strings.Repeat("a", 63), "abcdefghij012345678", "abcdefghij01234567890",
		"", "-db", "db-", "d.b", "db.", "Db", "d_b", "d b", "db\n", "dé", strings.Repeat("a", 64),
		"abcdefghij0123456789", "01234567890123456789",
	} {
		if l == "" {
			// No label is no pooler in the node file; here it is not a label.
			if ValidLabel(l) == nil {
				t.Error("ValidLabel accepts the empty label")
			}
			continue
		}
		c := defaultCfg()
		c.PoolerLabel = l
		err := c.Validate()
		file := err == nil || !strings.Contains(err.Error(), "pooler_label")
		if here := ValidLabel(l) == nil; here != file {
			t.Errorf("label %q: ValidLabel accepts = %v, the node file accepts = %v", l, here, file)
		}
	}
}
