package pgconf

import (
	"fmt"
	"slices"
	"strings"
)

// networkExtensions can open connections out of the cluster.
var networkExtensions = []string{"pg_net", "http", "dblink", "postgres_fdw", "wrappers"}

// Supautils renders the extension template from the image's supautils.conf:
// the backup role is added to reserved_roles and, unless outbound, the network
// extensions are dropped from privileged_extensions. Every other line is kept
// byte for byte. Either line missing, repeated or unquoted is ErrTemplate.
func Supautils(image []byte, outbound bool) ([]byte, error) {
	lines := strings.Split(string(image), "\n")
	err := editList(lines, "supautils.reserved_roles", func(l []string) []string {
		return append(l, "supapace_backup")
	})
	if err != nil {
		return nil, err
	}
	err = editList(lines, "supautils.privileged_extensions", func(l []string) []string {
		if outbound {
			return l
		}
		return slices.DeleteFunc(l, func(n string) bool { return slices.Contains(networkExtensions, n) })
	})
	if err != nil {
		return nil, err
	}
	return []byte(strings.Join(lines, "\n")), nil
}

// editList rewrites, in place, the one line "<key> = '<a>, <b>, …'" of lines.
func editList(lines []string, key string, edit func([]string) []string) error {
	at := -1
	for i, l := range lines {
		if name, _ := settingName(l); !strings.EqualFold(name, key) {
			continue
		}
		if at >= 0 {
			return fmt.Errorf("%w: supautils.conf sets %s twice", ErrTemplate, key)
		}
		at = i
	}
	if at < 0 {
		return fmt.Errorf("%w: supautils.conf has no %s line", ErrTemplate, key)
	}
	v, okPrefix := strings.CutPrefix(lines[at], key+" = '")
	v, okSuffix := strings.CutSuffix(v, "'")
	if !okPrefix || !okSuffix || strings.ContainsAny(v, `'\#`) {
		return fmt.Errorf("%w: supautils.conf %s line not a quoted list", ErrTemplate, key)
	}
	lines[at] = key + " = '" + strings.Join(edit(strings.Split(v, ", ")), ", ") + "'"
	return nil
}
