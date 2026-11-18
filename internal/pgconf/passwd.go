package pgconf

import (
	"fmt"
	"strconv"
	"strings"
)

// Passwd renders the image's /etc/passwd with the postgres entry's uid and gid
// replaced by the project's pair; every other byte is kept.
func Passwd(image []byte, uid, gid int) ([]byte, error) {
	return rewritePostgres(image, "passwd", 7, uid, gid)
}

// Group renders the image's /etc/group with the postgres group's gid replaced.
func Group(image []byte, gid int) ([]byte, error) {
	return rewritePostgres(image, "group", 4, gid)
}

// rewritePostgres replaces fields 3… of the one "postgres:" line, which must
// have nfields fields, with ids.
func rewritePostgres(image []byte, file string, nfields int, ids ...int) ([]byte, error) {
	for _, id := range ids {
		if id <= 0 || id > 1<<31-1 {
			return nil, fmt.Errorf("%w: id %d out of range for %s", ErrTemplate, id, file)
		}
	}
	lines := strings.Split(string(image), "\n")
	at := -1
	for i, l := range lines {
		if !strings.HasPrefix(l, "postgres:") {
			continue
		}
		if at >= 0 {
			return nil, fmt.Errorf("%w: %s has two postgres entries", ErrTemplate, file)
		}
		at = i
	}
	if at < 0 {
		return nil, fmt.Errorf("%w: %s has no postgres entry", ErrTemplate, file)
	}
	f := strings.Split(lines[at], ":")
	if len(f) != nfields {
		return nil, fmt.Errorf("%w: %s postgres entry has %d fields", ErrTemplate, file, len(f))
	}
	for i, id := range ids {
		f[2+i] = strconv.Itoa(id)
	}
	lines[at] = strings.Join(f, ":")
	return []byte(strings.Join(lines, "\n")), nil
}
