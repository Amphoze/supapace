// Package repl is the replication program: it runs only inside a replication
// job container, at the replicator's ids with the project's group, and copies
// the finished files of one repository to the object store. It also lists the
// store back for a rebuilt record and probes a bucket for the operator's check.
//
// Everything it reads is untrusted: the repository tree is written by a
// process at the project's uid, and the store's answers come over a network.
// Names pass walname.RepoPath and Key, nothing is followed, and every size,
// count and depth is bounded before it costs anything.
//
// Results: a copy may carry the six notice codes of a copy; a rebuild page
// carries no notice but unlisted-entry (keys under the subject's prefix that
// the layout does not admit, dropped from the page and counted); a probe
// carries none. The failure codes of each job kind are Codes'.
//
// Known limit, measured: the client bounds each connection attempt at 10 s
// and each call at CallTimeout (60 s), so at most five handed addresses that
// drop packets ahead of a good one are tolerated; with six or more every call
// fails.
package repl

import (
	"errors"
	"regexp"
	"strings"

	"github.com/Amphoze/supapace/internal/walname"
)

// ErrPath is a key Key refuses to build.
var ErrPath = errors.New("repl: path outside the repository layout")

var (
	subjectRE = regexp.MustCompile(`^(cp|[a-z0-9]{20})$`)
	stanzaRE  = regexp.MustCompile(`^(cp|[a-z0-9]{20})-[0-9]{1,20}$`)
)

// prefixMax bounds the declared prefix (a subject is at most 20 bytes, the
// longest repository path 568: every key stays within 1,024).
const prefixMax = 256

// Key is the one constructor of an object key: "<prefix>/<subject>/<rel>",
// without the leading slash when the prefix is empty. The subject is a
// project ref or "cp" (the job's input, never a name from the tree); rel is a
// repository path that walname.RepoPath admits for a stanza of that subject.
func Key(prefix, subject, rel string) (string, error) {
	if !validPrefix(prefix) || !subjectRE.MatchString(subject) {
		return "", ErrPath
	}
	parts := strings.SplitN(rel, "/", 3)
	if len(parts) < 3 || !stanzaRE.MatchString(parts[1]) || !strings.HasPrefix(parts[1], subject+"-") {
		return "", ErrPath
	}
	if _, _, _, ok := walname.RepoPath(parts[1], rel); !ok {
		return "", ErrPath
	}
	return base(prefix, subject) + "/" + rel, nil
}

// base is "<prefix>/<subject>", or the subject alone.
func base(prefix, subject string) string {
	if prefix == "" {
		return subject
	}
	return prefix + "/" + subject
}

// validPrefix: empty, or at most 256 bytes of segments that are neither
// empty, ".", ".." nor longer than 255 bytes, without a control byte.
func validPrefix(p string) bool {
	if p == "" {
		return true
	}
	if len(p) > prefixMax {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." || len(s) > 255 {
			return false
		}
	}
	return !hasControl(p)
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
