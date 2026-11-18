// Package walname is the one definition of the names a cluster may put in its
// spool, ask for during recovery, and of the paths a repository may hold. Every
// name it sees comes from an untrusted cluster or repository; anything it does
// not list exactly is refused, so a name never reaches a command line or a
// path in a shape that could be read as an option or leave its directory.
package walname

import (
	"regexp"
	"strconv"
	"strings"
)

// Kind is what a name or repository path is.
type Kind int

const (
	None Kind = iota
	// Spool and archive names.
	Segment // a WAL segment
	History // a timeline history file
	Label   // a backup label file, <segment>.<offset>.backup
	// Repository paths only.
	Info            // archive.info, backup.info and their copies
	SetManifest     // a backup set's backup.manifest
	SetManifestCopy // its backup.manifest.copy
	SetFile         // a file of a backup set under pg_data/
	HistoryManifest // a set's manifest kept in backup.history/
)

var (
	segmentRE  = regexp.MustCompile(`^[0-9A-F]{24}$`)
	historyRE  = regexp.MustCompile(`^[0-9A-F]{8}\.history$`)
	labelRE    = regexp.MustCompile(`^[0-9A-F]{24}\.[0-9A-F]{8}\.backup$`)
	archiveRE  = regexp.MustCompile(`^[0-9]{2}-[0-9]{1,3}$`)
	hexDirRE   = regexp.MustCompile(`^[0-9A-F]{16}$`)
	archSegRE  = regexp.MustCompile(`^([0-9A-F]{24})-[0-9a-f]{40}\.zst$`)
	setLabelRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}F$`)
	yearRE     = regexp.MustCompile(`^[0-9]{4}$`)
	histManRE  = regexp.MustCompile(`^([0-9]{8}-[0-9]{6}F)\.manifest\.gz$`)
	setPathRE  = regexp.MustCompile(`^[A-Za-z0-9_.+/-]{1,512}$`)
	partialRE  = regexp.MustCompile(`^[0-9A-F]{24}\.partial$`)
)

// tli reads the timeline from the first 8 hex digits of a name already matched.
func tli(name string) uint32 {
	v, _ := strconv.ParseUint(name[:8], 16, 32)
	return uint32(v)
}

// spoolForms is every form the spool admits, each with its kind; a form is
// added or dropped here alone (Request and SegmentOf name their kinds).
var spoolForms = []struct {
	re   *regexp.Regexp
	kind Kind
}{
	{segmentRE, Segment},
	{historyRE, History},
	{labelRE, Label},
}

// Spool classifies a name the archive command may write into the spool.
func Spool(name string) (k Kind, t uint32, ok bool) {
	for _, f := range spoolForms {
		if f.re.MatchString(name) {
			return f.kind, tli(name), true
		}
	}
	return None, 0, false
}

// Request classifies a name recovery may ask for: a segment or a history file.
func Request(name string) (k Kind, t uint32, ok bool) {
	if k, t, ok = Spool(name); ok && (k == Segment || k == History) {
		return k, t, true
	}
	return None, 0, false
}

// SegmentOf returns the 24 hex digits of a Segment or Label name, else "".
func SegmentOf(name string) string {
	if k, _, ok := Spool(name); ok && (k == Segment || k == Label) {
		return name[:24]
	}
	return ""
}

// Admitted reports whether timeline t is in admitted; nil admits every timeline.
func Admitted(t uint32, admitted []uint32) bool {
	if admitted == nil {
		return true
	}
	for _, a := range admitted {
		if a == t {
			return true
		}
	}
	return false
}

// RepoPath classifies rel, a path relative to the repository root, for stanza.
// label is the backup set's label for the set kinds and HistoryManifest.
func RepoPath(stanza, rel string) (k Kind, t uint32, label string, ok bool) {
	if stanza == "" || stanza == "." || stanza == ".." || strings.ContainsAny(stanza, "/\x00") {
		return None, 0, "", false
	}
	p := strings.Split(rel, "/")
	if len(p) < 3 || p[1] != stanza {
		return None, 0, "", false
	}
	switch p[0] {
	case "archive":
		return archivePath(p[2:])
	case "backup":
		return backupPath(p[2:])
	}
	return None, 0, "", false
}

// archivePath classifies the components below archive/<stanza>/.
func archivePath(p []string) (Kind, uint32, string, bool) {
	switch {
	case len(p) == 1 && (p[0] == "archive.info" || p[0] == "archive.info.copy"):
		return Info, 0, "", true
	case len(p) == 2 && archiveRE.MatchString(p[0]) && historyRE.MatchString(p[1]):
		return History, tli(p[1]), "", true
	case len(p) == 3 && archiveRE.MatchString(p[0]) && hexDirRE.MatchString(p[1]):
		if m := archSegRE.FindStringSubmatch(p[2]); m != nil && m[1][:16] == p[1] {
			return Segment, tli(m[1]), "", true
		}
		if labelRE.MatchString(p[2]) && p[2][:16] == p[1] {
			return Label, tli(p[2]), "", true
		}
	}
	return None, 0, "", false
}

// backupPath classifies the components below backup/<stanza>/.
func backupPath(p []string) (Kind, uint32, string, bool) {
	switch {
	case len(p) == 1 && (p[0] == "backup.info" || p[0] == "backup.info.copy"):
		return Info, 0, "", true
	case len(p) == 3 && p[0] == "backup.history" && yearRE.MatchString(p[1]):
		// pgBackRest files a set's manifest under the year of its label.
		if m := histManRE.FindStringSubmatch(p[2]); m != nil && m[1][:4] == p[1] {
			return HistoryManifest, 0, m[1], true
		}
	case len(p) == 2 && setLabelRE.MatchString(p[0]) && p[1] == "backup.manifest":
		return SetManifest, 0, p[0], true
	case len(p) == 2 && setLabelRE.MatchString(p[0]) && p[1] == "backup.manifest.copy":
		return SetManifestCopy, 0, p[0], true
	case len(p) >= 3 && setLabelRE.MatchString(p[0]) && p[1] == "pg_data":
		if setFile(p[2:]) {
			return SetFile, 0, p[0], true
		}
	}
	return None, 0, "", false
}

// setFile checks the path below pg_data/: 1 to 512 bytes of a fixed set, no
// empty, "." or ".." component.
func setFile(p []string) bool {
	if !setPathRE.MatchString(strings.Join(p, "/")) {
		return false
	}
	for _, c := range p {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// Partial reports whether name is exactly <24 hex digits>.partial. PostgreSQL
// archives such a file when a recovery ends inside a segment that has no
// archive status yet: the segment's beginning, kept under that name. No
// restore ever uses it, and refusing it would stop archiving for good, so the
// archive command acknowledges it and keeps nothing. Spool, Request and
// RepoPath still refuse it.
func Partial(name string) bool { return partialRE.MatchString(name) }
