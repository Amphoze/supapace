// Command check-public refuses content that must not appear in this public
// repository.
//
//	check-public --staged          every path and staged blob except deletions (pre-commit, pre-merge-commit)
//	check-public --tree            every path and blob of the index (CI, make public-check)
//	check-public --message FILE    a whole commit or tag message, or a ref name (commit-msg, pre-push)
//	check-public --tag OBJECT      an annotated tag: header lines and message (pre-push)
//	check-public --range REVS...   the commits git rev-list REVS selects: header lines,
//	                               message, and every path and blob each commit introduces (pre-push, CI)
//
// --range takes only revisions (rev, ^rev, a..b, a...b) and --not; any other
// option, which could reorder, limit or empty the selection, is a usage error. It
// prints the number of commits checked.
//
// Every header line of a commit or tag is scanned, continuation lines included,
// except tree, parent, object, type and the gpgsig blocks: author, committer and
// tagger with the identity rules (deny-list, e-mail, host name), every other line,
// mergetag blocks included, with all rules. Author, committer and tagger dates
// must be in UTC (+0000): make commits and tags with TZ=UTC.
//
// Refused: e-mail addresses (except the agent's noreply trailer and GitHub noreply
// addresses), home-directory paths, IPv4 addresses outside the platform and
// documentation ranges, IPv6 addresses other than unspecified, loopback,
// link-local, multicast, the metadata endpoint and the documentation range, host names (see
// the limits below for the TLDs that count), short codes (two letters of one case and
// two digits standing as a token or a name's start, not two hex letters such as
// fe80; see code in rules.go), and every pattern of the operator's deny-list
// (${SUPAPACE_DENYLIST:-$HOME/.config/supapace/denylist}, one case-insensitive
// regular expression per line). The deny-list sees every line as written. Exact
// host names, dotted quads, IPv6 addresses and home-path prefixes (/home/ or
// /Users/ and one user name) listed in scripts/public-allow.txt are accepted;
// the file is read from the index (for --range from the first commit git
// rev-list prints, the newest since ordering options are refused; for --tag from
// the commit the tag peels to), never from the work tree.
//
// In a patch of upstream (studio/patches/*.patch, read as the blob itself in every
// mode) the context and removed lines of its hunks (counted only after its first
// "diff --git " line, never in the commit message) quote the upstream tree and are
// not judged by the e-mail and host-name rules; every other rule applies to them,
// and every other line of the patch (header, message, file headers, added lines,
// anything outside a hunk's counted lines) is judged as any line. A context line
// is taken as written: the gate cannot see whether upstream holds it, the patch
// applying is what shows that.
//
// Blobs are scanned as bytes whatever their type or attributes, symlink targets
// included; a blob that starts with a UTF-16 byte-order mark is also scanned as
// decoded text. The whole repository is checked whatever the working directory.
// Any error — no deny-list, a pattern that does not compile or matches the empty
// string, a failing git command — fails the check. Findings name the file, line
// and rule only, never the matched text; a hit in a path name is reported against
// a hash of the path.
//
// What a pattern gate cannot catch, so the deny-list and review still matter:
//   - a word or address split by a line break, a zero-width character, a NUL or
//     an invalid byte;
//   - percent, HTML-entity, base64 or other encodings, UTF-16 text without a
//     byte-order mark, and UTF-32 text, which is not decoded;
//   - Unicode look-alike, full-width or ideographic letters, digits and dots;
//   - obfuscated forms such as corp[.]com or "a at corp dot com";
//   - an IPv4 address written as one integer (decimal, hex or octal), glued to
//     letters, or written after '.', '-' or '_' (skipped so versions pass);
//   - host names under a TLD missing from the list; two-label names (a.tld)
//     under a TLD other than com net org io in co ai edu gov cloud, skipped so
//     selectors such as x.info or t.at pass, so the deny-list must carry them;
//     two-label names with a title-case final label not directly after "://" or
//     '@' (skipped so Go identifiers such as big.Int pass);
//   - the stored object of a Git LFS pointer;
//   - anything committed with hooks skipped (--no-verify) or by commands that run
//     no hook (cherry-pick, rebase, fast-forward merges, tags) until the pre-push
//     hook or CI runs --range over it; local hooks also run the gate source from
//     the work tree, so an unstaged edit to the gate weakens them;
//   - anything pushed with git push --no-verify, which skips the pre-push hook.
//
// Note: git commit -v puts the diff in the message file, so removing a flagged
// line in such a commit is refused by the commit-msg hook (the removed line is
// in the message); commit without -v.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

type entry struct{ mode, sha, path string }

func run(args []string, stderr io.Writer) int {
	fail := func(err error) int { fmt.Fprintf(stderr, "check-public: %v\n", err); return 2 }
	// git push sends the original objects, so read those, never a replacement.
	if err := os.Setenv("GIT_NO_REPLACE_OBJECTS", "1"); err != nil {
		return fail(err)
	}
	var msg []byte
	switch {
	case len(args) == 1 && (args[0] == "--staged" || args[0] == "--tree"):
	case len(args) >= 2 && args[0] == "--range" && revisions(args[1:]), len(args) == 2 && args[0] == "--tag":
	case len(args) == 2 && args[0] == "--message":
		b, err := os.ReadFile(args[1])
		if err != nil {
			return fail(errors.New("message file cannot be read"))
		}
		msg = b
	default:
		fmt.Fprintln(stderr, "usage: check-public --staged | --tree | --message FILE | --tag OBJECT | --range REVISION... (rev, ^rev, a..b, a...b, --not)")
		return 2
	}
	denyPath := os.Getenv("SUPAPACE_DENYLIST")
	if denyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fail(errors.New("deny-list cannot be located (set SUPAPACE_DENYLIST)"))
		}
		denyPath = filepath.Join(home, ".config/supapace/denylist")
	}
	deny, err := loadDenyList(denyPath)
	if err != nil {
		return fail(err)
	}
	top, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return fail(err)
	}
	if err := os.Chdir(strings.TrimSuffix(string(top), "\n")); err != nil {
		return fail(err)
	}
	c := &checker{deny: deny}

	n := 0
	report := func(loc, rule string) { fmt.Fprintf(stderr, "check-public: %s: %s\n", loc, rule); n++ }
	switch {
	case args[0] == "--range":
		var k int
		if k, err = scanRange(c, args[1:], report); err == nil {
			fmt.Fprintf(stderr, "check-public: checked %d commits\n", k) // an empty selection shows
		}
	case args[0] == "--tag":
		err = scanTag(c, args[1], report)
	default:
		if c.allow, err = loadAllow(""); err != nil {
			break
		}
		if msg != nil {
			c.message("", msg, report)
			break
		}
		if args[0] == "--staged" { // the identities and zone the commit will carry
			for _, k := range []string{"author", "committer"} {
				var ident []byte
				if ident, err = git("var", "GIT_"+strings.ToUpper(k)+"_IDENT"); err != nil {
					return fail(errors.New("git identity is not set"))
				}
				if _, err = c.header("", append([]byte(k+" "), bytes.TrimSpace(ident)...), nil, report); err != nil {
					return fail(err)
				}
			}
		}
		var entries []entry
		if entries, err = list(args[0]); err == nil {
			err = c.entries("", entries, report)
		}
	}
	if err != nil {
		return fail(err)
	}
	if n > 0 {
		fmt.Fprintf(stderr, "check-public: %d finding(s); the matched text is not shown\n", n)
		return 1
	}
	return 0
}

func (c *checker) message(prefix string, msg []byte, report func(loc, rule string)) {
	for i, ln := range messageLines(msg) {
		for _, r := range c.line(ln) {
			report(prefix+"message:"+strconv.Itoa(i+1), r)
		}
	}
}

// entries scans the path and the blob of every entry; prefix starts each location.
func (c *checker) entries(prefix string, entries []entry, report func(loc, rule string)) error {
	blobs, err := catBlobs(entries)
	if err != nil {
		return err
	}
	for i, e := range entries {
		loc := prefix + e.path
		if rules := c.line(e.path); len(rules) > 0 {
			sum := sha256.Sum256([]byte(e.path))
			loc = prefix + "path#" + hex.EncodeToString(sum[:6])
			for _, r := range rules {
				report(loc+" (path name)", r)
			}
		}
		c.blob(loc, e.path, blobs[i], report)
	}
	return nil
}

// blob scans one blob, at path, reporting at loc. In a patch of upstream
// (upstreamPatch) the lines quoted from upstream (quoted) are judged by
// rules(s, true): the blob's own lines, whatever diff brought the blob.
func (c *checker) blob(loc, path string, b []byte, report func(loc, rule string)) {
	for k, text := range texts(b) {
		suffix := ""
		if k > 0 {
			suffix = " (UTF-16)"
		}
		q := make([]bool, len(text))
		if k == 0 && upstreamPatch(path) {
			q = quoted(text)
		}
		for ln, s := range text {
			for _, r := range c.rules(s, q[ln]) {
				report(loc+":"+strconv.Itoa(ln+1)+suffix, r)
			}
		}
	}
}

// revisions reports whether args are only revisions (rev, ^rev, a..b, a...b) and
// --not: an option could reorder, limit or empty the selection.
func revisions(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "--not" {
			return false
		}
	}
	return true
}

// scanRange scans every commit git rev-list selects with args: its header (see
// header), its message, and the paths and blobs it introduces against each
// parent. Each blob and path is scanned once. The allow file is taken from the
// first commit rev-list prints, the newest, since ordering options are refused.
// A final "--" makes git refuse anything that is not a revision. It returns the
// number of commits checked.
func scanRange(c *checker, args []string, report func(loc, rule string)) (int, error) {
	out, err := git(append(append([]string{"rev-list"}, args...), "--")...)
	if err != nil {
		return 0, err
	}
	shas := strings.Fields(string(out))
	if len(shas) == 0 {
		return 0, nil
	}
	if c.allow, err = loadAllow(shas[0]); err != nil {
		return 0, err
	}
	commits := make([]entry, len(shas))
	for i, s := range shas {
		commits[i] = entry{sha: s}
	}
	raws, err := catObjects(commits, "commit")
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for i, sha := range shas {
		prefix := sha[:12] + ":"
		msg, err := c.header(prefix, raws[i], []string{"author", "committer"}, report)
		if err != nil {
			return 0, fmt.Errorf("%s%v", prefix, err)
		}
		c.message(prefix, msg, report)
		b, err := git("diff-tree", "-r", "-z", "--no-commit-id", "--root", "-m", "--no-renames", "--diff-filter=d", sha)
		if err != nil {
			return 0, err
		}
		all, err := parseRaw(b)
		if err != nil {
			return 0, err
		}
		var todo []entry
		for _, e := range all {
			if seen["p"+e.path] && seen["b"+e.sha] {
				continue
			}
			if seen["b"+e.sha] {
				e.mode = "160000" // blob already scanned: path only
			}
			seen["p"+e.path], seen["b"+e.sha] = true, true
			todo = append(todo, e)
		}
		if err := c.entries(prefix, todo, report); err != nil {
			return 0, err
		}
	}
	return len(shas), nil
}

func git(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	return out, nil
}

// loadAllow reads scripts/public-allow.txt from the index (rev "") or from a
// commit. Absent there, nothing is allowed.
func loadAllow(rev string) (map[string]bool, error) {
	var out []byte
	var err error
	if rev == "" {
		out, err = git("ls-files", "-s", "-z", "--", allowPath)
	} else {
		out, err = git("ls-tree", "-z", rev, "--", allowPath)
	}
	if err != nil {
		return nil, err
	}
	meta, _, _ := strings.Cut(string(out), "\t")
	f := strings.Fields(meta)
	switch {
	case len(f) == 0:
		return map[string]bool{}, nil
	case f[0] != "100644" && f[0] != "100755":
		return nil, fmt.Errorf("%s: not a regular file", allowPath)
	}
	sha := f[1]
	if rev != "" {
		sha = f[2] // mode type sha
	}
	b, err := git("cat-file", "blob", sha)
	if err != nil {
		return nil, err
	}
	return parseAllow(b)
}

// list returns the index entries to scan. Gitlinks (submodules) carry no blob;
// their path is still scanned.
func list(mode string) ([]entry, error) {
	if mode == "--tree" {
		b, err := git("ls-files", "-z", "-s")
		if err != nil {
			return nil, err
		}
		var out []entry
		for _, rec := range strings.Split(string(b), "\x00") {
			meta, path, ok := strings.Cut(rec, "\t")
			if f := strings.Fields(meta); ok && len(f) == 3 {
				out = append(out, entry{f[0], f[1], path})
			} else if rec != "" {
				return nil, errors.New("git ls-files: unexpected output")
			}
		}
		return out, nil
	}
	b, err := git("diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames", "--diff-filter=d")
	if err != nil {
		return nil, err
	}
	return parseRaw(b)
}

// parseRaw reads -z raw diff output, ":oldmode newmode oldsha newsha status\0path\0"
// per change (renames off), into the new side of each change.
func parseRaw(b []byte) ([]entry, error) {
	if len(b) == 0 {
		return nil, nil
	}
	recs := strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
	if len(recs)%2 != 0 {
		return nil, errors.New("git diff: unexpected output")
	}
	var out []entry
	for i := 0; i < len(recs); i += 2 {
		f := strings.Fields(recs[i])
		if len(f) != 5 || !strings.HasPrefix(f[0], ":") {
			return nil, errors.New("git diff: unexpected output")
		}
		out = append(out, entry{f[1], f[3], recs[i+1]})
	}
	return out, nil
}

// catBlobs reads every entry's blob; gitlinks get none.
func catBlobs(entries []entry) ([][]byte, error) { return catObjects(entries, "blob") }

// catObjects reads the objects of the entries in one git cat-file --batch and
// requires each to be of type typ. Entries of mode 160000 are skipped.
func catObjects(entries []entry, typ string) ([][]byte, error) {
	var in strings.Builder
	for _, e := range entries {
		if e.mode != "160000" {
			in.WriteString(e.sha + "\n")
		}
	}
	objs := make([][]byte, len(entries))
	if in.Len() == 0 {
		return objs, nil
	}
	cmd := exec.Command("git", "cat-file", "--batch")
	cmd.Stdin = strings.NewReader(in.String())
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git cat-file: %w", err)
	}
	for i, e := range entries {
		if e.mode == "160000" {
			continue
		}
		hdr, rest, ok := bytes.Cut(out, []byte("\n"))
		f := strings.Fields(string(hdr))
		if !ok || len(f) != 3 || f[0] != e.sha || f[1] != typ {
			return nil, errors.New("git cat-file: unexpected output")
		}
		size, err := strconv.Atoi(f[2])
		if err != nil || size+1 > len(rest) {
			return nil, errors.New("git cat-file: short output")
		}
		objs[i], out = rest[:size], rest[size+1:]
	}
	return objs, nil
}

// scanTag scans an annotated tag object: its header (see header) and its
// message. The allow file is taken from the commit the tag peels to; a tag that
// does not peel to a commit is an error.
func scanTag(c *checker, obj string, report func(loc, rule string)) error {
	commit, err := git("rev-parse", "--verify", "-q", obj+"^{commit}")
	if err != nil {
		return errors.New("tag does not peel to a commit")
	}
	if c.allow, err = loadAllow(strings.TrimSpace(string(commit))); err != nil {
		return err
	}
	raw, err := git("cat-file", "tag", obj)
	if err != nil {
		return err
	}
	msg, err := c.header("tag:", raw, []string{"tagger"}, report)
	if err != nil {
		return err
	}
	c.message("tag:", msg, report)
	return nil
}
