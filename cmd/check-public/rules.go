package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// checker applies every rule to one line of text (a content line, a path name or
// a commit-message line).
type checker struct {
	deny  []*regexp.Regexp // operator deny-list, case-insensitive
	allow map[string]bool  // exact tokens of scripts/public-allow.txt
}

// Rule names, in report order.
const (
	ruleDeny  = "deny-list"
	ruleMail  = "e-mail"
	ruleHome  = "home path"
	ruleIPv4  = "IPv4"
	ruleIPv6  = "IPv6"
	ruleHost  = "host name"
	ruleZone  = "time zone" // an author, committer or tagger zone other than +0000
	allowPath = "scripts/public-allow.txt"
)

var (
	// The only addresses tolerated anywhere: the commit trailer of the coding agent
	// and GitHub's per-user noreply addresses.
	exemptMailRE = regexp.MustCompile(`<noreply@anthropic\.com>|<(?:[0-9]+\+)?[A-Za-z0-9-]+@users\.noreply\.github\.com>`)
	mailRE       = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	homeRE       = regexp.MustCompile(`/(?:home|Users)/[^/\s"'` + "`" + `]|(?i)\b[a-z]:[\\/]users[\\/][^\\/\s"']`)
	quadRE       = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)
	hexRunRE     = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	stampRE      = regexp.MustCompile(` [0-9]+ ([+-][0-9]{4})$`) // identity timestamp and zone
	hostRE       = regexp.MustCompile(`[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+`)
)

// IPv4 addresses that may appear: the platform defaults, loopback, 0.0.0.0/8
// (unspecified, masks such as 0.0.0.63), the metadata endpoint and RFC 5737.
// Netmasks such as 255.255.255.0 are accepted separately.
var allowed4 = []netip.Prefix{
	netip.MustParsePrefix("10.212.0.0/14"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

// IPv6 addresses that may appear: unspecified, loopback, link-local, multicast
// (neighbour-discovery firewall rules), the metadata endpoint and RFC 3849. An
// IPv4-mapped address is judged by the IPv4 rule.
var allowed6 = []netip.Prefix{
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// tlds are the final labels that make a name of three or more labels a host
// name: generic, common country-code and private-use TLDs. .test, .example,
// .invalid and .localhost are never listed. Left out on purpose because they
// collide with file extensions or ubiquitous code identifiers: ac am as br cc ch
// id is md mk ml mo pl pm ps py re rs sh so tf and the generic email host name
// page run store.
var tlds = map[string]bool{}

// strongTLDs are the final labels that make a two-label name (a.tld) a host name.
// Other TLDs collide with selectors and aliases such as x.info, x.dev or t.at, so
// two-label names under them pass and the deny-list must carry them.
var strongTLDs = map[string]bool{}

func init() {
	for _, t := range strings.Fields("com net org io in co ai edu gov cloud") {
		strongTLDs[t] = true
	}
	for _, t := range strings.Fields(`
		com net org edu gov mil int info biz pro xyz top site online tech dev app cloud ai io co me us tv ws fm gg ly to vc
		shop blog news live life world today space website club agency digital solutions company studio design software media global ltd inc llc
		uk eu fr de nl be at it es pt ie se no dk fi cz sk hu ro bg gr si hr ba lt lv ee lu li mt cy ru ua by tr ge az kz uz
		il ae sa qa kw om bh jo lb iq ir eg ma tn dz za ng ke gh tz ug et cm
		in pk bd lk np cn hk tw jp kr sg my th vn ph au nz ca mx ar cl pe ve uy
		local internal lan corp home intranet`) {
		tlds[t] = true
	}
}

// line returns the names of the rules that line breaks, in report order. The
// deny-list sees the line as written; the two noreply addresses are exempt from
// the e-mail and host rules only.
func (c *checker) line(s string) []string {
	ex := exemptMailRE.ReplaceAllString(s, " ")
	var hit []string
	add := func(rule string, ok bool) {
		if ok {
			hit = append(hit, rule)
		}
	}
	add(ruleDeny, c.denied(s))
	add(ruleMail, mailRE.MatchString(ex))
	add(ruleHome, c.home(s))
	add(ruleIPv4, c.ipv4(s))
	add(ruleIPv6, c.ipv6(s))
	add(ruleHost, c.host(ex))
	return hit
}

// identity checks an author, committer or tagger, "Name <e-mail>", with the
// deny-list, e-mail and host rules. A noreply address is exempt from the e-mail
// and host rules only; the deny-list always sees the whole identity, so a
// deny-list entry must not match the login the repository is published under.
func (c *checker) identity(s string) []string {
	ex := exemptMailRE.ReplaceAllString(s, " ")
	var hit []string
	if c.denied(s) {
		hit = append(hit, ruleDeny)
	}
	if mailRE.MatchString(ex) {
		hit = append(hit, ruleMail)
	}
	if c.host(ex) {
		hit = append(hit, ruleHost)
	}
	return hit
}

// home reports a home-directory path, unless its prefix (/home/ or /Users/ and
// the user name) is listed exactly in the allow file.
func (c *checker) home(s string) bool {
	for _, m := range homeRE.FindAllStringIndex(s, -1) {
		if name, end := m[1]-1, m[1]-1; s[m[0]] == '/' {
			for end < len(s) && (isAlnum(s[end]) || strings.IndexByte("._-", s[end]) >= 0) {
				end++
			}
			if end > name && c.allow[s[m[0]:end]] {
				continue
			}
		}
		return true
	}
	return false
}

func (c *checker) denied(s string) bool {
	for _, re := range c.deny {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func (c *checker) ipv4(s string) bool {
	for _, m := range quadRE.FindAllStringIndex(s, -1) {
		i, k := m[0], m[1]
		tok := s[i:k]
		// Part of a longer version or identifier: v17.6.1.166, pkg-1.2.3.4, 1.2.3.4.5, 1.2.3.4-rc.
		if i > 0 && (isAlnum(s[i-1]) || strings.IndexByte("_.-", s[i-1]) >= 0) {
			continue
		}
		if k < len(s) && (isAlnum(s[k]) || s[k] == '_' || s[k] == '-' || s[k] == '.' && k+1 < len(s) && s[k+1] >= '0' && s[k+1] <= '9') {
			continue
		}
		if imageTag(s, i) || c.allow[tok] {
			continue
		}
		var v uint32
		valid := true
		for _, o := range strings.Split(tok, ".") {
			n, _ := strconv.Atoi(o)
			valid = valid && n <= 255
			v = v<<8 | uint32(n&255)
		}
		if !valid {
			continue // 999.1.1.1 is not an address
		}
		if !ok4(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})) {
			return true
		}
	}
	return false
}

// ok4 reports whether an IPv4 address is in an allowed range or is a netmask
// (ones, then zeros).
func ok4(a netip.Addr) bool {
	b := a.As4()
	if inv := ^(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])); inv&(inv+1) == 0 {
		return true
	}
	for _, p := range allowed4 {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// imageTag reports whether the dotted quad at i is the tag of an image reference,
// name/name:TAG.
func imageTag(s string, i int) bool {
	if i == 0 || s[i-1] != ':' {
		return false
	}
	j := i - 1
	for j > 0 && (isAlnum(s[j-1]) || strings.IndexByte("._/-", s[j-1]) >= 0) {
		j--
	}
	ref := s[j : i-1]
	k := strings.IndexByte(ref, '/')
	return k > 0 && k < len(ref)-1
}

func (c *checker) ipv6(s string) bool {
	for _, m := range hexRunRE.FindAllStringIndex(s, -1) {
		// A run glued to a following letter is part of a word or a cast: x::date, std::vector.
		if k := m[1]; k < len(s) && (isAlnum(s[k]) || s[k] == '_') {
			continue
		}
		run := strings.TrimRight(s[m[0]:m[1]], ".")
		if strings.HasSuffix(run, ":") && !strings.HasSuffix(run, "::") {
			run = run[:len(run)-1]
		}
		// The run itself, else its longest tail after a ':' that parses (text joined
		// by ':' in front, as in addr:<address>).
		cand := run
		a, err := netip.ParseAddr(cand)
		for i := 0; err != nil && i < len(run); i++ {
			if run[i] == ':' {
				if cand = run[i+1:]; strings.HasPrefix(cand, ":") {
					cand = run[i:]
				}
				a, err = netip.ParseAddr(cand)
			}
		}
		if err != nil || !a.Is6() || c.allow[cand] {
			continue
		}
		if a.Is4In6() {
			if !ok4(a.Unmap()) {
				return true
			}
			continue
		}
		ok := false
		for _, p := range allowed6 {
			ok = ok || p.Contains(a.WithZone(""))
		}
		if !ok {
			return true
		}
	}
	return false
}

func (c *checker) host(s string) bool {
	for _, m := range hostRE.FindAllStringIndex(s, -1) {
		name := s[m[0]:m[1]]
		if m[1] < len(s) && s[m[1]] == '(' {
			continue // a call such as slog.Info(
		}
		last := name[strings.LastIndexByte(name, '.')+1:]
		short := strings.Count(name, ".") == 1
		before := s[:m[0]]
		if short && titleCase(last) && !strings.HasSuffix(before, "://") && !strings.HasSuffix(before, "@") {
			continue // a Go exported identifier: big.Int, time.Local
		}
		known := tlds
		if short && !strings.HasSuffix(before, "://") && !strings.HasSuffix(before, "@") {
			known = strongTLDs // x.info, t.at: selectors and aliases
		}
		if known[strings.ToLower(last)] && !c.allow[name] {
			return true
		}
	}
	return false
}

// loadDenyList reads the operator's deny-list: one case-insensitive regular
// expression per line, '#' comments and blank lines ignored. A file that cannot be
// read, that holds no pattern or a pattern that does not compile is an error, so
// the gate never runs without it. Errors never carry the file's text or path.
func loadDenyList(path string) ([]*regexp.Regexp, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("deny-list cannot be read (set SUPAPACE_DENYLIST)")
	}
	var out []*regexp.Regexp
	for n, ln := range strings.Split(strings.TrimPrefix(string(b), "\ufeff"), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' {
			continue
		}
		re, err := regexp.Compile("(?i)" + ln)
		if err != nil {
			return nil, fmt.Errorf("deny-list line %d does not compile", n+1)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("deny-list line %d matches the empty string", n+1)
		}
		out = append(out, re)
	}
	if len(out) == 0 {
		return nil, errors.New("deny-list holds no pattern")
	}
	return out, nil
}

// parseAllow reads the allow file: one exact token per line, each with a '#'
// comment giving the reason.
func parseAllow(b []byte) (map[string]bool, error) {
	out := map[string]bool{}
	for n, ln := range strings.Split(strings.TrimPrefix(string(b), "\ufeff"), "\n") {
		tok, why, _ := strings.Cut(ln, "#")
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.TrimSpace(why) == "" || strings.ContainsAny(tok, " \t") {
			return nil, fmt.Errorf("%s:%d: want one token and a '#' reason", allowPath, n+1)
		}
		out[tok] = true
	}
	return out, nil
}

// messageLines splits a whole commit message into lines. Nothing is cut: git
// keeps '#' lines and anything after a scissors line for -m, -F and most
// --cleanup modes.
func messageLines(b []byte) []string { return lines(string(b)) }

// lines splits text at '\n' and drops a trailing '\r'; a final '\n' does not
// start another line.
func lines(s string) []string {
	if s == "" {
		return nil
	}
	out := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, ln := range out {
		out[i] = strings.TrimSuffix(ln, "\r")
	}
	return out
}

// texts returns the lines of a blob as bytes and, for a blob that starts with a
// UTF-16 byte-order mark, also the lines of its decoded text.
func texts(b []byte) [][]string {
	out := [][]string{lines(string(b))}
	if len(b) < 2 || !(b[0] == 0xff && b[1] == 0xfe || b[0] == 0xfe && b[1] == 0xff) {
		return out
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 2; i+1 < len(b); i += 2 {
		if b[0] == 0xff {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		} else {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
	}
	return append(out, lines(string(utf16.Decode(u))))
}

// titleCase reports whether s is an upper-case letter followed only by
// lower-case letters, the shape of a Go exported identifier such as Int.
func titleCase(s string) bool {
	if len(s) < 2 || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

// header scans the header of a raw commit or tag object, continuation lines
// included, and returns the message. tree, parent, object and type lines and the
// gpgsig and gpgsig-sha256 blocks are skipped. An author, committer or tagger line
// goes through the identity rule, everything before its timestamp included (text
// after the address also through the line rules), and must carry the zone +0000 (rule "time zone"); every other line (mergetag
// blocks, encoding, a tag name, unknown headers) goes through the line rules. Each key of need must appear.
func (c *checker) header(prefix string, raw []byte, need []string, report func(loc, rule string)) ([]byte, error) {
	hdr, msg, _ := bytes.Cut(raw, []byte("\n\n"))
	seen := map[string]bool{}
	key := ""
	for i, ln := range strings.Split(string(hdr), "\n") {
		cont := strings.HasPrefix(ln, " ")
		val := ""
		if !cont {
			key, val, _ = strings.Cut(ln, " ")
			seen[key] = true
		}
		switch key {
		case "tree", "parent", "object", "type", "gpgsig", "gpgsig-sha256":
			continue
		case "author", "committer", "tagger":
			if !cont {
				id, zone := val, ""
				if m := stampRE.FindStringSubmatchIndex(val); m != nil {
					id, zone = val[:m[0]], val[m[2]:m[3]]
				}
				rules := c.identity(id)
				if j := strings.LastIndex(id, ">"); j >= 0 { // text after the address gets every line rule
					for _, r := range c.line(id[j+1:]) {
						if !slices.Contains(rules, r) {
							rules = append(rules, r)
						}
					}
				}
				for _, r := range rules {
					report(prefix+key, r)
				}
				if zone != "+0000" {
					report(prefix+key, ruleZone)
				}
				continue
			}
		}
		for _, r := range c.line(ln) {
			report(prefix+"header:"+strconv.Itoa(i+1), r)
		}
		if cont && strings.HasPrefix(ln, " tagger ") { // the tagger of a merged signed tag
			if m := stampRE.FindStringSubmatch(ln); m == nil || m[1] != "+0000" {
				report(prefix+"header:"+strconv.Itoa(i+1), ruleZone)
			}
		}
	}
	for _, k := range need {
		if !seen[k] {
			return nil, fmt.Errorf("object without %s", k)
		}
	}
	return msg, nil
}
