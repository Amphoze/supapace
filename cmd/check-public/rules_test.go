package main

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Flagged strings are assembled at run time so this file passes the gate itself:
// q turns '~' into ':' and '!' into '@'; j joins its arguments with '.'.
func q(s string) string        { return strings.NewReplacer("~", ":", "!", "@").Replace(s) }
func j(parts ...string) string { return strings.Join(parts, ".") }

func testChecker(t *testing.T, deny []string, allow ...string) *checker {
	t.Helper()
	c := &checker{allow: map[string]bool{}}
	for _, d := range deny {
		c.deny = append(c.deny, regexp.MustCompile("(?i)"+d))
	}
	for _, a := range allow {
		c.allow[a] = true
	}
	return c
}

func TestRules_Line(t *testing.T) {
	pub, ver := j("8", "8", "4", "4"), j("17", "6", "1", "166")
	c := testChecker(t, []string{"zz" + "deny", "^start", "end$", "ünique"}, j("www", "apache", "org"), j("12", "34", "56", "78"))
	cases := []struct {
		line string
		want []string
	}{
		{"clean text", nil},
		// deny-list: case-insensitive, anchors bind to the line alone
		{"a ZZ" + "Deny b", []string{"deny-list"}},
		{"start here", []string{"deny-list"}},
		{"not start", nil},
		{"the end", []string{"deny-list"}},
		{"end here", nil},
		{"x ÜNIQUE y", []string{"deny-list"}},
		{"bad \xe9 byte zz" + "deny", []string{"deny-list"}},
		// e-mail: two exemptions only, removed before every rule
		{"mail a" + q("!") + j("b", "test"), []string{"e-mail"}},
		{"Co-Authored-By: X <noreply" + q("!") + j("anthropic", "com") + ">", nil},
		{"Co-Authored-By: X <12345+some-one" + q("!") + j("users", "noreply", "github", "com") + ">", nil},
		{"Signed-off-by: X <someone" + q("!") + j("users", "noreply", "github", "com") + ">", nil},
		{"Co-Authored-By: zz" + "deny <noreply" + q("!") + j("anthropic", "com") + ">", []string{"deny-list"}},
		{"Co-Authored-By: X <123+zz" + "deny" + q("!") + j("users", "noreply", "github", "com") + ">", []string{"deny-list"}},
		{"Co-Authored-By: X <zz" + "deny-dev" + q("!") + j("users", "noreply", "github", "com") + ">", []string{"deny-list"}},
		{"Co-Authored-By: " + pub + " <noreply" + q("!") + j("anthropic", "com") + ">", []string{"IPv4"}},
		{"noreply" + q("!") + j("anthropic", "com"), []string{"e-mail", "host name"}},
		{"<noreply" + q("!") + j("evil", "org") + ">", []string{"e-mail", "host name"}},
		// home paths
		{"cd /" + "home/alice/x", []string{"home path"}},
		{"cd /" + "home/alice", []string{"home path"}},
		{"cd /" + "Users/bob/x", []string{"home path"}},
		{`C:\` + `Users\carol\x`, []string{"home path"}},
		{"C:/" + "users/carol", []string{"home path"}},
		{"~/x and /homes/x and /var/lib and /home/", nil},
		// IPv4
		{"server " + pub + " here", []string{"IPv4"}},
		{"host" + q("~") + pub, []string{"IPv4"}},
		{"--add-host db" + q("~") + pub, []string{"IPv4"}},
		{"ip=" + pub, []string{"IPv4"}},
		{"http://" + pub + q("~8080"), []string{"IPv4"}},
		{"see " + pub + ".", []string{"IPv4"}},
		{pub + "/24", []string{"IPv4"}},
		{q("~~ffff~") + pub, []string{"IPv4", "IPv6"}},
		{j("010", "8", "8", "8"), []string{"IPv4"}},
		{j("192", "168", "1", "1"), []string{"IPv4"}},
		{j("172", "16", "0", "1"), []string{"IPv4"}},
		{j("10", "0", "0", "1"), []string{"IPv4"}},
		{j("10", "211", "255", "255"), []string{"IPv4"}},
		{j("10", "216", "0", "0"), []string{"IPv4"}},
		{j("169", "254", "1", "1"), []string{"IPv4"}},
		{j("100", "64", "0", "1"), []string{"IPv4"}},
		{j("224", "0", "0", "1"), []string{"IPv4"}},
		{j("10", "212", "0", "0") + " " + j("10", "215", "255", "255"), nil},
		{j("127", "0", "0", "1") + " " + j("169", "254", "169", "254"), nil},
		{j("0", "0", "0", "0") + " mask " + j("0", "0", "0", "63"), nil},
		{j("192", "0", "2", "1") + " " + j("198", "51", "100", "9") + " " + j("203", "0", "113", "250"), nil},
		{j("255", "255", "255", "0") + " " + j("255", "255", "255", "255") + " " + j("255", "128", "0", "0"), nil},
		{j("255", "0", "255", "0"), []string{"IPv4"}},
		{"supabase/postgres" + q("~") + ver, nil},
		{"v" + ver + " postgres-" + ver + " x." + pub + " ip" + pub, nil},
		{ver + "-rc1 " + pub + "a " + j("8", "8", "8", "8", "8"), nil},
		{"version " + ver, []string{"IPv4"}},
		{"allowed " + j("12", "34", "56", "78"), nil},
		{j("256", "1", "1", "1") + " " + j("999", "1", "1", "1"), nil},
		// IPv6
		{q("ip 2606~4700~~1111"), []string{"IPv6"}},
		{q("2606~4700~4700~0~0~0~0~1111"), []string{"IPv6"}},
		{q("addr~2606~4700~~1111"), []string{"IPv6"}},
		{q("db~2606~4700~~1111"), []string{"IPv6"}},
		{q("x2606~4700~~1111"), []string{"IPv6"}},
		{q("[2606~4700~~1111]~443 and 2606~4700~~1111%eth0"), []string{"IPv6"}},
		{q("~~ ~~1 0~~ 0~~1 fe80~~1 FEBF~~1 fd00~ec2~~254 2001~db8~~1 2001~DB8~~2 ~~ffff~10.212.0.5"), nil},
		{q("12~30~45 aa~bb~cc~dd~ee~ff std~~vector x~~bigint y~~date '{}'~~jsonb Self~~Error"), nil},
		{q("fd12~abcd~~1"), []string{"IPv6"}},
		{q("fc00~~1"), []string{"IPv6"}},
		{q("ff02~~1 ff02~~1~ff00~0/104 FF05~~2"), nil},
		{q("fe00~~1"), []string{"IPv6"}},
		{q("fec0~~1"), []string{"IPv6"}},
		{q("~~2"), []string{"IPv6"}},
		{q("~~ffff~808~808"), []string{"IPv6"}},
		// host names
		{"see " + j("api", "corp", "com"), []string{"host name"}},
		{j("Corp", "Example", "com") + " " + j("CORP", "IO"), []string{"host name"}},
		{j("my_host", "evil", "com"), []string{"host name"}},
		{j("host", "evil", "fr"), []string{"host name"}},
		{j("db", "local") + " " + j("cp", "internal"), nil},
		{"x.info x.app x.dev x.local x.home x.me x.to t.at o.no y.fr", nil},
		{j("mail", "corp", "fr"), []string{"host name"}},
		{j("db", "corp", "local"), []string{"host name"}},
		{j("a", "b", "internal"), []string{"host name"}},
		{j("x", "corp", "lan") + " " + j("x", "corp", "home"), []string{"host name"}},
		{j("mail", "Mycorp", "Com"), []string{"host name"}},
		{"https://" + j("Corp", "Com") + "/x", []string{"host name"}},
		{q("!") + j("Corp", "Com"), []string{"host name"}},
		{"see " + j("mycorp", "Com"), nil},
		{q("http~//") + j("mycorp", "dev") + "/x", []string{"host name"}},
		{"see " + j("mycorp", "dev"), nil},
		{j("a", "net") + " " + j("a", "io") + " " + j("a", "in") + " " + j("a", "co") + " " + j("a", "ai") + " " + j("a", "edu") + " " + j("a", "gov") + " " + j("a", "cloud"), []string{"host name"}},
		{"xn--" + j("abc", "corp", "com"), []string{"host name"}},
		{j("corp", "com") + q("~8080"), []string{"host name"}},
		{j("a", "sp", "test") + " " + j("b", "example") + " " + j("c", "invalid") + " " + j("d", "localhost"), nil},
		{"slog." + "Info(x) cfg.Run(y) README.md main.go x.sh y.py z.rs errors.Is", nil},
		{"new(big." + "Int) *big.Int reflect.Int time.Local) c.Info node.Home x.Top s.In", nil},
		{"http://" + j("www", "apache", "org") + "/licenses", nil},
		{"https://" + j("apache", "org"), []string{"host name"}},
	}
	for _, tc := range cases {
		if got := c.line(tc.line); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("line(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestDenyList_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, path := range map[string]string{
		"missing":       dir + "/absent",
		"directory":     dir,
		"empty":         write("empty", ""),
		"comments only": write("comments", "# only\n\n   # indented\n"),
		"bad regex":     write("bad", "[unclosed\nzz"+"deny\n"),
		"empty match":   write("emptymatch", "zz"+"deny\n^$\n"),
		"optional":      write("optional", "a*\n"),
	} {
		if _, err := loadDenyList(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	re, err := loadDenyList(write("crlf", "\ufeffzz"+"deny\r\n# c\r\n  ^word$  \n"))
	if err != nil || len(re) != 2 || !re[0].MatchString("ZZ"+"DENY") || !re[1].MatchString("word") || re[1].MatchString("a word") {
		t.Fatalf("crlf deny-list: %v %v", re, err)
	}
}

func TestAllowFile(t *testing.T) {
	got, err := parseAllow([]byte("\ufeff# header\n\n" + j("a", "b", "org") + "   # why\n"))
	if err != nil || !reflect.DeepEqual(got, map[string]bool{j("a", "b", "org"): true}) {
		t.Fatalf("allow = %v %v", got, err)
	}
	for _, bad := range []string{j("a", "b", "org") + "\n", "a b # two tokens\n"} {
		if _, err := parseAllow([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMessageLines_WholeFile(t *testing.T) {
	msg := "subject\r\n\n# kept\n# ------------------------ >8 ------------------------\nafter\n"
	got := messageLines([]byte(msg))
	want := []string{"subject", "", "# kept", "# ------------------------ >8 ------------------------", "after"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("messageLines = %q, want %q", got, want)
	}
}

func TestTexts_LinesAndUTF16(t *testing.T) {
	for in, want := range map[string][]string{
		"":         nil,
		"a\n":      {"a"},
		"a\r\nb":   {"a", "b"},
		"a\n\n":    {"a", ""},
		"\n":       {""},
		"x\x00y\n": {"x\x00y"},
	} {
		if got := texts([]byte(in)); !reflect.DeepEqual(got, [][]string{want}) && !(want == nil && reflect.DeepEqual(got, [][]string{nil})) {
			t.Errorf("texts(%q) = %q, want %q", in, got, want)
		}
	}
	le := []byte{0xff, 0xfe}
	for _, r := range "x zz" + "deny\r\ny\n" {
		le = append(le, byte(r), 0)
	}
	got := texts(le)
	if len(got) != 2 || !reflect.DeepEqual(got[1], []string{"x zz" + "deny", "y"}) {
		t.Fatalf("UTF-16LE: %q", got)
	}
	be := []byte{0xfe, 0xff, 0, 'q'}
	if got := texts(be); len(got) != 2 || !reflect.DeepEqual(got[1], []string{"q"}) {
		t.Fatalf("UTF-16BE: %q", got)
	}
}

func TestIdentity(t *testing.T) {
	c := testChecker(t, []string{"zz" + "deny"})
	gh := q("!") + j("users", "noreply", "github", "com")
	for in, want := range map[string][]string{
		"Some One <noreply" + q("!") + j("anthropic", "com") + ">": nil,
		"Some One <123+someone" + gh + ">":                         nil,
		"Some One <123+zz" + "deny" + gh + ">":                     {"deny-list"},
		"A <a" + q("!") + j("corp", "com") + ">":                   {"e-mail", "host name"},
		"zz" + "deny <x" + gh + ">":                                {"deny-list"},
	} {
		if got := c.identity(in); !reflect.DeepEqual(got, want) {
			t.Errorf("identity(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestHeader(t *testing.T) {
	c := testChecker(t, []string{"zz" + "deny"})
	id := "A <1+a" + q("!") + j("users", "noreply", "github", "com") + "> 1700000000 +0000"
	sig := "gpgsig -----BEGIN-----\n zz" + "deny\n -----END-----\n"
	cases := []struct {
		name, hdr string
		want      []string // locations reported
	}{
		{"clean", "tree abc\nparent def\nauthor " + id + "\ncommitter " + id + "\n" + sig, nil},
		{"mergetag", "author " + id + "\ncommitter " + id + "\nmergetag object abc\n type commit\n tag v3\n tagger " + id + "\n \n notes zz" + "deny\n", []string{"x:header:8"}},
		{"mergetag zone", "author " + id + "\ncommitter " + id + "\nmergetag object abc\n type commit\n tag v3\n tagger A <1+a" + q("!") + j("users", "noreply", "github", "com") + "> 1700000000 +0100\n \n notes\n", []string{"x:header:6"}},
		{"unknown header", "author " + id + "\ncommitter " + id + "\nx-extra zz" + "deny\n", []string{"x:header:3"}},
		{"encoding", "author " + id + "\ncommitter " + id + "\nencoding zz" + "deny\n", []string{"x:header:3"}},
		{"after identity", "author A <1+a" + q("!") + j("users", "noreply", "github", "com") + "> zz" + "deny 1700000000 +0000\ncommitter " + id + "\n", []string{"x:author"}},
		{"address after identity", "author A <1+a" + q("!") + j("users", "noreply", "github", "com") + "> " + j("8", "8", "8", "8") + " 1700000000 +0000\ncommitter " + id + "\n", []string{"x:author"}},
		{"duplicate author", "author zz" + "deny <b> 1 +0000\nauthor " + id + "\ncommitter " + id + "\n", []string{"x:author"}},
		{"skipped keys", "tree zz" + "deny\nparent zz" + "deny\nobject zz" + "deny\ntype zz" + "deny\nauthor " + id + "\ncommitter " + id + "\n" + strings.Replace(sig, "gpgsig", "gpgsig-sha256", 1), nil},
	}
	for _, tc := range cases {
		var got []string
		msg, err := c.header("x:", []byte(tc.hdr+"\nsubject\n"), []string{"author", "committer"}, func(loc, rule string) { got = append(got, loc) })
		if err != nil || string(msg) != "subject\n" || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: header = %q %v, reported %v, want %v", tc.name, msg, err, got, tc.want)
		}
	}
	if _, err := c.header("x:", []byte("tree abc\nauthor "+id+"\n\nx"), []string{"author", "committer"}, func(string, string) {}); err == nil {
		t.Fatal("commit without committer accepted")
	}
}

func TestHeader_TimeZone(t *testing.T) {
	c := testChecker(t, []string{"zz" + "deny"})
	for zone, want := range map[string][]string{
		" 1700000000 +0000": nil,
		" 1700000000 +0100": {"x:tagger time zone"},
		" 1700000000 -0000": {"x:tagger time zone"},
		"":                  {"x:tagger time zone"},
	} {
		var got []string
		_, err := c.header("x:", []byte("tag v1\ntagger A <b>"+zone+"\n\nm\n"), []string{"tagger"}, func(loc, rule string) { got = append(got, loc+" "+rule) })
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("zone %q: %v %v, want %v", zone, got, err, want)
		}
	}
}

func TestHome_Allow(t *testing.T) {
	h := "/" + "home/"
	c := testChecker(t, nil, h+"nonroot")
	for in, want := range map[string][]string{
		"ENV HOME=" + h + "nonroot":              nil,
		"cd " + h + "nonroot/x:" + h + "nonroot": nil,
		h + "nonroot2":                           {"home path"},
		h + "non":                                {"home path"},
		"/" + "Users/nonroot":                    {"home path"},
		h + "nonroot " + h + "alice":             {"home path"},
		`C:\` + `Users\nonroot`:                  {"home path"},
	} {
		if got := c.line(in); !reflect.DeepEqual(got, want) {
			t.Errorf("line(%q) = %v, want %v", in, got, want)
		}
	}
}
