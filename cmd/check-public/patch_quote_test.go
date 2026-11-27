package main

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

// findings scans text as the blob at path and returns the rules broken per
// 1-based line (UTF-16 lines are keyed by their number plus 1000).
func findings(c *checker, path, text string) map[int][]string {
	got := map[int][]string{}
	c.blob("x", path, []byte(text), func(loc, rule string) {
		k := 0
		if s, ok := strings.CutSuffix(loc, " (UTF-16)"); ok {
			loc, k = s, 1000
		}
		n, _ := strconv.Atoi(loc[strings.LastIndex(loc, ":")+1:])
		got[n+k] = append(got[n+k], rule)
	})
	return got
}

// A hunk header in the commit message is not a hunk: git am keeps the message
// out of what it applies, so the patch applies whatever the "context" after
// it says, and the message is judged in full.
func TestQuoted_NoHunkBeforeTheDiff(t *testing.T) {
	mail, host := "dev"+q("!")+j("corp", "example", "com"), j("db", "corp", "example", "com")
	ls := []string{
		"From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001", // 1
		"Subject: [PATCH] x", // 2
		"",                   // 3
		"@@ -1,2 +1,2 @@",    // 4: in the message
		" ask " + mail,       // 5
		"-see " + host,       // 6
		"---",                // 7
		"diff --git a/f b/f", // 8
		"--- a/f",            // 9
		"+++ b/f",            // 10
		"@@ -1 +1 @@",        // 11
		"-a",                 // 12
		"+b",                 // 13
	}
	got := findings(testChecker(t, nil), "studio/patches/0001-x.patch", strings.Join(ls, "\n")+"\n")
	want := map[int][]string{5: {"e-mail", "host name"}, 6: {"host name"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines refused %v, want %v (the message's lines)", got, want)
	}
}

// On a quoted line every rule but the e-mail and host-name rules applies.
func TestQuoted_OtherRulesStillApply(t *testing.T) {
	code, pub := "qz"+"42", j("8", "8", "4", "4")
	ls := []string{
		"diff --git a/f b/f",          // 1
		"--- a/f",                     // 2
		"+++ b/f",                     // 3
		"@@ -1,5 +1,5 @@",             // 4
		" ip " + pub,                  // 5
		" ip " + q("2606~4700~~1111"), // 6
		" cd /" + "home/alice/x",      // 7
		" name sp-" + code + "-x",     // 8
		"-ip " + pub,                  // 9
		"+x",                          // 10
	}
	got := findings(testChecker(t, nil), "studio/patches/0001-x.patch", strings.Join(ls, "\n")+"\n")
	want := map[int][]string{5: {"IPv4"}, 6: {"IPv6"}, 7: {"home path"}, 8: {"short code"}, 9: {"IPv4"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines refused %v, want %v", got, want)
	}
}

// A line of a kind whose count is used up ends the hunk.
func TestQuoted_EachCountBoundsItsLines(t *testing.T) {
	for _, tc := range []struct {
		lines []string
		want  []bool
	}{
		{[]string{"@@ -1,2 +1,1 @@", "+a", "+b", "-c"}, []bool{false, false, false, false}}, // no new line left for +b
		{[]string{"@@ -1,1 +1,2 @@", "-a", "-b", "+c"}, []bool{false, true, false, false}},  // no old line left for -b
	} {
		if got := quoted(append([]string{"diff --git a/f b/f"}, tc.lines...)); !reflect.DeepEqual(got[1:], tc.want) {
			t.Errorf("quoted(%q) = %v, want %v", tc.lines, got, tc.want)
		}
	}
}

// A patch stored as UTF-16 is judged in full in its decoded text.
func TestQuoted_UTF16PatchJudgedInFull(t *testing.T) {
	mail := "dev" + q("!") + j("corp", "example", "com")
	text := "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n " + mail + "\n"
	u := utf16.Encode([]rune(text))
	b := []byte{0xff, 0xfe}
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	got := findings(testChecker(t, nil), "studio/patches/0001-x.patch", string(b))
	if want := []string{"e-mail", "host name"}; !reflect.DeepEqual(got[1005], want) {
		t.Errorf("decoded line 5 refused %v, want %v (all: %v)", got[1005], want, got)
	}
}

// One hex letter is not two: such a code is refused.
func TestRules_CodeOneHexLetter(t *testing.T) {
	c := testChecker(t, nil)
	for _, s := range []string{"fz" + "42", "zf" + "42", "FZ" + "42"} {
		if got := c.line(s); !reflect.DeepEqual(got, []string{"short code"}) {
			t.Errorf("line(%q) = %v, want the short-code rule", s, got)
		}
	}
}
