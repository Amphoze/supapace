package pgsock

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// sharedChecks are the functions and constants of internal/pgwire the guard
// must use for every judgement of a server's message header, authentication
// subtype and SCRAM iteration count.
var sharedChecks = []string{
	"Header", "AuthSubtype", "ScramIterations",
	"AuthOK", "AuthCleartext", "AuthMD5", "AuthSASL", "AuthSASLContinue", "AuthSASLFinal",
}

// wireParsing lists what in a Go source reads the wire on its own, and the
// shared checks it never references. What it reports:
//   - an import of encoding/binary (byte-order decoding of lengths and
//     subtypes) or strconv (decimal reading or writing of a count);
//   - a shift or bitwise or/and with an operand that is not a literal
//     (big-endian decoding by hand);
//   - in a method of the guard, a comparison of a variable or of len() with a
//     non-zero integer literal, or a case on one (a length bound such as
//     len(b) < 4, or a subtype such as code == 10; the subtype 0 is held by
//     the required AuthOK; a library's verdict such as
//     subtle.ConstantTimeCompare(…) != 1 is not a reading);
//   - a string literal naming a server-first attribute ("r=", "s=", "i=") or
//     made of decimal digits only (an iteration count compared as text).
func wireParsing(t *testing.T, src []byte) (found []string, missing []string) {
	t.Helper()
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, "src.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	at := func(n ast.Node, what string) { found = append(found, fs.Position(n.Pos()).String()+": "+what) }
	used := map[string]bool{}
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "encoding/binary" || p == "strconv" {
			at(im, "imports "+p)
		}
	}
	nonZeroInt := func(e ast.Expr) bool {
		l, ok := e.(*ast.BasicLit)
		return ok && l.Kind == token.INT && l.Value != "0"
	}
	// read: a variable, or len() of one — not another call's result
	read := func(e ast.Expr) bool {
		c, ok := e.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := c.Fun.(*ast.Ident)
		return ok && id.Name == "len"
	}
	inGuard := func(fn *ast.FuncDecl) bool {
		if fn.Recv == nil || len(fn.Recv.List) != 1 {
			return false
		}
		s, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && id.Name == "guard"
	}
	var method bool
	ast.Inspect(f, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			method = inGuard(fn)
		}
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if x, ok := n.X.(*ast.Ident); ok && x.Name == "pgwire" {
				used[n.Sel.Name] = true
			}
		case *ast.BinaryExpr:
			_, lx := n.X.(*ast.BasicLit)
			_, ly := n.Y.(*ast.BasicLit)
			switch n.Op {
			case token.SHL, token.SHR, token.OR, token.AND:
				if !lx || !ly {
					at(n, "bit operation on a variable")
				}
			case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
				if method && (nonZeroInt(n.X) && read(n.Y) || nonZeroInt(n.Y) && read(n.X)) {
					at(n, "comparison with an integer literal")
				}
			}
		case *ast.CaseClause:
			for _, e := range n.List {
				if method && nonZeroInt(e) {
					at(e, "case on an integer literal")
				}
			}
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				s, _ := strconv.Unquote(n.Value)
				if strings.Contains(s, "r=") || strings.Contains(s, "s=") || strings.Contains(s, "i=") ||
					s != "" && strings.Trim(s, "0123456789") == "" {
					at(n, "literal "+n.Value)
				}
			}
		}
		return true
	})
	for _, name := range sharedChecks {
		if !used[name] {
			missing = append(missing, "pgwire."+name)
		}
	}
	return found, missing
}

// TestGuard_CallsTheSharedChecks: guard.go reads no message length, no
// authentication subtype and no iteration count itself, and it references
// every shared check of internal/pgwire. The control source holds each
// forbidden form once, the forms the rules leave alone, and none of the shared
// checks: the same inspection reports exactly the forbidden ones.
func TestGuard_CallsTheSharedChecks(t *testing.T) {
	control := []byte(`package x
import ("encoding/binary"; "strconv")
func (g *guard) f(b []byte, s string, n uint32) bool {
	n = uint32(b[0])<<24
	switch binary.BigEndian.Uint32(b) { case 10: }
	_ = strconv.Itoa(1)
	_ = len(b) < 4
	_ = n == 3
	_ = s == "i="
	_ = s == "4096"
	_ = 1 << 20
	_ = len(b) == 0 || cmp(b) != 1
	return false
}
func h(r rune) bool { return r < 0x20 }`)
	found, missing := wireParsing(t, control)
	want := []string{"src.go:2:9: imports encoding/binary", "src.go:2:28: imports strconv",
		"src.go:4:6: bit operation on a variable", "src.go:5:43: case on an integer literal",
		"src.go:7:6: comparison with an integer literal", "src.go:8:6: comparison with an integer literal",
		`src.go:9:11: literal "i="`, `src.go:10:11: literal "4096"`}
	if !slices.Equal(found, want) {
		t.Errorf("control: reported\n%q\nwant\n%q", found, want)
	}
	if len(missing) != len(sharedChecks) {
		t.Errorf("control: missing %q, want all %d shared checks", missing, len(sharedChecks))
	}

	src, err := os.ReadFile("guard.go")
	if err != nil {
		t.Fatal(err)
	}
	found, missing = wireParsing(t, src)
	for _, s := range found {
		t.Errorf("guard.go reads the wire itself: %s", s)
	}
	if len(missing) > 0 {
		t.Errorf("guard.go does not use %s", strings.Join(missing, ", "))
	}
}

// TestGuard_ServerFirstShortRefusedBeforeTheSalt: a server-first message of
// fewer than three fields is refused on its shape, before the salt is taken
// from its second field; the control, the platform's own message, logs in.
func TestGuard_ServerFirstShortRefusedBeforeTheSalt(t *testing.T) {
	for _, tc := range []struct {
		first string
		want  error
	}{
		{"", ErrScramParams}, {"r=NONCEsrv", ErrScramParams}, {"r=NONCEsrv,s=" + b64salt(), ErrScramParams},
		{"r=NONCEsrv,s=" + b64salt() + ",i=4096", nil},
	} {
		f := newFake(t, func(c *fconn) error {
			if tc.want == nil {
				return c.login()
			}
			return serverFirst(func(n string) string { return strings.ReplaceAll(tc.first, "NONCE", n) })(c)
		})
		c, err := dial(t, f.target(t))
		if c != nil {
			c.close()
		}
		f.result(t)
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("server-first %q: error %v, want %v", tc.first, err, tc.want)
		}
	}
}
