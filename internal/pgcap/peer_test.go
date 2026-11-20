//go:build !nopeer

package pgcap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

// In the product build the check of a socket's two addresses is on, and no
// file of that build can turn it off: the one assignment is in the file a
// build with the tag nopeer adds.
func TestPeerCheck_OnAndNothingTurnsItOff(t *testing.T) {
	if !peerCheck {
		t.Fatal("the address check is off in a build without the tag")
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range pkgs["pgcap"].Files {
		tagged := false
		for _, g := range f.Comments {
			if g.Pos() < f.Package && strings.Contains(g.Text(), "go:build nopeer") {
				tagged = true
			}
		}
		for _, c := range f.Comments {
			for _, l := range c.List {
				if strings.HasPrefix(l.Text, "//go:build") && strings.Contains(l.Text, "nopeer") && !strings.Contains(l.Text, "!nopeer") {
					tagged = true
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == "peerCheck" && !tagged {
						t.Errorf("%s assigns peerCheck in the product build", name)
					}
				}
			case *ast.UnaryExpr:
				if id, ok := n.X.(*ast.Ident); ok && n.Op == token.AND && id.Name == "peerCheck" {
					t.Errorf("%s takes the address of peerCheck", name)
				}
			}
			return true
		})
	}
}

// A socket from an address that is no peer of the class is closed at its
// accept — not kept until a deadline — whatever it sends: nothing of it is
// read, nothing is dialled, and it never holds a unit or a place.
func TestAccept_AStrangerIsClosedAtItsAccept(t *testing.T) {
	r := newRig(t, func(tb *Table) { withB(tb); tb.PreambleMS = 60000 })
	f := r.cluster(3)
	for _, from := range []byte{stranger, peerB} {
		t0 := time.Now()
		c := r.mustDial(from, "a", 3)
		c.Write(rigStartup)
		unanswered(t, c)
		if d := time.Since(t0); d > 20*time.Second {
			t.Fatalf(".%d: closed after %v — at a deadline, not at its accept", from, d)
		}
	}
	if u, pool := r.counts("a"); u != 0 || pool != 0 || f.count() != 0 {
		t.Fatalf("%d units, %d places, %d dials for sockets that are no peer's", u, pool, f.count())
	}
	if !strings.Contains(r.logs.String(), `"reason":"not a peer of the class"`) {
		t.Fatalf("log: %s", r.logs)
	}
}
