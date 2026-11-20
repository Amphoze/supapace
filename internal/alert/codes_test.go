package alert

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestCodes_EveryNoticeCodeOfTheStoreAndRunnerIsListed reads the notice codes
// the store and the backup runner raise from their source and fails when one
// is missing from the table: a code off the table is never delivered. A code
// the test cannot read (not a literal at the call, nor one of the forms below)
// fails too, so that a new raiser is looked at.
func TestCodes_EveryNoticeCodeOfTheStoreAndRunnerIsListed(t *testing.T) {
	fset := gotoken.NewFileSet()
	codes := map[string]string{} // code → where
	var unread []string
	for _, dir := range []string{"../store", "../backup"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			lit := func(e ast.Expr) (string, bool) {
				b, ok := e.(*ast.BasicLit)
				if !ok || b.Kind != gotoken.STRING {
					return "", false
				}
				s, err := strconv.Unquote(b.Value)
				return s, err == nil
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CompositeLit: // store.Gap{Cause: "…"}: a gap's cause is its notice's code
						if !strings.HasSuffix(types(x.Type), "Gap") {
							return true
						}
						for _, el := range x.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok && types(kv.Key) == "Cause" {
								if s, ok := lit(kv.Value); ok {
									codes[s] = fset.Position(kv.Pos()).String()
								}
							}
						}
					case *ast.AssignStmt: // failureNotice: n = "…"
						if fn.Name.Name == "failureNotice" && len(x.Lhs) == 1 && types(x.Lhs[0]) == "n" {
							if s, ok := lit(x.Rhs[0]); ok && s != "" {
								codes[s] = fset.Position(x.Pos()).String()
							}
						}
					case *ast.CallExpr:
						name := types(x.Fun)
						i := map[string]int{"Notice": 2, "st.Notice": 2, "notice": 3}[strings.TrimPrefix(name, "r.")]
						if i == 0 || len(x.Args) <= i {
							return true
						}
						if s, ok := lit(x.Args[i]); ok {
							codes[s] = fset.Position(x.Pos()).String()
							return true
						}
						where := fn.Name.Name + ":" + types(x.Args[i])
						switch where {
						case "Notice:code", "RecordPush:g.Cause", "failureNotice:n":
						default:
							unread = append(unread, fset.Position(x.Pos()).String()+" "+where)
						}
					}
					return true
				})
			}
		}
	}
	for _, u := range unread {
		t.Errorf("a notice code this test cannot read: %s", u)
	}
	if len(codes) < 5 {
		t.Fatalf("found only %v: the test no longer reads the raisers", codes)
	}
	for c, where := range codes {
		if _, known := Severity(c); !known {
			t.Errorf("notice code %q (%s) is not in the alert table", c, where)
		}
	}
}

// types renders a selector or identifier as written ("st.Notice", "g.Cause").
func types(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return types(x.X) + "." + x.Sel.Name
	}
	return ""
}
