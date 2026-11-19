package agent

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/parser"
	"go/token"
	"math/big"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/jwtx"
)

// renderRecord is what the agent rendered for one container, normalised so
// that it does not depend on the test's directory or on the image lock: each
// written file below dir (its relative name, mode and SHA-256), then the
// create argv without the configuration label (a digest of the same inputs).
func renderRecord(a *Agent, f *fakeHost, dir string, argv []string) string {
	var lines []string
	f.mu.Lock()
	for p, w := range f.writes {
		if rel, err := filepath.Rel(dir, p); err == nil && !strings.HasPrefix(rel, "..") && rel != "state.json" {
			sum := sha256.Sum256(w.Data)
			lines = append(lines, fmt.Sprintf("file %s %o %s", rel, w.Mode, hex.EncodeToString(sum[:])))
		}
	}
	f.mu.Unlock()
	slices.Sort(lines)
	norm := strings.NewReplacer(a.p.Root, "<root>", a.cfg.Images.Postgres, "<postgres-image>", a.cfg.Images.PostgREST, "<postgrest-image>")
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--label" && i+1 < len(argv) && strings.HasPrefix(argv[i+1], labelConfig+"=") {
			i++
			continue
		}
		lines = append(lines, "arg "+norm.Replace(argv[i]))
	}
	return strings.Join(lines, "\n")
}

// fixedKey is a public key the token package accepts (an odd 2048-bit
// modulus), the same on every run.
func fixedKey() jwtx.Key {
	n := new(big.Int).Lsh(big.NewInt(1), 2047)
	return jwtx.Key{KID: "k1", Class: "anon", Pub: &rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: 65537}}
}

// The recordings were taken on the code before the operability fields
// existed. A change that means to alter a rendering re-records them; a zero
// OpsSpec must never be the cause.
const (
	recordedCluster = "a3c52bfb551e5ad945cdb5ad991f2eb19c82ebec89f5cf034d013df09a5a4f90"
	recordedREST    = "5a3abc83bdab8fe17f9dc64d9a11ae65be3e6cb4dea4482698fbccc6c2d80348"
)

func TestOpsSpec_ZeroValueChangesNoRenderedByte(t *testing.T) {
	digest := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

	t.Run("cluster", func(t *testing.T) {
		a, f, s, _ := clSetup(t)
		s.OpsSpec = OpsSpec{}
		clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
		if err := a.EnsureCluster(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		rec := renderRecord(a, f, a.p.RenderDir(s.Ref), clLastRun(t, f, "pg-"+s.Ref))
		if got := digest(rec); got != recordedCluster {
			t.Fatalf("cluster rendering %s, recorded %s:\n%s", got, recordedCluster, rec)
		}
	})
	t.Run("rest", func(t *testing.T) {
		a, f, s := newTestAgent(t)
		s.OpsSpec = OpsSpec{}
		s.Keys = []jwtx.Key{fixedKey()}
		s.UserRoles = []string{"authenticated"}
		s.Secrets.AuthenticatorPassword = "pw-authenticator-0123456789"
		healthy(a, f, s)
		writeSeccomp(t, a)
		if err := a.EnsurePostgREST(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		rec := renderRecord(a, f, a.p.RenderDir(s.Ref), prCreateArgv(t, f))
		if got := digest(rec); got != recordedREST {
			t.Fatalf("REST rendering %s, recorded %s:\n%s", got, recordedREST, rec)
		}
	})
}

// The file every later package compiles against imports the standard library
// only, so that it builds whatever else has merged.
func TestSpecOps_ImportsTheStandardLibraryOnly(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "spec_ops.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Imports) == 0 {
		t.Fatal("no imports read") // control: the file names net/netip
	}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
			t.Errorf("spec_ops.go imports %s", p)
		}
	}
}
