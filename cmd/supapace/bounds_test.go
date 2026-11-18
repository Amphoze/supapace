package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLI_FileBound: a valid key set file over the bound is a usage error.
func TestCLI_FileBound(t *testing.T) {
	p := filepath.Join(t.TempDir(), "padded.json")
	os.WriteFile(p, append([]byte(`{"keys":[]}`), bytes.Repeat([]byte(" "), maxFile)...), 0o600)
	f := newFake(t, reply{202, accepted})
	if out, _, code := f.run(t, "project", "create", "--name", "d", "--issuer-jwks", p); code != 2 || out != "" || len(f.requests()) != 0 {
		t.Fatalf("exit %d stdout %q, %d requests", code, out, len(f.requests()))
	}
}

// TestCLI_ResponseBound: an oversized response is not printed.
func TestCLI_ResponseBound(t *testing.T) {
	f := newFake(t, reply{200, `{"projects":[],"x":"` + strings.Repeat("x", maxResponse) + `"}`})
	if out, _, code := f.run(t, "project", "list"); code != 1 || out != "" {
		t.Fatalf("exit %d, %d bytes on stdout", code, len(out))
	}
}
