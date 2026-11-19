package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

func runOut(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestStubMain_UnknownSubcommandExits2(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}, {""}, {"-h"}} {
		code, out, errs := runOut(args...)
		if code != 2 || out != "" || !strings.Contains(errs, "usage") {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", args, code, out, errs)
		}
	}
	// Control: a known sub-command runs.
	if code, _, _ := runOut("limits"); code != 0 {
		t.Fatalf("limits: exit %d", code)
	}
}

func TestStubLimits_JSONAndNames(t *testing.T) {
	code, out, _ := runOut("limits")
	if code != 0 || out != dashcfg.Limits.StudioJSON()+"\n" {
		t.Fatalf("limits: %d %q", code, out)
	}
	code, out, _ = runOut("limits", "--names")
	if code != 0 {
		t.Fatalf("limits --names: exit %d", code)
	}
	var names struct{ Fixed, Listener []string }
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&names); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names.Fixed, dashcfg.FixedEnvNames()) || !slices.Equal(names.Listener, dashcfg.ListenerNames) {
		t.Fatalf("names = %+v", names)
	}
	if !strings.HasPrefix(out, `{"fixed":[`) || !slices.Contains(names.Fixed, "SUPAPACE_LIMITS") || len(names.Listener) != 6 {
		t.Fatalf("names output %q", out)
	}
	for _, args := range [][]string{{"limits", "--bogus"}, {"limits", "extra"}} {
		if code, out, _ := runOut(args...); code != 2 || out != "" {
			t.Errorf("%q: exit %d, stdout %q", args, code, out)
		}
	}
}
