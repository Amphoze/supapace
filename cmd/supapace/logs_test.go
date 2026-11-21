package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/poolcfg"
)

const logsRef = "abcdefghij0123456789"

// The two commands make one read each; stdout is the body; the flags map to
// the query and nothing else.
func TestCLI_LogsRequests(t *testing.T) {
	body := `{"lines":[],"notes":[]}` + "\n"
	for _, c := range []struct {
		args []string
		uri  string
	}{
		{[]string{"project", "logs", logsRef}, "/v1/projects/" + logsRef + "/logs"},
		{[]string{"project", "logs", logsRef, "--container", "rest", "--tail", "20"}, "/v1/projects/" + logsRef + "/logs?container=rest&tail=20"},
		{[]string{"project", "logs", "--tail", "5", logsRef}, "/v1/projects/" + logsRef + "/logs?tail=5"},
		{[]string{"node", "logs", "--container", "pooler"}, "/v1/node/logs?container=pooler"},
		{[]string{"node", "logs", "--container", "platform-db", "--tail", "1000"}, "/v1/node/logs?container=platform-db&tail=1000"},
	} {
		f := newFake(t, reply{200, body})
		out, _, code := f.run(t, c.args...)
		if r := f.requests(); code != 0 || out != body || len(r) != 1 || r[0].method != "GET" || r[0].uri != c.uri {
			t.Errorf("%q: %d %q %+v", c.args, code, out, r)
		}
	}
	for _, args := range [][]string{{"node", "logs"}, {"node", "logs", "--container", ""}, {"node", "logs", "gateway"},
		{"project", "logs"}, {"project", "logs", logsRef, "--tail", "x"}, {"project", "logs", logsRef, logsRef}} {
		f := newFake(t, reply{200, body})
		if _, _, code := f.run(t, args...); code != 2 || len(f.requests()) != 0 {
			t.Errorf("%q: exit %d, %d requests", args, code, len(f.requests()))
		}
	}
	u := usageText()
	for _, s := range []string{"\n  project logs REF", "\n  node logs --container", "gateway, pooler, proxy or platform-db", "cluster or rest"} {
		if !strings.Contains(u, s) {
			t.Errorf("usage lacks %q", s)
		}
	}
}

// stderr lists every line, oldest first, as "<container> <time> | <text>",
// cleaned of control characters, then every note; stdout is the body
// unchanged.
func TestCLI_LogsListing(t *testing.T) {
	body := `{"lines":[{"container":"cluster","at":"2026-11-21T10:00:00.000000001Z","text":"LOG:  ready"},` +
		`{"container":"rest","at":"2026-11-21T10:00:00.000000002Z","text":"x\u001b[2Jy\r\nrest 2026 | forged"}],` +
		`"notes":["older lines not shown: the answer holds the newest 2 lines (--tail, at most 1000)"]}` + "\n"
	f := newFake(t, reply{200, body})
	out, errOut, code := f.run(t, "project", "logs", logsRef, "--tail", "2")
	if code != 0 || out != body {
		t.Fatalf("%d %q", code, out)
	}
	want := "cluster 2026-11-21T10:00:00.000000001Z | LOG:  ready\n" +
		"rest    2026-11-21T10:00:00.000000002Z | x[2Jyrest 2026 | forged\n" +
		"supapace: older lines not shown: the answer holds the newest 2 lines (--tail, at most 1000)\n"
	if errOut != want {
		t.Fatalf("stderr\n%s\nwant\n%s", errOut, want)
	}
	// No lines: said so.
	f = newFake(t, reply{200, `{"lines":[],"notes":["rest: the project has no such container on this node"]}` + "\n"})
	if _, errOut, code := f.run(t, "project", "logs", logsRef); code != 0 ||
		errOut != "supapace: no lines\nsupapace: rest: the project has no such container on this node\n" {
		t.Fatalf("%d %q", code, errOut)
	}
}

// A daemon that cannot serve logs yet: exit 1, its message, and what to do
// meanwhile on the node, by the container's name. Another refusal is its
// message alone.
func TestCLI_LogsNotAvailable(t *testing.T) {
	refusal := `{"code":"conflict","message":"logs are not available on this node: this daemon cannot read containers' logs yet"}` + "\n"
	for _, c := range []struct {
		args  []string
		names []string
	}{
		{[]string{"project", "logs", logsRef}, []string{"pg-" + logsRef, "postgrest-" + logsRef}},
		{[]string{"project", "logs", logsRef, "--container", "rest", "--tail", "7"}, []string{"postgrest-" + logsRef}},
		{[]string{"node", "logs", "--container", "proxy"}, []string{dashcfg.PgcapName}},
		{[]string{"node", "logs", "--container", "gateway"}, []string{"sp-gateway"}},
		// Only a ref in its valid form is repeated (the API refuses any other first).
		{[]string{"project", "logs", "Bad';x", "--container", "cluster"}, []string{"pg-REF"}},
	} {
		f := newFake(t, reply{409, refusal})
		out, errOut, code := f.run(t, c.args...)
		if code != 1 || out != refusal || !strings.HasPrefix(errOut, "supapace: logs are not available on this node") ||
			strings.Count(errOut, "docker logs") != len(c.names) {
			t.Errorf("%q: %d %q", c.args, code, errOut)
		}
		tail := map[bool]string{true: "7", false: "100"}[slices.Contains(c.args, "7")]
		for _, n := range c.names {
			if !strings.Contains(errOut, "'docker logs --timestamps --tail "+tail+" "+n+" 2>&1 | cat -v'") {
				t.Errorf("%q: no command for %s: %q", c.args, n, errOut)
			}
		}
	}
	f := newFake(t, reply{409, `{"code":"conflict","message":"the pooler does not run on this node (no container sp-pooler)"}` + "\n"})
	if _, errOut, code := f.run(t, "node", "logs", "--container", "pooler"); code != 1 ||
		errOut != "supapace: the pooler does not run on this node (no container sp-pooler)\n" {
		t.Fatalf("%d %q", code, errOut)
	}
	if got := []string{nodeContainer["pooler"], nodeContainer["platform-db"], nodeContainer["proxy"]}; !slices.Equal(got,
		[]string{poolcfg.PoolerName, poolcfg.PlatformDBName, dashcfg.PgcapName}) {
		t.Fatalf("names %q", got)
	}
}

// The command the hint gives must keep the container's standard error off
// the terminal too: docker logs writes it there, and the database logs there.
func TestCLI_LogsHintPassesBothStreamsThroughCatV(t *testing.T) {
	refusal := `{"code":"conflict","message":"logs are not available on this node: this daemon cannot read containers' logs yet"}` + "\n"
	for _, args := range [][]string{{"project", "logs", logsRef, "--container", "cluster"}, {"node", "logs", "--container", "pooler"}} {
		f := newFake(t, reply{409, refusal})
		_, errOut, _ := f.run(t, args...)
		if !strings.Contains(errOut, " 2>&1 | cat -v") {
			t.Errorf("%q: the hint lets standard error reach the terminal: %q", args, errOut)
		}
	}
	// Without a container, each of the two is a command of its own.
	f := newFake(t, reply{409, refusal})
	if _, errOut, _ := f.run(t, "project", "logs", logsRef); strings.Contains(errOut, "(or ") ||
		!strings.Contains(errOut, "pg-"+logsRef+" 2>&1") || !strings.Contains(errOut, "postgrest-"+logsRef+" 2>&1") {
		t.Errorf("both: %q", errOut)
	}
}
