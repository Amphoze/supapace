package nodecfg

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// makeN is what make would run for target with vars, joined into one text.
func makeN(t *testing.T, target string, vars ...string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	cmd := exec.Command("make", append([]string{"-n", target, "NODE=sp-t", "IMAGE_CACHE=/nonexistent/cache"}, vars...)...)
	cmd.Dir = "../.."
	// The Makefile takes these from the environment too.
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !slices.Contains([]string{"DASH", "POOLER", "NODE_MEM", "OUT_SUBNET", "S3_SLOT", "SP_OFFSITE", "PULL_ONLY", "MAKEFLAGS", "MAKELEVEL"}, k) {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %s %v: %v\n%s", target, vars, err, out)
	}
	return string(out)
}

// A public address inside any network of the node is refused, whichever
// network it is; the address beside each is accepted.
func TestValidate_PublicAddrInsideEachNodeNetwork(t *testing.T) {
	set := valid()
	set.EgressSubnet = "10.212.12.0/24"
	for name, c := range map[string]struct {
		cfg    Config
		inside string
	}{
		"project block":         {valid(), "10.213.255.254"},
		"platform subnet":       {valid(), "10.212.7.255"},
		"ingress subnet":        {valid(), "10.212.8.200"},
		"docker pool":           {valid(), "10.214.200.1"},
		"backup subnet":         {valid(), "10.212.9.77"},
		"default egress subnet": {valid(), "10.212.10.77"},
		"egress subnet as set":  {set, "10.212.12.77"},
	} {
		c.cfg.PublicAddrs = []string{c.inside}
		if err := c.cfg.Validate(); err == nil || !strings.Contains(err.Error(), "public_addrs: "+c.inside) {
			t.Errorf("%s: %s: %v, want it refused", name, c.inside, err)
		}
	}
	// Control on the same path: addresses beside the networks, and the
	// default egress subnet once another is set.
	set.PublicAddrs = []string{"10.212.10.77", "10.212.11.1", "10.215.0.1", "192.0.2.1"}
	if err := set.Validate(); err != nil {
		t.Errorf("control: %v", err)
	}
}

// The node sizes and what a pooler node is given, as make would run them.
func TestMakefile_PoolerNodeSizesLabAndRemoval(t *testing.T) {
	for _, c := range []struct {
		target string
		vars   []string
		mem    string
		pooler bool
	}{
		{"node-up", nil, "--memory 4g", false},
		{"node-up", []string{"DASH=1"}, "--memory 6g", false},
		{"node-up", []string{"POOLER=1"}, "--memory 6g", true},
		{"node-up", []string{"DASH=1", "POOLER=1"}, "--memory 8g", true},
		{"node-bare", []string{"POOLER=1"}, "--memory 6g", true},
		{"node-up", []string{"POOLER=1", "NODE_MEM=5"}, "--memory 5g", true},
	} {
		out := makeN(t, c.target, c.vars...)
		if !strings.Contains(out, c.mem+" ") {
			t.Errorf("%s %v: no %q", c.target, c.vars, c.mem)
		}
		for _, s := range []string{"-e POOLER=1 -e SP_POOLER_LABEL=db", "docker network create --label supapace.test=1 --internal",
			"sp-t-out", "--name sp-t-client --label supapace.test=1", "/var/lib/sp/outside"} {
			if strings.Contains(out, s) != c.pooler {
				t.Errorf("%s %v: %q present = %v, want %v", c.target, c.vars, s, !c.pooler, c.pooler)
			}
		}
	}
	// The default subnet is a /28 of the documentation range, the node at its
	// base + 8 and the client at base + 9; OUT_SUBNET replaces it.
	out := makeN(t, "node-up", "POOLER=1", "S3_SLOT=29")
	if !strings.Contains(out, "'198.51.100.240/28'") {
		t.Errorf("slot 29: not 198.51.100.240/28:\n%s", out)
	}
	out = makeN(t, "node-up", "POOLER=1", "OUT_SUBNET=203.0.113.32/28")
	for _, s := range []string{"--subnet '203.0.113.32/28'", "echo '203.0.113.32/28'"} {
		if !strings.Contains(out, s) {
			t.Errorf("OUT_SUBNET: no %q", s)
		}
	}
	// node-down removes the lab by its exact names, whatever the variables.
	for _, vars := range [][]string{nil, {"POOLER=1"}} {
		out := makeN(t, "node-down", vars...)
		for _, s := range []string{"docker network disconnect -f sp-t-out sp-t ", "docker rm -f -v sp-t-client ", "docker network rm sp-t-out "} {
			if !strings.Contains(out, s) {
				t.Errorf("node-down %v: no %q", vars, s)
			}
		}
		if strings.Contains(out, "--filter") || strings.Contains(out, "prune") {
			t.Errorf("node-down %v removes by a filter:\n%s", vars, out)
		}
	}
	// make reach asks the node for both facts; make images hands SP_POOLER on.
	for _, target := range []string{"reach", "reach-dash"} {
		out := makeN(t, target)
		for _, s := range []string{`grep -qs '"pooler_label"' /etc/supapace/node.json && echo --env SUPAPACE_POOLER=1`,
			"test -e /var/lib/sp/outside && echo --env SUPAPACE_OUTSIDE=1"} {
			if !strings.Contains(out, s) {
				t.Errorf("%s: no %q", target, s)
			}
		}
	}
	mk := readText(t, "../../Makefile")
	if !strings.Contains(mk, "ifneq ($(POOLER),)\nexport SP_POOLER := 1\nendif\n") {
		t.Error("the Makefile does not export SP_POOLER with POOLER=1")
	}
	if out := makeN(t, "images", "POOLER=1", "PULL_ONLY=1"); !strings.Contains(out, "deploy/pgcap/Dockerfile") || strings.Contains(out, "supapace-pgcap.tar") {
		t.Errorf("images POOLER=1 PULL_ONLY=1: the proxy's image is built and not saved:\n%s", out)
	}
	if out := makeN(t, "images"); strings.Contains(out, "deploy/pgcap/Dockerfile") {
		t.Errorf("images without DASH or POOLER names the proxy's image:\n%s", out)
	}
}

// node-init.sh in a node: the module list is written and nothing is loaded,
// and init is given the label only through the guard.
func TestNodeInit_ModuleListAndLabelText(t *testing.T) {
	ni := readText(t, "../../test/harness/node/node-init.sh")
	for _, s := range []string{
		`printf 'nf_conntrack_bridge\nnft_connlimit\n' >/etc/modules-load.d/supapace.conf`,
		`${label:+--pooler-label "$label"}`,
		`"$BIN/supapaced" init -h 2>&1 | grep -q -- '-pooler-label'`,
	} {
		if !strings.Contains(ni, s) {
			t.Errorf("node-init.sh: no %q", s)
		}
	}
	for i, l := range strings.Split(ni, "\n") {
		if s := strings.TrimSpace(l); !strings.HasPrefix(s, "#") && (strings.Contains(s, "modprobe") || strings.Contains(s, "insmod")) {
			t.Errorf("node-init.sh line %d loads a module: %s", i+1, s)
		}
	}
}

// An archive that holds the index under another image's name is not the
// row's: it is saved again.
func TestCacheScript_AnArchiveNamingAnotherImageIsReplaced(t *testing.T) {
	e := supavisorRow(t)
	dir, d := t.TempDir(), t.TempDir()
	idx := `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"` + e.Digest +
		`","size":1,"annotations":{"io.containerd.image.name":"example.com/other/image:1"}}]}`
	if err := os.WriteFile(filepath.Join(d, "index.json"), []byte(idx), 0o644); err != nil {
		t.Fatal(err)
	}
	tar := filepath.Join(dir, "pool", "supavisor-"+e.Digest[7:19]+".tar")
	os.MkdirAll(filepath.Dir(tar), 0o755)
	if b, err := exec.Command("tar", "-cf", tar, "-C", d, "index.json").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, b)
	}
	code, out, calls := cacheRun(t, []string{"SP_POOLER=1"}, dir)
	if code != 0 || !strings.Contains(calls, "save -o "+tar+".tmp supabase/supavisor@"+e.Digest) {
		t.Fatalf("exit %d\n%s\n%s", code, out, calls)
	}
	if idx := archiveIndex(t, tar); !strings.Contains(idx, `"io.containerd.image.name":"example.com/supabase/supavisor@`+e.Digest+`"`) {
		t.Errorf("not replaced: %s", idx)
	}
}

// make images POOLER=1 saves the wire proxy's archive beside the dashboard's;
// a pooler node without a studio domain must load that one archive too, or
// the proxy's image is not in the node.
func TestNodeInit_PoolerNodeLoadsTheProxyArchive(t *testing.T) {
	ni := readText(t, "../../test/harness/node/node-init.sh")
	if !regexp.MustCompile(`\$\{pooler:\+[^}]*/images/dash/supapace-pgcap\.tar[^}]*\}`).MatchString(ni) {
		t.Error("node-init.sh does not load /images/dash/supapace-pgcap.tar in a node started with POOLER=1")
	}
}

// Every script of the harness and the installation starts with its
// interpreter line and is executable: a line that slips in front of it passes
// a syntax check and every test that names the interpreter itself.
func TestScripts_StartWithTheirInterpreterLine(t *testing.T) {
	for rel, first := range map[string]string{
		"test/harness/node/node-init.sh":       "#!/bin/sh\n",
		"scripts/install-node.sh":              "#!/bin/sh\n",
		"scripts/cache-images.sh":              "#!/usr/bin/env bash\n",
		"test/harness/experiments/pool-lab.sh": "#!/usr/bin/env bash\n",
	} {
		p := filepath.Join("../..", rel)
		if s := readText(t, p); !strings.HasPrefix(s, first) {
			t.Errorf("%s does not start with %q", rel, first)
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode()&0o111 == 0 {
			t.Errorf("%s is not executable: %v", rel, err)
		}
	}
}
