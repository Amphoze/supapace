package nodecfg

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The pooler's row of images.lock, as the cache script reads it.
func supavisorRow(t *testing.T) lockEntry {
	t.Helper()
	var lock map[string]lockEntry
	if err := json.Unmarshal(imagesLock, &lock); err != nil {
		t.Fatal(err)
	}
	e, ok := lock["supavisor"]
	if !ok {
		t.Fatal("images.lock has no supavisor row")
	}
	return e
}

// dockerStub records every call in calls and answers what the cache script
// asks: the image store, a pull (one whose reference holds FAIL_PULL fails) and a save, which
// writes an archive whose index.json names the saved reference's digest as
// its manifest's, as a save without a platform does.
const dockerStub = `#!/bin/sh
echo "$*" >>"$CALLS"
case $1 in
info) echo '[[driver-type io.containerd.snapshotter.v1]]' ;;
pull) case $3 in *"${FAIL_PULL:-@@}"*) exit 1 ;; esac; echo "example.com/$3" ;;
save)
	d=$(mktemp -d)
	printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"%s","size":1,"annotations":{"io.containerd.image.name":"example.com/%s"}}]}' "${4#*@}" "$4" >"$d/index.json"
	tar -cf "$3" -C "$d" index.json
	rm -r "$d"
	;;
*) exit 9 ;;
esac
`

// cacheRun runs a copy of scripts/cache-images.sh beside the real lock, with
// the stub first on PATH; it returns the exit status, the output and the
// recorded docker calls.
func cacheRun(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	tree, stub := t.TempDir(), t.TempDir()
	src, err := os.ReadFile("../../scripts/cache-images.sh")
	if err != nil {
		t.Fatal(err)
	}
	for rel, b := range map[string][]byte{"scripts/cache-images.sh": src, "internal/nodecfg/images.lock": imagesLock} {
		p := filepath.Join(tree, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stub, "docker"), []byte(dockerStub), 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(t.TempDir(), "calls")
	cmd := exec.Command("bash", append([]string{filepath.Join(tree, "scripts/cache-images.sh")}, args...)...)
	cmd.Env = append(os.Environ(), "PATH="+stub+":"+os.Getenv("PATH"), "CALLS="+calls, "SP_POOLER=", "SP_DASH=")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	c, _ := os.ReadFile(calls)
	return code, string(out), string(c)
}

// archiveIndex is index.json of an archive.
func archiveIndex(t *testing.T, tar string) string {
	t.Helper()
	b, err := exec.Command("tar", "-xOf", tar, "index.json").Output()
	if err != nil {
		t.Fatalf("%s: %v", tar, err)
	}
	return string(b)
}

func readText(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCacheScript_PoolerArchiveInItsSubdirectoryAndLoadedOnlyWithPooler(t *testing.T) {
	e := supavisorRow(t)
	name := "supavisor-" + e.Digest[7:19] + ".tar"
	dir := t.TempDir()
	code, out, calls := cacheRun(t, []string{"SP_POOLER=1"}, dir)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if idx := archiveIndex(t, filepath.Join(dir, "pool", name)); !strings.Contains(idx, `"digest":"`+e.Digest+`"`) ||
		!strings.Contains(idx, `"io.containerd.image.name":"example.com/supabase/supavisor@`+e.Digest+`"`) {
		t.Errorf("pool/%s does not name the index: %s", name, idx)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Errorf("the pooler's archive is at the cache's top level (%v): every node would load it", err)
	}
	for _, l := range strings.Split(calls, "\n") {
		if strings.HasPrefix(l, "save") && strings.Contains(l, "--platform") {
			t.Errorf("saved for one platform: %s", l)
		}
	}
	if !strings.Contains(calls, "save -o "+filepath.Join(dir, "pool", name)+".tmp supabase/supavisor@"+e.Digest) {
		t.Errorf("not saved by the index:\n%s", calls)
	}
	// Control on the same path: without SP_POOLER the row is neither pulled nor saved.
	dir2 := t.TempDir()
	code, out, calls = cacheRun(t, nil, dir2)
	if code != 0 || strings.Contains(calls, "supavisor") {
		t.Fatalf("without SP_POOLER: exit %d\n%s\n%s", code, out, calls)
	}
	if _, err := os.Stat(filepath.Join(dir2, "pool")); !os.IsNotExist(err) {
		t.Errorf("pool/ made without SP_POOLER: %v", err)
	}
	if !strings.Contains(calls, "save -o "+filepath.Join(dir2, "postgrest-")) {
		t.Errorf("control: the other rows were not saved:\n%s", calls)
	}

	// node-init.sh loads pool/ only in a node started with POOLER=1, the
	// variable the Makefile passes to the node container, and never the
	// lab's own archive.
	ni := readText(t, "../../test/harness/node/node-init.sh")
	if !strings.Contains(ni, `[ "${POOLER:-}" = 1 ]`) || !strings.Contains(ni, "${pooler:+/images/pool/*.tar ") {
		t.Error("node-init.sh does not guard the load of /images/pool by POOLER=1")
	}
	if !strings.Contains(ni, "/images/pool/lab-*") {
		t.Error("node-init.sh would load the lab's archive")
	}
	if mk := readText(t, "../../Makefile"); !strings.Contains(mk, "-e POOLER=1") {
		t.Error("the Makefile does not pass POOLER=1 to the node container")
	}
	if lab := readText(t, "../../test/harness/experiments/pool-lab.sh"); !strings.Contains(lab, "pool/lab-supavisor-${SUPAVISOR_INDEX:7:12}-$arch.tar") {
		t.Error("pool-lab.sh does not write its archive under a name of its own")
	}
}

func TestCacheScript_PoolerPulledByTheIndexInPullOnly(t *testing.T) {
	e := supavisorRow(t)
	code, out, calls := cacheRun(t, []string{"SP_POOLER=1"}, "--pull-only")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(calls, "pull -q supabase/supavisor@"+e.Digest+"\n") {
		t.Errorf("not pulled by the index:\n%s", calls)
	}
	if strings.Contains(calls, "save") {
		t.Errorf("pull-only saved an archive:\n%s", calls)
	}
	code, out, calls = cacheRun(t, nil, "--pull-only")
	if code != 0 || strings.Contains(calls, "supavisor") || !strings.Contains(calls, "pull -q postgrest/postgrest@") {
		t.Errorf("without SP_POOLER: exit %d\n%s\n%s", code, out, calls)
	}
}

func TestCacheScript_AnArchiveSavedForOnePlatformIsReplaced(t *testing.T) {
	e := supavisorRow(t)
	ref := "supabase/supavisor@" + e.Digest
	plant := func(t *testing.T, dir, manifest string) string {
		t.Helper()
		d := t.TempDir()
		// As the lab saved it: the platform's manifest, annotated with the index's name.
		idx := `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + manifest +
			`","size":1,"annotations":{"io.containerd.image.name":"example.com/` + ref + `"},"platform":{"architecture":"amd64","os":"linux"}}]}`
		if err := os.WriteFile(filepath.Join(d, "index.json"), []byte(idx), 0o644); err != nil {
			t.Fatal(err)
		}
		tar := filepath.Join(dir, "pool", "supavisor-"+e.Digest[7:19]+".tar")
		os.MkdirAll(filepath.Dir(tar), 0o755)
		if b, err := exec.Command("tar", "-cf", tar, "-C", d, "index.json").CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, b)
		}
		return tar
	}
	t.Run("one platform's manifest: removed and saved again", func(t *testing.T) {
		dir := t.TempDir()
		tar := plant(t, dir, e.AMD64)
		code, out, calls := cacheRun(t, []string{"SP_POOLER=1"}, dir)
		if code != 0 || !strings.Contains(calls, "save -o "+tar+".tmp "+ref) {
			t.Fatalf("exit %d\n%s\n%s", code, out, calls)
		}
		if idx := archiveIndex(t, tar); !strings.Contains(idx, `"digest":"`+e.Digest+`"`) || strings.Contains(idx, e.AMD64) {
			t.Errorf("not replaced: %s", idx)
		}
	})
	t.Run("one platform's manifest and the pull fails: nothing loadable is left", func(t *testing.T) {
		dir := t.TempDir()
		tar := plant(t, dir, e.AMD64)
		if code, out, _ := cacheRun(t, []string{"SP_POOLER=1", "FAIL_PULL=supavisor"}, dir); code == 0 {
			t.Fatalf("a failed pull succeeded:\n%s", out)
		}
		if _, err := os.Stat(tar); !os.IsNotExist(err) {
			t.Errorf("the platform archive is still there: %v", err)
		}
	})
	t.Run("the index: kept", func(t *testing.T) {
		dir := t.TempDir()
		tar := plant(t, dir, e.Digest)
		before := archiveIndex(t, tar)
		code, out, calls := cacheRun(t, []string{"SP_POOLER=1"}, dir)
		if code != 0 || strings.Contains(calls, "supavisor") || !strings.Contains(out, "cached   "+ref) {
			t.Fatalf("exit %d\n%s\n%s", code, out, calls)
		}
		if archiveIndex(t, tar) != before {
			t.Error("a good archive was rewritten")
		}
	})
}

// A node started with POOLER=1 from a cache that holds no pooler archive (the
// lab's own does not count) stops before it loads anything, with one line
// naming the command that makes the archive.
func TestNodeInit_PoolerNodeWithoutTheArchiveStops(t *testing.T) {
	ni := readText(t, "../../test/harness/node/node-init.sh")
	if !strings.HasPrefix(ni, "#!/bin/sh\n# Boot sequence") {
		t.Fatal("node-init.sh does not start with its interpreter line")
	}
	guard := "if [ -n \"$pooler\" ]; then\n\tls /images/pool/*.tar 2>/dev/null | grep -qv '^/images/pool/lab-' || { log \"a node started with POOLER=1 has no pooler image archive: run make images POOLER=1\"; exit 1; }\nfi\n"
	i, j := strings.Index(ni, guard), strings.Index(ni, "\nloaded=0 refs=\n")
	if i < 0 || j < 0 || i > j {
		t.Error("node-init.sh does not stop a POOLER=1 node without the pooler's archive before the image load")
	}
}
