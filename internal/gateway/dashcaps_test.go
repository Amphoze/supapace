package gateway

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashfile"
)

// capsRaceBuild reports whether the test binary was built with the race
// detector, whose bookkeeping would be counted as the loader's memory.
func capsRaceBuild() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" {
			return s.Value == "true"
		}
	}
	return false
}

// capsWorstFile is a legal dashboard file at every row cap with every string
// it can choose at its cap, written in "<", which the encoder writes as six
// bytes: the largest file the caps allow but for the issuer keys' moduli,
// which are real keys so that the loader takes them.
func capsWorstFile(t *testing.T, gen int64) []byte {
	t.Helper()
	long := func(n int, suffix string) string { return strings.Repeat("<", n-len(suffix)) + suffix }
	key := issuerKey(issuerSigner)
	f := dashfile.File{Generation: gen, Node: long(dashfile.MaxNodeBytes, ""), StudioDomain: studioDom,
		Studio: "http://10.212.0.3:3000", Projects: make(map[string]dashfile.Project, dashfile.MaxProjects),
		Issuer: &dashfile.Issuer{Iss: long(255, ""), ClientID: long(dashfile.MaxClientIDBytes, ""),
			AuthorizeURL: long(dashfile.MaxURLBytes, ""), EndSessionURL: long(dashfile.MaxURLBytes, ""), SessionSeconds: 28800}}
	for i := range dashfile.MaxKeys {
		f.Issuer.Keys = append(f.Issuer.Keys, dashfile.IssuerKey{Kid: long(dashfile.MaxKidBytes, fmt.Sprint(i)), Kty: "RSA", N: key.N, E: key.E})
	}
	for i := range dashfile.MaxRevocations {
		f.Revoked = append(f.Revoked, dashfile.Revocation{Iss: long(255, ""), Sub: long(255, fmt.Sprint(i)), NotBefore: 1<<62 + int64(i)})
	}
	perProject := dashfile.MaxMemberRows / dashfile.MaxProjects
	for p := range dashfile.MaxProjects {
		ms := make([]dashfile.Member, perProject)
		for i := range ms {
			ms[i] = dashfile.Member{Iss: long(255, ""), Sub: long(255, fmt.Sprint(i)), Role: "read_only"}
		}
		f.Projects[fmt.Sprintf("r%019d", p)] = dashfile.Project{Name: long(dashfile.MaxNameBytes, ""), Members: ms}
	}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// capsHeapEnv names, in the child process of the heap test, the gateway
// directory that holds the two files.
const capsHeapEnv = "SP_TEST_CAPS_HEAP_DIR"

// TestDashTable_AtTheCaps_GatewayHeap: the loader holds a table at the caps
// and reloads to a second one; the heap's growth across that one reload, the
// old and the new table both held, stays under 128 MiB.
//
// The reload runs in a child process whose heap holds nothing else, with the
// collector run, stopping the world, at every 10 % of growth, so that the heap
// follows what is live whatever the machine's load: the stdlib decoder's
// transient buffers are garbage; the read buffer, the parsed file and the
// built table are not. The heap's mapped size never shrinks, so at the end it
// is at least the reload's peak; less what was live before the reload, that
// bounds the growth from above. A loader that grew its buffer by
// re-allocation would hold the file several times over and fail it.
func TestDashTable_AtTheCaps_GatewayHeap(t *testing.T) {
	if dir := os.Getenv(capsHeapEnv); dir != "" {
		capsHeapChild(dir)
		return
	}
	if testing.Short() {
		t.Skip("writes and loads two files of the largest legal size")
	}
	if capsRaceBuild() {
		t.Skip("the race detector's memory is not the gateway's; run without -race")
	}
	dir, _ := dashDir(t)
	b := capsWorstFile(t, 1)
	if len(b) < dashfile.MaxBytes*97/100 {
		t.Fatalf("the fixture is %d bytes, not near the worst case", len(b))
	}
	put(t, filepath.Join(dir, "dashboard.json"), b)
	put(t, filepath.Join(dir, "dashboard.json.2"), capsWorstFile(t, 2))
	cmd := exec.Command(os.Args[0], "-test.run=^TestDashTable_AtTheCaps_GatewayHeap$", "-test.count=1")
	cmd.Env = append(os.Environ(), capsHeapEnv+"="+dir, "GOGC=10", "GOMEMLIMIT=off", "GODEBUG=gcstoptheworld=1")
	out, err := cmd.CombinedOutput()
	var live, sys, alloc uint64
	_, rest, _ := bytes.Cut(out, []byte("caps-heap "))
	if _, serr := fmt.Sscanf(string(rest), "%d %d %d", &live, &sys, &alloc); err != nil || serr != nil {
		t.Fatalf("child: %v %v\n%s", err, serr, out)
	}
	growth := sys - live
	t.Logf("file %d bytes; live before the reload %.1f MiB; heap's peak growth at most %.1f MiB; allocated during it %.1f MiB",
		len(b), float64(live)/(1<<20), float64(growth)/(1<<20), float64(alloc)/(1<<20))
	if growth >= 128<<20 {
		t.Errorf("the heap grew by up to %.1f MiB across the reload, want under 128 MiB", float64(growth)/(1<<20))
	}
}

// capsHeapChild loads dashboard.json, replaces it by dashboard.json.2 and
// reloads, then prints what was live before the reload, the heap's mapped size
// after it, and what the reload allocated. Any failure is printed instead.
func capsHeapChild(dir string) {
	fail := func(err error) { fmt.Println("caps-heap failed:", err) }
	d := LoadDashboard(dir)
	if d == nil || d.broken != nil {
		fail(fmt.Errorf("dashboard not loaded"))
		return
	}
	if err := d.table.Reload(); err != nil {
		fail(err)
		return
	}
	old := d.table.cur.Load()
	if err := os.Rename(filepath.Join(dir, "dashboard.json.2"), filepath.Join(dir, "dashboard.json")); err != nil {
		fail(err)
		return
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := d.table.Reload()
	runtime.ReadMemStats(&after)
	cur := d.table.cur.Load()
	runtime.KeepAlive(old)
	if err != nil || cur.file.Generation != 2 || len(cur.roles) != dashfile.MaxProjects || len(cur.notBefore) != dashfile.MaxRevocations {
		fail(fmt.Errorf("second table: %v", err))
		return
	}
	fmt.Printf("caps-heap %d %d %d\n", before.HeapAlloc, after.HeapSys, after.TotalAlloc-before.TotalAlloc)
}
