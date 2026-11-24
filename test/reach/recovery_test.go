//go:build reach

package reach

// Recovery of the control plane from the escrow set alone: the node is
// wiped — every container, /etc/supapace, the projects and the repository
// filesystems, everything else under /var/lib/supapace — and brought back by
// `supapaced recover` with the two escrow parts the test saved, `init` and
// `offsite set`; then the projects are restored from the object store. It is a
// drill: every phase's duration is logged.
//
// What the object store holds is not trusted: beside the honest objects the
// control-plane bucket holds another control-plane database's objects under
// another stanza name, a history of a timeline far above every real one, and,
// at the key of a control-plane segment the replicator had not uploaded, a
// copy of another valid segment of the stanza (the honest upload of that
// segment would be refused: the stand-in stays paused until the wipe); A's
// prefix holds 5,000 objects of a set that does not exist. Each negative
// stands next to a control on the same path.
//
// The wipe is the replaced node: /etc/supapace and everything under
// /var/lib/supapace are removed but for the two filesystems, which are
// emptied. Kept, as on a node an operator prepares: the images (so the worker
// image archive option of recover is not exercised), the kernel tables, the
// quota limits and /run.
//
// It destroys the node's state by design, so it runs last, in an invocation
// of its own: the suite's run passes -test.skip '^TestReach27_WipedNode$',
// then a second run selects it alone with SUPAPACE_WIPE_NODE=1. Without that
// switch it skips, or fails where SUPAPACE_BACKUP=1 says every backup test
// must run. A failure after the plant or the wipe leaves a node and a
// stand-in to recreate (make node-down, node-up): the planted objects stay
// locked for a day.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/s3x"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/Amphoze/supapace/internal/walname"
)

// ───────── helpers of the wiped-node test ─────────

const (
	wipeEnv      = "SUPAPACE_WIPE_NODE" // set: the wiped-node drill may run (alone, last)
	wnPauseTable = "reach_standin"      // inet table that keeps job traffic from the stand-in
	recoverWait  = 40 * time.Minute
	reportLine   = "memberships, session revocations and service keys are as of the recovered point"
	partlyRefuse = "partly declared"
)

// wnStep logs a phase of the drill with its duration.
func wnStep(t testing.TB, what string, since time.Time) time.Time {
	t.Helper()
	now := time.Now()
	t.Logf("drill: %s: %v", what, now.Sub(since).Round(time.Second))
	return now
}

// wnDaemon runs `supapaced ARGS…` and returns the run; a deadline or a failure
// to start fails the test.
func wnDaemon(t testing.TB, timeout time.Duration, args ...string) result {
	t.Helper()
	r, err := run(timeout, nil, append([]string{daemonBin}, args...)...)
	if err != nil {
		t.Fatalf("supapaced %s: %v", strings.Join(args[:min(2, len(args))], " "), err)
	}
	return r
}

// wnStore opens the control-plane store the way the daemon does.
func wnStore(t testing.TB) *store.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(paths.CPDir(), "sock"))
	if err != nil {
		t.Fatalf("control-plane store: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func wnCtx(t testing.TB, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// wnS3x is the suite's stand-in client of role (s3Client), without its configuration.
func wnS3x(t testing.TB, role string) *s3x.Client {
	t.Helper()
	cl, _ := s3Client(t, role)
	return cl
}

// wnVersions lists every version and delete marker under prefix (at most 64
// pages).
func wnVersions(t testing.TB, cl *s3x.Client, prefix string) []s3x.Object {
	t.Helper()
	ctx := wnCtx(t, 5*time.Minute)
	var out []s3x.Object
	key, ver := "", ""
	for range 64 {
		page, nk, nv, err := cl.ListVersions(ctx, prefix, key, ver)
		if err != nil {
			t.Fatalf("listing %q: %v", prefix, err)
		}
		out = append(out, page...)
		if nk == "" && nv == "" {
			return out
		}
		key, ver = nk, nv
	}
	t.Fatalf("listing %q: more than 64 pages", prefix)
	return nil
}

// wnPut creates key by conditional create: it fails when the key exists.
func wnPut(t testing.TB, cl *s3x.Client, key string, body []byte) (versionID string) {
	t.Helper()
	v, err := cl.Put(wnCtx(t, time.Minute), key, body, nil, true)
	if err != nil {
		t.Fatalf("put %q: %v", key, err)
	}
	return v
}

// wnOp is one `op show` of operation id.
func wnOp(t testing.TB, id int64) Op {
	t.Helper()
	out, code := cli(t, "op", "show", strconv.FormatInt(id, 10))
	var op Op
	decode(t, "op show", out, &op)
	if code != 0 || op.ID != id {
		t.Fatalf("op show %d: exit %d", id, code)
	}
	return op
}

func wnRandom(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// wnSegNo is a 24-hex-digit segment name's number (16 MiB segments); wnSegName
// is its inverse on timeline tli.
func wnSegNo(name string) uint64 {
	log, _ := strconv.ParseUint(name[8:16], 16, 32)
	seg, _ := strconv.ParseUint(name[16:24], 16, 32)
	return log*256 + seg
}

func wnSegName(tli uint32, no uint64) string { return fmt.Sprintf("%08X%08X%08X", tli, no/256, no%256) }

// wnHold creates the hold file without stopping the running daemon, so that
// a daemon that exits is not started again. release removes it and waits for
// the daemon (also a cleanup).
func wnHold(t testing.TB) (release func()) {
	t.Helper()
	if err := os.WriteFile(holdFile, nil, 0o600); err != nil {
		t.Fatalf("hold file: %v", err)
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			if err := os.Remove(holdFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("releasing the hold: %v", err)
				return
			}
			for deadline := time.Now().Add(2 * time.Minute); !daemonUp(); time.Sleep(200 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Errorf("the daemon did not come back within 2 minutes of the hold's end")
					return
				}
			}
		})
	}
	t.Cleanup(release)
	return release
}

// wnPause keeps every forwarded packet from the stand-in's addresses — the
// path of the node's job containers — while the node's own namespace, where
// the test writes, still reaches it. The returned function (also a cleanup)
// removes the table.
func wnPause(t testing.TB) (resume func()) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s3Dir, "addrs"))
	if err != nil {
		t.Fatalf("object-store stand-in: %v", err)
	}
	var addrs []string
	for _, a := range strings.Fields(string(b)) {
		if _, err := netip.ParseAddr(a); err != nil {
			t.Fatalf("object-store stand-in: address %q", a)
		}
		addrs = append(addrs, a)
	}
	var once sync.Once
	resume = func() {
		once.Do(func() {
			if r, err := run(cmdTimeout, nil, "nft", "delete", "table", "inet", wnPauseTable); err != nil ||
				(r.code != 0 && !strings.Contains(r.stderr, "No such file")) {
				t.Errorf("removing the stand-in pause: %v %s", err, brief(r.stderr))
			}
		})
	}
	t.Cleanup(resume)
	must(t, cmdTimeout, "nft", "add", "table", "inet", wnPauseTable)
	must(t, cmdTimeout, "nft", "add", "chain", "inet", wnPauseTable, "fwd", "{ type filter hook forward priority -50 ; policy accept ; }")
	must(t, cmdTimeout, "nft", "add", "rule", "inet", wnPauseTable, "fwd", "ip", "daddr", "{ "+strings.Join(addrs, ", ")+" }", "drop")
	return resume
}

// wnCreate creates a project at the node's default layout (--no-wait, its
// removal a cleanup at once). With wait it must end done and the full Project
// is returned; else only Ref is set. It also returns the create's operation.
func wnCreate(t testing.TB, wait bool) (Project, int64) {
	t.Helper()
	priv, kid, jwks := newIssuer(t)
	out, code := cli(t, "project", "create", "--name", scratchName, "--issuer-jwks", jwks, "--no-wait")
	var m mutationJSON
	if json.Unmarshal([]byte(out), &m) != nil || m.Ref == "" || code != 0 {
		t.Fatalf("project create: exit %d, no ref", code)
	}
	t.Cleanup(func() { removeProject(t, m.Ref) })
	if !wait {
		return Project{Ref: m.Ref, Issuer: priv, IssuerKID: kid}, m.OperationID
	}
	if op := waitOp(t, m.OperationID); op.State != "done" {
		t.Fatalf("create %s: %s at step %q: %s", m.Ref, op.State, op.Step, op.LastError)
	}
	return loadProject(t, m.Ref, priv, kid), m.OperationID
}

// wnRestore restores ref (ARGS as `project restore` takes them) and waits up
// to within; the operation must end done. It returns the restore's result.
func wnRestore(t testing.TB, ref string, within time.Duration, args ...string) restoreResultJSON {
	t.Helper()
	ro := restoreLong(t, ref, within, args...)
	if ro.State != "done" {
		t.Fatalf("restore %s %v: operation %d %s at step %q: %s", ref, args, ro.ID, ro.State, ro.Step, ro.LastError)
	}
	var rr restoreResultJSON
	if err := json.Unmarshal(ro.Result, &rr); err != nil {
		t.Fatalf("restore %s: result: %v", ref, err)
	}
	return rr
}

// wnWaitReplicated waits until ref's replication last ended complete after
// after.
func wnWaitReplicated(t testing.TB, ref string, after time.Time) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Minute); ; time.Sleep(2 * time.Second) {
		b := backups(t, ref)
		if b.Replication.LastOK != nil {
			if at, err := time.Parse(time.RFC3339Nano, *b.Replication.LastOK); err == nil && at.After(after) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("project %s: no complete replication after %v within 15 minutes", ref, after)
		}
	}
}

// wnWaitRebuilt waits until ref's record is rebuilt in epoch (the store's
// rebuild epoch reached, no page pending) and holds at least least rows. The
// shown rebuilding flag alone is false before a rebuild starts as well.
func wnWaitRebuilt(t testing.TB, st *store.Store, ref string, epoch, least int64) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Minute); ; time.Sleep(5 * time.Second) {
		bs, err := st.GetBackupState(wnCtx(t, 30*time.Second), ref)
		if err != nil {
			t.Fatalf("backup state of %s: %v", ref, err)
		}
		b := backups(t, ref)
		if bs.RebuildEpoch >= epoch && bs.RebuildPages == 0 && bs.RebuildKeyMarker == "" && b.Replication.ObjectsRecorded >= least {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("project %s: record not rebuilt in epoch %d within 30 minutes (rebuild epoch %d, %d pages, %d rows, want at least %d)",
				ref, epoch, bs.RebuildEpoch, bs.RebuildPages, b.Replication.ObjectsRecorded, least)
		}
	}
}

// wnScrub is out for a failure message: every form of every secret of
// needles replaced by its name, then redacted and cut.
func wnScrub(out string, needles []needle) string {
	for _, n := range needles {
		for _, f := range n.b {
			if len(f) > 0 {
				out = strings.ReplaceAll(out, string(f), "<"+n.name+">")
			}
		}
	}
	return brief(redact(out))
}

// wnStarted reports whether evs holds a container start.
func wnStarted(evs []jobEvent) bool {
	return slices.ContainsFunc(evs, func(e jobEvent) bool { return e.action == "start" })
}

// wnHistoriesAbove lists the history files of dir (not followed through a link)
// whose timeline is above tli.
func wnHistoriesAbove(t testing.TB, dir string, tli uint32) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []string
	for _, e := range ents {
		if k, tl, ok := walname.Spool(e.Name()); ok && k == walname.History && tl > tli {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// wnEmpty removes every entry of dir except keep.
func wnEmpty(t testing.TB, dir string, keep ...string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("wipe: %v", err)
	}
	for _, e := range ents {
		if slices.Contains(keep, e.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			t.Fatalf("wipe: %v", err)
		}
	}
}

func wnEntries(t testing.TB, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// wnWipe makes the node a replaced one: every container, network and volume
// of its Docker removed; /etc/supapace removed; the projects and repository
// filesystems emptied; every other entry of /var/lib/supapace removed. Images
// stay (the installation's), and so do the harness's files.
func wnWipe(t testing.TB) {
	t.Helper()
	if ids := strings.Fields(docker(t, "ps", "-aq")); len(ids) > 0 {
		docker(t, append([]string{"rm", "-f", "-v"}, ids...)...)
	}
	for name := range strings.Lines(docker(t, "network", "ls", "--format", "{{.Name}}")) {
		if n := strings.TrimSpace(name); n != "" && n != "bridge" && n != "host" && n != "none" {
			docker(t, "network", "rm", n)
		}
	}
	if vs := strings.Fields(docker(t, "volume", "ls", "-q")); len(vs) > 0 {
		docker(t, append([]string{"volume", "rm"}, vs...)...)
	}
	if err := os.RemoveAll(filepath.Dir(paths.NodeJSON())); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if err := os.Remove(paths.Failpoint()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("wipe: %v", err)
	}
	wnEmpty(t, paths.ProjectsDir())
	wnEmpty(t, paths.RepoRoot())
	wnEmpty(t, filepath.Dir(paths.ProjectsDir()), filepath.Base(paths.ProjectsDir()), filepath.Base(paths.RepoRoot()))
	if ids := strings.Fields(docker(t, "ps", "-aq")); len(ids) > 0 {
		t.Fatalf("wipe: containers remain: %v", ids)
	}
	for _, d := range []string{paths.ProjectsDir(), paths.RepoRoot()} {
		if n := wnEntries(t, d); len(n) > 0 {
			t.Fatalf("wipe: %s still holds %v", d, n)
		}
	}
}

// wnNoSecret fails the test when out holds one of needles' forms.
func wnNoSecret(t testing.TB, what, out string, needles []needle) {
	t.Helper()
	for _, n := range needles {
		if containsAny([]byte(out), n.b) >= 0 {
			t.Errorf("%s prints %s", what, n.name)
		}
	}
}

// wnSecretKey is the secret key (second line) of a stand-in identity.
func wnSecretKey(t testing.TB, role string) needle {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s3Dir, role+".keys"))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		t.Fatalf("%s.keys holds %d fields", role, len(f))
	}
	return needle{"the secret key of " + role, [][]byte{[]byte(f[1])}}
}

// ───────── test 27 ─────────

// TestReach27_WipedNode is the recovery drill: the control plane recovered
// from the escrow set alone on a wiped node, then the projects restored from
// the object store. Fails if the escrow set does not bring the node back; if the
// recovery takes another control-plane database's objects, passes over the
// planted segment without stopping, or promotes after its serve job was
// killed; if it accepts a key that is not the escrowed one or runs on a node
// that still has its database; if the recovered store leaves an operation
// open (but the purge), keeps the create held at the wipe, or loses the purge
// obligation; if a job creates a project's path before the store is declared;
// or if A, the finished create and B cannot be restored from the object store.
//
// It runs last and alone (see the file's head): every later test of the same
// invocation would find a recovered node, or a broken one.
func TestReach27_WipedNode(t *testing.T) {
	// The test wipes the node: it runs only in the test node, whose supervisor
	// honours the hold file — never on a host install. First, before anything
	// is asked of the node or registered.
	if _, err := os.Stat("/run/sp-node-ready"); err != nil || os.Getenv("SUPAPACE_HOST") == "1" {
		t.Skip("wipes the node's state: runs only in the test node (make node-up), never on a host")
	}
	needBackups(t)
	needStandin(t)
	if os.Getenv(wipeEnv) != "1" {
		msg := "wipes the node: run it alone and last, with " + wipeEnv + "=1"
		if os.Getenv(backupEnv) == "1" {
			t.Fatalf("%s (%s=1 is set: -test.skip it in the suite's run instead)", msg, backupEnv)
		}
		t.Skip(msg)
	}
	A, B := fixtureAB(t)
	start := time.Now()
	step := start
	wiped, poisoned := false, false
	// Last cleanup: the fixtures serve again for the tests that follow.
	t.Cleanup(func() {
		if poisoned && t.Failed() {
			t.Errorf("a control-plane segment is planted in the stand-in: recreate the node and its stand-in (make node-down, node-up)")
		}
		if !daemonUp() {
			t.Errorf("the daemon does not answer; the node must be recreated (make node-down, node-up)")
			return
		}
		for _, p := range []Project{A, B} {
			out, code := cli(t, "project", "show", p.Ref)
			var pj projectJSON
			if code != 0 || json.Unmarshal([]byte(out), &pj) != nil {
				continue
			}
			if pj.State == "active" && wnRunning(t, pgName(p)) {
				continue
			}
			args := []string{"project", "restore", p.Ref, "--to", "latest"}
			if wiped {
				args = append(args, "--from", "offsite")
			}
			if out, code := cli(t, args...); code != 0 {
				t.Errorf("fixture %s (%s) not restored after the test: exit %d %s", p.Ref, pj.State, code, brief(redact(out)))
			}
		}
	})

	// ── the escrow set, shown and saved ──
	dir := t.TempDir()
	kekFile, restFile := filepath.Join(dir, "escrow-kek.json"), filepath.Join(dir, "escrow-rest.json")
	parts := map[string][]byte{}
	for _, part := range []string{"kek", "rest"} {
		r := wnDaemon(t, cmdTimeout, "escrow", "show", "--part", part)
		if r.code != 0 {
			t.Fatalf("supapaced escrow show --part %s: exit %d: %s", part, r.code, brief(r.stderr))
		}
		parts[part] = []byte(r.stdout)
	}
	if err := os.WriteFile(kekFile, parts["kek"], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restFile, parts["rest"], 0o600); err != nil {
		t.Fatal(err)
	}
	esc, err := offsite.ParseEscrow(bytes.TrimSpace(parts["kek"]), bytes.TrimSpace(parts["rest"]))
	if err != nil {
		t.Fatalf("the escrow parts do not parse: %v", err)
	}
	kek, err := secrets.LoadKEK(paths.KEK())
	if err != nil {
		t.Fatal(err)
	}
	st := wnStore(t)
	cpState, err := st.GetBackupState(wnCtx(t, 30*time.Second), "cp")
	if err != nil {
		t.Fatalf("backup state of cp: %v", err)
	}
	stanza := esc.ControlPlane.Stanza
	cpRead, cpWrite := strings.Fields(wnRead(t, filepath.Join(s3Dir, "cp-read.keys"))), strings.Fields(wnRead(t, filepath.Join(s3Dir, "cp-write.keys")))
	switch {
	case esc.KEK != kek:
		t.Fatal("the escrowed key is not the node's key")
	case stanza != "cp-"+cpState.Incarnation || esc.ControlPlane.Incarnation != cpState.Incarnation:
		t.Fatalf("the escrowed stanza %q is not the control plane's (incarnation %s)", stanza, cpState.Incarnation)
	case esc.Offsite.Bucket != s3Bucket("cp-read"):
		t.Fatalf("the escrow names bucket %q, not the control plane's", esc.Offsite.Bucket)
	case len(cpRead) != 2 || esc.Offsite.Read.AccessKey != cpRead[0] || esc.Offsite.Read.SecretKey != cpRead[1] || !esc.Offsite.ReadOnly:
		t.Fatal("the escrow does not carry the control-plane bucket's read-only credential")
	case len(cpWrite) == 2 && esc.Offsite.Read.SecretKey == cpWrite[1]:
		t.Fatal("the escrow carries the control-plane bucket's write credential")
	}
	secretNeedles := []needle{{"the key-encryption key", keyForms(kek[:])},
		{"the control-plane passphrase", keyForms([]byte(esc.ControlPlane.CipherPass))},
		wnSecretKey(t, "cp-read"), wnSecretKey(t, "cp-write")}
	step = wnStep(t, "escrow shown and saved", step)

	// ── another control-plane database's objects under another stanza name ──
	cpW := wnS3x(t, "cp-write")
	other := "cp-" + strconv.FormatUint(uint64(time.Now().UnixNano())|1, 10)
	if other == stanza {
		t.Fatal("the other stanza name equals the real one")
	}
	otherSeg := "00000001FFFFFFFF000000FE"
	for _, rel := range []string{
		"archive/" + other + "/archive.info",
		"archive/" + other + "/17-1/" + otherSeg[:16] + "/" + otherSeg + "-" + randHex(20) + ".zst",
		"backup/" + other + "/backup.info",
		"backup/" + other + "/29991231-235959F/backup.manifest",
	} {
		if _, _, _, ok := walname.RepoPath(other, rel); !ok {
			t.Fatalf("planted path %q is not a repository path of %s", rel, other)
		}
		wnPut(t, cpW, "cp/"+rel, wnRandom(512))
	}

	// ── a deleted project whose purge waits for its retention ──
	D, _ := wnCreate(t, true)
	if out, code := cli(t, "project", "delete", D.Ref); code != 0 {
		t.Fatalf("delete %s: exit %d %s", D.Ref, code, brief(redact(out)))
	}
	var dPurge int64
	for _, o := range opListing(t) {
		if o.Ref == D.Ref && o.Kind == "purge" && o.State == "pending" {
			dPurge = o.ID
		}
	}
	if dPurge == 0 {
		t.Fatalf("deleted project %s has no pending purge", D.Ref)
	}
	step = wnStep(t, "a project created and deleted", step)

	// ── A: marker rows around a time, a Vault secret, 5,000 forged objects ──
	tag, secretName, secretValue := randHex(6), "reach-recovery-"+randHex(6), randHex(24)
	if _, err := sqlAs(t, A, "postgres", "create table if not exists public.reach_recovery(tag text primary key, at timestamptz default clock_timestamp())"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminSQL(t, A, fmt.Sprintf("select vault.create_secret('%s', '%s')", secretValue, secretName)); err != nil {
		t.Fatalf("vault secret in %s: %v", A.Ref, err)
	}
	if _, err := sqlAs(t, A, "postgres", fmt.Sprintf("insert into public.reach_recovery(tag) values ('before-%s')", tag)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // the target lies strictly between the two commits
	target, err := sqlAs(t, A, "postgres", `select to_char(clock_timestamp() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := sqlAs(t, A, "postgres", fmt.Sprintf("insert into public.reach_recovery(tag) values ('after-%s')", tag)); err != nil {
		t.Fatal(err)
	}
	switchWAL(t, A)
	pushed := waitPush(t, A.Ref)
	at, _ := time.Parse(time.RFC3339Nano, *pushed.Push.LastOK)
	wnWaitReplicated(t, A.Ref, at)
	bA := backups(t, A.Ref)
	if !slices.ContainsFunc(bA.Sets, func(s setJSON) bool { return s.Replicated }) {
		t.Fatalf("A has no replicated backup set")
	}
	projW := wnS3x(t, "projects-write")
	// A label of its own each run: the store keeps every earlier run's objects.
	forgedSet := fmt.Sprintf("20000101-%06dF", time.Now().UnixNano()%1000000)
	forged := make(chan int)
	var fwg sync.WaitGroup
	var ferr error
	var fmu sync.Mutex
	for range 16 {
		fwg.Add(1)
		go func() {
			defer fwg.Done()
			for i := range forged {
				rel := fmt.Sprintf("backup/%s/%s/pg_data/base/1/reach.%d", bA.Stanza, forgedSet, i)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				_, err := projW.Put(ctx, A.Ref+"/"+rel, []byte{'x'}, nil, true)
				cancel()
				if err != nil {
					fmu.Lock()
					ferr = err
					fmu.Unlock()
				}
			}
		}()
	}
	for i := range 5000 {
		forged <- i
	}
	close(forged)
	fwg.Wait()
	if ferr != nil {
		t.Fatalf("forging objects in A's prefix: %v", ferr)
	}
	if _, _, _, ok := walname.RepoPath(bA.Stanza, fmt.Sprintf("backup/%s/%s/pg_data/base/1/reach.0", bA.Stanza, forgedSet)); !ok {
		t.Fatal("the forged names are not repository paths of A's stanza")
	}
	if slices.ContainsFunc(bA.Sets, func(s setJSON) bool { return s.Label == forgedSet }) {
		t.Fatal("the forged set exists")
	}
	recordedA := backups(t, A.Ref).Replication.ObjectsRecorded
	if recordedA <= 0 {
		t.Fatalf("A's record holds %d rows before the wipe", recordedA)
	}
	step = wnStep(t, "A marked and its prefix forged", step)

	// ── the create window: one held at a running job, one finished ──
	// The holds: C2's backup job paused until the forced control-plane segment
	// below is off-site, then the failpoint before 12a with the hold file, then
	// the stand-in paused. Caveats: 12b waits at most 900 s before the create
	// fails (cp_not_replicated), so the wipe follows within that bound; the
	// daemon's restart at the failpoint kills B's paused push, which changes
	// nothing recovered — the recovered point predates it.
	C2, c2Op := wnCreate(t, false)
	_, resumeC2 := catchJob(t, C2.Ref, "backup", 10*time.Minute)
	C1, _ := wnCreate(t, true)
	if _, err := sqlAs(t, C1, "postgres", "create table public.reach_recovery(tag text primary key); insert into public.reach_recovery values ('c1')"); err != nil {
		t.Fatal(err)
	}
	switchWAL(t, C1)
	pushed = waitPush(t, C1.Ref)
	at, _ = time.Parse(time.RFC3339Nano, *pushed.Push.LastOK)
	wnWaitReplicated(t, C1.Ref, at)

	// ── B: a restore parked on a held push ──
	out, code := cli(t, "project", "restore", B.Ref, "--to", "latest", "--no-wait")
	var bm mutationJSON
	if json.Unmarshal([]byte(out), &bm) != nil || bm.OperationID == 0 || code != 0 {
		t.Fatalf("restore %s: exit %d", B.Ref, code)
	}
	bRestore := bm.OperationID
	catchJob(t, B.Ref, "push", 5*time.Minute)

	// Everything above is in the control plane's segment switched here, and
	// that segment is off-site before the stand-in is paused.
	lsn, err := st.WALPosition(wnCtx(t, 30*time.Second))
	if err != nil {
		t.Fatalf("control-plane WAL position: %v", err)
	}
	cpSeg, err := st.SwitchWAL(wnCtx(t, 30*time.Second), lsn)
	if err != nil {
		t.Fatalf("control-plane WAL switch: %v", err)
	}
	for deadline := time.Now().Add(15 * time.Minute); ; time.Sleep(2 * time.Second) {
		ok, err := st.SegmentReplicated(wnCtx(t, 30*time.Second), "cp", cpSeg)
		if err != nil {
			t.Fatalf("control-plane segment %s: %v", cpSeg, err)
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("control-plane segment %s not replicated within 15 minutes", cpSeg)
		}
	}
	step = wnStep(t, "the create window set up and the control plane's segment replicated", step)

	// C2 runs on to step 12a, where the daemon stops and is held; with the
	// stand-in paused it then waits at 12b.
	releaseC2 := wnHold(t)
	if err := os.WriteFile(paths.Failpoint(), []byte("create:12a"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(paths.Failpoint()) })
	resumeC2()
	for deadline := time.Now().Add(20 * time.Minute); len(daemonProcs()) > 0; time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("create %s did not reach step 12a within 20 minutes", C2.Ref)
		}
	}
	if _, err := os.Stat(paths.Failpoint()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the daemon stopped, but not at the failpoint")
	}
	pauseOff := wnPause(t)
	releaseC2()
	for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(time.Second) {
		op := wnOp(t, c2Op)
		if op.Step == "12b" && (op.State == "pending" || op.State == "running") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("create %s not waiting at 12b within 5 minutes: %s at %q", C2.Ref, op.State, op.Step)
		}
	}
	step = wnStep(t, "a create held at 12b with the stand-in paused", step)

	// ── shortfall control ──
	cpR := wnS3x(t, "cp-read")
	// realMax is the control-plane database's own timeline (that of its current
	// segment), the highest real one (its timelines arise only at its
	// recoveries); the store, and a repository seeded from it, may hold
	// histories planted by an earlier run.
	tl64, err := strconv.ParseUint(cpSeg[:8], 16, 32)
	if err != nil || tl64 == 0 {
		t.Fatalf("the control plane's timeline: %v", err)
	}
	realMax := uint32(tl64)
	inBucket := map[string]bool{}
	var newestUp, newestUpRel string
	for _, tree := range []string{"archive/", "backup/"} {
		for _, o := range wnVersions(t, cpR, "cp/"+tree+stanza+"/") {
			rel := strings.TrimPrefix(o.Key, "cp/")
			k, _, _, ok := walname.RepoPath(stanza, rel)
			if !ok || o.DeleteMarker {
				continue
			}
			inBucket[rel] = true
			if base := filepath.Base(rel); k == walname.Segment && (newestUp == "" || wnSegNo(base) > wnSegNo(newestUp)) {
				newestUp, newestUpRel = base[:24], rel
			}
		}
	}
	var planted, plantedRel string
	for deadline := time.Now().Add(5 * time.Minute); planted == ""; time.Sleep(2 * time.Second) {
		for _, rel := range repoFiles(t, "cp") {
			if k, _, _, ok := walname.RepoPath(stanza, rel); !ok || k != walname.Segment || inBucket[rel] {
				continue
			}
			if base := filepath.Base(rel)[:24]; planted == "" || wnSegNo(base) < wnSegNo(planted) {
				planted, plantedRel = base, rel
			}
		}
		if planted == "" && time.Now().After(deadline) {
			t.Fatal("no control-plane segment waits for its upload within 5 minutes")
		}
	}
	if newestUp == "" || wnSegNo(planted) <= wnSegNo(newestUp) {
		t.Fatalf("segment %s waits for its upload but %s, not below it, is off-site", planted, newestUp)
	}
	plantedTL, _ := strconv.ParseUint(planted[:8], 16, 32)
	// "Reached" is the end of replay: the segment that holds the promoted
	// timeline's switch point, here the last one before the planted key — not
	// the last segment the serve job handed out, which is the planted one.
	reached := wnSegName(uint32(plantedTL), wnSegNo(planted)-1)
	aid := strings.Split(plantedRel, "/")[2]
	// Far above every real timeline: recovery never asks for it (it probes
	// timelines upward to the first gap), it cannot empty the newest-segment
	// figure, and the restore follows the highest history not above the newest
	// fetched segment's timeline, so its timeline lookup never opens it. A
	// history at the very next timeline — which stops recover with a message
	// of its own — is the recovery commands' unit test, not this drill's.
	historyRel := fmt.Sprintf("archive/%s/%s/%08X.history", stanza, aid, realMax+0x10000)
	// The unusable object is a valid object of the stanza — the uploaded
	// segment newestUp's: the archive tool serves it, and the server rejects
	// it as the wrong segment, so recovery ends at the segment before it. An
	// object the tool cannot read would stop the recovery instead: its request
	// is never answered, and the server stops at the archive binary's timeout.
	// The honest upload of the planted segment would be refused; the stand-in
	// stays paused until the wipe, so it is never attempted. Assumed, not yet
	// seen on a node: the tool's archive-get serves the copy without checking
	// it against the checksum in its name.
	body, err := os.ReadFile(filepath.Join(repoDir("cp"), newestUpRel))
	if err != nil {
		t.Fatalf("the uploaded segment %s: %v", newestUp, err)
	}
	poisoned = true
	plantedVer := wnPut(t, cpW, "cp/"+plantedRel, body) // a conditional create: the key was still free
	wnPut(t, cpW, "cp/"+historyRel, wnRandom(64))
	step = wnStep(t, "an unusable segment and a higher history planted", step)

	// ── state before the wipe ──
	epoch, err := st.Epoch(wnCtx(t, 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if op := wnOp(t, c2Op); op.Step != "12b" || op.State != "pending" && op.State != "running" {
		t.Fatalf("create %s is %s at %q before the wipe, not held at 12b", C2.Ref, op.State, op.Step)
	}
	for _, o := range wnVersions(t, cpR, "cp/archive/"+stanza+"/") {
		rel := strings.TrimPrefix(o.Key, "cp/")
		if k, _, _, ok := walname.RepoPath(stanza, rel); ok && k == walname.Segment && rel != plantedRel &&
			wnSegNo(filepath.Base(rel)) >= wnSegNo(planted) {
			t.Fatalf("segment %s reached the store while it was paused", filepath.Base(rel))
		}
		if rel == plantedRel && o.VersionID != plantedVer {
			t.Fatalf("the planted segment's key holds another version (%s)", o.VersionID)
		}
	}
	release := holdDaemon(t)

	// recover on a node that still has its control-plane database: refused,
	// nothing changed.
	before := containerState(t, "sp-cp-db")
	if r := wnDaemon(t, recoverWait, "recover", "--escrow", kekFile, "--escrow", restFile); r.code != 1 {
		t.Fatalf("recover on a node that has its control-plane database: exit %d, want 1: %s", r.code, wnScrub(r.stderr, secretNeedles))
	}
	if containerState(t, "sp-cp-db") != before || !wnRunning(t, "sp-cp-db") {
		t.Fatal("recover changed the running control-plane database")
	}
	if _, err := os.Lstat(paths.CPRestoring()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the refused recover left a restore marker")
	}

	// ── the wipe ──
	wiped = true
	pauseOff()
	wnWipe(t)
	step = wnStep(t, "the node wiped", step)

	// A kek part holding another key: refused before anything is written or
	// fetched.
	badKEK := filepath.Join(dir, "escrow-kek-other.json")
	var kp struct {
		KEK string `json:"kek"`
	}
	if err := json.Unmarshal(parts["kek"], &kp); err != nil || kp.KEK == "" {
		t.Fatalf("the kek part names no key: %v", err)
	}
	if err := os.WriteFile(badKEK, bytes.Replace(parts["kek"], []byte(kp.KEK), []byte(base64.StdEncoding.EncodeToString(wnRandom(32))), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	r := wnDaemon(t, recoverWait, "recover", "--escrow", badKEK, "--escrow", restFile)
	if r.code != 1 {
		t.Fatalf("recover with another key: exit %d, want 1: %s", r.code, wnScrub(r.stderr, secretNeedles))
	}
	// Starts only: the wipe's removals may fall inside the window's slack.
	if wnStarted(jobEvents(t, "cp", since)) {
		t.Errorf("recover with another key started a job container")
	}
	for _, p := range []string{filepath.Dir(paths.NodeJSON()), paths.CPRestoring(), paths.RepoDir("cp")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("recover with another key made %s", p)
		}
	}
	wnNoSecret(t, "recover with another key", r.stdout+r.stderr, secretNeedles)

	// A serve job killed mid-recovery: no promotion.
	since = time.Now()
	wait := inBackground(t, func() result {
		r, err := run(recoverWait, nil, daemonBin, "recover", "--escrow", kekFile, "--escrow", restFile)
		if err != nil {
			r.code = -1
		}
		return r
	})
	// Polled as catchJob polls: the kill comes before the server can replay to the end.
	for deadline := time.Now().Add(recoverWait); jobRunning(t, jobName("cp", "serve")) == ""; {
		if r, done := wait(50 * time.Millisecond); done {
			t.Fatalf("recover ended (exit %d) before its serve job ran: %s", r.code, wnScrub(r.stderr, secretNeedles))
		}
		if time.Now().After(deadline) {
			t.Fatalf("no serve job of the control plane ran within %v", recoverWait)
		}
	}
	if rr, err := run(cmdTimeout, nil, "docker", "kill", jobName("cp", "serve")); err != nil || rr.code != 0 {
		t.Fatalf("killing the serve job: %v %s", err, brief(rr.stderr))
	}
	r, done := wait(recoverWait)
	if !done || r.code == 0 || r.code == -1 {
		t.Fatalf("recover with its serve job killed: ended %v, exit %d", done, r.code)
	}
	if !wnStarted(jobEvents(t, "cp", since)) {
		t.Error("control: recover started no job container; the event filter proves nothing")
	}
	cpData := filepath.Join(paths.CPProjectDir(), "data")
	if _, err := os.Stat(filepath.Join(cpData, "PG_VERSION")); err != nil {
		t.Errorf("control: no restored database before the serve job ended: %v", err)
	}
	if _, err := os.Lstat(paths.CPRestoring()); err != nil {
		t.Errorf("control: the stopped run left no restore marker; its absence after the recovery proves nothing: %v", err)
	}
	if wnRunning(t, "sp-cp-recovery") {
		time.Sleep(bklimit.GetTimeout + 30*time.Second) // one request of the archive binary runs out
		if wnRunning(t, "sp-cp-recovery") {
			t.Error("sp-cp-recovery still runs a request timeout after its serve job was killed")
		}
	}
	if h := slices.Concat(wnHistoriesAbove(t, filepath.Join(cpData, "pg_wal"), realMax),
		wnHistoriesAbove(t, filepath.Join(paths.CPProjectDir(), "spool"), realMax)); len(h) > 0 {
		t.Errorf("the recovery promoted although its serve job was killed: %v", h)
	}
	wnNoSecret(t, "recover with its serve job killed", r.stdout+r.stderr, secretNeedles)
	step = wnStep(t, "recover with its serve job killed", step)

	// The shortfall: recover stops before the new epoch and names both
	// segments — the newest fetched (the planted key) and the end of replay
	// (the one before it); it prints nothing of the other stanza.
	r = wnDaemon(t, recoverWait, "recover", "--escrow", kekFile, "--escrow", restFile)
	text := r.stdout + r.stderr
	switch {
	case r.code == 0 || r.code == 2:
		t.Fatalf("recover past a planted segment: exit %d, want a stop", r.code)
	case !strings.Contains(text, planted) || !strings.Contains(text, reached):
		t.Fatalf("recover's shortfall names neither or not both of %s (fetched) and %s (reached): %s", planted, reached, wnScrub(text, secretNeedles))
	case strings.Contains(text, otherSeg):
		t.Fatalf("recover's shortfall counts the other database's segment %s", otherSeg)
	}
	if h := wnHistoriesAbove(t, filepath.Join(cpData, "pg_wal"), realMax); len(h) == 0 {
		t.Error("control: the run that stopped at the shortfall shows no promotion; the check above proves nothing")
	}
	wnNoSecret(t, "recover at the shortfall", text, secretNeedles)
	step = wnStep(t, "recover stopped at the shortfall", step)

	// --accept-shortfall: the recovery finishes.
	r = wnDaemon(t, recoverWait, "recover", "--escrow", kekFile, "--escrow", restFile, "--accept-shortfall")
	if r.code != 0 {
		t.Fatalf("recover --accept-shortfall: exit %d: %s", r.code, wnScrub(r.stderr, secretNeedles))
	}
	text = r.stdout + r.stderr
	wnNoSecret(t, "recover", text, secretNeedles)
	lines := strings.Split(text, "\n")
	if !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, reportLine) }) {
		t.Errorf("the recovery report lacks the line %q", reportLine)
	}
	if !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, C2.Ref) }) {
		t.Errorf("the recovery report has no line for the undone create %s", C2.Ref)
	}
	for _, p := range []Project{A, B, C1, D} {
		if strings.Contains(text, p.Ref) {
			t.Errorf("the recovery report names %s, which was no create in progress", p.Ref)
		}
	}
	etc := filepath.Dir(paths.NodeJSON())
	var est syscall.Stat_t
	if err := syscall.Lstat(etc, &est); err != nil || est.Mode&syscall.S_IFMT != syscall.S_IFDIR || est.Uid != 0 || est.Mode&0o7777 != 0o700 {
		t.Errorf("%s after recover: %v, mode %o, uid %d; want a directory of root's, 0700", etc, err, est.Mode, est.Uid)
	}
	if got, err := secrets.LoadKEK(paths.KEK()); err != nil || got != kek {
		t.Errorf("recover did not install the escrowed key: %v", err)
	}
	if sh := wnDaemon(t, cmdTimeout, "offsite", "show"); sh.code != 0 || !strings.Contains(sh.stdout, `"state": "partial"`) {
		t.Errorf("offsite show after recover: exit %d, want the partial declaration", sh.code)
	}
	for _, p := range []string{paths.CPRestoring(), filepath.Join(paths.RepoDir("cp"), "fetch")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("recover left %s", p)
		}
	}
	for _, tree := range []string{"archive", "backup"} {
		if _, err := os.Lstat(filepath.Join(repoDir("cp"), tree, other)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the recovery took the other control-plane database's %s tree", tree)
		}
		if _, err := os.Lstat(filepath.Join(repoDir("cp"), tree, stanza)); err != nil {
			t.Errorf("control: the escrowed stanza's %s tree is not in the repository: %v", tree, err)
		}
	}
	// The far history may be fetched: what keeps it from the restore is the
	// timeline the restore is told to follow, seen as this run finishing. The
	// planted segment is taken at its only version.
	if _, err := os.Lstat(filepath.Join(repoDir("cp"), plantedRel)); err != nil {
		t.Errorf("control: the planted segment is not in the seeded repository: %v", err)
	}
	if h := wnHistoriesAbove(t, filepath.Join(cpData, "pg_wal"), realMax); len(h) == 0 {
		t.Error("the recovered database shows no promotion")
	}
	step = wnStep(t, "recover", step)

	// ── init, the daemon released ──
	initArgs := []string{"init", "--dev", "--no-systemd", "--ack-escrow", "--domain", "sp.test"}
	if d := os.Getenv("SP_STUDIO_DOMAIN"); d != "" { // a dashboard node, as its boot runs init
		initArgs = append(initArgs, "--studio-domain", d)
	}
	r = wnDaemon(t, cmdTimeout, initArgs...)
	if r.code != 0 {
		t.Fatalf("init after recover: exit %d", r.code) // its output shows the key escrow: never logged
	}
	if r := wnDaemon(t, cmdTimeout, "nft", "load"); r.code != 0 {
		t.Fatalf("supapaced nft load: exit %d: %s", r.code, brief(r.stderr))
	}
	release()
	step = wnStep(t, "init and the daemon's start", step)

	// Before offsite set: creates are refused, and no job makes a project's
	// path although the store lists A as active.
	if pj := wnState(t, A.Ref); pj != "active" {
		t.Fatalf("the recovered store lists A as %s, want active", pj)
	}
	_, _, jwks := newIssuer(t)
	cr, err := run(cliTimeout, nil, cliBin, "project", "create", "--name", scratchName, "--issuer-jwks", jwks, "--no-wait")
	if err != nil {
		t.Fatal(err)
	}
	var cm mutationJSON
	if json.Unmarshal([]byte(cr.stdout), &cm) == nil && cm.Ref != "" {
		t.Cleanup(func() { removeProject(t, cm.Ref) })
	}
	if cr.code != 1 || !strings.Contains(cr.stderr, partlyRefuse) {
		t.Errorf("a create before offsite set: exit %d %s; want the partly-declared refusal", cr.code, brief(cr.stderr))
	}
	for deadline := time.Now().Add(130 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		if n := wnEntries(t, paths.ProjectsDir()); !slices.Equal(n, []string{"cp"}) {
			t.Fatalf("the projects directory holds %v before offsite set, want only the control plane's", n)
		}
	}
	step = wnStep(t, "two retry rounds with the store partly declared", step)

	// ── offsite set ──
	sf := func(n string) string { return filepath.Join(s3Dir, n) }
	r = wnDaemon(t, cmdTimeout, "offsite", "set", "--endpoint", wnRead(t, sf("endpoint")), "--region", "us-east-1",
		"--ca-file", sf("ca.pem"), "--projects-bucket", s3Bucket("projects-write"), "--cp-bucket", s3Bucket("cp-write"),
		"--projects-write-keys", sf("projects-write.keys"), "--projects-read-keys", sf("projects-read.keys"),
		"--cp-write-keys", sf("cp-write.keys"), "--cp-read-keys", sf("cp-read.keys"))
	if r.code != 0 {
		t.Fatalf("offsite set: exit %d: %s", r.code, brief(r.stderr))
	}
	st = wnStore(t)
	if e, err := st.Epoch(wnCtx(t, 30*time.Second)); err != nil || e != epoch+1 {
		t.Errorf("the store is at epoch %d (%v) after three runs of recover, want %d: one new epoch", e, err, epoch+1)
	}
	// Operations carry no code: an open one ends failed — aborted for the
	// create of a provisioning project — with last_error "recovered: …".
	ops := opListing(t)
	for id, o := range ops {
		switch {
		case id == dPurge:
			if o.State != "pending" {
				t.Errorf("the deleted project's purge is %s after the recovery, want pending", o.State)
			}
		case o.State == "pending" || o.State == "running" || o.State == "waiting_job" || o.State == "aborting":
			t.Errorf("operation %d (%s %s) is still %s after the recovery", id, o.Kind, o.Ref, o.State)
		}
	}
	if o := ops[bRestore]; o.State != "failed" || !strings.HasPrefix(o.LastError, "recovered") {
		t.Errorf("B's open restore is %s (%q) after the recovery, want failed, recovered", o.State, o.LastError)
	}
	if o := ops[c2Op]; o.State != "aborted" || !strings.HasPrefix(o.LastError, "recovered") {
		t.Errorf("the create held at 12b is %s (%q) after the recovery, want aborted, recovered", o.State, o.LastError)
	}
	if s := wnState(t, C2.Ref); s != "aborted" {
		t.Errorf("project %s, held at 12b at the wipe, is %s, want aborted", C2.Ref, s)
	}
	if s := wnState(t, C1.Ref); s != "active" {
		t.Errorf("project %s, whose create finished, is %s, want active", C1.Ref, s)
	}

	// The purge completes on a node that holds nothing of D and destroys its
	// keys.
	if _, _, err := st.GetDEK(wnCtx(t, 30*time.Second), D.Ref); err != nil {
		t.Fatalf("control: the deleted project's key is not in the recovered store: %v", err)
	}
	if out, code := cli(t, "project", "purge", D.Ref); code != 0 {
		t.Fatalf("purge %s after the recovery: exit %d %s", D.Ref, code, brief(redact(out)))
	}
	if s := wnState(t, D.Ref); s != "purged" {
		t.Errorf("project %s is %s after its purge", D.Ref, s)
	}
	if _, _, err := st.GetDEK(wnCtx(t, 30*time.Second), D.Ref); !errors.Is(err, store.ErrDestroyed) {
		t.Errorf("the purge did not destroy %s's key: %v", D.Ref, err)
	}
	step = wnStep(t, "the store checked and the purge done", step)

	// ── the projects back from the object store ──
	wnWaitRebuilt(t, st, A.Ref, epoch+1, recordedA+5000) // more than one page of listed versions holds
	step = wnStep(t, "A's record rebuilt over two pages", step)
	rr := wnRestore(t, A.Ref, 45*time.Minute, "--to", target, "--from", "offsite")
	if rr.From != "offsite" {
		t.Errorf("A's restore came from %q", rr.From)
	}
	step = wnStep(t, "A restored from the object store to a time", step)
	if got := mustSQL(t, A, "postgres", "select count(*) from public.reach_recovery where tag in ('before-"+tag+"')"); got != "1" {
		t.Errorf("A after the restore: the marker before the target is missing")
	}
	if got := mustSQL(t, A, "postgres", "select count(*) from public.reach_recovery where tag in ('after-"+tag+"')"); got != "0" {
		t.Errorf("A after the restore: the marker after the target is present")
	}
	if got, err := adminSQL(t, A, fmt.Sprintf("select decrypted_secret from vault.decrypted_secrets where name = '%s'", secretName)); err != nil || got != secretValue {
		t.Errorf("A's Vault secret does not decrypt after the restore: %v", err)
	}
	waitServed(t, A)

	wnWaitRebuilt(t, st, C1.Ref, epoch+1, 1)
	if rr := wnRestore(t, C1.Ref, 45*time.Minute, "--to", "latest", "--from", "offsite"); rr.From != "offsite" {
		t.Errorf("C1's restore came from %q", rr.From)
	}
	if got := mustSQL(t, C1, "postgres", "select count(*) from public.reach_recovery where tag = 'c1'"); got != "1" {
		t.Errorf("the project whose create finished lost its row in the restore")
	}
	step = wnStep(t, "the finished create restored", step)

	wnWaitRebuilt(t, st, B.Ref, epoch+1, 1)
	wnRestore(t, B.Ref, 45*time.Minute, "--to", "latest", "--from", "offsite")
	waitServed(t, B)
	wnStep(t, "B restored", step)
	wnStep(t, "the whole drill", start)
}

// wnRead is a file's content without surrounding space.
func wnRead(t testing.TB, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// wnState is ref's state as `project show` prints it.
func wnState(t testing.TB, ref string) string {
	t.Helper()
	out, code := cli(t, "project", "show", ref)
	var pj projectJSON
	decode(t, "project show", out, &pj)
	if code != 0 || pj.Ref != ref {
		t.Fatalf("project show %s: exit %d", ref, code)
	}
	return pj.State
}

// wnRunning reports whether a container called name runs.
func wnRunning(t testing.TB, name string) bool {
	t.Helper()
	return jobRunning(t, name) != ""
}
