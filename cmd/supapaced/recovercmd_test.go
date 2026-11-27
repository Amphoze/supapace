package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

// recAgent is the fake agent of a recovery: the job side of jobAgent plus
// the control plane's restore calls, every one logged in order.
type recAgent struct {
	jobAgent
	p          nodecfg.Paths
	cfg        nodecfg.Config // what the agent was made with
	systemID   string
	promoted   bool
	stateErr   error
	recovering bool // with promoted false: still replaying, not exited
	polls      int
	fail       map[string]error // by logged name
	serving    chan struct{}    // closed once the serve job has started
	once       sync.Once
	rerun      bool // the last prepare found the marker

	// Where the recovery start ends: replay on timeline endTLI up to position
	// endLSN, promoted to timeline endTLI+1, whose history it writes.
	endTLI  int
	endLSN  uint64
	history string // that history's content when not ""
}

func (a *recAgent) call(name string) error {
	a.log(name)
	return a.fail[strings.Fields(name)[0]]
}

func (a *recAgent) EnsureImageFiles(context.Context) error     { return a.call("image-files") }
func (a *recAgent) KillJobs(_ context.Context, s string) error { return a.call("kill-jobs " + s) }
func (a *recAgent) SetReplicatorQuota(_ context.Context, mb int) error {
	return a.call(fmt.Sprintf("replicator-quota %d", mb))
}
func (a *recAgent) EnsureBackupNetwork(context.Context) error      { return a.call("backup-network") }
func (a *recAgent) StopControlPlaneRecovery(context.Context) error { return a.call("recovery-stop") }

// PrepareControlPlaneRestore does what the agent's does to the trees: the
// marker and the directories; on a marked node it empties data and spool.
func (a *recAgent) PrepareControlPlaneRestore(context.Context) error {
	if err := a.call("prepare"); err != nil {
		return err
	}
	_, err := os.Lstat(a.p.CPRestoring())
	a.rerun = err == nil
	if a.rerun {
		os.RemoveAll(filepath.Join(a.p.RepoDir("cp"), "fetch"))
	}
	for _, d := range []string{"data", "spool"} {
		dir := filepath.Join(a.p.CPProjectDir(), d)
		if a.rerun {
			os.RemoveAll(dir)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(a.p.CPDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(a.p.CPRestoring(), nil, 0o600)
}

// EnsureControlPlaneRecovery leaves what a recovery start leaves: a database
// in data, and the new timeline's history in the spool.
func (a *recAgent) EnsureControlPlaneRecovery(_ context.Context, t pgconf.RecoveryTarget) error {
	if err := a.call("recovery-start " + t.Timeline); err != nil {
		return err
	}
	if !t.Time.IsZero() || t.LSN != "" {
		return errors.New("a recovery to the end of the archive has no target")
	}
	pd := a.p.CPProjectDir()
	os.WriteFile(filepath.Join(pd, "data", "PG_VERSION"), []byte("17\n"), 0o600)
	if !a.promoted {
		return nil
	}
	hist := a.history
	if hist == "" {
		// As a server writes it: its parents' lines, then its own switch.
		for tli := 1; tli < a.endTLI; tli++ {
			hist += fmt.Sprintf("%d\t0/%X\tno recovery target specified\n", tli, (tli+1)<<24)
		}
		hist += fmt.Sprintf("%d\t%X/%X\tno recovery target specified\n", a.endTLI, a.endLSN>>32, a.endLSN&0xFFFFFFFF)
	}
	name := fmt.Sprintf("%08X.history", a.endTLI+1)
	os.MkdirAll(filepath.Join(pd, "data", "pg_wal"), 0o700)
	os.WriteFile(filepath.Join(pd, "data", "pg_wal", name), []byte(hist), 0o600)
	return os.WriteFile(filepath.Join(pd, "spool", name), []byte(hist), 0o600)
}

// ControlPlaneRecoveryState answers once the serve job runs beside the
// recovery start, as the real one cannot promote before it is served.
func (a *recAgent) ControlPlaneRecoveryState(ctx context.Context) (bool, bool, string, error) {
	select {
	case <-a.serving:
	case <-ctx.Done():
		return false, false, "", ctx.Err()
	}
	if err := a.call("recovery-state"); err != nil {
		return false, false, "", err
	}
	if a.stateErr != nil {
		return false, false, "", a.stateErr
	}
	// A command that never stops asking is a failure with a name, not a test
	// that runs into its timeout.
	if a.polls++; a.polls > 20000 {
		return false, false, "", errors.New("the fake recovery start was asked for its state 20,000 times")
	}
	if !a.promoted {
		return false, !a.recovering, "", nil
	}
	return true, false, a.systemID, nil
}

func (a *recAgent) FinishControlPlaneRestore(context.Context) error {
	if err := a.call("finish"); err != nil {
		return err
	}
	return os.Remove(a.p.CPRestoring())
}

func (a *recAgent) RunJob(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
	a.mu.Lock()
	a.calls = append(a.calls, "job "+j.Kind+"/"+j.Subject)
	a.specs = append(a.specs, j)
	f := a.script[j.Kind+"/"+j.Subject]
	a.mu.Unlock()
	if j.Kind == "serve" {
		a.once.Do(func() { close(a.serving) })
	}
	if err := a.fail["job-"+j.Kind]; err != nil {
		return agent.JobResult{}, err
	}
	return f(ctx, j)
}

func (a *recAgent) has(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.ContainsFunc(a.calls, func(c string) bool { return strings.HasPrefix(c, name) })
}

// fakeRecovered is the restored database as a recovery uses it.
type fakeRecovered struct {
	log      func(string)
	projects []store.Project
	epoch    int64
	floors   []int
	fail     map[string]error
}

func (f *fakeRecovered) Migrate(context.Context) error {
	f.log("store-migrate")
	return f.fail["migrate"]
}
func (f *fakeRecovered) ListProjects(context.Context) ([]store.Project, error) {
	f.log("store-list")
	return f.projects, f.fail["list"]
}
func (f *fakeRecovered) EnterNewEpoch(_ context.Context, floor int) (int64, error) {
	f.log("store-new-epoch")
	if err := f.fail["epoch"]; err != nil {
		return 0, err
	}
	f.floors = append(f.floors, floor)
	f.epoch++
	return f.epoch, nil
}
func (f *fakeRecovered) Close() { f.log("store-close") }

func segName(tli, n int) string { return fmt.Sprintf("%08X%016X", tli, n) }

const recSet = "20261120-101500F"

// recNode is a wiped node, the escrow set of the node it replaces, and
// fakes of everything a recovery reaches outside its own files.
type recNode struct {
	*node
	ag      *recAgent
	db      *fakeRecovered
	k       secrets.KEK
	pass    string
	inc     string
	d       offsite.Declaration // the lost node's: its control-plane bucket with both credentials
	all     string              // the escrow file, whole
	kekPart string
	rest    string
	dir     string // where the escrow files are, outside the node

	workerID   string            // the id the escrow document records
	images     map[string]string // loaded images: reference → id
	loaded     []string
	archiveID  string // the id an archive loads
	inspectErr error  // an image inspection that fails for another reason than absence
	container  *dockerx.Container
	owners     map[string]int
	tools      error
	instErr    error
	installed  [][]netip.AddrPort
	resolvedAt []string
	opens      int
}

func randPass() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newRecNode(t *testing.T) *recNode {
	t.Helper()
	n := newNode(t)
	r := &recNode{node: n, pass: randPass(), inc: "7437201938442670123", dir: t.TempDir(),
		workerID: "sha256:" + strings.Repeat("ab", 32), owners: map[string]int{}}
	r.images = map[string]string{nodecfg.WorkerImage: r.workerID}
	r.archiveID = r.workerID
	rand.Read(r.k[:])
	cred := func() offsite.Credential { return offsite.Credential{AccessKey: randText(), SecretKey: randText()} }
	r.d = offsite.Declaration{Endpoint: "https://s3.example.test:9443", Region: "test-1", PathStyle: true,
		CAPEM:        "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",
		Projects:     offsite.Bucket{Name: "sp-projects", Prefix: "node-a", Write: cred(), Read: cred()},
		ControlPlane: offsite.Bucket{Name: "sp-cp", Prefix: "node-c", Write: cred(), Read: cred()}}
	r.writeEscrow(nil)

	r.ag = &recAgent{p: n.p, systemID: r.inc, promoted: true, fail: map[string]error{}, serving: make(chan struct{})}
	r.replayed(1, 9)
	r.ag.script = map[string]func(context.Context, agent.JobSpec) (agent.JobResult, error){
		"seed/cp":    jobDone(t, jobio.SeedResult{OK: true, Files: 12, Bytes: 3400}),
		"restore/cp": jobDone(t, jobio.RestoreResult{OK: true, Mode: "none"}),
	}
	r.fetch(jobio.FetchResult{OK: true, Files: 12, Bytes: 3400, NewestSegment: segName(1, 9), NewestSet: recSet})
	r.serve(&jobio.ServeResult{OK: true, Served: 9, Last: segName(1, 10), LastNone: true, LastSegment: segName(1, 9)})
	r.db = &fakeRecovered{log: r.ag.log, epoch: 4, fail: map[string]error{}}

	oldKEK, oldID, oldLoad, oldInspect, oldAgent := loadKEK, imageID, loadImage, inspectContainer, newRecoverAgent
	oldResolve, oldInstall, oldOpen, oldOwner, oldTools, oldPoll := resolveEndpoint, installSet, openRecovered, ownerUID, recoverTools, recoverPoll
	t.Cleanup(func() {
		loadKEK, imageID, loadImage, inspectContainer, newRecoverAgent = oldKEK, oldID, oldLoad, oldInspect, oldAgent
		resolveEndpoint, installSet, openRecovered, ownerUID, recoverTools, recoverPoll = oldResolve, oldInstall, oldOpen, oldOwner, oldTools, oldPoll
	})
	// The key file as it is, without the owner rule: the tests are not root.
	loadKEK = func(path string) (secrets.KEK, error) {
		var k secrets.KEK
		b, err := os.ReadFile(path)
		if err != nil || len(b) != len(k) {
			return k, fmt.Errorf("key file: %d bytes, %v", len(b), err)
		}
		copy(k[:], b)
		return k, nil
	}
	imageID = func(_ context.Context, ref string) (string, error) {
		if r.inspectErr != nil {
			return "", r.inspectErr
		}
		if id, ok := r.images[ref]; ok {
			return id, nil
		}
		return "", fmt.Errorf("%w: %s", errNoImage, ref)
	}
	loadImage = func(_ context.Context, archive string) error {
		r.loaded = append(r.loaded, archive)
		r.images[nodecfg.WorkerImage] = r.archiveID
		return nil
	}
	inspectContainer = func(_ context.Context, name string) (*dockerx.Container, error) {
		if name != "sp-cp-db" {
			t.Errorf("inspected %q", name)
		}
		return r.container, nil
	}
	newRecoverAgent = func(c nodecfg.Config) recoverAgent { r.ag.cfg = c; return r.ag }
	resolveEndpoint = func(_ context.Context, d offsite.Declaration, c nodecfg.Config) ([]netip.AddrPort, error) {
		r.ag.log("resolve " + d.Endpoint)
		r.resolvedAt = append(r.resolvedAt, c.Domain+"|"+c.BackupSubnet)
		return probeAddrs, nil
	}
	installSet = func(_ context.Context, p nodecfg.Paths, c nodecfg.Config, set []netip.AddrPort) error {
		r.ag.log("install-set")
		// The lock file and the addresses file need the node directory.
		if fi, err := os.Lstat(filepath.Dir(p.NftLock())); err != nil || !fi.IsDir() {
			t.Errorf("the set is installed before the node directory exists: %v", err)
		}
		r.installed = append(r.installed, set)
		return r.instErr
	}
	openRecovered = func(context.Context) (recoveredStore, error) {
		r.opens++
		r.ag.log("store-open")
		return r.db, nil
	}
	ownerUID = func(path string) (int, error) {
		if uid, ok := r.owners[path]; ok {
			return uid, nil
		}
		return 0, fs.ErrNotExist
	}
	recoverTools = func() error { return r.tools }
	recoverPoll = time.Millisecond
	return r
}

// replayed makes the recovery start replay to the end of segment seg on
// timeline tli and promote to the next timeline.
func (r *recNode) replayed(tli, seg int) {
	r.ag.endTLI, r.ag.endLSN, r.ag.history = tli, uint64(seg+1)<<24, ""
}

// fetch makes the fetch job leave res and, in the fetch directory, the
// history files named (a timeline, then its content), as the program writes
// what the store held under those names.
func (r *recNode) fetch(res jobio.FetchResult, histories ...any) {
	line := resultLine(r.t, res)
	r.ag.script["fetch/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		dir := filepath.Join(r.p.RepoDir("cp"), "fetch", "archive", "cp-"+r.inc, "17-1")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return agent.JobResult{}, err
		}
		for i := 0; i+1 < len(histories); i += 2 {
			name := fmt.Sprintf("%08X.history", histories[i].(int))
			if err := os.WriteFile(filepath.Join(dir, name), []byte(histories[i+1].(string)), 0o640); err != nil {
				return agent.JobResult{}, err
			}
		}
		return agent.JobResult{Result: line}, nil
	}
}

// serve makes the serve job run until it is stopped and then leave sv (nil:
// no result line).
func (r *recNode) serve(sv *jobio.ServeResult) {
	r.ag.script["serve/cp"] = func(ctx context.Context, _ agent.JobSpec) (agent.JobResult, error) {
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
			// A serve job nobody stops would hang the test: name it instead.
			r.t.Error("the serve job was not stopped within 30 s")
			return agent.JobResult{}, errors.New("the serve job was never stopped")
		}
		if sv == nil {
			return agent.JobResult{ExitCode: 137}, ctx.Err()
		}
		return agent.JobResult{Result: resultLine(r.t, *sv)}, nil
	}
}

// writeEscrow prints the lost node's escrow set into files; change edits the
// document's inputs first.
func (r *recNode) writeEscrow(change func(cp *offsite.EscrowControlPlane, w *offsite.EscrowWorkerImage)) {
	r.t.Helper()
	cp := offsite.EscrowControlPlane{Stanza: "cp-" + r.inc, Incarnation: r.inc, CipherPass: r.pass,
		Image: nodecfg.Defaults().Images.ControlPlane, SchemaVersion: store.SchemaVersion()}
	w := offsite.EscrowWorkerImage{Reference: nodecfg.WorkerImage, ID: r.workerID, Archive: "supapace-worker.tar"}
	if change != nil {
		change(&cp, &w)
	}
	all, kek, rest, err := offsite.BuildEscrow(r.k, r.d, cp, w, "v0.2.0", time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC))
	if err != nil {
		r.t.Fatal(err)
	}
	r.all, r.kekPart, r.rest = filepath.Join(r.dir, "escrow.json"), filepath.Join(r.dir, "kek.json"), filepath.Join(r.dir, "rest.json")
	for path, b := range map[string][]byte{r.all: all, r.kekPart: kek, r.rest: rest} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			r.t.Fatal(err)
		}
	}
}

// recover runs `supapaced recover --escrow <the whole set>` with more arguments.
func (r *recNode) recover(args ...string) (int, string, string) {
	r.t.Helper()
	// Each run has its own serve job.
	r.ag.serving, r.ag.once = make(chan struct{}), sync.Once{}
	return r.run("", append([]string{"recover", "--escrow", r.all}, args...)...)
}

func (r *recNode) mustRecover(args ...string) string {
	r.t.Helper()
	code, out, errs := r.recover(args...)
	if code != 0 || errs != "" {
		r.t.Fatalf("recover %v: exit %d, stderr %q\ncalls %v", args, code, errs, r.ag.calls)
	}
	return out
}

func (r *recNode) input(kind string) jobio.Input {
	r.t.Helper()
	in, err := jobio.ParseInput(r.ag.spec(kind, "cp").Input)
	if err != nil {
		r.t.Fatalf("the %s job's input: %v", kind, err)
	}
	return in
}

// secretTexts are what a recovery must never print, log or put where a job
// that is not meant to hold it can read it.
func (r *recNode) secretTexts() map[string]string {
	return map[string]string{"the key": base64.StdEncoding.EncodeToString(r.k[:]), "the key in hex": hex.EncodeToString(r.k[:]),
		"the key's bytes": string(r.k[:]), "the passphrase": r.pass,
		"the read access key": r.d.ControlPlane.Read.AccessKey, "the read secret key": r.d.ControlPlane.Read.SecretKey}
}

// tree is every entry below the node's root with its type, mode and content.
func (n *node) tree() string {
	n.t.Helper()
	var b strings.Builder
	err := filepath.Walk(n.root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		sum := ""
		if fi.Mode().IsRegular() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum = fmt.Sprintf("%x", sha256.Sum256(data))
		}
		fmt.Fprintf(&b, "%s %v %s\n", strings.TrimPrefix(p, n.root), fi.Mode(), sum)
		return nil
	})
	if err != nil {
		n.t.Fatal(err)
	}
	return b.String()
}

func (n *node) etc() string { return filepath.Dir(n.p.NodeJSON()) }

// temporaries are the files an interrupted write leaves in the node directory.
func (n *node) temporaries() []string {
	left, _ := filepath.Glob(filepath.Join(n.etc(), ".*.tmp-*"))
	return left
}

// refused runs a recovery that must refuse before anything is written, with
// one line naming why.
func (r *recNode) refused(what, want string, args ...string) {
	r.t.Helper()
	before := r.tree()
	code, out, errs := r.recover(args...)
	if code != 1 || out != "" || strings.Count(errs, "\n") != 1 || !strings.HasPrefix(errs, "supapaced recover: ") || !strings.Contains(errs, want) {
		r.t.Fatalf("%s: exit %d, stdout %q, stderr %q", what, code, out, errs)
	}
	if after := r.tree(); after != before {
		r.t.Fatalf("%s: the refusal wrote to the node:\nbefore\n%s\nafter\n%s", what, before, after)
	}
	if len(r.ag.calls) != 0 {
		r.t.Fatalf("%s: the refusal came after %v", what, r.ag.calls)
	}
	for name, s := range r.secretTexts() {
		if strings.Contains(errs, s) {
			r.t.Fatalf("%s: the refusal shows %s", what, name)
		}
	}
}

func TestRecover_RefusalsBeforeAnyWrite(t *testing.T) {
	r := newRecNode(t)
	etc := r.etc()
	mk := func(path string, data []byte) func() {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return func() { os.Remove(path) }
	}
	// A key file that differs: this node has its own key.
	other := make([]byte, 32)
	rand.Read(other)
	if err := os.Mkdir(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	undo := mk(r.p.KEK(), other)
	r.refused("another key", "holds another key than the escrow document")
	undo()
	undo = mk(r.p.KEK(), other[:31])
	r.refused("a key file that does not read", "cannot be read")
	undo()
	// A sealed passphrase that is not the document's.
	foreign, _ := secrets.SealNode(r.k, "cp-stanza", []byte(randPass()))
	undo = mk(r.p.CPStanzaSealed(), foreign)
	r.refused("another passphrase", "is not the escrow document's")
	undo()
	if err := os.Remove(etc); err != nil {
		t.Fatal(err)
	}

	// The control-plane database's container exists.
	r.container = &dockerx.Container{Name: "sp-cp-db"}
	r.refused("sp-cp-db exists", "the container sp-cp-db exists")
	r.container = nil
	// The data directory holds a database and no restore is marked.
	data := filepath.Join(r.p.CPProjectDir(), "data")
	undo = mk(filepath.Join(data, "PG_VERSION"), []byte("17\n"))
	r.refused("a database", "holds a database and no restore is marked")
	undo()
	undo = mk(filepath.Join(r.p.CPDir(), "data", "PG_VERSION"), []byte("17\n"))
	r.refused("a database of an older build", "holds a database of an older build")
	undo()
	os.Remove(filepath.Join(r.p.CPDir(), "data"))
	mk(filepath.Join(r.p.RepoDir("cp"), "repo", "backup", "x"), nil)
	r.refused("a repository", "holds a repository and no restore is marked")
	os.RemoveAll(r.p.RepoRoot())

	// A document of a newer schema, or of a newer format.
	r.writeEscrow(func(cp *offsite.EscrowControlPlane, _ *offsite.EscrowWorkerImage) {
		cp.SchemaVersion = store.SchemaVersion() + 1
	})
	r.refused("a newer schema", fmt.Sprintf("schema version %d is above this build's (%d)", store.SchemaVersion()+1, store.SchemaVersion()))
	r.writeEscrow(nil)
	all, _ := os.ReadFile(r.all)
	os.WriteFile(r.all, []byte(strings.Replace(string(all), `"version": 1`, `"version": 2`, 1)), 0o600)
	r.refused("a newer document", "version")
	os.WriteFile(r.all, append(all, []byte(`{"x":1}`)...), 0o600)
	r.refused("a malformed document", "offsite:")
	r.writeEscrow(nil)

	// The daemon's programs are not as a job needs them.
	r.tools = errors.New("the archive binary supapace-arch must lie beside the executable")
	r.refused("the tools", "supapace-arch must lie beside")
	r.tools = nil

	// A daemon holds the node.
	lock, err := claimRunDir(r.p.AdminSock())
	if err != nil {
		t.Fatal(err)
	}
	r.refused("a running daemon", "a daemon or another recover is running on this node")
	lock.Close()

	// Usage: one or two escrow files, nothing else.
	for _, args := range [][]string{{"recover"}, {"recover", "--escrow", r.all, "--escrow", r.kekPart, "--escrow", r.rest},
		{"recover", "--escrow", r.all, "extra"}, {"recover", "--escrow", ""}} {
		if code, out, _ := r.run("", args...); code != 2 || out != "" || len(r.ag.calls) != 0 {
			t.Errorf("%v: exit %d, stdout %q", args, code, out)
		}
	}
	rootOnly = true
	if code, _, errs := r.recover(); code != 1 || !strings.Contains(errs, "must run as root") || len(r.ag.calls) != 0 {
		t.Fatalf("not root: exit %d, %q", code, errs)
	}
	rootOnly = false

	// Control: the same node with none of the above recovers; a key file
	// that holds the document's key, and a restore already marked over a
	// database, are no refusal.
	if err := os.Mkdir(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	mk(r.p.KEK(), r.k[:])
	mk(filepath.Join(data, "PG_VERSION"), []byte("17\n"))
	mk(r.p.CPRestoring(), nil)
	r.mustRecover()
}

func TestRecover_KeyNotMatchingKEKIDRefusedBeforeAnyFetch(t *testing.T) {
	r := newRecNode(t)
	// A kek part of another node's set beside this node's rest part.
	var other secrets.KEK
	rand.Read(other[:])
	_, kek, _, err := offsite.BuildEscrow(other, r.d, offsite.EscrowControlPlane{Stanza: "cp-1", Incarnation: "1", CipherPass: randPass(),
		Image: nodecfg.Defaults().Images.ControlPlane, SchemaVersion: 1}, offsite.EscrowWorkerImage{Reference: "w", ID: r.workerID, Archive: "a"}, "v", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(r.dir, "foreign-kek.json")
	os.WriteFile(foreign, kek, 0o600)
	before := r.tree()
	for _, args := range [][]string{{"--escrow", foreign, "--escrow", r.rest}, {"--escrow", r.rest, "--escrow", foreign}} {
		code, out, errs := r.run("", append([]string{"recover"}, args...)...)
		if code != 1 || out != "" || !strings.Contains(errs, "does not match kek_id") || strings.Count(errs, "\n") != 1 {
			t.Fatalf("%v: exit %d, %q", args, code, errs)
		}
		if len(r.ag.calls) != 0 || r.tree() != before {
			t.Fatalf("%v: refused after %v, or something was written", args, r.ag.calls)
		}
	}
	// Control: the two parts of one set, in either order, recover.
	r.ag.serving, r.ag.once = make(chan struct{}), sync.Once{}
	if code, _, errs := r.run("", "recover", "--escrow", r.rest, "--escrow", r.kekPart); code != 0 || !r.ag.has("job fetch") {
		t.Fatalf("control: exit %d, %q", code, errs)
	}
}

func TestRecover_NoNodeJSONUsesTheDefaults(t *testing.T) {
	r := newRecNode(t)
	// No node.json; one that would not load changes nothing either: it is not read.
	r.write("etc/supapace/node.json", "{not a configuration", 0o600)
	os.Chmod(r.etc(), 0o700)
	r.mustRecover()
	want := nodecfg.Defaults()
	got := r.ag.cfg
	if got.Domain != "" || got.Images != want.Images || got.BackupSubnet != want.BackupSubnet || got.ProjectBlock != want.ProjectBlock ||
		got.PlatformSubnet != want.PlatformSubnet || got.UIDBase != want.UIDBase {
		t.Fatalf("the agent was made with %+v", got)
	}
	if err := got.Validate(); err == nil {
		t.Fatal("control: the defaults without a domain validate; the test proves nothing")
	}
	if fmt.Sprint(r.resolvedAt) != fmt.Sprint([]string{"|" + want.BackupSubnet}) {
		t.Fatalf("resolved with %v", r.resolvedAt)
	}
	if b := r.read("etc/supapace/node.json"); string(b) != "{not a configuration" {
		t.Fatal("node.json was written")
	}
}

// A node.json that survived is not what a recovery runs with, and the run
// says so; only its uid range is taken, when the file loads, so that an owner
// left on disk inside that range still raises the counter.
func TestRecover_AnExistingNodeJSONIsNamedAndOnlyItsUIDRangeTaken(t *testing.T) {
	r := newRecNode(t)
	c := nodecfg.Default("sp.test")
	c.MemAllocMB, c.PidsAlloc, c.Uplinks = 1<<20, 1<<20, nil
	c.UIDBase, c.BackupSubnet = 1700000, "10.212.10.0/24"
	b, _ := json.Marshal(c)
	r.write("etc/supapace/node.json", string(b), 0o600)
	os.Chmod(r.etc(), 0o700)
	if _, err := nodecfg.Load(r.p.NodeJSON()); err != nil {
		t.Fatalf("control: the test's node.json does not load: %v", err)
	}
	inside, outside := r.p.ProjectDir("aaaaaaaaaaaaaaaaaaaa"), r.p.ProjectDir("bbbbbbbbbbbbbbbbbbbb")
	for dir, uid := range map[string]int{inside: 1700041, outside: 700099} {
		os.MkdirAll(dir, 0o700)
		r.owners[dir] = uid
	}
	out := r.mustRecover()
	if !strings.Contains(out, "supapaced recover: "+r.p.NodeJSON()+" exists and is not read") || !strings.Contains(out, "defaults") {
		t.Fatalf("the run does not say what the file means:\n%s", out)
	}
	if fmt.Sprint(r.db.floors) != "[1700042]" {
		t.Fatalf("uid floors %v, want one above the owner inside the file's range", r.db.floors)
	}
	// Everything else is the defaults': the subnets and the images.
	if r.ag.cfg.BackupSubnet != nodecfg.Defaults().BackupSubnet || r.ag.cfg.Domain != "" || r.ag.cfg.UIDBase != nodecfg.Defaults().UIDBase {
		t.Fatalf("the agent was made with the file's configuration: %+v", r.ag.cfg)
	}
	// Without the file nothing is said of it.
	r2 := newRecNode(t)
	if out := r2.mustRecover(); strings.Contains(out, "node.json") {
		t.Fatalf("a node without the file:\n%s", out)
	}
}

func TestRecover_InstallsKeyWithMarker_PassphraseSealed_PartialDeclaration(t *testing.T) {
	r := newRecNode(t)
	r.mustRecover()
	mode := func(path string) fs.FileMode {
		t.Helper()
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode()
	}
	if b := r.read("etc/supapace/kek"); string(b) != string(r.k[:]) || mode(r.p.KEK()) != 0o400 {
		t.Fatalf("the key file: mode %v, the document's key %t", mode(r.p.KEK()), string(b) == string(r.k[:]))
	}
	// With its marker, init neither shows this key nor makes another.
	if m := filepath.Join(r.etc(), "kek.escrowed"); mode(m) != 0o600 {
		t.Fatalf("the key's marker: %v", mode(m))
	}
	// The passphrase is sealed under the key, under its own name, and is the document's.
	sealed := r.read("etc/supapace/cp-stanza.sealed")
	if strings.Contains(string(sealed), r.pass) || mode(r.p.CPStanzaSealed()) != 0o600 {
		t.Fatalf("the passphrase file: mode %v, sealed %t", mode(r.p.CPStanzaSealed()), !strings.Contains(string(sealed), r.pass))
	}
	if got, err := offsite.EnsureControlPlanePass(r.p, r.k); err != nil || got != r.pass {
		t.Fatalf("the sealed passphrase does not open to the document's: %v", err)
	}
	// The declaration: where the control plane's copy is and how to read it; nothing else.
	d, state, err := offsite.Load(r.p, r.k)
	if err != nil || state != offsite.StatePartial {
		t.Fatalf("declaration state %q, %v", state, err)
	}
	want := offsite.Declaration{Endpoint: r.d.Endpoint, Region: r.d.Region, PathStyle: true, CAPEM: r.d.CAPEM,
		ControlPlane: offsite.Bucket{Name: "sp-cp", Prefix: "node-c", Read: r.d.ControlPlane.Read}}
	if d != want {
		t.Fatal("the saved declaration is not the escrowed location with its read-only credential alone")
	}
	if mode(r.p.OffsiteSealed()) != 0o600 || mode(r.etc()) != fs.ModeDir|0o700 {
		t.Fatalf("modes: declaration %v, directory %v", mode(r.p.OffsiteSealed()), mode(r.etc()))
	}
	if left := r.temporaries(); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
	// Nothing else is written there: no node.json, no acknowledgement of this set.
	ents, _ := os.ReadDir(r.etc())
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if fmt.Sprint(names) != "[cp-stanza.sealed kek kek.escrowed offsite.sealed]" {
		t.Fatalf("the node directory holds %v", names)
	}
}

func TestRecover_ImageIdMustMatch(t *testing.T) {
	r := newRecNode(t)
	other := "sha256:" + strings.Repeat("cd", 32)
	// Another image under the worker's name, and no archive: both ids, and the next step.
	r.images[nodecfg.WorkerImage] = other
	r.refused("another worker image", "has id "+other+", the escrow document records "+r.workerID+": pass --worker-image-archive")
	// Not loaded, and no archive to load it from.
	delete(r.images, nodecfg.WorkerImage)
	r.refused("no worker image", "is not loaded: pass --worker-image-archive")
	// An inspection that fails for another reason is not "not loaded", and no archive is loaded over it.
	r.inspectErr = errors.New("Cannot connect to the Docker daemon")
	r.refused("docker does not answer", "could not be inspected")
	r.refused("docker does not answer, an archive given", "could not be inspected", "--worker-image-archive", "/media/w.tar")
	if len(r.loaded) != 0 {
		t.Fatalf("an archive was loaded although the image could not be inspected: %v", r.loaded)
	}
	r.inspectErr = nil
	// The archive holds another image than the recorded one: absent before, or present.
	for _, present := range []bool{false, true} {
		delete(r.images, nodecfg.WorkerImage)
		if present {
			r.images[nodecfg.WorkerImage] = "sha256:" + strings.Repeat("ef", 32)
		}
		r.archiveID, r.loaded = other, nil
		before := r.tree()
		code, _, errs := r.recover("--worker-image-archive", "/media/w.tar")
		if code != 1 || !strings.Contains(errs, "the archive loaded an image with id "+other) || !strings.Contains(errs, r.workerID) ||
			len(r.ag.calls) != 0 || r.tree() != before {
			t.Fatalf("a wrong archive (image present: %t): exit %d, %q, calls %v", present, code, errs, r.ag.calls)
		}
	}
	// The control-plane image of the document is not this build's.
	r.images[nodecfg.WorkerImage] = r.workerID
	r.loaded = nil
	r.writeEscrow(func(cp *offsite.EscrowControlPlane, _ *offsite.EscrowWorkerImage) {
		cp.Image = "postgres@sha256:" + strings.Repeat("0", 64)
	})
	r.refused("another control-plane image", "the control-plane image of the escrow document is not this build's")
	r.writeEscrow(nil)
	// The recorded image present: an archive given is not loaded.
	r.mustRecover("--worker-image-archive", "/media/w.tar")
	if len(r.loaded) != 0 {
		t.Fatalf("an archive was loaded over the recorded image: %v", r.loaded)
	}
	// Absent, or present under another id: the archive is loaded, and its image is the recorded one.
	for _, present := range []bool{false, true} {
		r := newRecNode(t)
		delete(r.images, nodecfg.WorkerImage)
		if present {
			r.images[nodecfg.WorkerImage] = other
		}
		r.mustRecover("--worker-image-archive", "/media/w.tar")
		if fmt.Sprint(r.loaded) != "[/media/w.tar]" {
			t.Fatalf("image present %t: loaded %v", present, r.loaded)
		}
	}
}

func TestRecover_StepOrder(t *testing.T) {
	r := newRecNode(t)
	r.mustRecover()
	_, repoMB := nodecfg.CPQuotas(nodecfg.Defaults(), r.p)
	want := []string{
		"image-files", // before the preparation: a second one runs removal tasks under the seccomp profile
		"kill-jobs cp",
		"prepare",
		fmt.Sprintf("replicator-quota %d", 2*repoMB),
		"backup-network",
		"resolve " + r.d.Endpoint,
		"install-set",
		"job fetch/cp",
		"job seed/cp",
		"job restore/cp",
		"recovery-start latest",
		"job serve/cp",
		"recovery-state",
		// the two checks, then the restored database
		"store-open", "store-migrate", "store-list", "store-new-epoch", "store-close",
		"kill-jobs cp",
		"finish",
	}
	if fmt.Sprint(r.ag.calls) != fmt.Sprint(want) {
		t.Fatalf("calls\n %v\nwant\n %v", r.ag.calls, want)
	}
	// The serve job is stopped at promotion, not left to its deadline.
	if exists(r.p.CPRestoring()) {
		t.Fatal("the restore marker is left")
	}
}

func TestRecover_FetchBoundedAtTheRepoQuota(t *testing.T) {
	for _, dev := range []bool{false, true} {
		r := newRecNode(t)
		if dev { // a development node's smaller quota: one figure moves both
			r.write("etc/supapace/dev-mode", "", 0o600)
			os.Chmod(r.etc(), 0o700)
		}
		r.mustRecover()
		diskMB, repoMB := nodecfg.CPQuotas(nodecfg.Defaults(), r.p)
		if want := map[bool]int{false: 32768, true: 2048}[dev]; repoMB != want {
			t.Fatalf("dev %t: the control plane's repository quota is %d", dev, repoMB)
		}
		in, j := r.input("fetch"), r.ag.spec("fetch", "cp")
		deadline, _ := bklimit.Deadline("fetch", 0, repoMB)
		if in.MaxBytes != int64(repoMB)<<20 || j.Deadline != deadline {
			t.Fatalf("dev %t: max_bytes %d, deadline %v; want %d MiB and %v", dev, in.MaxBytes, j.Deadline, repoMB, deadline)
		}
		if !r.ag.has(fmt.Sprintf("replicator-quota %d", 2*repoMB)) {
			t.Fatalf("dev %t: the replicator's quota is not twice the repository quota: %v", dev, r.ag.calls)
		}
		for kind, want := range map[string][2]int{"seed": {0, repoMB}, "restore": {diskMB, repoMB}, "serve": {diskMB, repoMB}} {
			d, _ := bklimit.Deadline(kind, want[0], want[1])
			if got := r.ag.spec(kind, "cp").Deadline; got != d {
				t.Errorf("dev %t: the %s job's deadline is %v, want %v", dev, kind, got, d)
			}
		}
	}
}

func TestRecover_FetchesOnlyTheEscrowedStanzasTwoTrees(t *testing.T) {
	r := newRecNode(t)
	r.mustRecover()
	in, j := r.input("fetch"), r.ag.spec("fetch", "cp")
	// The program lists archive/<stanza>/ and backup/<stanza>/ of the subject
	// below the prefix, for the stanza its input names and no other: another
	// control-plane database's objects under the same prefix are never listed.
	if in.Stanza != "cp-"+r.inc || in.Subject != "cp" || in.Kind != "fetch" || !in.ListCurrent || in.Timelines != nil || in.Repl != nil {
		t.Fatalf("the fetch job's input %s", j.Input)
	}
	want := map[string]string{"SUPAPACE_S3_ENDPOINT": r.d.Endpoint, "SUPAPACE_S3_REGION": "test-1", "SUPAPACE_S3_BUCKET": "sp-cp",
		"SUPAPACE_S3_PREFIX": "node-c", "SUPAPACE_S3_PATH_STYLE": "1", "SUPAPACE_S3_ADDRS": "192.0.2.10:9443,192.0.2.11:9443"}
	if fmt.Sprint(j.Env) != fmt.Sprint(want) {
		t.Fatalf("the fetch job's environment %v", j.Env)
	}
	if j.Subject != "cp" || j.UID != nodecfg.ControlPlaneUID || j.GID != nodecfg.ControlPlaneUID || j.ID <= 0 || in.Job != j.ID || in.UID != nodecfg.ControlPlaneUID {
		t.Fatalf("the fetch job's spec %v, input %s", j, j.Input)
	}
	if string(j.Files["ca.pem"]) != r.d.CAPEM || len(j.Files) != 1 {
		t.Fatalf("the fetch job's files %v", j.Files)
	}
	// Every later job works on that stanza too.
	for _, kind := range []string{"seed", "restore", "serve"} {
		if in := r.input(kind); in.Stanza != "cp-"+r.inc || in.Subject != "cp" {
			t.Errorf("the %s job's input names stanza %q", kind, in.Stanza)
		}
	}
}

// stopped runs a recovery that must stop after the recovery start, before
// anything is written to the restored database.
func (r *recNode) stopped(what string, args ...string) string {
	r.t.Helper()
	code, _, errs := r.recover(args...)
	if code != 1 || strings.Count(errs, "\n") != 1 {
		r.t.Fatalf("%s: exit %d, stderr %q", what, code, errs)
	}
	if r.opens != 0 || len(r.db.floors) != 0 || r.ag.has("store-") || r.ag.has("finish") {
		r.t.Fatalf("%s: the restored database was opened or the restore finished: %v", what, r.ag.calls)
	}
	// The new database does not stay up, and the node stays marked: a start
	// of the daemon is refused, and a re-run starts from nothing.
	if r.ag.calls[len(r.ag.calls)-1] != "recovery-stop" || !exists(r.p.CPRestoring()) {
		r.t.Fatalf("%s: the recovery start was left running or the marker removed: %v", what, r.ag.calls)
	}
	// Nor does a job container of the run stay, created or running: its
	// configuration holds the passphrase.
	if r.ag.calls[len(r.ag.calls)-2] != "kill-jobs cp" {
		r.t.Fatalf("%s: the control plane's job containers were not removed when the run stopped: %v", what, r.ag.calls)
	}
	for name, s := range r.secretTexts() {
		if strings.Contains(errs, s) {
			r.t.Fatalf("%s: the message shows %s", what, name)
		}
	}
	return errs
}

func TestRecover_RefusesADatabaseThatIsNotTheEscrowedStanzas(t *testing.T) {
	r := newRecNode(t)
	r.ag.systemID = "7437201938442670124"
	errs := r.stopped("another database")
	if !strings.Contains(errs, "system identifier 7437201938442670124") || !strings.Contains(errs, r.inc) || !strings.Contains(errs, "nothing was written to it") {
		t.Fatalf("stderr %q", errs)
	}
	// Not even accepting a shortfall lets another database through.
	if errs := r.stopped("another database, shortfall accepted", "--accept-shortfall"); !strings.Contains(errs, "system identifier") {
		t.Fatalf("stderr %q", errs)
	}
	// Control: the escrowed database is taken.
	r.ag.systemID = r.inc
	r.mustRecover()
}

func TestRecover_ShortfallStopsBeforeTheNewEpoch(t *testing.T) {
	r := newRecNode(t)
	// The fetch took segments through 9; replay ended in 6.
	r.replayed(1, 6)
	errs := r.stopped("a shortfall")
	for _, want := range []string{"shortfall", segName(1, 6), segName(1, 9), "3 segments", "every change after the reached position is lost",
		"creates and their keys included", "off-site backups cannot be opened", "nothing was written to the restored database", "--accept-shortfall"} {
		if !strings.Contains(errs, want) {
			t.Errorf("the message lacks %q: %s", want, errs)
		}
	}
	// By segment number, whatever the timeline: replay that ended on timeline
	// 2 in number 5 is below number 9 of timeline 1, though its name sorts above.
	r.replayed(2, 5)
	if errs := r.stopped("a shortfall on a later timeline"); !strings.Contains(errs, "4 segments") || !strings.Contains(errs, segName(2, 5)) {
		t.Fatalf("stderr %q", errs)
	}
	// Control: replay through number 9 on timeline 2 is no shortfall.
	r.replayed(2, 9)
	r.mustRecover()
}

func TestRecover_AcceptShortfallProceeds(t *testing.T) {
	r := newRecNode(t)
	r.replayed(1, 6)
	out := r.mustRecover("--accept-shortfall")
	// What is accepted is said, and the report names the segment reached.
	for _, want := range []string{"shortfall accepted", "3 segments", segName(1, 9), "reached segment " + segName(1, 6), "new epoch 5"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q: %s", want, out)
		}
	}
	if len(r.db.floors) != 1 || !r.ag.has("finish") {
		t.Fatalf("the recovery did not finish: %v", r.ag.calls)
	}
	// Without a shortfall the flag changes nothing and nothing is said of one.
	r2 := newRecNode(t)
	if out := r2.mustRecover("--accept-shortfall"); strings.Contains(out, "shortfall") {
		t.Fatalf("no shortfall, yet: %s", out)
	}
}

// The store offered a history of a timeline far above every real one, and a
// valid object of the stanza copied to the key of the next segment, which the
// replicator had not uploaded. The fetch took both: its figure is that
// segment's number, not emptied by the higher timeline. The history never
// reaches the restore; the server is served the copy, cannot use it, and
// ends replay in the last real segment.
func TestRecover_APlantedHigherHistoryAndAPlantedSegmentStillStop(t *testing.T) {
	r := newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 14, Bytes: 4000, NewestSegment: segName(1, 10), NewestSet: recSet},
		0x10001, "not a history the archive tool can read")
	r.serve(&jobio.ServeResult{OK: true, Served: 10, Last: segName(1, 11), LastNone: true, LastSegment: segName(1, 10)})
	r.replayed(1, 9)
	errs := r.stopped("planted names")
	if !strings.Contains(errs, "shortfall") || !strings.Contains(errs, segName(1, 9)) || !strings.Contains(errs, segName(1, 10)) || !strings.Contains(errs, "1 segments") {
		t.Fatalf("stderr %q", errs)
	}
	if in := r.input("restore"); in.Mode != "standby" || in.TargetTimeline != 1 {
		t.Fatalf("the restore job was not told to follow timeline 1: %+v", in)
	}
	// The loss can be accepted: the run then finishes.
	if out := r.mustRecover("--accept-shortfall"); !strings.Contains(out, "reached segment "+segName(1, 9)) {
		t.Fatalf("output %s", out)
	}
}

// What was reached is where replay ended — the position the promoted
// timeline forks at — never the last segment the serve job handed over.
func TestRecover_ReachedIsTheEndOfReplayNotTheLastSegmentServed(t *testing.T) {
	r := newRecNode(t)
	// The serve job handed over segment 9, the newest fetched; the server did
	// not use it: the new timeline forks at 9's first byte.
	r.ag.endTLI, r.ag.endLSN = 1, 9<<24
	errs := r.stopped("a segment served and not replayed")
	if !strings.Contains(errs, "replay ended in segment "+segName(1, 8)) || !strings.Contains(errs, segName(1, 9)) || !strings.Contains(errs, "1 segments") {
		t.Fatalf("stderr %q", errs)
	}
	// Control: one byte of segment 9 replayed, and it is reached.
	r.ag.endLSN = 9<<24 + 1
	if out := r.mustRecover(); !strings.Contains(out, "reached segment "+segName(1, 9)) {
		t.Fatalf("output %s", out)
	}
	// A history that inherits its parents' lines: the last switch is this timeline's.
	r = newRecNode(t)
	r.ag.endTLI, r.ag.history = 3, "1\t0/3000028\tno recovery target specified\n\n# a comment\n2\t0/5000000\tno recovery target specified\n3\t0/A000000\tno recovery target specified\n"
	if out := r.mustRecover(); !strings.Contains(out, "reached segment "+segName(3, 9)) {
		t.Fatalf("output %s", out)
	}
	// The newest history in the WAL directory is the promotion's: an older one,
	// which the server fetched to follow its timeline, is not read for it.
	r = newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 13, Bytes: 3500, NewestSegment: segName(2, 9), NewestSet: recSet}, 2, "1\t0/3000000\tx\n")
	r.replayed(2, 9)
	serve := r.ag.script["serve/cp"]
	r.ag.script["serve/cp"] = func(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
		os.WriteFile(filepath.Join(r.p.CPProjectDir(), "data", "pg_wal", "00000002.history"), []byte("1\t0/3000000\tx\n"), 0o600)
		return serve(ctx, j)
	}
	if out := r.mustRecover(); !strings.Contains(out, "reached segment "+segName(2, 9)) {
		t.Fatalf("output %s", out)
	}
	// Positions above 4 GiB: the segment's name carries the high half.
	r = newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 12, Bytes: 3400, NewestSegment: "000000010000000200000001", NewestSet: recSet})
	r.ag.history = "1\t2/2000000\tno recovery target specified\n"
	if out := r.mustRecover(); !strings.Contains(out, "reached segment 000000010000000200000001") {
		t.Fatalf("output %s", out)
	}
	// A promotion whose history cannot be read is no pass.
	for what, hist := range map[string]string{"no switch line": "# nothing\n", "a position of zero": "1\t0/0\tx\n",
		"a malformed position": "1\tA000000\tx\n"} {
		r := newRecNode(t)
		r.ag.history = hist
		if errs := r.stopped(what); !strings.Contains(errs, "where replay ended is not known") {
			t.Errorf("%s: stderr %q", what, errs)
		}
	}
	// Nor is a history that is a link to another file.
	r = newRecNode(t)
	old := r.ag.script["serve/cp"]
	r.ag.script["serve/cp"] = func(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
		wal := filepath.Join(r.p.CPProjectDir(), "data", "pg_wal")
		os.Rename(filepath.Join(wal, "00000002.history"), filepath.Join(wal, "elsewhere"))
		os.Symlink("elsewhere", filepath.Join(wal, "00000002.history"))
		return old(ctx, j)
	}
	r.stopped("a history that is a link")
}

// A history above the newest fetched segment's timeline is not the
// replicator's: it never reaches the archive tool's timeline lookup, readable
// or not, because the restore job is told which timeline to follow.
func TestRecover_AHistoryAboveTheNewestSegmentsTimelineNeverReachesTheRestore(t *testing.T) {
	readable := "1\t0/3000000\tno recovery target specified\n"
	for what, tc := range map[string]struct {
		newest    string
		histories []any
		want      int
	}{
		"none fetched":                         {segName(1, 9), nil, 1},
		"far above, unreadable":                {segName(1, 9), []any{0x10001, "\x00\x01garbage"}, 1},
		"far above, readable":                  {segName(1, 9), []any{0x10001, readable}, 1},
		"two above, and the highest there is":  {segName(1, 9), []any{3, readable, 0xFFFFFFFF, "x"}, 1},
		"the segment's own timeline":           {segName(2, 9), []any{2, readable}, 2},
		"its own and an older one":             {segName(3, 9), []any{2, readable, 3, readable}, 3},
		"its own, and planted ones above":      {segName(2, 9), []any{2, readable, 4, "garbage", 0x10000, readable}, 2},
		"only an older one: its own is hidden": {segName(3, 9), []any{2, readable}, 2},
	} {
		r := newRecNode(t)
		r.fetch(jobio.FetchResult{OK: true, Files: 12, Bytes: 3400, NewestSegment: tc.newest, NewestSet: recSet}, tc.histories...)
		r.replayed(7, 9) // replay reaches the newest number, on whatever timeline
		r.mustRecover()
		if in := r.input("restore"); in.Mode != "standby" || in.TargetTimeline != tc.want || in.Set != recSet {
			t.Errorf("%s: the restore job's input %+v, want timeline %d", what, in, tc.want)
		}
	}
	// Names that are no history of a timeline are not read as one, and a link
	// in place of an archive id is not followed.
	plant := func(r *recNode, more func(dir string)) {
		dir := filepath.Join(r.p.RepoDir("cp"), "fetch", "archive", "cp-"+r.inc)
		elsewhere := t.TempDir()
		os.WriteFile(filepath.Join(elsewhere, "00000002.history"), nil, 0o640)
		fetch := r.ag.script["fetch/cp"]
		r.ag.script["fetch/cp"] = func(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
			res, err := fetch(ctx, j)
			os.WriteFile(filepath.Join(dir, "17-1", "0000000g.history"), nil, 0o640)
			os.WriteFile(filepath.Join(dir, "17-1", "00000002.history.partial"), nil, 0o640)
			os.WriteFile(filepath.Join(dir, "17-1", "x00000002.history"), nil, 0o640)
			os.WriteFile(filepath.Join(dir, "00000002.history"), nil, 0o640) // not inside an archive id
			os.Symlink(elsewhere, filepath.Join(dir, "18-1"))
			more(dir)
			return res, err
		}
	}
	r := newRecNode(t)
	plant(r, func(string) {})
	r.mustRecover()
	// Control: the same name inside a second archive id is one.
	r = newRecNode(t)
	plant(r, func(dir string) {
		os.MkdirAll(filepath.Join(dir, "16-1"), 0o750)
		os.WriteFile(filepath.Join(dir, "16-1", "00000002.history"), nil, 0o640)
	})
	if code, _, errs := r.recover(); code != 1 || !strings.Contains(errs, "history of timeline 2") {
		t.Fatalf("control: exit %d, %q", code, errs)
	}
}

// A history of the very next timeline stops the run before anything is
// restored, readable or not, and accepting a shortfall does not pass it.
func TestRecover_AHistoryOfTheNextTimelineStopsBeforeAnythingIsRestored(t *testing.T) {
	for what, content := range map[string]string{
		"readable, of another promotion": "1\t0/9000000\tno recovery target specified\n",
		"unreadable":                     "\x00\x01not something the archive tool can decrypt",
	} {
		for _, args := range [][]string{nil, {"--accept-shortfall"}} {
			r := newRecNode(t)
			r.fetch(jobio.FetchResult{OK: true, Files: 13, Bytes: 3500, NewestSegment: segName(1, 9), NewestSet: recSet}, 2, content)
			code, _, errs := r.recover(args...)
			if code != 1 || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "the store holds a history of timeline 2 and no segment of that timeline") ||
				!strings.Contains(errs, "the newest fetched segment is on timeline 1") || !strings.Contains(errs, "is refused") || strings.Contains(errs, "the store denies") || !strings.Contains(errs, "--accept-shortfall does not pass it") ||
				strings.Contains(errs, "shortfall:") {
				t.Fatalf("%s %v: exit %d, %q", what, args, code, errs)
			}
			for _, later := range []string{"job seed", "job restore", "recovery-start", "store-", "finish"} {
				if r.ag.has(later) {
					t.Fatalf("%s %v: %q ran: %v", what, args, later, r.ag.calls)
				}
			}
			if r.opens != 0 || !exists(r.p.CPRestoring()) {
				t.Fatalf("%s %v: the restored database was opened, or the marker removed", what, args)
			}
		}
	}
	// On a later timeline too: the one above the newest segment's.
	r := newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 13, Bytes: 3500, NewestSegment: segName(2, 9), NewestSet: recSet}, 2, "x", 3, "y")
	if code, _, errs := r.recover(); code != 1 || !strings.Contains(errs, "history of timeline 3") {
		t.Fatalf("timeline 3 above 2: exit %d, %q", code, errs)
	}
	// Control: the same history with a segment on its timeline is the archive's own.
	r = newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 13, Bytes: 3500, NewestSegment: segName(2, 9), NewestSet: recSet}, 2, "1\t0/9000000\tx\n")
	r.replayed(2, 9)
	r.mustRecover()
}

// What the archive tool cannot read is a denial: the run stops, names what
// it stopped at, and accepting a shortfall does not pass it.
func TestRecover_AnObjectTheToolCannotReadIsADenialNotAShortfall(t *testing.T) {
	for _, args := range [][]string{nil, {"--accept-shortfall"}} {
		// A segment recovery needs: the server asks, is never answered, and exits.
		r := newRecNode(t)
		r.ag.promoted = false
		r.serve(&jobio.ServeResult{OK: true, Served: 7, Last: segName(1, 8), LastSegment: segName(1, 7)})
		code, _, errs := r.recover(args...)
		if code != 1 || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "exited before it promoted") ||
			!strings.Contains(errs, "the last request the serve job answered was "+segName(1, 8)+"; what the server asked for after it") || !strings.Contains(errs, "the store denies this recovery") ||
			strings.Contains(errs, "shortfall:") || r.opens != 0 || r.ag.calls[len(r.ag.calls)-1] != "recovery-stop" {
			t.Fatalf("%v: exit %d, %q, calls %v", args, code, errs, r.ag.calls)
		}
		// A history it asked for.
		r = newRecNode(t)
		r.ag.promoted = false
		r.serve(&jobio.ServeResult{OK: true, Served: 9, Last: "00000002.history", LastSegment: segName(1, 9)})
		if _, _, errs := r.recover(args...); !strings.Contains(errs, "the last request the serve job answered was 00000002.history") {
			t.Fatalf("%v: %q", args, errs)
		}
		// The restore job: an object of the set, or the history it was told to follow.
		r = newRecNode(t)
		r.ag.script["restore/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 1, Result: resultLine(t, jobio.Failure{Code: "pgbackrest", Message: "restore of set: exit 95: cipher header missing"})}, nil
		}
		code, _, errs = r.recover(args...)
		if code != 1 || !strings.Contains(errs, "the restore job failed: pgbackrest:") || !strings.Contains(errs, "exit 95") ||
			!strings.Contains(errs, "the store denies this recovery") || r.ag.has("recovery-start") {
			t.Fatalf("%v: a failed restore: exit %d, %q", args, code, errs)
		}
	}
	// The serve job left no result, or a last name that is none: nothing is named.
	for what, sv := range map[string]*jobio.ServeResult{"no result": nil, "a name that is no request": {OK: true, Last: "../../etc/passwd\x1b[31m"}} {
		r := newRecNode(t)
		r.ag.promoted = false
		r.serve(sv)
		if _, _, errs := r.recover(); !strings.Contains(errs, "exited before it promoted") || !strings.Contains(errs, "the serve job answered no request it can name") || strings.Contains(errs, "passwd") {
			t.Errorf("%s: %q", what, errs)
		}
	}
	// A fetch that took no segment cannot be recovered either.
	r := newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 3, Bytes: 100, NewestSet: recSet})
	if code, _, errs := r.recover("--accept-shortfall"); code != 1 || !strings.Contains(errs, "took no segment") || r.ag.has("job seed") {
		t.Fatalf("no segment: exit %d, %q", code, errs)
	}
}

func TestRecover_NoServeResultStopsAsAShortfall(t *testing.T) {
	r := newRecNode(t)
	for what, f := range map[string]func(ctx context.Context) (agent.JobResult, error){
		"no result line": func(ctx context.Context) (agent.JobResult, error) { return agent.JobResult{ExitCode: 137}, ctx.Err() },
		"a failure document": func(context.Context) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 1, Result: resultLine(t, jobio.Failure{Code: "rspool", Message: "x"})}, nil
		},
		"a result that does not parse": func(context.Context) (agent.JobResult, error) {
			return agent.JobResult{Result: []byte(`{"ok":true,"served":"many"}` + "\n")}, nil
		},
		"a result with another exit status": func(context.Context) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 3, Result: resultLine(t, jobio.ServeResult{OK: true, Served: 9, LastSegment: segName(1, 9)})}, nil
		},
	} {
		r.ag.script["serve/cp"] = func(ctx context.Context, _ agent.JobSpec) (agent.JobResult, error) {
			<-ctx.Done()
			return f(ctx)
		}
		// Replay ended in the newest fetched segment, and still it is no pass.
		errs := r.stopped(what)
		if !strings.Contains(errs, "shortfall") || !strings.Contains(errs, "the serve job left no result") || !strings.Contains(errs, segName(1, 9)) {
			t.Errorf("%s: stderr %q", what, errs)
		}
	}
	// It is a shortfall like any other: the operator may accept it.
	out := r.mustRecover("--accept-shortfall")
	if !strings.Contains(out, "shortfall accepted") || !strings.Contains(out, "reached segment "+segName(1, 9)) {
		t.Fatalf("output %s", out)
	}
}

// A job's or a tool's message is printed as it came: a secret in it is not.
func TestRecover_NeverPrintsASecretAJobEchoes(t *testing.T) {
	r := newRecNode(t)
	for name, s := range r.secretTexts() {
		if name == "the key's bytes" {
			continue // not text a failure document can carry
		}
		r.ag.script["fetch/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 1, Result: resultLine(t, jobio.Failure{Code: "store", Message: "the store answered 403 for " + s + " twice: " + s})}, nil
		}
		code, out, errs := r.recover()
		if code != 1 || strings.Contains(out+errs, s) || !strings.Contains(errs, "the store answered 403 for [secret] twice: [secret]") {
			t.Errorf("%s echoed by a job: exit %d, %q", name, code, errs)
		}
	}
	// Nor a control character: a message is one printable line.
	r.ag.script["fetch/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{ExitCode: 1, Result: resultLine(t, jobio.Failure{Code: "store", Message: "answered \x1b[31mred\nsupapaced recover: recovered point"})}, nil
	}
	if _, _, errs := r.recover(); strings.ContainsAny(errs, "\x1b") || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "the fetch job failed: store: answered") {
		t.Fatalf("a message with control characters: %q", errs)
	}
	// A launch error can carry one too.
	r.fetch(jobio.FetchResult{OK: true, Files: 12, Bytes: 3400, NewestSegment: segName(1, 9), NewestSet: recSet})
	r.ag.fail["finish"] = errors.New("docker: env PGBACKREST_REPO1_CIPHER_PASS=" + r.pass)
	if _, out, errs := r.recover(); strings.Contains(out+errs, r.pass) || !strings.Contains(errs, "CIPHER_PASS=[secret]") {
		t.Fatalf("a launch error with the passphrase: %q", errs)
	}
	// So can the warning of the stop that follows a failed run.
	r = newRecNode(t)
	r.ag.fail["job-restore"] = errors.New("forced")
	r.ag.fail["recovery-stop"] = errors.New("docker: env PGBACKREST_REPO1_CIPHER_PASS=" + r.pass)
	if _, out, errs := r.recover(); strings.Contains(out+errs, r.pass) || !strings.Contains(errs, "CIPHER_PASS=[secret]") {
		t.Fatalf("a failed stop with the passphrase: %q", errs)
	}
	// A secret cut short by a message's bound is still one: its beginning is replaced.
	r = newRecNode(t)
	r.ag.script["fetch/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{ExitCode: 1, Result: resultLine(t, jobio.Failure{Code: "store", Message: "the request was signed with " + r.pass[:12]})}, nil
	}
	if _, _, errs := r.recover(); strings.Contains(errs, r.pass[:12]) || !strings.Contains(errs, "signed with [secret]") {
		t.Fatalf("the beginning of a secret: %q", errs)
	}
	// And a line of the report, whatever a row of the restored database holds.
	r = newRecNode(t)
	r.db.projects = []store.Project{layout2(r.pass, "provisioning")}
	if out := r.mustRecover(); strings.Contains(out, r.pass) || !strings.Contains(out, "project [secret]: its create was undone") {
		t.Fatalf("the report with a secret in a row:\n%s", out)
	}
}

func TestRecover_ResolvesTheEscrowedEndpointAndInstallsTheSetBeforeTheFetch(t *testing.T) {
	r := newRecNode(t)
	r.mustRecover()
	if len(r.installed) != 1 || fmt.Sprint(r.installed[0]) != fmt.Sprint(probeAddrs) {
		t.Fatalf("installed %v", r.installed)
	}
	i := func(name string) int { return slices.Index(r.ag.calls, name) }
	if !(i("resolve "+r.d.Endpoint) >= 0 && i("resolve "+r.d.Endpoint) < i("install-set") && i("install-set") < i("job fetch/cp")) {
		t.Fatalf("order %v", r.ag.calls)
	}
	// The fetch job is handed the installed set, whole, and nothing else.
	j := r.ag.spec("fetch", "cp")
	if fmt.Sprint(j.Addrs) != fmt.Sprint(probeAddrs) || j.Env["SUPAPACE_S3_ADDRS"] != "192.0.2.10:9443,192.0.2.11:9443" {
		t.Fatalf("the fetch job's addresses %v, %q", j.Addrs, j.Env["SUPAPACE_S3_ADDRS"])
	}
	// No other job has a way out of the node.
	for _, kind := range []string{"seed", "restore", "serve"} {
		if j := r.ag.spec(kind, "cp"); j.Addrs != nil || j.Env != nil || j.Cred != nil || j.Files != nil {
			t.Errorf("the %s job is given addresses, an environment, a credential or files", kind)
		}
	}
	// An answer that is refused, or a set that does not install: no fetch.
	for what, tc := range map[string]struct {
		resolve, install error
		want, not        string
	}{
		"a refused answer": {errors.New("offsite: an address of the answer is the node's own"), nil, "the node's own", "ruleset"},
		"a failed load":    {nil, fmt.Errorf("nft: %w: syntax error", nft.ErrUnverified), "the ruleset could not be loaded", "busy"},
		"a busy lock":      {nil, fmt.Errorf("nft: lock: %w", context.DeadlineExceeded), "the ruleset lock is busy", "could not be loaded"},
	} {
		r := newRecNode(t)
		if tc.resolve != nil {
			resolveEndpoint = func(context.Context, offsite.Declaration, nodecfg.Config) ([]netip.AddrPort, error) {
				return nil, tc.resolve
			}
		}
		r.instErr = tc.install
		code, _, errs := r.recover()
		if code != 1 || !strings.Contains(errs, tc.want) || strings.Contains(errs, tc.not) || r.ag.has("job ") {
			t.Errorf("%s: exit %d, %q, calls %v", what, code, errs, r.ag.calls)
		}
	}
}

func TestRecover_RestoresTheNewestFetchedSet(t *testing.T) {
	r := newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 30, Bytes: 9000, NewestSegment: segName(1, 9), NewestSet: "20261121-020000F"})
	r.mustRecover()
	// The fetch lists the store itself: no plan, there is no record to plan from.
	fj, fin := r.ag.spec("fetch", "cp"), r.input("fetch")
	if _, plan := fj.Files["plan"]; plan || !fin.ListCurrent {
		t.Fatalf("the fetch job: files %v, input %s", fj.Files, fj.Input)
	}
	in := r.input("restore")
	// Restored as it is, to be recovered: the tool is told the timeline to follow.
	if in.Set != "20261121-020000F" || in.Mode != "standby" || in.TargetTimeline != 1 {
		t.Fatalf("the restore job's input %+v", in)
	}
	if sv := r.input("serve"); sv.MaxAnswers != bklimit.ServeMaxAnswers {
		t.Fatalf("the serve job's input %+v", sv)
	}
	// No set fetched: refused before any restore.
	for what, f := range map[string]func(context.Context, agent.JobSpec) (agent.JobResult, error){
		"the program's own refusal": func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 1, Result: resultLine(t, jobio.Failure{Code: "missing", Message: "no backup.manifest was fetched"})}, nil
		},
		"a result without a set":      jobDone(t, jobio.FetchResult{OK: true, Files: 3, Bytes: 10, NewestSegment: segName(1, 9)}),
		"a set name out of shape":     jobDone(t, jobio.FetchResult{OK: true, Files: 3, Bytes: 10, NewestSegment: segName(1, 9), NewestSet: "../../20261121-020000F"}),
		"a segment name out of shape": jobDone(t, jobio.FetchResult{OK: true, Files: 3, Bytes: 10, NewestSegment: "000000010000000000000009.partial", NewestSet: recSet}),
		"no result line": func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 137, TimedOut: true}, nil
		},
		"a result of a job that ran past its deadline": func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{TimedOut: true, Result: resultLine(t, jobio.FetchResult{OK: true, Files: 3, Bytes: 10, NewestSegment: segName(1, 9), NewestSet: recSet})}, nil
		},
		"a result with another exit status": func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 3, Result: resultLine(t, jobio.FetchResult{OK: true, Files: 3, Bytes: 10, NewestSegment: segName(1, 9), NewestSet: recSet})}, nil
		},
	} {
		r := newRecNode(t)
		r.ag.script["fetch/cp"] = f
		code, _, errs := r.recover()
		if code != 1 || strings.Count(errs, "\n") != 1 || r.ag.has("job seed") || r.ag.has("job restore") || r.ag.has("recovery-start") {
			t.Errorf("%s: exit %d, %q, calls %v", what, code, errs, r.ag.calls)
		}
	}
}

// A job that fails, or a step of the agent that does, ends the run there:
// nothing later is started, the recovery start is not left running, and no
// temporary file stays.
func TestRecover_AFailureAtAnyStepStopsThereAndCleansUp(t *testing.T) {
	steps := []string{"image-files", "kill-jobs", "prepare", "replicator-quota", "backup-network", "job-fetch", "job-seed", "job-restore",
		"recovery-start", "recovery-state", "finish"}
	order := []string{"image-files", "kill-jobs", "prepare", "replicator-quota", "backup-network", "resolve", "install-set", "job fetch", "job seed",
		"job restore", "recovery-start", "job serve", "recovery-state", "store-open", "store-new-epoch", "finish"}
	for _, step := range steps {
		r := newRecNode(t)
		r.ag.fail[step] = errors.New("forced: " + step)
		code, _, errs := r.recover()
		if code != 1 || !strings.Contains(errs, "forced: "+step) || strings.Count(errs, "\n") != 1 {
			t.Errorf("%s: exit %d, %q", step, code, errs)
			continue
		}
		at := slices.IndexFunc(order, func(o string) bool { return strings.ReplaceAll(o, " ", "-") == step || o == step })
		for _, later := range order[at+1:] {
			if step == "recovery-start" && later == "job serve" || step == "finish" {
				continue
			}
			if r.ag.has(later) {
				t.Errorf("%s failed, yet %q ran: %v", step, later, r.ag.calls)
			}
		}
		if r.ag.has("recovery-start") && step != "finish" && r.ag.calls[len(r.ag.calls)-1] != "recovery-stop" {
			t.Errorf("%s: the recovery start was not stopped: %v", step, r.ag.calls)
		}
		if left := r.temporaries(); len(left) != 0 {
			t.Errorf("%s: temporary files left: %v", step, left)
		}
		for name, s := range r.secretTexts() {
			if strings.Contains(errs, s) {
				t.Errorf("%s: the message shows %s", step, name)
			}
		}
	}
	// The restored database's own steps.
	for _, step := range []string{"migrate", "list", "epoch"} {
		r := newRecNode(t)
		r.db.fail[step] = errors.New("forced: " + step)
		code, _, errs := r.recover()
		if code != 1 || !strings.Contains(errs, "forced: "+step) || r.ag.has("finish") || len(r.db.floors) != 0 ||
			r.ag.calls[len(r.ag.calls)-1] != "recovery-stop" || !slices.Contains(r.ag.calls, "store-close") {
			t.Errorf("%s: exit %d, %q, calls %v", step, code, errs, r.ag.calls)
		}
	}
	// A recovery start that exits, or a serve job that ends, before promotion.
	r := newRecNode(t)
	r.ag.promoted = false
	if code, _, errs := r.recover(); code != 1 || !strings.Contains(errs, "exited before it promoted") || r.opens != 0 {
		t.Fatalf("an exited recovery start: exit %d, %q", code, errs)
	}
	// A serve job that ends while the server still replays: the run does not
	// wait for a server that can no longer be served.
	r = newRecNode(t)
	r.ag.promoted, r.ag.recovering = false, true
	r.ag.script["serve/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{ExitCode: 137}, nil
	}
	if code, _, errs := r.recover(); code != 1 || !strings.Contains(errs, "the serve job ended before the recovery promoted") ||
		r.opens != 0 || r.ag.calls[len(r.ag.calls)-1] != "recovery-stop" {
		t.Fatalf("a serve job that ended early: exit %d, %q", code, errs)
	}
	// A seed or a restore job that ends with a failure document stops the run too.
	for _, kind := range []string{"seed", "restore"} {
		r := newRecNode(t)
		r.ag.script[kind+"/cp"] = func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 1, Result: resultLine(t, jobio.Failure{Code: "refused-by-" + kind, Message: "no"})}, nil
		}
		code, _, errs := r.recover()
		if code != 1 || !strings.Contains(errs, "the "+kind+" job failed: refused-by-"+kind+": no") || r.ag.has("recovery-start") || kind == "seed" && r.ag.has("job restore") {
			t.Errorf("a failed %s job: exit %d, %q, calls %v", kind, code, errs, r.ag.calls)
		}
	}
}

func TestRecover_RerunEmptiesSpoolToo(t *testing.T) {
	r := newRecNode(t)
	// A first run stops after promotion, at the shortfall: the recovery start
	// has left a database, and its promotion archived the new timeline's
	// history into the spool.
	r.replayed(1, 6)
	r.serve(&jobio.ServeResult{OK: true, Served: 6, Last: segName(1, 7), LastNone: true, LastSegment: segName(1, 6)})
	r.stopped("the first run")
	key1, _ := os.Lstat(r.p.KEK())
	pass1, _ := os.Lstat(r.p.CPStanzaSealed())
	pd := r.p.CPProjectDir()
	for _, left := range []string{filepath.Join(pd, "data", "PG_VERSION"), filepath.Join(pd, "spool", "00000002.history"), r.p.CPRestoring()} {
		if !exists(left) {
			t.Fatalf("the first run did not leave %s", left)
		}
	}
	// The second run is not refused over that database — the restore is
	// marked — and prepares again before anything else touches the trees: on
	// a marked node the preparation empties data, spool, the restore spool
	// and the repository, so the promotion archives the same names again.
	r.ag.calls, r.ag.specs = nil, nil
	out := r.mustRecover("--accept-shortfall")
	if !r.ag.rerun {
		t.Fatal("the second preparation did not find the marker")
	}
	i := func(name string) int { return slices.Index(r.ag.calls, name) }
	if !(i("prepare") >= 0 && i("prepare") < i("job fetch/cp") && i("kill-jobs cp") < i("prepare") && i("image-files") < i("prepare")) {
		t.Fatalf("order of the second run %v", r.ag.calls)
	}
	if strings.Count(strings.Join(r.ag.calls, "\n"), "prepare") != 1 {
		t.Fatalf("prepared more than once: %v", r.ag.calls)
	}
	if !strings.Contains(out, "new epoch") || exists(r.p.CPRestoring()) {
		t.Fatalf("the second run did not finish: %s", out)
	}
	// The key, the passphrase and the declaration of the first run are taken as they are.
	if got, err := offsite.EnsureControlPlanePass(r.p, r.k); err != nil || got != r.pass {
		t.Fatalf("the passphrase after the second run: %v", err)
	}
	key2, _ := os.Lstat(r.p.KEK())
	pass2, _ := os.Lstat(r.p.CPStanzaSealed())
	if key1 == nil || !os.SameFile(key1, key2) || !os.SameFile(pass1, pass2) {
		t.Fatal("a file already in place was written again")
	}
}

func TestRecover_CounterAboveDiskOwners(t *testing.T) {
	r := newRecNode(t)
	c := nodecfg.Defaults()
	mkdir := func(dir string, uid int) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		r.owners[dir] = uid
	}
	// Trees that survived: a project's directory, another project's
	// repository, the control plane's own, and owners outside the project range.
	mkdir(r.p.ProjectDir("aaaaaaaaaaaaaaaaaaaa"), c.UIDBase+41)
	mkdir(r.p.ProjectDir("cp"), nodecfg.ControlPlaneUID)
	mkdir(r.p.ProjectDir("lost+found"), 0)
	mkdir(filepath.Join(r.p.RepoDir("bbbbbbbbbbbbbbbbbbbb"), "repo"), c.UIDBase+77)
	mkdir(filepath.Join(r.p.RepoDir("cccccccccccccccccccc"), "fetch"), c.UIDBase+900) // not a repo directory
	mkdir(filepath.Join(r.p.RepoDir("dddddddddddddddddddd"), "repo"), c.UIDBase+c.UIDCount)
	r.owners[r.p.RepoDir("bbbbbbbbbbbbbbbbbbbb")] = c.UIDBase + 500 // the entry itself is root's: not asked
	os.MkdirAll(r.p.RepoDir("eeeeeeeeeeeeeeeeeeee"), 0o700)         // an entry without a repo directory
	r.mustRecover()
	if fmt.Sprint(r.db.floors) != fmt.Sprint([]int{c.UIDBase + 78}) {
		t.Fatalf("uid floors %v, want one above the highest owner %d", r.db.floors, c.UIDBase+77)
	}
	// Control: the projects directory's owner alone decides when it is the highest.
	r2 := newRecNode(t)
	os.MkdirAll(r2.p.ProjectDir("aaaaaaaaaaaaaaaaaaaa"), 0o700)
	r2.owners[r2.p.ProjectDir("aaaaaaaaaaaaaaaaaaaa")] = c.UIDBase + 41
	r2.mustRecover()
	if fmt.Sprint(r2.db.floors) != fmt.Sprint([]int{c.UIDBase + 42}) {
		t.Fatalf("uid floors %v", r2.db.floors)
	}
	// Nothing of a project on disk — the control plane's own tree and root's
	// entries are no project's: no floor.
	r3 := newRecNode(t)
	for dir, uid := range map[string]int{r3.p.ProjectDir("cp"): nodecfg.ControlPlaneUID, r3.p.ProjectDir("lost+found"): 0,
		filepath.Join(r3.p.RepoDir("cp"), "repo"): nodecfg.ControlPlaneUID} {
		os.MkdirAll(dir, 0o700)
		r3.owners[dir] = uid
	}
	r3.mustRecover()
	if fmt.Sprint(r3.db.floors) != "[0]" {
		t.Fatalf("uid floors %v", r3.db.floors)
	}
}

func TestRecover_NeverUsesWriteCredential(t *testing.T) {
	r := newRecNode(t)
	// The node directory survived with the lost node's full declaration.
	if err := os.Mkdir(r.etc(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := offsite.Save(r.p, r.k, r.d); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(r.p.KEK(), r.k[:], 0o400)
	out := r.mustRecover()
	write := []string{r.d.ControlPlane.Write.AccessKey, r.d.ControlPlane.Write.SecretKey, r.d.Projects.Write.AccessKey,
		r.d.Projects.Write.SecretKey, r.d.Projects.Read.AccessKey, r.d.Projects.Read.SecretKey}
	read := r.d.ControlPlane.Read
	for _, j := range r.ag.specs {
		all := fmt.Sprintf("%s|%s|%v|%v|%s", j.Cred, j.Input, j.Env, j.SecretEnv, j.Files)
		for _, k := range write {
			if strings.Contains(all, k) {
				t.Fatalf("the %s job holds a credential that is not the control plane's read-only one", j.Kind)
			}
		}
		// The read-only credential: the fetch job's file, nowhere else.
		if j.Kind == "fetch" {
			if string(j.Cred) != read.AccessKey+"\n"+read.SecretKey || len(j.SecretEnv) != 0 {
				t.Fatal("the fetch job's credential file is not the read-only pair alone, or it holds a passphrase")
			}
			all = fmt.Sprintf("%s|%v|%s", j.Input, j.Env, j.Files)
		}
		if strings.Contains(all, read.AccessKey) || strings.Contains(all, read.SecretKey) {
			t.Fatalf("the %s job holds the read-only credential outside a credential file", j.Kind)
		}
		// The passphrase: the restore and the serve job's environment, nowhere else.
		pass := j.Kind == "restore" || j.Kind == "serve"
		if got := j.SecretEnv["PGBACKREST_REPO1_CIPHER_PASS"]; pass != (got == r.pass) || len(j.SecretEnv) > 1 ||
			strings.Contains(fmt.Sprintf("%s|%s|%v|%s", j.Cred, j.Input, j.Env, j.Files), r.pass) {
			t.Fatalf("the %s job and the passphrase: given %t", j.Kind, got != "")
		}
		if strings.Contains(fmt.Sprintf("%s|%s|%v|%v|%s", j.Cred, j.Input, j.Env, j.SecretEnv, j.Files), string(r.k[:])) {
			t.Fatalf("the %s job holds the key", j.Kind)
		}
	}
	for _, k := range write {
		if strings.Contains(out, k) {
			t.Fatal("the output shows a credential")
		}
	}
	// The node's own full declaration, of the same location, is left as it
	// was: a recovery does not take the other credentials away.
	d, state, err := offsite.Load(r.p, r.k)
	if err != nil || state != offsite.StateDeclared || d != r.d {
		t.Fatalf("the declaration after the recovery: %q, %v", state, err)
	}
}

// A declaration already on the node is the node's: one that names another
// control-plane location than the document, or that the document's key does
// not open, is refused before anything is written; a partial one of the same
// location — a recovery that did not finish wrote it — is written again.
func TestRecover_ADeclarationOnTheNodeIsKeptOrRefused(t *testing.T) {
	for what, change := range map[string]func(d *offsite.Declaration){
		"another bucket":   func(d *offsite.Declaration) { d.ControlPlane.Name = "sp-cp-other" },
		"another prefix":   func(d *offsite.Declaration) { d.ControlPlane.Prefix = "node-z" },
		"another endpoint": func(d *offsite.Declaration) { d.Endpoint = "https://s3.other.test:9443" },
		"another region":   func(d *offsite.Declaration) { d.Region = "test-2" },
		"another CA":       func(d *offsite.Declaration) { d.CAPEM = "" },
		"a partial one of another bucket": func(d *offsite.Declaration) {
			d.Projects, d.ControlPlane.Write, d.ControlPlane.Name = offsite.Bucket{}, offsite.Credential{}, "sp-cp-other"
		},
	} {
		r := newRecNode(t)
		if err := os.Mkdir(r.etc(), 0o700); err != nil {
			t.Fatal(err)
		}
		d := r.d
		change(&d)
		if err := offsite.Save(r.p, r.k, d); err != nil {
			t.Fatal(err)
		}
		r.refused(what, "names another control-plane location than the escrow document")
	}
	r := newRecNode(t)
	if err := os.Mkdir(r.etc(), 0o700); err != nil {
		t.Fatal(err)
	}
	var other secrets.KEK
	rand.Read(other[:])
	if err := offsite.Save(r.p, other, r.d); err != nil {
		t.Fatal(err)
	}
	r.refused("a declaration under another key", "does not open with the escrow document's key")
	// Control: a partial declaration of the same location is replaced by the document's.
	r = newRecNode(t)
	if err := os.Mkdir(r.etc(), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := offsite.Declaration{Endpoint: r.d.Endpoint, Region: r.d.Region, PathStyle: true, CAPEM: r.d.CAPEM,
		ControlPlane: offsite.Bucket{Name: "sp-cp", Prefix: "node-c", Read: offsite.Credential{AccessKey: randText(), SecretKey: randText()}}}
	if err := offsite.Save(r.p, r.k, stale); err != nil {
		t.Fatal(err)
	}
	r.mustRecover()
	if d, state, err := offsite.Load(r.p, r.k); err != nil || state != offsite.StatePartial || d.ControlPlane.Read != r.d.ControlPlane.Read {
		t.Fatalf("the partial declaration after the recovery: %q, %v", state, err)
	}
}

// A run a signal ends — a closed output is one — says so and what to do, and
// leaves neither the recovery start nor a job container.
func TestRecover_AnInterruptedRunSaysSoAndCleansUp(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGPIPE} {
		r := newRecNode(t)
		r.ag.promoted, r.ag.recovering = false, true // replaying until the signal
		r.ag.script["serve/cp"] = func(ctx context.Context, _ agent.JobSpec) (agent.JobResult, error) {
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Error(err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(30 * time.Second):
				t.Errorf("%v did not end the run", sig)
			}
			return agent.JobResult{ExitCode: 143}, ctx.Err()
		}
		code, _, errs := r.recover()
		if code != 1 || !strings.Contains(errs, "interrupted") || !strings.Contains(errs, "run recover again") || strings.Contains(errs, "context canceled") {
			t.Errorf("%v: exit %d, %q", sig, code, errs)
		}
		if n := len(r.ag.calls); r.ag.calls[n-2] != "kill-jobs cp" || r.ag.calls[n-1] != "recovery-stop" {
			t.Errorf("%v: the run ended with %v", sig, r.ag.calls[n-2:])
		}
	}
}

func TestRecover_PrintsNextSteps_NoSecrets(t *testing.T) {
	r := newRecNode(t)
	code, out, errs := r.recover()
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, %q", code, errs)
	}
	last := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	next := last[len(last)-1]
	// In the order the operator takes them.
	at := -1
	for _, step := range []string{"supapaced init", "start the daemon", "supapaced offsite set", "all four credentials", "restore"} {
		i := strings.Index(next, step)
		if i <= at {
			t.Fatalf("the next steps lack %q, or out of order: %s", step, next)
		}
		at = i
	}
	for name, s := range r.secretTexts() {
		if strings.Contains(out+errs, s) {
			t.Errorf("the output shows %s", name)
		}
	}
	for _, line := range last {
		if !strings.HasPrefix(line, "supapaced recover: ") {
			t.Errorf("a line without the command's name: %q", line)
		}
	}
	// Nor is a secret left in a file outside the three it is installed in.
	filepath.Walk(r.root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || !fi.Mode().IsRegular() || p == r.p.KEK() {
			return err
		}
		b, _ := os.ReadFile(p)
		for name, s := range r.secretTexts() {
			if strings.Contains(string(b), s) {
				t.Errorf("%s holds %s", p, name)
			}
		}
		return nil
	})
}

func layout2(ref, state string) store.Project {
	return store.Project{Ref: ref, State: state, Config: store.ProjectConfig{Layout: 2}}
}

func TestRecover_ReportLines(t *testing.T) {
	r := newRecNode(t)
	r.db.projects = []store.Project{layout2("aaaaaaaaaaaaaaaaaaaa", "active"), layout2("bbbbbbbbbbbbbbbbbbbb", "provisioning"),
		layout2("cccccccccccccccccccc", "provisioning")}
	out := r.mustRecover()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	i := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "recovered point") })
	if i < 0 || len(lines)-i != 5 {
		t.Fatalf("the report:\n%s", out)
	}
	want := []string{
		"supapaced recover: recovered point: set " + recSet + ", reached segment " + segName(1, 9) + ", new epoch 5",
		"supapaced recover: memberships, session revocations and service keys are as of the recovered point",
		"supapaced recover: project bbbbbbbbbbbbbbbbbbbb: its create was undone; the off-site purge will destroy what is under bbbbbbbbbbbbbbbbbbbb/ below the projects bucket's prefix",
		"supapaced recover: project cccccccccccccccccccc: its create was undone; the off-site purge will destroy what is under cccccccccccccccccccc/ below the projects bucket's prefix",
	}
	for k, w := range want {
		if lines[i+k] != w {
			t.Errorf("report line %d:\n %q\nwant\n %q", k+1, lines[i+k], w)
		}
	}
	if !strings.HasPrefix(lines[i+4], "supapaced recover: next: ") {
		t.Errorf("the last line: %q", lines[i+4])
	}
	// No undone create: no such line, and nothing else said of the projects.
	r2 := newRecNode(t)
	r2.db.projects = []store.Project{layout2("aaaaaaaaaaaaaaaaaaaa", "active")}
	if out := r2.mustRecover(); strings.Contains(out, "project ") || strings.Contains(out, "aaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("report:\n%s", out)
	}
	// The control-plane bucket's prefix is not where a project's objects lie:
	// it is not printed as if it were.
	if strings.Contains(out, "node-c") {
		t.Fatalf("the report names the control-plane bucket's prefix:\n%s", out)
	}
}

func TestRecover_ReadsTheProvisioningRefsBeforeTheNewEpoch(t *testing.T) {
	r := newRecNode(t)
	l1 := store.Project{Ref: "llllllllllllllllllll", State: "provisioning", Config: store.ProjectConfig{Layout: 1}}
	l0 := store.Project{Ref: "oooooooooooooooooooo", State: "provisioning"}
	r.db.projects = []store.Project{layout2("pppppppppppppppppppp", "provisioning"), l1, l0, layout2("dddddddddddddddddddd", "deleted"),
		layout2("xxxxxxxxxxxxxxxxxxxx", "aborted"), layout2("gggggggggggggggggggg", "purged"), layout2("rrrrrrrrrrrrrrrrrrrr", "restoring")}
	out := r.mustRecover()
	// The list is read before the transaction, which leaves no trace of it.
	if i, j := slices.Index(r.ag.calls, "store-list"), slices.Index(r.ag.calls, "store-new-epoch"); i < 0 || j < i {
		t.Fatalf("order %v", r.ag.calls)
	}
	if strings.Count(strings.Join(r.ag.calls, "\n"), "store-list") != 1 {
		t.Fatalf("listed more than once: %v", r.ag.calls)
	}
	if n := strings.Count(out, "its create was undone"); n != 1 || !strings.Contains(out, "project pppppppppppppppppppp: its create was undone") {
		t.Fatalf("%d lines of undone creates:\n%s", n, out)
	}
	// A create at layout 1 has nothing off-site; a deleted project's prefix
	// is its purge's, not an undone create's.
	for _, ref := range []string{l1.Ref, l0.Ref, "dddddddddddddddddddd", "xxxxxxxxxxxxxxxxxxxx", "gggggggggggggggggggg", "rrrrrrrrrrrrrrrrrrrr"} {
		if strings.Contains(out, ref) {
			t.Errorf("the report names %s", ref)
		}
	}
}

func TestRecover_CallsEnterNewEpochOnce(t *testing.T) {
	r := newRecNode(t)
	out := r.mustRecover()
	if len(r.db.floors) != 1 || r.db.epoch != 5 || !strings.Contains(out, "new epoch 5") {
		t.Fatalf("epoch %d after %d calls: %s", r.db.epoch, len(r.db.floors), out)
	}
	// A run that entered the new epoch and then did not finish is run again:
	// it restores again, so the database is at the lost node's epoch again,
	// and the run adds one to it — never two.
	r = newRecNode(t)
	r.ag.fail["finish"] = errors.New("forced")
	if code, _, _ := r.recover(); code != 1 || len(r.db.floors) != 1 || r.db.epoch != 5 {
		t.Fatalf("the unfinished run: exit %d, epoch %d after %d calls", code, r.db.epoch, len(r.db.floors))
	}
	delete(r.ag.fail, "finish")
	r.db.epoch, r.db.floors = 4, nil // as restored
	out = r.mustRecover()
	if len(r.db.floors) != 1 || r.db.epoch != 5 || !strings.Contains(out, "new epoch 5") {
		t.Fatalf("re-run: epoch %d after %d calls", r.db.epoch, len(r.db.floors))
	}
	// Finished, the node has its control plane: another run is refused.
	if code, _, errs := r.recover(); code != 1 || !strings.Contains(errs, "holds a database and no restore is marked") || len(r.db.floors) != 1 {
		t.Fatalf("a run after a finished recovery: exit %d, %q", code, errs)
	}
}

func TestRecover_CreatesTheNodeDirectoryBeforeItsFirstWrite(t *testing.T) {
	r := newRecNode(t)
	etc := r.etc()
	if exists(etc) {
		t.Fatal("the test's node already has its directory")
	}
	r.mustRecover()
	fi, err := os.Lstat(etc)
	if err != nil || fi.Mode() != fs.ModeDir|0o700 || int(fi.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		t.Fatalf("the node directory: %v, %v", fi.Mode(), err)
	}
	// Anything else at its path is refused before a byte is written.
	elsewhere := t.TempDir()
	for what, plant := range map[string]func(etc string){
		"a link":                          func(etc string) { os.Symlink(elsewhere, etc) },
		"a file":                          func(etc string) { os.WriteFile(etc, nil, 0o600) },
		"a directory others can write":    func(etc string) { os.Mkdir(etc, 0o700); os.Chmod(etc, 0o702) },
		"a directory its group can write": func(etc string) { os.Mkdir(etc, 0o700); os.Chmod(etc, 0o720) },
	} {
		r := newRecNode(t)
		plant(r.etc())
		r.refused(what, "must be a real directory of uid")
		if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
			t.Fatalf("%s: written through the link: %v", what, ents)
		}
	}
	// Control: a directory of the right shape that exists is used as it is.
	r4 := newRecNode(t)
	os.Mkdir(r4.etc(), 0o750)
	r4.mustRecover()
}

// The restored database, for real: what the one transaction leaves of the
// lost node's open work.
func TestRecover_EndsOpenOperationsAndJobs(t *testing.T) {
	p, _, st := realStore(t, false)
	r := newRecNode(t)
	ctx := context.Background()
	openRecovered = func(ctx context.Context) (recoveredStore, error) {
		r.opens++
		return store.Open(ctx, filepath.Join(p.CPDir(), "sock"))
	}
	mk := func(ref string, layout int) int64 {
		t.Helper()
		id, err := st.CreateProject(ctx, store.NewProject{Ref: ref, Name: "demo",
			Config: store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{}, Layout: layout}, Params: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Place(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if err := st.StartOperation(ctx, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	active := func(ref string) {
		t.Helper()
		if err := st.FinishCreate(ctx, mk(ref, 2)); err != nil {
			t.Fatal(err)
		}
		dbExec(t, p, "insert into backup_state (subject) values ($1)", ref)
	}
	one := func(q string, args ...any) (s string) {
		t.Helper()
		c, err := dbConn(p.Root)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		if err := c.QueryRow(ctx, q, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return s
	}
	const (
		jobRef     = "jjjjjjjjjjjjjjjjjjjj" // a running job no operation owns
		restoreRef = "rrrrrrrrrrrrrrrrrrrr" // a restore parked on its job, holding the slot
		restartRef = "ssssssssssssssssssss" // a restart parked at S4
		createRef  = "cccccccccccccccccccc" // a create at 12b
		purgeRef   = "dddddddddddddddddddd" // deleted, its purge waiting for its retention
	)
	active(jobRef)
	dbExec(t, p, "insert into backup_job (subject, lane, kind, state, deadline_s) values ($1, 'push', 'push', 'running', 60)", jobRef)
	active(restoreRef)
	restore, _, err := st.SubmitRestore(ctx, restoreRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	dbExec(t, p, "update operation set state = 'waiting_job', step = 'T7' where id = $1", restore)
	dbExec(t, p, "update project set state = 'restoring', slot_op = $2 where ref = $1", restoreRef, restore)
	dbExec(t, p, "insert into backup_job (subject, lane, kind, state, op_id, op_step, deadline_s) values ($1, 'backup', 'fetch', 'queued', $2, 'T7', 60)", restoreRef, restore)
	active(restartRef)
	restart, err := st.SubmitOperation(ctx, restartRef, "restart", nil, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dbExec(t, p, "update operation set state = 'waiting_job', step = 'S4' where id = $1", restart)
	dbExec(t, p, "update project set state = 'restarting', slot_op = $2 where ref = $1", restartRef, restart)
	create := mk(createRef, 2)
	dbExec(t, p, "update operation set state = 'waiting_job', step = '12b' where id = $1", create)
	dbExec(t, p, "insert into backup_state (subject) values ($1)", createRef)
	active(purgeRef)
	if err := st.SetProjectState(ctx, purgeRef, "deleting"); err != nil {
		t.Fatal(err)
	}
	purge, err := st.MarkDeleted(ctx, purgeRef, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before, err := st.Epoch(ctx)
	if err != nil {
		t.Fatal(err)
	}

	out := r.mustRecover()
	if e, _ := st.Epoch(ctx); e != before+1 || !strings.Contains(out, fmt.Sprintf("new epoch %d", before+1)) {
		t.Fatalf("epoch %d after %d: %s", e, before, out)
	}
	for id, want := range map[int64]string{restore: "failed", restart: "failed", create: "aborted", purge: "pending"} {
		state := one("select state from operation where id = $1", id)
		lastErr := one("select coalesce(last_error, '') from operation where id = $1", id)
		if state != want || (id != purge) != strings.HasPrefix(lastErr, "recovered: ") {
			t.Errorf("operation %d: %s, last error %q; want %s", id, state, lastErr, want)
		}
	}
	if n := one("select count(*)::text from backup_job where state <> 'failed' or code <> 'recovered'"); n != "0" {
		t.Errorf("%s jobs not ended as recovered", n)
	}
	if n := one("select count(*)::text from backup_job"); n != "2" {
		t.Fatalf("control: %s jobs", n)
	}
	for ref, want := range map[string]string{jobRef: "active", restoreRef: "restoring", restartRef: "restarting", createRef: "aborted", purgeRef: "deleted"} {
		if got := one("select state from project where ref = $1", ref); got != want {
			t.Errorf("project %s is %s, want %s", ref, got, want)
		}
	}
	// The aborted create's prefix is an obligation; no slot is left set.
	if got := one("select offsite_purge::text from backup_state where subject = $1", createRef); got != "true" {
		t.Error("the aborted create's prefix obligation is not recorded")
	}
	if n := one("select count(*)::text from project where slot_op is not null"); n != "0" {
		t.Errorf("%s slots still set", n)
	}
	// And the report names that create, and only it.
	if strings.Count(out, "its create was undone") != 1 || !strings.Contains(out, "project "+createRef+": its create was undone") {
		t.Fatalf("report:\n%s", out)
	}
}

// The promoted history names the timelines below its own once each and in
// order: the right number of lines is not enough, nor are lines in order
// that stop short of the timeline before its own.
func TestRecover_ThePromotedHistoryNamesEveryTimelineBelowItsOwnInOrder(t *testing.T) {
	line := func(tli, seg int) string {
		return fmt.Sprintf("%d\t0/%X\tno recovery target specified\n", tli, seg<<24)
	}
	for what, tc := range map[string]struct {
		end  int // the timeline replay ended on; the history is that of the next
		hist string
	}{
		"a timeline named twice":           {2, line(1, 6) + line(1, 10)},
		"out of order":                     {3, line(2, 6) + line(1, 8) + line(3, 10)},
		"the last line of another":         {2, line(1, 6) + line(3, 10)},
		"stops short of the one before":    {3, line(1, 6) + line(2, 10)},
		"one line more than its timelines": {1, line(1, 6) + line(2, 10)},
		"a timeline written with a sign":   {2, line(1, 6) + "+2\t0/A000000\tx\n"},
		"a timeline written with zeros":    {2, line(1, 6) + "02\t0/A000000\tx\n"},
	} {
		for _, args := range [][]string{nil, {"--accept-shortfall"}} {
			r := newRecNode(t)
			r.ag.endTLI, r.ag.history = tc.end, tc.hist
			errs := r.stopped(what+fmt.Sprint(args), args...)
			if !strings.Contains(errs, "does not name every timeline below its own") || !strings.Contains(errs, "the store denies this recovery") ||
				strings.Contains(errs, "shortfall:") {
				t.Errorf("%s %v: %q", what, args, errs)
			}
		}
	}
	// Control: three timelines, each named once and in order, replayed to the newest segment.
	r := newRecNode(t)
	r.fetch(jobio.FetchResult{OK: true, Files: 16, Bytes: 4100, NewestSegment: segName(3, 9), NewestSet: recSet},
		2, line(1, 6), 3, line(1, 6)+line(2, 8))
	r.ag.endTLI, r.ag.history = 3, line(1, 6)+line(2, 8)+line(3, 10)
	if out := r.mustRecover(); !strings.Contains(out, "reached segment "+segName(3, 9)) {
		t.Fatalf("control: %s", out)
	}
}

// killCtx records the context the control plane's job containers are removed with.
type killCtx struct {
	*recAgent
	errs []error
}

func (k *killCtx) KillJobs(ctx context.Context, subject string) error {
	k.errs = append(k.errs, ctx.Err())
	return k.recAgent.KillJobs(ctx, subject)
}

// After a signal the job containers are removed with a context that has not
// ended: with the run's own, the removal would not run at all.
func TestRecover_ASignalStillRemovesTheJobContainers(t *testing.T) {
	r := newRecNode(t)
	ag := &killCtx{recAgent: r.ag}
	newRecoverAgent = func(c nodecfg.Config) recoverAgent { r.ag.cfg = c; return ag }
	r.ag.promoted, r.ag.recovering = false, true // replaying until the signal
	r.ag.script["serve/cp"] = func(ctx context.Context, _ agent.JobSpec) (agent.JobResult, error) {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Error(err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
			t.Error("the signal did not end the run")
		}
		return agent.JobResult{ExitCode: 143}, ctx.Err()
	}
	if code, _, _ := r.recover(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	// The first removal is the preparation's, before the signal; the last is the clean-up's.
	if n := len(ag.errs); n != 2 || ag.errs[0] != nil || ag.errs[1] != nil {
		t.Fatalf("the job containers were removed with contexts %v, want two live ones", ag.errs)
	}
}
