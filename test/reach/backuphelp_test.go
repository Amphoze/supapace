package reach

// Helpers of the backup tests. Untagged, like helpers_test.go, so that
// go test ./... vets them and runs their self-tests (backuphelp_self_test.go).
// They reach the node through the supapace CLI, sp-probe, docker and the files
// the harness writes; every command has a deadline.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/walname"
)

const (
	backupEnv  = "SUPAPACE_BACKUP"  // set: a node below layout 2 fails the backup tests
	standinEnv = "SUPAPACE_STANDIN" // set by `make reach` when the node's stand-in exists
	spoolInPG  = "/opt/supapace/spool"
	rspoolInPG = "/opt/supapace/rspool"
	archInPG   = "/opt/supapace/tools/supapace-arch"
)

var (
	// holdFile keeps the harness's supervisor from starting supapaced.
	holdFile = "/run/sp-hold"
	// s3Dir is where the harness declares its object-store stand-in.
	s3Dir = "/var/lib/sp/s3"
	// pushWait bounds waitPush: one push period, one push deadline, a margin.
	pushWait = 5 * time.Minute
	// daemonProcs lists the running daemons; daemonUp says whether the admin
	// socket answers. Variables for the self-tests.
	daemonProcs = func() []int {
		ps := slices.Concat(procsOf(daemonBin, "serve"), procsOf("/usr/local/bin/supapaced", "serve"))
		return slices.DeleteFunc(slices.Clone(ps), func(p int) bool { return slices.Contains(ps, ppidOf(p)) })
	}
	daemonUp = func() bool {
		c, err := net.DialTimeout("unix", paths.AdminSock(), time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil && len(daemonProcs()) == 1
	}
)

// ───────── the documents of the backup interfaces ─────────

// backupsJSON is GET /v1/projects/{ref}/backups (`supapace project backups`).
type backupsJSON struct {
	Ref          string        `json:"ref"`
	Stanza       string        `json:"stanza"`
	Incarnation  string        `json:"incarnation"`
	Layout       int           `json:"layout"`
	Sets         []setJSON     `json:"sets"`
	Window       windowJSON    `json:"window"`
	Push         pushJSON      `json:"push"`
	Quota        *quotaJSON    `json:"quota"`
	Replication  replJSON      `json:"replication"`
	InfoVersions []infoJSON    `json:"info_versions"`
	Timelines    []tliJSON     `json:"timelines"`
	Gaps         []gapJSON     `json:"gaps"`
	Notices      []noticeJSON  `json:"notices"`
	Restores     []restoreJSON `json:"restores"`
}

type setJSON struct {
	Label        string `json:"label"`
	Timeline     int    `json:"timeline"`
	Start        string `json:"start"`
	Stop         string `json:"stop"`
	StartSegment string `json:"start_segment"`
	StopSegment  string `json:"stop_segment"`
	Replicated   bool   `json:"replicated"`
	ListedAt     string `json:"listed_at"`
}

type windowJSON struct {
	From *string `json:"from"`
	To   *string `json:"to"`
}

type pushJSON struct {
	LastOK        *string `json:"last_ok"`
	LagSeconds    *int64  `json:"lag_seconds"`
	SpoolEntries  int64   `json:"spool_entries"`
	SpoolBytes    int64   `json:"spool_bytes"`
	SpoolOldest   *string `json:"spool_oldest"`
	NewestSegment *string `json:"newest_segment"`
}

type quotaJSON struct {
	At          string `json:"at"`
	DiskUsedMB  int64  `json:"disk_used_mb"`
	DiskQuotaMB int64  `json:"disk_quota_mb"`
	RepoUsedMB  int64  `json:"repo_used_mb"`
	RepoQuotaMB int64  `json:"repo_quota_mb"`
}

type replJSON struct {
	Declared        string  `json:"declared"`
	LastOK          *string `json:"last_ok"`
	LagSeconds      *int64  `json:"lag_seconds"`
	PausedUntil     *string `json:"paused_until"`
	Rebuilding      bool    `json:"rebuilding"`
	BytesToday      int64   `json:"bytes_today"`
	BytesBudget     int64   `json:"bytes_budget"`
	ObjectsToday    int64   `json:"objects_today"`
	ObjectsBudget   int64   `json:"objects_budget"`
	ObjectsRecorded int64   `json:"objects_recorded"`
}

type infoJSON struct {
	Name      string `json:"name"`
	VersionID string `json:"version_id"`
	At        string `json:"at"`
	SHA256    string `json:"sha256"`
}

type tliJSON struct {
	Timeline    int    `json:"timeline"`
	State       string `json:"state"`
	OperationID *int64 `json:"operation_id"`
}

type gapJSON struct {
	Cause        string `json:"cause"`
	FirstSegment string `json:"first_segment"`
	LastSegment  string `json:"last_segment"`
	At           string `json:"at"`
	Detail       string `json:"detail"`
}

type noticeJSON struct {
	Code    string `json:"code"`
	Count   int64  `json:"count"`
	FirstAt string `json:"first_at"`
	LastAt  string `json:"last_at"`
	Detail  string `json:"detail"`
}

type restoreJSON struct {
	OperationID int64  `json:"operation_id"`
	State       string `json:"state"`
	To          string `json:"to"`
	From        string `json:"from"`
	NewTimeline int    `json:"new_timeline"`
	FinishedAt  string `json:"finished_at"`
}

// resultOp is an operation with its result (null until it ends).
type resultOp struct {
	Op
	Result json.RawMessage `json:"result"`
}

// restoreResultJSON is a restore's result. Shortfall is null, an object or the
// string "not checked".
type restoreResultJSON struct {
	To                    string          `json:"to"`
	From                  string          `json:"from"`
	Set                   string          `json:"set"`
	Mode                  string          `json:"mode"`
	ReachedSegment        string          `json:"reached_segment"`
	NewTimeline           int             `json:"new_timeline"`
	PreviousTimeline      int             `json:"previous_timeline"`
	PreviousNewestSegment string          `json:"previous_newest_segment"`
	Seeded                bool            `json:"seeded"`
	Shortfall             json.RawMessage `json:"shortfall"`
	Steps                 []struct {
		Step    string `json:"step"`
		Seconds int64  `json:"seconds"`
	} `json:"steps"`
}

// deleteResultJSON is a delete's result: "ok", "skipped" or a failure code each.
type deleteResultJSON struct {
	FinalBackup      string `json:"final_backup"`
	FinalPush        string `json:"final_push"`
	FinalReplication string `json:"final_replication"`
}

// ───────── when the backup tests run ─────────

// layoutOf is the layout of ref's configuration as `project show` prints it;
// an absent member is layout 1.
func layoutOf(t testing.TB, ref string) int {
	t.Helper()
	out, code := cli(t, "project", "show", ref)
	var p struct {
		Ref    string `json:"ref"`
		Config struct {
			Layout *int `json:"layout"`
		} `json:"config"`
	}
	decode(t, "project show", out, &p)
	if code != 0 || p.Ref != ref {
		t.Fatalf("project show %s: exit %d", ref, code)
	}
	if p.Config.Layout == nil {
		return 1
	}
	if l := *p.Config.Layout; l != 2 {
		t.Fatalf("project %s: layout %d in its configuration; only 2 is written", ref, l)
	}
	return 2
}

// nodeLayout is fixture A's layout: the layout the node's daemon gives a
// project it creates.
func nodeLayout(t testing.TB) int {
	t.Helper()
	A, _ := fixtureAB(t)
	return layoutOf(t, A.Ref)
}

// needBackups is the first line of every backup test: it runs at layout 2.
// Below it the test skips — or fails, when SUPAPACE_BACKUP=1 says the node
// should be at layout 2.
func needBackups(t testing.TB) {
	t.Helper()
	if l := nodeLayout(t); l != 2 {
		msg := fmt.Sprintf("the node creates projects at layout %d; the backup tests need layout 2", l)
		if os.Getenv(backupEnv) == "1" {
			t.Fatalf("%s, and %s=1 is set", msg, backupEnv)
		}
		t.Skip(msg)
	}
}

// needStandin skips where the harness declares no object-store stand-in — or
// fails, when SUPAPACE_STANDIN=1 says there is one.
func needStandin(t testing.TB) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(s3Dir, "endpoint")); err != nil {
		msg := "no object-store stand-in is declared on this node (" + filepath.Join(s3Dir, "endpoint") + " absent)"
		if os.Getenv(standinEnv) == "1" {
			t.Fatalf("%s, and %s=1 is set", msg, standinEnv)
		}
		t.Skip(msg)
	}
}

// ───────── the CLI ─────────

// backups is `supapace project backups REF`, which must answer for ref.
func backups(t testing.TB, ref string) backupsJSON {
	t.Helper()
	out, code := cli(t, "project", "backups", ref)
	var b backupsJSON
	decode(t, "project backups", out, &b)
	if code != 0 || b.Ref != ref {
		t.Fatalf("project backups %s: exit %d, document of %q", ref, code, b.Ref)
	}
	return b
}

// restore runs `supapace project restore REF ARGS…` (it waits unless ARGS
// has --no-wait) and returns the operation document and the exit status.
func restore(t testing.TB, ref string, args ...string) (resultOp, int) {
	t.Helper()
	out, code := cli(t, append([]string{"project", "restore", ref}, args...)...)
	var op resultOp
	decode(t, "project restore", out, &op)
	return op, code
}

// waitPush waits until a push that took every spool entry present at its start
// has ended after the call, and returns the document that shows it. push.last_ok
// is the time a complete push was recorded, after it ended: a push already
// running at the call may have listed the spool before it. So two are awaited —
// the second was created after the first had ended, so after the call.
func waitPush(t testing.TB, ref string) backupsJSON {
	t.Helper()
	after := time.Now()
	var b backupsJSON
	for range 2 {
		for deadline := time.Now().Add(pushWait); ; time.Sleep(time.Second) {
			b = backups(t, ref)
			if b.Push.LastOK != nil {
				at, err := time.Parse(time.RFC3339Nano, *b.Push.LastOK)
				if err != nil {
					t.Fatalf("project backups %s: push.last_ok %q: %v", ref, *b.Push.LastOK, err)
				}
				if at.After(after) {
					after = at
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("project %s: no complete push within %v (last %v)", ref, pushWait, b.Push.LastOK)
			}
		}
	}
	return b
}

// opListing is one `supapace op list` document, by operation id.
func opListing(t testing.TB) map[int64]Op {
	t.Helper()
	out, code := cli(t, "op", "list")
	var ops opsJSON
	decode(t, "op list", out, &ops)
	if code != 0 {
		t.Fatalf("op list: exit %d", code)
	}
	m := map[int64]Op{}
	for _, o := range ops.Operations {
		m[o.ID] = o
	}
	return m
}

// ───────── the daemon and the object store ─────────

// holdDaemon creates the hold file, then kills every supapaced serve and waits
// until none runs. The returned release (also a cleanup; idempotent) removes
// the file and waits until the supervisor's new daemon answers on its socket.
func holdDaemon(t testing.TB) (release func()) {
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
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		ps := daemonProcs()
		if len(ps) == 0 {
			return release
		}
		for _, p := range ps {
			syscall.Kill(p, syscall.SIGKILL)
		}
		if time.Now().After(deadline) {
			t.Fatalf("supapaced still runs 30 s into the hold: %v", ps)
		}
	}
}

// s3Bucket is the bucket each identity of the stand-in may use.
func s3Bucket(role string) string {
	if strings.HasPrefix(role, "cp-") {
		return "sp-cp"
	}
	return "sp-projects"
}

// s3 runs `sp-probe s3 ARGS…` on the node against the stand-in with role's
// keys (admin, projects-write, projects-read, cp-write, cp-read), dialling
// the stand-in's declared addresses only; a --bucket in ARGS replaces the
// role's. It returns the whole output (versions prints a line per entry,
// possibly none) and the exit status, which must agree with the verdict of
// the last line (0 a success line; 1 denied, not-found, exists or bad-digest;
// 2 timeout); an error verdict fails the test.
func s3(t testing.TB, role string, args ...string) (string, int) {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(s3Dir, name))
		if err != nil {
			t.Fatalf("object-store stand-in: %v", err)
		}
		return strings.TrimSpace(string(b))
	}
	endpoint := read("endpoint")
	u, err := url.Parse(endpoint)
	if err != nil || u.Port() == "" {
		t.Fatalf("object-store stand-in: endpoint %q names no port", endpoint)
	}
	argv := []string{probeBin, "s3"}
	argv = append(argv, args...)
	argv = append(argv, "--endpoint", endpoint, "--keys", filepath.Join(s3Dir, role+".keys"),
		"--ca", filepath.Join(s3Dir, "ca.pem"), "--timeout", "30s")
	for _, a := range strings.Fields(read("addrs")) {
		argv = append(argv, "--addr", net.JoinHostPort(a, u.Port()))
	}
	if !slices.Contains(args, "--bucket") {
		argv = append(argv, "--bucket", s3Bucket(role))
	}
	r, err := run(probeTimeout, nil, argv...)
	if err != nil {
		t.Fatalf("sp-probe s3 %s: %v", argOne(argv[1:]), err)
	}
	out := strings.TrimSpace(r.stdout)
	if out == "" && r.code == 0 && args[0] == "versions" {
		return "", 0 // no version under the prefix
	}
	last := out[strings.LastIndexByte(out, '\n')+1:]
	word := strings.SplitN(last, " ", 2)[0]
	want := 0
	switch word {
	case "denied", "not-found", "exists", "bad-digest":
		want = 1
	case "timeout":
		want = 2
	case "error", "":
		t.Fatalf("sp-probe s3 %s: exit %d: %q %s", args[0], r.code, last, brief(r.stderr))
	}
	if want != r.code {
		t.Fatalf("sp-probe s3 %s: exit %d with verdict %q", args[0], r.code, last)
	}
	return out, r.code
}

// asProjectUID runs cmd in a scratch container of the worker image at ref's
// uid and gid, with the job containers' hardening, no network, a private /tmp
// and mounts ("SOURCE:TARGET[:ro]"); the container is removed when cmd ends.
func asProjectUID(t testing.TB, ref string, mounts []string, cmd ...string) result {
	t.Helper()
	out, code := cli(t, "project", "show", ref)
	var p projectJSON
	decode(t, "project show", out, &p)
	if code != 0 || p.Ref != ref || p.UID <= 0 {
		t.Fatalf("project show %s: exit %d, uid %d", ref, code, p.UID)
	}
	return workerRun(t, p.UID, mounts, nil, cmd...)
}

// workerRun is asProjectUID at uid with env ("NAME=value"): the values reach
// the container through the docker client's environment, never its argv.
func workerRun(t testing.TB, uid int, mounts, env []string, cmd ...string) result {
	t.Helper()
	argv := []string{"docker", "run", "--rm", "--label", testLabel, "--network", "none",
		"--user", fmt.Sprintf("%d:%d", uid, uid), "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", "--memory", "512m", "--pids-limit", "256"}
	for _, m := range mounts {
		argv = append(argv, "-v", m)
	}
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		argv = append(argv, "-e", name)
	}
	argv = append(argv, "--entrypoint", cmd[0], workerImage)
	r, err := run(cmdTimeout, env, append(argv, cmd[1:]...)...)
	if err != nil {
		t.Fatalf("worker container at uid %d: %v", uid, err)
	}
	return r
}

// ───────── the project's trees, read on the node ─────────

func spoolDir(ref string) string { return filepath.Join(paths.ProjectDir(ref), "spool") }
func repoDir(ref string) string  { return filepath.Join(paths.RepoDir(ref), "repo") }

// repoFiles lists the regular files of ref's repository by their path
// relative to repo/, without following a link.
func repoFiles(t testing.TB, ref string) []string {
	t.Helper()
	var out []string
	top := repoDir(ref)
	err := filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			out = append(out, strings.TrimPrefix(p, top+"/"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("repository of %s: %v", ref, err)
	}
	return out
}

// archived is the repository path of the archived WAL file name of stanza
// ("" when none): a segment is stored as <name>-<sha1>.zst, a label as itself,
// a history file as itself.
func archived(files []string, stanza, name string) string {
	for _, f := range files {
		k, _, _, ok := walname.RepoPath(stanza, f)
		if !ok || (k != walname.Segment && k != walname.Label && k != walname.History) {
			continue
		}
		base := filepath.Base(f)
		if base == name || strings.HasPrefix(base, name+"-") {
			return f
		}
	}
	return ""
}

// spoolEntry is one entry of a spool, read without following links.
type spoolEntry struct {
	name, link string // link: the target when the entry is a symbolic link
	mode       fs.FileMode
	data       []byte // a regular file's bytes
}

// spool lists ref's spool as root on the node, without following links.
func spool(t testing.TB, ref string) []spoolEntry {
	t.Helper()
	ents, err := os.ReadDir(spoolDir(ref))
	if err != nil {
		t.Fatalf("spool of %s: %v", ref, err)
	}
	var out []spoolEntry
	for _, e := range ents {
		p := filepath.Join(spoolDir(ref), e.Name())
		s := spoolEntry{name: e.Name(), mode: e.Type()}
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			s.link, _ = os.Readlink(p)
		case e.Type().IsRegular():
			s.data, _ = os.ReadFile(p)
		}
		out = append(out, s)
	}
	return out
}

// quarantined finds the entries of a spool outside the archive pattern that
// are not the archive binary's temporaries — where a refused entry is renamed.
func quarantined(es []spoolEntry) []spoolEntry {
	return slices.DeleteFunc(slices.Clone(es), func(e spoolEntry) bool {
		_, _, ok := walname.Spool(e.name)
		return ok || strings.HasPrefix(e.name, ".tmp-")
	})
}

// ───────── secrets at rest ─────────

// readableBy reports whether uid:gid (no supplementary group) may read the file
// at p and traverse every directory above it up to top (top included; "/" for
// a host path, a mount's source for what a container reaches through it).
// ponytail: mode bits only; ACLs and capabilities are not modelled.
func readableBy(uid, gid int, p, top string) bool {
	ok := func(st *syscall.Stat_t, bit uint32) bool {
		switch {
		case int(st.Uid) == uid:
			return st.Mode&(bit<<6) != 0
		case int(st.Gid) == gid:
			return st.Mode&(bit<<3) != 0
		}
		return st.Mode&bit != 0
	}
	var st syscall.Stat_t
	if syscall.Lstat(p, &st) != nil || !ok(&st, 4) {
		return false
	}
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		if syscall.Stat(d, &st) != nil || !ok(&st, 1) {
			return false
		}
		if d == top || d == "/" {
			return true
		}
	}
}

// secretsReadableBy walks roots without following links and returns every
// regular file uid:gid could read that holds one of needles' forms. A root
// that does not exist is skipped; a walk error is returned. mounted: each
// root is a mount source, reached inside a container without the directories
// above it, so only those from the root down are checked.
func secretsReadableBy(uid, gid int, roots []string, mounted bool, needles []needle) ([]string, error) {
	var hits []string
	for _, r := range roots {
		top := "/"
		if mounted {
			top = r
		}
		err := filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) { // an absent root, or an entry gone while walking
					return nil
				}
				return err
			}
			if !d.Type().IsRegular() || !readableBy(uid, gid, p, top) {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Size() > 16<<20 { // ponytail: a secret file is small; larger files are not read
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for _, n := range needles {
				if containsAny(b, n.b) >= 0 {
					hits = append(hits, p+" ("+n.name+")")
				}
			}
			return nil
		})
		if err != nil {
			return hits, err
		}
	}
	return hits, nil
}

// s3KeyNeedles are the stand-in's keys of every identity, when it is declared.
func s3KeyNeedles(t testing.TB) []needle {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(s3Dir, "*.keys"))
	var out []needle
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range bytes.Fields(b) {
			out = append(out, needle{fmt.Sprintf("key %d of %s", i+1, filepath.Base(f)), [][]byte{line}})
		}
	}
	return out
}

// workerImage is the image every job container runs.
const workerImage = nodecfg.WorkerImage
