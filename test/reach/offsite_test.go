//go:build reach

package reach

// The off-site copy: what a project's replication may reach and upload, the
// object lock of the store and the rollback past a forged version, and the
// replicator under hostile repository content, budgets, an unreachable store
// and a full repository quota. The repository is the project's own tree and
// is untrusted: entries are planted at the project's uid (a root helper only
// where another owner is the point). What the store holds is read with the
// harness's own keys, never from a job's report. Each test runs at layout 2
// with the object-store stand-in (needBackups, needStandin).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/repl"
	"github.com/Amphoze/supapace/internal/s3x"
	"github.com/Amphoze/supapace/internal/walname"
)

// ───────── shared ─────────

// replWait bounds the wait for one replication: a push period, the push, the
// copy's own bound and a margin.
var replWait = bklimit.PushInterval + 2*repl.CopyBound + 2*time.Minute

// s3Ver is one line of `sp-probe s3 versions`.
type s3Ver struct {
	marker  bool
	key, id string
	latest  bool
}

// versionsAt lists every version and delete marker below prefix ("" the
// whole bucket) of the projects' bucket, read with the read-only keys.
func versionsAt(t testing.TB, prefix string) []s3Ver {
	t.Helper()
	args := []string{"versions"}
	if prefix != "" {
		args = append(args, prefix)
	}
	out, code := s3(t, "projects-read", args...)
	if code != 0 {
		t.Fatalf("versions %q: exit %d: %s", prefix, code, brief(out))
	}
	var vs []s3Ver
	for line := range strings.Lines(out) {
		kind, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
		q, err := strconv.QuotedPrefix(rest)
		if err != nil || kind != "version" && kind != "marker" {
			t.Fatalf("versions %q: line %q", prefix, line)
		}
		key, _ := strconv.Unquote(q)
		f := strings.Fields(rest[len(q):])
		if len(f) != 2 {
			t.Fatalf("versions %q: line %q", prefix, line)
		}
		vs = append(vs, s3Ver{kind == "marker", key, f[0], f[1] == "latest"})
	}
	return vs
}

// objectsOf is versionsAt reduced to the object versions of exactly key.
func objectsOf(t testing.TB, key string) []s3Ver {
	t.Helper()
	return slices.DeleteFunc(versionsAt(t, key), func(v s3Ver) bool { return v.marker || v.key != key })
}

// inStore reports whether key has a current object in the projects' bucket.
func inStore(t testing.TB, key string) bool {
	t.Helper()
	_, code := s3(t, "projects-read", "head", key)
	return code == 0
}

// waitKey waits until key is in the store, switching a WAL segment of p now
// and then so that pushes, and the replications queued at them, keep coming.
func waitKey(t testing.TB, p Project, key string) {
	t.Helper()
	var next time.Time
	for deadline := time.Now().Add(replWait); !inStore(t, key); time.Sleep(5 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("%s is not in the store within %v", key, replWait)
		}
		if time.Now().After(next) {
			switchWAL(t, p)
			next = time.Now().Add(bklimit.PushInterval)
		}
	}
}

// waitRepl switches a segment of p, waits for its push, and returns the
// document that shows a complete replication recorded after that push.
func waitRepl(t testing.TB, p Project) backupsJSON {
	t.Helper()
	seg := switchWAL(t, p)
	b := waitPush(t, p.Ref)
	waitKey(t, p, p.Ref+"/"+archived(repoFiles(t, p.Ref), b.Stanza, seg))
	after, _ := time.Parse(time.RFC3339Nano, *b.Push.LastOK)
	for deadline := time.Now().Add(replWait); ; time.Sleep(5 * time.Second) {
		b = backups(t, p.Ref)
		if r := b.Replication.LastOK; r != nil {
			if at, err := time.Parse(time.RFC3339Nano, *r); err == nil && at.After(after) {
				return b
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("project %s: no complete replication recorded within %v of a push (last %v)", p.Ref, replWait, b.Replication.LastOK)
		}
	}
}

// noticeCount is the count of the notice code in b (0 when none).
func noticeCount(b backupsJSON, code string) int64 {
	for _, n := range b.Notices {
		if n.Code == code {
			return n.Count
		}
	}
	return 0
}

// noticeEntries is the count of entries the last job reported under code, from
// the notice's detail "job <id>: <count>: <first>" (-1 when none parses).
func noticeEntries(b backupsJSON, code string) int64 {
	for _, n := range b.Notices {
		if n.Code == code {
			_, rest, _ := strings.Cut(n.Detail, ": ")
			c, _, _ := strings.Cut(rest, ":")
			if v, err := strconv.ParseInt(c, 10, 64); err == nil {
				return v
			}
		}
	}
	return -1
}

// waitNotice waits until p's notice code was reported again after b0; with
// kick it switches a segment of p now and then, so that jobs keep coming.
func waitNotice(t testing.TB, p Project, code string, b0 backupsJSON, kick bool) backupsJSON {
	t.Helper()
	next := time.Time{}
	if !kick {
		next = time.Now().Add(24 * time.Hour)
	}
	for deadline := time.Now().Add(replWait); ; time.Sleep(5 * time.Second) {
		b := backups(t, p.Ref)
		if noticeCount(b, code) > noticeCount(b0, code) {
			return b
		}
		if time.Now().After(deadline) {
			t.Fatalf("project %s: no %s notice within %v (notices %+v)", p.Ref, code, replWait, b.Notices)
		}
		if time.Now().After(next) {
			switchWAL(t, p)
			next = time.Now().Add(bklimit.PushInterval)
		}
	}
}

// archiveDir is "archive/<stanza>/<archive id>" of p's newest pushed segment.
func archiveDir(t testing.TB, p Project) (string, backupsJSON) {
	t.Helper()
	seg := switchWAL(t, p)
	b := waitPush(t, p.Ref)
	f := archived(repoFiles(t, p.Ref), b.Stanza, seg)
	if f == "" {
		t.Fatalf("control: %s is not in %s's repository after a push", seg, p.Ref)
	}
	return strings.Join(strings.Split(f, "/")[:3], "/"), b
}

// plantRepo runs script at p's uid in a worker container with p's repository
// mounted writable at /repo; it must succeed.
func plantRepo(t testing.TB, p Project, script string, args ...string) string {
	t.Helper()
	r := asProjectUID(t, p.Ref, []string{repoDir(p.Ref) + ":/repo"}, append([]string{"sh", "-c", script, "sh"}, args...)...)
	if r.code != 0 {
		t.Fatalf("planting in %s's repository: exit %d: %s", p.Ref, r.code, brief(r.stderr))
	}
	return strings.TrimSpace(r.stdout)
}

// segPath is the repository path, below dir (archive/<stanza>/<id>), of the
// segment seg stored under a forged digest.
func segPath(dir, seg string) string {
	return dir + "/" + seg[:16] + "/" + seg + "-" + strings.Repeat("0", 40) + ".zst"
}

// handRestore restores p's set label by hand into a fresh directory with the
// passphrase pass; it returns the run.
func handRestore(t testing.TB, p Project, label string, pass []byte) result {
	t.Helper()
	out := handRepo(t, p)
	return workerRun(t, p.UID, []string{repoDir(p.Ref) + ":/repo:ro", out + ":/out"},
		[]string{"PGBACKREST_STANZA=" + backups(t, p.Ref).Stanza, "PGBACKREST_REPO1_PATH=/repo", "PGBACKREST_CONFIG=/dev/null",
			"PGBACKREST_REPO1_CIPHER_TYPE=aes-256-cbc", "PGBACKREST_REPO1_CIPHER_PASS=" + string(pass), "PGBACKREST_PG1_PATH=/out",
			"PGBACKREST_LOCK_PATH=/tmp/lock", "PGBACKREST_LOG_PATH=/tmp/log", "PGBACKREST_LOG_LEVEL_FILE=off"},
		"pgbackrest", "restore", "--set="+label, "--type=none")
}

// s3Client is a client of role's bucket on the stand-in, dialling its
// declared addresses only.
func s3Client(t testing.TB, role string) (*s3x.Client, s3x.Config) {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(s3Dir, name))
		if err != nil {
			t.Fatalf("object-store stand-in: %v", err)
		}
		return strings.TrimSpace(string(b))
	}
	u, err := url.Parse(read("endpoint"))
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.Fields(read(role + ".keys"))
	cfg := s3x.Config{Endpoint: u.String(), Region: "us-east-1", Bucket: s3Bucket(role), PathStyle: true,
		AccessKey: keys[0], SecretKey: keys[1], CAPEM: read("ca.pem"), Timeout: 30 * time.Second}
	for _, a := range strings.Fields(read("addrs")) {
		ap, err := netip.ParseAddrPort(a + ":" + u.Port())
		if err != nil {
			t.Fatal(err)
		}
		cfg.Addrs = append(cfg.Addrs, ap)
	}
	cl, err := s3x.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cl, cfg
}

// s3Delete sends one signed DELETE of key (a version when version is not "")
// to the projects' bucket with role's keys, the governance-bypass header when
// bypass, and returns the answer's status.
func s3Delete(t testing.TB, role, key, version string, bypass bool) int {
	t.Helper()
	cl, cfg := s3Client(t, role)
	u, _ := url.Parse(cfg.Endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "DELETE", "https://"+u.Host+"/", nil)
	r.URL.Path = "/" + cfg.Bucket + "/" + key
	if version != "" {
		r.URL.RawQuery = "versionId=" + url.QueryEscape(version)
	}
	if bypass {
		r.Header.Set("X-Amz-Bypass-Governance-Retention", "true")
	}
	empty := sha256.Sum256(nil)
	s3x.Sign(r, hex.EncodeToString(empty[:]), cfg.AccessKey, cfg.SecretKey, cfg.Region, time.Now())
	resp, err := cl.HTTPClient().Do(r)
	if err != nil {
		t.Fatalf("DELETE %s: %v", key, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// restoreLong is `project restore REF ARGS… --no-wait`, then a wait of up to
// within for its end; it returns the operation with its result.
func restoreLong(t testing.TB, ref string, within time.Duration, args ...string) resultOp {
	t.Helper()
	out, code := cli(t, append([]string{"project", "restore", ref, "--no-wait"}, args...)...)
	var m mutationJSON
	decode(t, "project restore", out, &m)
	if code != 0 || m.OperationID == 0 {
		t.Fatalf("project restore %s --no-wait: exit %d", ref, code)
	}
	if op, ok := pollOp(t, m.OperationID, time.Now().Add(within)); !ok {
		t.Fatalf("restore of %s still %s at step %q after %v", ref, op.State, op.Step, within)
	}
	out, _ = cli(t, "op", "show", strconv.FormatInt(m.OperationID, 10))
	var op resultOp
	decode(t, "op show", out, &op)
	return op
}

// ───────── test 24 ─────────

// TestReach24_RepositoryScope: A's jobs mount A's repository and nothing of B;
// what A plants in its repository — B's stanza name, a directory named for
// B's ref, links into B's tree — reaches the store nowhere, and A's keys are
// all below "<A's ref>/" and name A's own stanza (control: a forged file with
// a valid name of A's stanza is uploaded there). The replication job's
// credential is the write pair, which on the stand-in can place a delete
// marker but not remove a locked version. A's set restored by hand with B's
// passphrase fails (control: with A's it succeeds).
func TestReach24_RepositoryScope(t *testing.T) {
	needBackups(t)
	needStandin(t)
	_, B := fixtureAB(t)
	A := fixtureScratch(t)
	bOut := func(c string) {
		t.Helper()
		for dst, m := range containerMounts(t, c) {
			if strings.HasPrefix(m.Source, paths.RepoDir(B.Ref)) || strings.HasPrefix(m.Source, paths.ProjectDir(B.Ref)) {
				t.Errorf("%s mounts %s of B at %s", c, m.Source, dst)
			}
		}
		if m := containerMounts(t, c)["/repo"]; m.Source != repoDir(A.Ref) || m.RW && strings.HasSuffix(c, "-replicate") {
			t.Errorf("%s mounts %+v at /repo, want A's repository (read-only for a replication)", c, m)
		}
	}

	switchWAL(t, A)
	job, resume := catchJob(t, A.Ref, "push", 3*time.Minute)
	bOut(job)
	resume()

	switchWAL(t, A)
	job, resume = catchJob(t, A.Ref, "replicate", replWait)
	bOut(job)
	cred, err := os.ReadFile(containerMounts(t, job)["/cred"].Source)
	resume()
	write, _ := os.ReadFile(filepath.Join(s3Dir, "projects-write.keys"))
	read, _ := os.ReadFile(filepath.Join(s3Dir, "projects-read.keys"))
	if err != nil || !slices.Equal(strings.Fields(string(cred)), strings.Fields(string(write))[:2]) {
		t.Errorf("the replication job's credential is not the projects' write pair (%v)", err)
	}
	if slices.Equal(strings.Fields(string(write))[:2], strings.Fields(string(read))[:2]) {
		t.Fatal("control: the write and read-only key files hold the same pair; the comparison proves nothing")
	}

	// The write pair's delete right on the stand-in: the documented limit.
	probe := "reach-scope/" + randHex(8)
	out, code := s3(t, "projects-write", "put", probe)
	if code != 0 {
		t.Fatalf("put %s with the write pair: %s", probe, out)
	}
	vid := strings.Fields(out)[1]
	if out, code := s3(t, "projects-write", "rm", probe, "--version", vid); code != 1 || !strings.HasPrefix(out, "denied") {
		t.Errorf("the write pair removed a locked version: exit %d %q", code, out)
	}
	if out, code := s3(t, "projects-write", "rm", probe); code != 0 || !strings.Contains(out, "marker=true") {
		t.Errorf("the write pair placed no delete marker (exit %d %q): the stand-in's documented limit changed", code, out)
	} else {
		t.Log("documented limit: on the stand-in the write pair places delete markers; locked versions stay")
	}

	// Planted names and links.
	dir, b := archiveDir(t, A)
	stanzaB := backups(t, B.Ref).Stanza
	ctl := segPath(dir, "00000001000000AC00000001")
	planted := []string{
		"archive/" + stanzaB + "/" + strings.Split(dir, "/")[2] + "/00000001000000AD/00000001000000AD00000001-" + strings.Repeat("0", 40) + ".zst",
		B.Ref + "/" + segPath(dir, "00000001000000AE00000001"),
		dir + "/00000001000000AB",
		segPath(dir, "00000001000000AF00000001"),
	}
	bFile := ""
	for _, f := range repoFiles(t, B.Ref) {
		if k, _, _, ok := walname.RepoPath(stanzaB, f); ok && k == walname.Segment {
			bFile = filepath.Join(repoDir(B.Ref), f)
			break
		}
	}
	if bFile == "" {
		t.Fatal("control: B's repository holds no segment to link to")
	}
	plantRepo(t, A, `cd /repo && for p in "$1" "$2" "$5"; do mkdir -p "$(dirname "$p")"; head -c 4096 /dev/urandom > "$p"; done &&
		ln -s "$6" "$3" && mkdir -p "$(dirname "$4")" && ln -s "$7" "$4"`,
		planted[0], planted[1], planted[2], planted[3], ctl, filepath.Join(repoDir(B.Ref), "archive", stanzaB), bFile)
	waitKey(t, A, A.Ref+"/"+ctl)

	for _, v := range versionsAt(t, "") {
		rel, inA := strings.CutPrefix(v.key, A.Ref+"/")
		if strings.HasPrefix(v.key, A.Ref) && !inA {
			t.Errorf("key %q begins with A's ref but is not below its prefix", v.key)
		}
		if inA {
			if _, _, _, ok := walname.RepoPath(b.Stanza, rel); !ok {
				t.Errorf("A's key %q names no path of A's stanza", v.key)
			}
		}
		for _, p := range planted {
			// The planted path may be the key itself (B's ref or no ref in front of it).
			if v.key == p || strings.HasSuffix(v.key, "/"+p) || strings.HasPrefix(rel, p+"/") && inA {
				t.Errorf("the planted entry %s reached the store as %q", p, v.key)
			}
		}
	}

	// B's passphrase on A's stanza.
	label := backups(t, A.Ref).Sets[0].Label
	restoredSet(t, A, label) // control: A's own passphrase restores it
	if r := handRestore(t, A, label, platformSecret(t, B, "backup.cipher_pass")); r.code == 0 {
		t.Error("A's set was restored with B's passphrase")
	}
}

// ───────── test 25 ─────────

// TestReach25_ObjectLock: a locked version of a project's key cannot be
// removed with the admin keys (control: they place a delete marker, so the
// right is held), nor with the governance-bypass header (control: the same
// request without a version is answered); a forged overwrite of the info
// files and of a segment succeeds and is the current version; a restore with
// --from offsite then fetches the recorded versions and completes, the marker
// written before it present.
func TestReach25_ObjectLock(t *testing.T) {
	needBackups(t)
	needStandin(t)
	S := fixtureScratch(t)
	mustSQL(t, S, "postgres", "create table public.reach_mark(x text); insert into public.reach_mark values ('before')")
	seg := switchWAL(t, S)
	b := waitPush(t, S.Ref)
	segKey := S.Ref + "/" + archived(repoFiles(t, S.Ref), b.Stanza, seg)
	waitKey(t, S, segKey)
	for deadline := time.Now().Add(replWait); !slices.ContainsFunc(b.Sets, func(s setJSON) bool { return s.Replicated && s.ListedAt != "" }); time.Sleep(5 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("no set of %s recorded as replicated and listed within %v", S.Ref, replWait)
		}
		b = backups(t, S.Ref)
	}

	vs := objectsOf(t, segKey)
	if len(vs) != 1 {
		t.Fatalf("%s: %d versions, want 1", segKey, len(vs))
	}
	if st := s3Delete(t, "admin", segKey, vs[0].id, false); st != http.StatusForbidden {
		t.Errorf("deleting a locked version with the admin keys: HTTP %d, want 403", st)
	}
	if st := s3Delete(t, "admin", segKey, vs[0].id, true); st != http.StatusForbidden {
		t.Errorf("deleting a locked version with the governance-bypass header: HTTP %d, want 403", st)
	}
	probe := "reach-lock/" + randHex(8)
	if _, code := s3(t, "admin", "put", probe); code != 0 {
		t.Fatal("control: the admin keys cannot write")
	}
	if st := s3Delete(t, "admin", probe, "", true); st/100 != 2 {
		t.Errorf("control: the admin keys could not place a delete marker (HTTP %d); the refusals prove nothing", st)
	}
	if _, code := s3(t, "projects-read", "head", segKey, "--version", vs[0].id); code != 0 {
		t.Errorf("the locked version of %s is gone", segKey)
	}

	forged := []string{segKey, S.Ref + "/archive/" + b.Stanza + "/archive.info", S.Ref + "/backup/" + b.Stanza + "/backup.info"}
	for _, k := range forged {
		if out, code := s3(t, "projects-write", "put", k); code != 0 {
			t.Fatalf("a forged overwrite of %s: exit %d %q", k, code, out)
		}
		if out, _ := s3(t, "projects-read", "get", k); !strings.HasPrefix(out, "object 0 ") {
			t.Fatalf("control: the current version of %s is not the forged one: %q", k, out)
		}
	}
	if got := objectsOf(t, segKey); len(got) != 2 || !slices.ContainsFunc(got, func(v s3Ver) bool { return v.id == vs[0].id && !v.latest }) {
		t.Errorf("%s after the overwrite: %+v", segKey, got)
	}

	op := restoreLong(t, S.Ref, 45*time.Minute, "--to", "latest", "--from", "offsite")
	if op.State != "done" {
		t.Fatalf("restore --from offsite past forged versions: %s at %q: %s", op.State, op.Step, op.LastError)
	}
	var res restoreResultJSON
	if err := json.Unmarshal(op.Result, &res); err != nil || res.From != "offsite" {
		t.Errorf("restore result %s: from %q, want offsite (%v)", op.Result, res.From, err)
	}
	if got := mustSQL(t, S, "postgres", "select x from public.reach_mark"); got != "before" {
		t.Errorf("after the rollback the marker reads %q", got)
	}
}

// ───────── test 29 ─────────

// TestReach29_Replicator: the replication program against what a tenant can
// do to its own repository, and the replication beside the rest of the node
// when budgets, the store or the repository quota run out. Each sub-test says
// what makes it fail.
func TestReach29_Replicator(t *testing.T) {
	needBackups(t)
	needStandin(t)
	A, B := fixtureAB(t)

	// Fails if anything planted is uploaded or followed, or goes unnoticed;
	// control: S's real segment beside them is uploaded.
	t.Run("walk", func(t *testing.T) {
		S := fixtureScratch(t)
		dir, b0 := archiveDir(t, S)
		noise := []string{segPath(dir, "00000001000000B000000001"), dir + "/00000001000000B1", segPath(dir, "00000001000000B200000001"),
			segPath(dir, "00000001000000B300000001"), segPath(dir, "00000001000000B400000001"), dir + "/d1"}
		swap := segPath(dir, "00000001000000B500000001")
		other := segPath(dir, "00000001000000B600000001")
		t.Cleanup(func() {
			run(cmdTimeout, nil, "docker", "rm", "-f", "sp-test-offsite-swap")
			asProjectUID(t, S.Ref, []string{repoDir(S.Ref) + ":/repo"}, "sh", "-c",
				`cd /repo && rm -rf "$1"/00000001000000B? "$1"/7FFFFFF000000000 "$1"/d1`, "sh", dir)
		})
		// Links out, to the root and to B's tree; a FIFO; 100 GB sparse; a
		// directory 14 levels deep; 5,000 valid names of a timeline S never had.
		plantRepo(t, S, `cd /repo && mkdir -p "$(dirname "$1")" "$(dirname "$4")" "$(dirname "$5")" "$(dirname "$7")" "$8/7FFFFFF000000000" &&
			ln -s /etc/passwd "$1" && ln -s / "$2" && mkdir -p "$(dirname "$3")" && ln -s "$6" "$3" && mkfifo "$4" && truncate -s 100G "$5" &&
			mkdir -p "$9"/2/3/4/5/6/7/8/9/10/11/12/13/14 && printf x > "$9"/2/3/4/5/6/7/8/9/10/11/12/13/14/x &&
			mkdir -p "$(dirname "$7")" && i=0 && while [ $i -lt 5000 ]; do
				printf x > "$8/7FFFFFF000000000/7FFFFFF000000000$(printf %08X $i)-0000000000000000000000000000000000000000.zst"; i=$((i+1)); done`,
			noise[0], noise[1], noise[2], noise[3], noise[4], filepath.Join(repoDir(B.Ref), "archive"), swap, dir, noise[5])
		// A file of another uid, made by root in a directory of S's.
		plantRepo(t, S, `mkdir -p "/repo/$(dirname "$1")"`, other)
		f, err := os.Create(filepath.Join(repoDir(S.Ref), other))
		if err != nil || f.Close() != nil || os.Chown(f.Name(), B.UID, B.UID) != nil {
			t.Fatalf("a file of another uid: %v", err)
		}
		honest := "reach-honest-" + randHex(16)
		sum := sha256.Sum256([]byte(honest))
		docker(t, "run", "-d", "--name", "sp-test-offsite-swap", "--label", testLabel, "--network", "none",
			"--user", fmt.Sprintf("%d:%d", S.UID, S.UID), "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"-v", repoDir(S.Ref)+":/repo", "--entrypoint", "sh", workerImage, "-c",
			`cd /repo && while :; do printf %s "$1" > "$2.r"; mv -f "$2.r" "$2"; ln -s "$3" "$2.l"; mv -f "$2.l" "$2"; done`,
			"sh", honest, swap, filepath.Join(repoDir(B.Ref), "archive"))

		seg := switchWAL(t, S)
		b := waitPush(t, S.Ref)
		waitKey(t, S, S.Ref+"/"+archived(repoFiles(t, S.Ref), b.Stanza, seg)) // control
		b = waitNotice(t, S, "unlisted-entry", b0, true)
		// Each planted entry is counted: three links, the FIFO, the file of
		// another uid, the directory past the depth bound and the 5,000 names.
		// A copy that walked during the planting counts fewer; a later one all.
		const planted = 5006
		for deadline := time.Now().Add(replWait); noticeEntries(b, "unlisted-entry") < planted; time.Sleep(5 * time.Second) {
			if time.Now().After(deadline) {
				t.Fatalf("no copy counted the %d unlisted entries within %v (last %d)", planted, replWait, noticeEntries(b, "unlisted-entry"))
			}
			b = backups(t, S.Ref)
		}
		if noticeEntries(b, "unreadable-entry") < 1 {
			t.Error("no unreadable entry counted (the 100 GB file)")
		}
		for _, v := range versionsAt(t, "") {
			rel, inS := strings.CutPrefix(v.key, S.Ref+"/")
			if strings.Contains(v.key, "7FFFFFF0") || strings.Contains(v.key, "/d1/") {
				t.Errorf("a planted entry reached the store: %q", v.key)
			}
			if !inS || v.marker {
				continue
			}
			if slices.Contains(noise, rel) || rel == other || strings.HasPrefix(rel, noise[1]+"/") {
				t.Errorf("a planted entry reached the store: %q", v.key)
				continue
			}
			if rel == swap {
				out, code := s3(t, "projects-read", "get", v.key, "--version", v.id)
				if f := strings.Fields(out); code != 0 || len(f) < 3 || f[2] != hex.EncodeToString(sum[:]) {
					t.Errorf("a version of the swapped name holds other bytes than the honest file: %q", out)
				}
				continue
			}
			if fi, err := os.Lstat(filepath.Join(repoDir(S.Ref), rel)); err != nil || !fi.Mode().IsRegular() {
				t.Errorf("key %q has no regular file in S's repository (%v)", v.key, err)
			}
		}
	})

	// Fails if a data file rewritten after its upload goes up again or
	// unnoticed; control: a later segment is uploaded.
	t.Run("write_once", func(t *testing.T) {
		S := fixtureScratch(t)
		seg := switchWAL(t, S)
		b0 := waitPush(t, S.Ref)
		rel := archived(repoFiles(t, S.Ref), b0.Stanza, seg)
		waitKey(t, S, S.Ref+"/"+rel)
		b0 = backups(t, S.Ref)
		plantRepo(t, S, `cd /repo && cp "$1" /tmp/x && printf reach >> /tmp/x && cat /tmp/x > "$1"`, rel)
		next := switchWAL(t, S)
		b := waitPush(t, S.Ref)
		waitKey(t, S, S.Ref+"/"+archived(repoFiles(t, S.Ref), b.Stanza, next))
		waitNotice(t, S, "history-rewritten", b0, true)
		if vs := objectsOf(t, S.Ref+"/"+rel); len(vs) != 1 {
			t.Errorf("%s: %d versions after a local rewrite, want 1", rel, len(vs))
		}
	})

	// Fails if a set directory without its manifest — what a running backup
	// leaves — is uploaded in part; control: with the manifest it goes up.
	t.Run("copy_order", func(t *testing.T) {
		S := fixtureScratch(t)
		b := backups(t, S.Ref)
		set := "backup/" + b.Stanza + "/" + b.Sets[0].Label
		part := "backup/" + b.Stanza + "/20991231-235959F"
		plantRepo(t, S, `cd /repo && mkdir "$2" && cp -a "$1"/pg_data "$1"/backup.manifest.copy "$2"/`, set, part)
		waitRepl(t, S)
		if vs := versionsAt(t, S.Ref+"/"+part+"/"); len(vs) != 0 {
			t.Errorf("a set without its manifest was uploaded in part: %d keys, first %q", len(vs), vs[0].key)
		}
		plantRepo(t, S, `cd /repo && cp "$1"/backup.manifest "$2"/`, set, part)
		waitKey(t, S, S.Ref+"/"+part+"/backup.manifest")
		if vs := versionsAt(t, S.Ref+"/"+part+"/pg_data/"); len(vs) == 0 {
			t.Error("control: the completed set's files did not go up")
		}
	})

	// Fails if a timeline's segments go up before its history, or the info
	// files before them; control: with the history readable both go up.
	t.Run("history_first", func(t *testing.T) {
		S := fixtureScratch(t)
		waitRepl(t, S)
		// The restore runs to its replication step, where the daemon stops
		// and stays held: timeline 2's history and segments are then pushed,
		// not replicated.
		if err := os.WriteFile(holdFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			os.Remove(paths.Failpoint())
			os.Remove(holdFile)
			for deadline := time.Now().Add(2 * time.Minute); !daemonUp() && time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			}
		})
		if err := os.WriteFile(paths.Failpoint(), []byte("restore:T10r"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, code := cli(t, "project", "restore", S.Ref, "--to", "latest", "--no-wait")
		var m mutationJSON
		decode(t, "project restore", out, &m)
		if code != 0 {
			t.Fatalf("restore --no-wait: exit %d", code)
		}
		var asked time.Time
		for deadline := time.Now().Add(45 * time.Minute); len(daemonProcs()) != 0; time.Sleep(time.Second) {
			if time.Now().After(deadline) {
				t.Fatal("the daemon did not stop at the restore's replication step within 45 minutes")
			}
			// A restore that ends before that step never stops the daemon: fail
			// at once (a call refused while the daemon exits is not an answer).
			if time.Since(asked) >= 10*time.Second {
				asked = time.Now()
				if out, code := cli(t, "op", "show", strconv.FormatInt(m.OperationID, 10)); code == 0 {
					var op Op
					decode(t, "op show", out, &op)
					if op.State == "done" || op.State == "failed" || op.State == "aborted" {
						t.Fatalf("the restore ended %s at %q before its replication step: %s", op.State, op.Step, op.LastError)
					}
				}
			}
		}
		release := holdDaemon(t)
		if _, err := os.Stat(paths.Failpoint()); err == nil {
			t.Fatal("the daemon stopped, but not at the failpoint")
		}
		stanza := backups(t, S.Ref).Stanza
		hist := ""
		for _, f := range repoFiles(t, S.Ref) {
			if k, tl, _, ok := walname.RepoPath(stanza, f); ok && k == walname.History && tl == 2 {
				hist = f
			}
		}
		if hist == "" {
			t.Fatal("control: timeline 2's history is not in the repository at the replication step")
		}
		tl2 := S.Ref + "/" + strings.TrimSuffix(hist, ".history")
		if inStore(t, S.Ref+"/"+hist) || len(versionsAt(t, tl2)) != 0 {
			t.Fatal("control: timeline 2 was already in the store before the replication step")
		}
		infoKeys := []string{S.Ref + "/archive/" + stanza + "/archive.info", S.Ref + "/backup/" + stanza + "/backup.info"}
		infos := map[string]int{}
		for _, k := range infoKeys {
			infos[k] = len(objectsOf(t, k))
		}
		histPath := filepath.Join(repoDir(S.Ref), hist)
		if err := os.Chmod(histPath, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(histPath, 0o640) })
		b0 := backups(t, S.Ref)
		release()
		waitNotice(t, S, "segment-without-history", b0, false)
		if vs := versionsAt(t, tl2); len(vs) != 0 {
			t.Errorf("timeline 2 went up with its history unreadable: %q", vs[0].key)
		}
		for _, k := range infoKeys {
			if n := len(objectsOf(t, k)); n != infos[k] {
				t.Errorf("%s gained a version while segments were held (%d, then %d)", k, infos[k], n)
			}
		}
		if err := os.Chmod(histPath, 0o640); err != nil {
			t.Fatal(err)
		}
		op, ok := pollOp(t, m.OperationID, time.Now().Add(30*time.Minute))
		if ok && op.State == "failed" {
			if _, code := cli(t, "op", "retry", strconv.FormatInt(op.ID, 10)); code != 0 {
				t.Fatalf("op retry %d: exit %d", op.ID, code)
			}
			op, ok = pollOp(t, m.OperationID, time.Now().Add(30*time.Minute))
		}
		if !ok || op.State != "done" {
			t.Fatalf("the restore with its history readable again: %s at %q: %s", op.State, op.Step, op.LastError)
		}
		if !inStore(t, S.Ref+"/"+hist) || !slices.ContainsFunc(versionsAt(t, tl2), func(v s3Ver) bool {
			k, _, _, _ := walname.RepoPath(stanza, strings.TrimPrefix(v.key, S.Ref+"/"))
			return k == walname.Segment
		}) {
			t.Error("control: with the history readable, timeline 2's history and segments did not go up")
		}
	})

	// Fails if a project over its object budget keeps replicating, its notice
	// carries no projected time, its pushes stop, or B is paused with it.
	t.Run("budgets", func(t *testing.T) {
		S := fixtureScratch(t)
		if b := waitRepl(t, S); b.Replication.PausedUntil != nil {
			t.Fatalf("control: %s is paused before its budget is lowered", S.Ref)
		}
		if out, code := cli(t, "project", "restart", S.Ref, "--set", "upload_objects_per_day=1"); code != 0 {
			t.Fatalf("restart with a budget of one object: exit %d %s", code, brief(out))
		}
		b0 := backups(t, S.Ref)
		b := waitNotice(t, S, "budget-exceeded", b0, true)
		if b.Replication.PausedUntil == nil {
			t.Fatal("over its budget, S's replication is not paused")
		}
		until, err := time.Parse(time.RFC3339, *b.Replication.PausedUntil)
		if midnight := time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour); err != nil || !until.Equal(midnight) && !until.Equal(midnight.Add(-24*time.Hour)) {
			t.Errorf("paused until %v (%v), want the next 00:00 UTC", b.Replication.PausedUntil, err)
		}
		for _, n := range b.Notices {
			if n.Code != "budget-exceeded" {
				continue
			}
			_, fill, ok := strings.Cut(n.Detail, "quota fills in ")
			if _, err := time.ParseDuration(fill); !ok || err != nil {
				t.Errorf("the budget notice carries no projected time: %q", n.Detail)
			}
		}
		seg := switchWAL(t, S)
		b = waitPush(t, S.Ref)
		if archived(repoFiles(t, S.Ref), b.Stanza, seg) == "" {
			t.Error("S's pushes stopped with its replication paused")
		}
		if bb := waitRepl(t, B); bb.Replication.PausedUntil != nil {
			t.Errorf("B is paused with S: %s", *bb.Replication.PausedUntil)
		}
	})

	// Fails if an unreachable store stops A's pushes or changes the other
	// projects, if the lag does not show it, or if replication does not
	// catch up afterwards.
	t.Run("offsite_outage", func(t *testing.T) {
		waitRepl(t, A)
		addrs, err := os.ReadFile(filepath.Join(s3Dir, "addrs"))
		if err != nil {
			t.Fatal(err)
		}
		// The stand-in runs outside the node: what the replication jobs send to
		// it is dropped where it leaves their bridge — silently, as an
		// unreachable store drops it, so a job waits out its own timeouts. The
		// suite's own reads still reach the store. The tables are reloaded when
		// the outage ends (and by the suite's reset after a killed run).
		rule := fmt.Sprintf(`iifname %q ip daddr { %s } drop comment "reach-outage"`, nodecfg.BackupBridge,
			strings.Join(strings.Fields(string(addrs)), ", "))
		var held []string // keys of A's segments pushed during the outage
		withRuleInserted(t, "inet supapace", "forward", rule, func() {
			start := time.Now()
			var last *string
			for i := range 3 {
				driftHold(t) // refreshed: the outage may outlast one hold
				seg := switchWAL(t, A)
				b := waitPush(t, A.Ref)
				f := archived(repoFiles(t, A.Ref), b.Stanza, seg)
				if f == "" {
					t.Fatal("A's push did not reach the repository during the outage")
				}
				held = append(held, A.Ref+"/"+f)
				if i == 0 { // every replication of A from now on has this segment to upload
					if last = backups(t, A.Ref).Replication.LastOK; last == nil {
						t.Fatal("control: no replication of A was recorded before the outage")
					}
				}
			}
			driftHold(t)
			seg := switchWAL(t, B)
			if bb := waitPush(t, B.Ref); archived(repoFiles(t, B.Ref), bb.Stanza, seg) == "" {
				t.Error("B's push did not reach the repository during the outage")
			}
			b := backups(t, A.Ref)
			if b.Replication.LastOK == nil || *b.Replication.LastOK != *last {
				t.Errorf("a replication of A completed during the outage: %s, then %v", *last, b.Replication.LastOK)
			}
			if l := b.Replication.LagSeconds; l == nil || time.Duration(*l+1)*time.Second < time.Since(start) {
				t.Errorf("A's replication lag %v does not cover the outage of %v", l, time.Since(start))
			}
			if _, code := s3(t, "projects-read", "head"); code != 0 {
				t.Fatal("control: the store does not answer the suite during the outage")
			}
			for _, k := range held {
				if inStore(t, k) {
					t.Errorf("%s reached the store during the outage", k)
				}
			}
			for _, p := range []Project{A, B} {
				if st := projectState(t, p.Ref); st != "active" {
					t.Errorf("project %s is %s during the outage", p.Ref, st)
				}
			}
		})
		b := waitRepl(t, A)
		if l := b.Replication.LagSeconds; l == nil || time.Duration(*l)*time.Second > replWait {
			t.Errorf("A's replication lag after the outage: %v, want at most %v", l, replWait)
		}
		for _, k := range held {
			if !inStore(t, k) {
				t.Errorf("%s is not in the store after the outage", k)
			}
		}
	})

	// Fails if a project at its repository quota stops B's or the control
	// plane's pushes, keeps pushing itself, or does not recover once its
	// quota is raised.
	t.Run("repository_quota_full", func(t *testing.T) {
		S := fixtureScratch(t, "--disk-quota", "1g")
		waitPush(t, S.Ref)
		cpSegs := func() int {
			n := 0
			for _, f := range repoFiles(t, "cp") {
				if p := strings.Split(f, "/"); len(p) > 1 {
					if k, _, _, ok := walname.RepoPath(p[1], f); ok && k == walname.Segment {
						n++
					}
				}
			}
			return n
		}
		cp0 := cpSegs()
		t.Cleanup(func() {
			asProjectUID(t, S.Ref, []string{repoDir(S.Ref) + ":/repo"}, "rm", "-f", "/repo/reach-fill")
		})
		r := asProjectUID(t, S.Ref, []string{repoDir(S.Ref) + ":/repo"}, "sh", "-c", `dd if=/dev/zero of=/repo/reach-fill bs=1M count=2048 2>&1; echo "exit $?"`)
		if !strings.Contains(r.stdout, "exit 1") {
			t.Fatalf("control: 2 GiB fitted in S's repository quota of 1 GiB: %s", brief(r.stdout))
		}
		var segs []string
		for range 3 {
			segs = append(segs, switchWAL(t, S))
		}
		// Two push jobs of S end after the segments were spooled: the second
		// started after the first had ended, so it listed all three.
		since := time.Now()
		pushEnds := func() int {
			return len(strings.Fields(docker(t, "events", "--since", fmt.Sprintf("%d.%09d", since.Unix(), since.Nanosecond()),
				"--until", strconv.FormatInt(time.Now().Unix()+1, 10), "--filter", "type=container", "--filter", "event=die",
				"--filter", "label=supapace.role=job", "--filter", "label=supapace.kind=push", "--filter", "label=supapace.ref="+S.Ref,
				"--format", "{{.Actor.ID}}")))
		}
		for deadline := time.Now().Add(3 * pushWait); pushEnds() < 2; time.Sleep(5 * time.Second) {
			if time.Now().After(deadline) {
				t.Fatalf("fewer than two push jobs of S ended within %v of its quota filling", 3*pushWait)
			}
		}
		es := spool(t, S.Ref)
		for _, s := range segs {
			if !spoolHas(es, s) {
				t.Errorf("segment %s left S's spool with its repository quota full", s)
			}
		}
		seg := switchWAL(t, B)
		if bb := waitPush(t, B.Ref); archived(repoFiles(t, B.Ref), bb.Stanza, seg) == "" {
			t.Error("B's push did not reach its repository")
		}
		for deadline := time.Now().Add(10 * time.Minute); cpSegs() <= cp0; time.Sleep(10 * time.Second) {
			if time.Now().After(deadline) {
				t.Fatal("no segment of the control plane reached its repository within 10 minutes")
			}
		}
		if out, code := cli(t, "project", "restart", S.Ref, "--set", "disk_quota_mb=4096"); code != 0 {
			t.Fatalf("raising S's quota: exit %d %s", code, brief(out))
		}
		b := waitPush(t, S.Ref)
		es, files := spool(t, S.Ref), repoFiles(t, S.Ref)
		for _, s := range segs {
			if spoolHas(es, s) || archived(files, b.Stanza, s) == "" {
				t.Errorf("segment %s after the quota was raised: spooled %v", s, spoolHas(es, s))
			}
		}
	})
}
