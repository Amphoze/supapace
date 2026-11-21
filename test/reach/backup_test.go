//go:build reach

package reach

// The backup path: the archive binary in the cluster, the archive spool, the
// worker jobs that push, back up and restore, the backup role and the
// quarantine of refused spool entries. The cluster and every tree it writes
// are untrusted: entries are planted at the project's uid inside its
// container. Every negative stands next to a control on the same path; each
// test says what makes it fail. Each test runs at layout 2 only (needBackups).

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/walname"
)

// ───────── shared ─────────

const backupRole = "supapace_backup"

// switchWAL writes one WAL record in p and ends the segment it is in; it
// returns that segment's name.
func switchWAL(t testing.TB, p Project) string {
	t.Helper()
	out, err := adminSQL(t, p, "create temp table reach_wal(x int); select pg_walfile_name(pg_switch_wal());")
	if err != nil {
		t.Fatalf("switching WAL in %s: %v", p.Ref, err)
	}
	lines := strings.Fields(out)
	if len(lines) == 0 {
		t.Fatalf("switching WAL in %s: no segment name", p.Ref)
	}
	name := lines[len(lines)-1]
	if k, _, ok := walname.Spool(name); !ok || k != walname.Segment {
		t.Fatalf("switching WAL in %s: %q is not a segment name", p.Ref, name)
	}
	return name
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// spoolHas reports whether a spool holds name as a regular file.
func spoolHas(es []spoolEntry, name string) bool {
	return slices.ContainsFunc(es, func(e spoolEntry) bool { return e.name == name && e.mode.IsRegular() })
}

// jobName is the container name of ref's job of kind.
func jobName(ref, kind string) string { return "job-" + ref + "-" + kind }

// jobRunning is the id of the running container called name, or "".
func jobRunning(t testing.TB, name string) string {
	t.Helper()
	return strings.TrimSpace(docker(t, "ps", "-q", "--no-trunc", "--filter", "name=^"+name+"$", "--filter", "status=running"))
}

// waitJob waits up to within for ref's job of kind to run and returns its id.
func waitJob(t testing.TB, ref, kind string, within time.Duration) string {
	t.Helper()
	for deadline := time.Now().Add(within); ; time.Sleep(50 * time.Millisecond) {
		if id := jobRunning(t, jobName(ref, kind)); id != "" {
			return id
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s job of %s ran within %v", kind, ref, within)
		}
	}
}

// catchJob waits for ref's job of kind and pauses it, so that a short job can
// be read while it runs; it is resumed in cleanup (or by the returned func).
func catchJob(t testing.TB, ref, kind string, within time.Duration) (name string, resume func()) {
	t.Helper()
	name = jobName(ref, kind)
	for deadline := time.Now().Add(within); ; {
		waitJob(t, ref, kind, time.Until(deadline))
		if r, err := run(cmdTimeout, nil, "docker", "pause", name); err == nil && r.code == 0 {
			resume = func() { run(cmdTimeout, nil, "docker", "unpause", name) }
			t.Cleanup(resume)
			return name, resume
		}
	}
}

// envHolds says where the environment of container c holds one of n's forms:
// its configured environment or that of a process in it ("" for nowhere).
func envHolds(t testing.TB, c string, n needle) string {
	t.Helper()
	if containsAny([]byte(docker(t, "inspect", "-f", "{{json .Config.Env}}", c)), n.b) >= 0 {
		return "its configured environment"
	}
	pid, _ := containerPid(t, c)
	ns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	procs, _ := os.ReadDir("/proc")
	for _, e := range procs {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if other, _ := os.Readlink("/proc/" + e.Name() + "/ns/pid"); other != ns {
			continue
		}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/environ"); err == nil && containsAny(b, n.b) >= 0 {
			return "the environment of process " + e.Name()
		}
	}
	return ""
}

// namesIn lists the paths in container c's filesystem (its image and mounts,
// /proc, /sys and /dev left out) whose last element is one of names.
func namesIn(t testing.TB, c string, names ...string) []string {
	t.Helper()
	pid, _ := containerPid(t, c)
	root := fmt.Sprintf("/proc/%d/root", pid)
	var hits []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		rel := strings.TrimPrefix(p, root)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() && (rel == "/proc" || rel == "/sys" || rel == "/dev") {
			return filepath.SkipDir
		}
		if slices.Contains(names, d.Name()) {
			hits = append(hits, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", c, err)
	}
	return hits
}

// jobEvent is one container event of a job.
type jobEvent struct {
	at         int64
	action, id string
}

// jobEvents lists the container events of ref's jobs from since until now.
func jobEvents(t testing.TB, ref string, since time.Time) []jobEvent {
	t.Helper()
	out := docker(t, "events", "--since", strconv.FormatInt(since.Unix()-1, 10), "--until", strconv.FormatInt(time.Now().Unix()+1, 10),
		"--filter", "type=container", "--filter", "label=supapace.role=job", "--filter", "label=supapace.ref="+ref,
		"--format", "{{.TimeNano}} {{.Action}} {{.Actor.ID}}")
	var evs []jobEvent
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		at, _ := strconv.ParseInt(f[0], 10, 64)
		evs = append(evs, jobEvent{at, f[1], f[2]})
	}
	return evs
}

// overlaps names two job containers of one subject whose lives (start to die)
// overlap in evs, or "".
func overlaps(evs []jobEvent) string {
	type life struct{ start, end int64 }
	lives := map[string]*life{}
	for _, e := range evs {
		l := lives[e.id]
		if l == nil {
			l = &life{end: 1 << 62}
			lives[e.id] = l
		}
		switch e.action {
		case "start":
			l.start = e.at
		case "die":
			l.end = min(l.end, e.at)
		}
	}
	for a, la := range lives {
		for b, lb := range lives {
			if a < b && la.start > 0 && lb.start > 0 && la.start < lb.end && lb.start < la.end {
				return a[:12] + " and " + b[:12]
			}
		}
	}
	return ""
}

// deleteResult deletes p, waits, and returns the delete's result.
func deleteResult(t testing.TB, p Project) deleteResultJSON {
	t.Helper()
	out, code := cli(t, "project", "delete", p.Ref)
	var op resultOp
	decode(t, "project delete", out, &op)
	if code != 0 || op.State != "done" {
		t.Fatalf("delete %s: exit %d, %s at step %q: %s", p.Ref, code, op.State, op.Step, op.LastError)
	}
	var r deleteResultJSON
	if err := json.Unmarshal(op.Result, &r); err != nil {
		t.Fatalf("delete %s: result: %v", p.Ref, err)
	}
	return r
}

// handRepo is an empty directory owned by p's uid for a backup run by hand.
func handRepo(t testing.TB, p Project) string {
	t.Helper()
	d, err := os.MkdirTemp(suiteDir, "hand-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(d, p.UID, p.UID); err != nil {
		t.Fatal(err)
	}
	return d
}

// handBackup runs stanza-create and a full backup of p by hand in a container
// of the worker image at p's uid — without the platform's job program, so
// without its pre-check — into the plain, uncompressed repository repo, with
// extra environment env; it returns the run.
func handBackup(t testing.TB, p Project, repo string, env ...string) result {
	t.Helper()
	pd := paths.ProjectDir(p.Ref)
	base := []string{"PGBACKREST_STANZA=reach", "PGBACKREST_REPO1_PATH=/repo", "PGBACKREST_CONFIG=/dev/null",
		"PGBACKREST_PG1_PATH=/var/lib/postgresql/data", "PGBACKREST_PG1_SOCKET_PATH=/var/run/postgresql",
		"PGBACKREST_PG1_USER=" + backupRole, "PGBACKREST_LOCK_PATH=/tmp/lock", "PGBACKREST_LOG_PATH=/tmp/log",
		"PGBACKREST_SPOOL_PATH=/tmp/spool", "PGBACKREST_LOG_LEVEL_FILE=off", "PGBACKREST_COMPRESS_TYPE=none",
		"PGBACKREST_ARCHIVE_CHECK=n", "PGBACKREST_START_FAST=y"}
	return workerRun(t, p.UID, []string{pd + "/data:/var/lib/postgresql/data:ro", pd + "/sock:/var/run/postgresql", repo + ":/repo"},
		append(base, env...), "sh", "-c", "pgbackrest stanza-create && pgbackrest backup --type=full")
}

// treeHolds names the files below dir (no link followed) whose bytes hold n.
func treeHolds(t testing.TB, dir string, n needle) []string {
	t.Helper()
	var hits []string
	counts, errs := searchTree(dir, []string{"/"}, func(p string, data []byte) {
		if containsAny(data, n.b) >= 0 {
			hits = append(hits, p)
		}
	})
	if len(errs) != 0 || counts["/"] == 0 {
		t.Fatalf("reading %s: %d files, %v", dir, counts["/"], errs)
	}
	return hits
}

// ───────── test 20 ─────────

// TestReach20_NoBackupSecret: the search for secrets over pg-A (every mount,
// every process's environment and command line, the configuration) finds
// neither A's stanza passphrase nor any object-store key, and A's filesystem
// holds no pgBackRest binary or configuration. Control: the same reads of a
// running push job of A find the passphrase and the binary. Fails if a backup
// secret or the tool reaches the cluster, or if the control finds nothing.
func TestReach20_NoBackupSecret(t *testing.T) {
	needBackups(t)
	A, _ := fixtureAB(t)
	pass := needle{"A's stanza passphrase", keyForms(platformSecret(t, A, "backup.cipher_pass"))}
	own, err := os.ReadFile(filepath.Join(paths.RenderDir(A.Ref), "pgsodium_root.key"))
	if err != nil {
		t.Fatal(err)
	}
	searchContainer(t, pgName(A), append([]needle{pass}, s3KeyNeedles(t)...), needle{"A's own pgsodium key", keyForms(own)})
	tool := []string{"pgbackrest", "pgbackrest.conf", "pgbackrest.conf.d"}
	if hits := namesIn(t, pgName(A), tool...); len(hits) != 0 {
		t.Errorf("pg-A holds pgBackRest files: %v", hits)
	}

	switchWAL(t, A)
	job, resume := catchJob(t, A.Ref, "push", 3*time.Minute)
	defer resume()
	if envHolds(t, job, pass) == "" {
		t.Error("control: the passphrase is not found in a running push job of A; the search proves nothing")
	}
	if hits := namesIn(t, job, tool...); len(hits) == 0 {
		t.Error("control: no pgBackRest binary is found in a push job")
	}
}

// ───────── test 21 ─────────

// TestReach21_ArchiveContract: the archive binary in pg-A, at A's uid, with
// the daemon held so no push takes the planted names: an identical re-archive
// succeeds, a different one fails and leaves the entry as it was; a history
// name is accepted; a process killed anywhere in its copy leaves no final name
// short of the whole file; a backup label reaches the repository; and a server
// killed after archiving a segment but before marking it done archives it
// again on restart and goes on archiving.
func TestReach21_ArchiveContract(t *testing.T) {
	needBackups(t)
	A, _ := fixtureAB(t)
	const name = "7FFFFFF000000000000000AA" // a timeline no project reaches
	clean := func() {
		asUID(t, A, `cd `+spoolInPG+` && rm -f "$1" .tmp-"$1"-* 7FFFFFF0.history; rm -f /tmp/reach-* /var/lib/postgresql/data/reach-src`, name)
	}

	t.Run("re_archive", func(t *testing.T) {
		holdDaemon(t)
		t.Cleanup(clean)
		mustUID(t, A, `printf one > /tmp/reach-a; printf two > /tmp/reach-b`)
		push := func(src, as string) result { return asUID(t, A, archInPG+` push "$1" "$2"`, src, as) }
		if r := push("/tmp/reach-a", name); r.code != 0 {
			t.Fatalf("first archive: exit %d: %s", r.code, brief(r.stderr))
		}
		if r := push("/tmp/reach-a", name); r.code != 0 {
			t.Errorf("identical re-archive: exit %d, want 0: %s", r.code, brief(r.stderr))
		}
		r := push("/tmp/reach-b", name)
		if r.code != 1 || strings.Count(strings.TrimSpace(r.stderr), "\n") != 0 || strings.TrimSpace(r.stderr) == "" {
			t.Errorf("different re-archive: exit %d with stderr %q, want exit 1 and one line", r.code, brief(r.stderr))
		}
		if es := spool(t, A.Ref); !slices.ContainsFunc(es, func(e spoolEntry) bool { return e.name == name && string(e.data) == "one" }) {
			t.Error("the spooled entry changed after a refused re-archive")
		}
		if r := push("/tmp/reach-a", "7FFFFFF0.history"); r.code != 0 || !spoolHas(spool(t, A.Ref), "7FFFFFF0.history") {
			t.Errorf("a history name: exit %d: %s", r.code, brief(r.stderr))
		}
	})

	// Fails if a segment archived again with other content (its header intact)
	// replaces the stored one or goes unrecorded: while the first copy is
	// spooled the archive binary refuses it; once that copy is pushed the name
	// is free, the repository refuses the second, and the push sets it aside
	// with its bytes, records a gap and raises a quarantine notice.
	t.Run("different_content_after_the_push", func(t *testing.T) {
		S := fixtureScratch(t)
		b0 := backups(t, S.Ref)
		quarantines := func(b backupsJSON) int64 {
			for _, n := range b.Notices {
				if n.Code == "quarantine" {
					return n.Count
				}
			}
			return 0
		}
		release := holdDaemon(t)
		seg := switchWAL(t, S)
		for deadline := time.Now().Add(time.Minute); !spoolHas(spool(t, S.Ref), seg); time.Sleep(500 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s did not reach the spool within a minute", seg)
			}
		}
		const other = "/var/lib/postgresql/data/reach-other"
		mustUID(t, S, `cp `+spoolInPG+`/"$1" `+other+` && printf reachrea | dd of=`+other+` bs=1 seek=8000000 conv=notrunc 2>/dev/null`, seg)
		if r := asUID(t, S, archInPG+` push `+other+` "$1"`, seg); r.code != 1 {
			t.Errorf("other content while the first copy is spooled: exit %d, want 1: %s", r.code, brief(r.stderr))
		}
		release()
		b := waitPush(t, S.Ref)
		first := archived(repoFiles(t, S.Ref), b.Stanza, seg)
		if first == "" {
			t.Fatalf("control: %s is not in the repository after a push", seg)
		}
		if r := asUID(t, S, archInPG+` push `+other+` "$1"`, seg); r.code != 0 {
			t.Fatalf("other content once the name is free: exit %d, want 0: %s", r.code, brief(r.stderr))
		}
		data, err := os.ReadFile(filepath.Join(paths.ProjectDir(S.Ref), "data", "reach-other"))
		if err != nil {
			t.Fatal(err)
		}
		b = waitPush(t, S.Ref)
		es := spool(t, S.Ref)
		if spoolHas(es, seg) || !slices.ContainsFunc(quarantined(es), func(e spoolEntry) bool { return string(e.data) == string(data) }) {
			t.Errorf("the second copy of %s was not set aside with its bytes", seg)
		}
		if got := archived(repoFiles(t, S.Ref), b.Stanza, seg); got != first {
			t.Errorf("the stored %s changed: %s, then %s", seg, first, got)
		}
		if len(b.Gaps) != len(b0.Gaps)+1 || quarantines(b) <= quarantines(b0) {
			t.Errorf("the refused copy: gaps %+v, quarantine notices %d (before %d)", b.Gaps, quarantines(b), quarantines(b0))
		}
	})

	t.Run("kill_during_copy", func(t *testing.T) {
		holdDaemon(t)
		t.Cleanup(clean)
		mustUID(t, A, `head -c 16777216 /dev/urandom > /var/lib/postgresql/data/reach-src`)
		src := mustUID(t, A, `sha256sum < /var/lib/postgresql/data/reach-src`)
		cut, whole := 0, 0
		for i := 0; i < 60 && cut == 0; i++ {
			// Kill after i ms: early kills land in the copy, late ones after the link.
			r := asUID(t, A, archInPG+` push /var/lib/postgresql/data/reach-src "$1" & p=$!; sleep "$2"; kill -9 $p 2>/dev/null; wait $p; echo $?`,
				name, fmt.Sprintf("0.%03d", i))
			if r.code != 0 {
				t.Fatalf("kill run %d: exit %d: %s", i, r.code, brief(r.stderr))
			}
			es := spool(t, A.Ref)
			if spoolHas(es, name) {
				whole++
				if got := mustUID(t, A, `sha256sum < `+spoolInPG+`/"$1"`, name); got != src {
					t.Fatalf("kill after %d ms left %s under its final name with other content", i, name)
				}
			} else if slices.ContainsFunc(es, func(e spoolEntry) bool { return strings.HasPrefix(e.name, ".tmp-"+name+"-") }) {
				cut++
			}
			mustUID(t, A, `cd `+spoolInPG+` && rm -f "$1" .tmp-"$1"-*`, name)
		}
		if cut == 0 {
			t.Fatalf("control: no kill landed during the copy (%d ended with the whole file); the window was never tried", whole)
		}
	})

	t.Run("label_travels", func(t *testing.T) {
		out, err := adminSQL(t, A, `select f.file_name || '.' || lpad(upper(to_hex(f.file_offset)), 8, '0') || '.backup'
  from pg_walfile_name_offset(pg_backup_start('reach-label', true)) f; select 1 from pg_backup_stop(true);`)
		if err != nil {
			t.Fatal(err)
		}
		label := strings.Fields(out)[0]
		if k, _, ok := walname.Spool(label); !ok || k != walname.Label {
			t.Fatalf("%q is not a label name", label)
		}
		b := waitPush(t, A.Ref)
		if archived(repoFiles(t, A.Ref), b.Stanza, label) == "" {
			t.Errorf("the backup label %s is not in A's repository after a push", label)
		}
	})

	t.Run("server_killed_before_its_bookkeeping", func(t *testing.T) {
		driftHold(t) // the cluster restarts its own processes; the container stays
		status := "/var/lib/postgresql/data/pg_wal/archive_status/"
		waitFile := func(f string) {
			t.Helper()
			for deadline := time.Now().Add(2 * time.Minute); asUID(t, A, `test -e "$1"`, f).code != 0; time.Sleep(time.Second) {
				if time.Now().After(deadline) {
					t.Fatalf("%s did not appear within 2 minutes", f)
				}
			}
		}
		seg := switchWAL(t, A)
		waitFile(status + seg + ".done")
		// What a crash between the copy and the server's own bookkeeping leaves:
		// the segment still marked ready.
		mustUID(t, A, `mv "$1.done" "$1.ready"`, status+seg)
		mustUID(t, A, `for p in /proc/[0-9]*; do case "$(tr '\0' ' ' < $p/cmdline 2>/dev/null)" in "postgres: "*archiver*) kill -9 "${p#/proc/}";; esac; done`)
		waitFile(status + seg + ".done")
		next := switchWAL(t, A)
		waitFile(status + next + ".done")
		if out, err := adminSQL(t, A, "select failed_count from pg_stat_archiver"); err != nil || out != "0" {
			t.Errorf("archiver after the restart: failed_count %q (%v), want 0", out, err)
		}
		b := waitPush(t, A.Ref)
		files := repoFiles(t, A.Ref)
		for _, s := range []string{seg, next} {
			if archived(files, b.Stanza, s) == "" {
				t.Errorf("segment %s is not in A's repository", s)
			}
		}
	})
}

// ───────── test 22 ─────────

// TestReach22_Spool: with segments spooled while the daemon is held, the
// first push job is killed as soon as it runs: every segment is then still in
// the spool or already in the repository, and at least one is still spooled
// (else the kill came too late to prove anything). After the next complete
// push none is spooled and every one is in the repository; with the stand-in,
// its key appears in the store after the next replication.
func TestReach22_Spool(t *testing.T) {
	needBackups(t)
	A, _ := fixtureAB(t)
	stanza := backups(t, A.Ref).Stanza
	var segs []string
	for attempt := 0; ; attempt++ {
		release := holdDaemon(t)
		segs = segs[:0]
		for range 12 {
			segs = append(segs, switchWAL(t, A))
		}
		for deadline := time.Now().Add(time.Minute); ; time.Sleep(500 * time.Millisecond) {
			es := spool(t, A.Ref)
			if !slices.ContainsFunc(segs, func(s string) bool { return !spoolHas(es, s) }) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the switched segments did not all reach the spool within a minute")
			}
		}
		release()
		waitJob(t, A.Ref, "push", 3*time.Minute)
		run(cmdTimeout, nil, "docker", "kill", jobName(A.Ref, "push")) // it may have ended already
		es, files := spool(t, A.Ref), repoFiles(t, A.Ref)
		still := 0
		for _, s := range segs {
			switch {
			case spoolHas(es, s):
				still++
			case archived(files, stanza, s) == "":
				t.Fatalf("segment %s is neither in the spool nor in the repository after the push job was killed", s)
			}
		}
		if still > 0 {
			break
		}
		if attempt == 2 {
			t.Fatal("control: in three tries the kill never came before the repository acknowledged a segment")
		}
	}
	waitPush(t, A.Ref)
	es, files := spool(t, A.Ref), repoFiles(t, A.Ref)
	for _, s := range segs {
		if spoolHas(es, s) || archived(files, stanza, s) == "" {
			t.Errorf("segment %s after a complete push: spooled %v, in the repository %v", s, spoolHas(es, s), archived(files, stanza, s) != "")
		}
	}

	t.Run("replicated", func(t *testing.T) {
		needStandin(t)
		key := A.Ref + "/" + archived(files, stanza, segs[len(segs)-1])
		for deadline := time.Now().Add(6 * time.Minute); ; time.Sleep(5 * time.Second) {
			if _, code := s3(t, "projects-read", "head", key); code == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s is not in the store 6 minutes after its push", key)
			}
		}
	})
}

// ───────── test 23 ─────────

// TestReach23_WorkerConfinement: what a worker can reach, with the tenant
// planting links and names in every tree a worker reads. Each sub-test says
// what makes it fail.
func TestReach23_WorkerConfinement(t *testing.T) {
	needBackups(t)
	A, B := fixtureAB(t)

	// Fails if the worker image holds a database server binary; control: the
	// same search finds the server in the cluster image.
	t.Run("no_database_server_in_the_worker_image", func(t *testing.T) {
		c := imageContainer(t, "sp-test-worker-files", workerImage, "--network", "none")
		server := []string{"postgres", "postmaster", "initdb", "pg_ctl"}
		if hits := namesIn(t, c, server...); len(hits) != 0 {
			t.Errorf("the worker image holds %v", hits)
		}
		if hits := namesIn(t, pgName(A), server...); len(hits) == 0 {
			t.Error("control: the search finds no server binary in the cluster image")
		}
	})

	// B's canary: what no worker of another project may ever read.
	canary := "reach-canary-" + randHex(16)
	bCanary := filepath.Join(paths.ProjectDir(B.Ref), "data", "reach-canary")
	mustUID(t, B, `printf %s "$1" > /var/lib/postgresql/data/reach-canary`, canary)
	t.Cleanup(func() { asUID(t, B, `rm -f /var/lib/postgresql/data/reach-canary`) })
	bNeedle := needle{"B's canary", [][]byte{[]byte(canary)}}

	t.Run("tenant_trees", func(t *testing.T) { tenantTrees(t, bCanary, bNeedle) })

	// Fails if a link swapped in while a backup runs gets B's canary into the
	// stored set.
	t.Run("link_swapped_during_backup", func(t *testing.T) {
		S := fixtureScratch(t)
		stop := "/tmp/reach-stop"
		docker(t, "exec", "-d", "--user", fmt.Sprintf("%d:%d", S.UID, S.UID), pgName(S), "sh", "-c",
			`cd /var/lib/postgresql/data; while [ ! -e `+stop+` ]; do echo plain > f.r; mv -f f.r reach-swap; ln -s "$1" f.l; mv -f f.l reach-swap; done`,
			"sh", bCanary)
		before := backups(t, S.Ref).Sets
		res := deleteResult(t, S)
		after := backups(t, S.Ref).Sets
		// Which the pre-check sees is a race; each outcome is checked. A link it
		// saw is refused; one swapped in after it fails in the tool (its target
		// is not in the job's tree) or is stored as a link to nothing of B.
		switch res.FinalBackup {
		case "symlink", "pgbackrest":
			t.Logf("the final backup with a link swapped in ended %q", res.FinalBackup)
			return
		case "ok":
		default:
			t.Fatalf("the final backup with a link swapped in ended %q, want ok, symlink or pgbackrest", res.FinalBackup)
		}
		if len(after) != len(before)+1 {
			t.Fatalf("final backup ok, but %d sets before and %d after", len(before), len(after))
		}
		if hits := treeHolds(t, restoredSet(t, S, after[0].Label), bNeedle); len(hits) != 0 {
			t.Errorf("the stored set holds B's canary at %v", hits)
		}
	})

	t.Run("hostile_server", hostileServer)
	t.Run("crafted_control_data", func(t *testing.T) {
		S := fixtureScratch(t, "--disk-quota", "1g")
		// The running server rewrites pg_control at every checkpoint (the
		// backup's own start asks for one): the tenant writes it again every
		// 100 ms until the delete stops the cluster, so the job reads it crafted.
		mustUID(t, S, `head -c 8192 /dev/urandom > /tmp/reach-control`)
		docker(t, "exec", "-d", "--user", fmt.Sprintf("%d:%d", S.UID, S.UID), pgName(S), "sh", "-c",
			`while :; do cp /tmp/reach-control /var/lib/postgresql/data/global/pg_control; sleep 0.1; done`)
		start := time.Now()
		res := deleteResult(t, S)
		if res.FinalBackup == "ok" {
			t.Errorf("a backup of a data directory with random control data was stored")
		}
		if el := time.Since(start); el > backupDeadline(1024)+5*time.Minute {
			t.Errorf("the delete with crafted control data took %v", el)
		}
	})

	// Fails if a replication job's environment holds the passphrase or any
	// object-store key; control: the same read finds its declared bucket.
	t.Run("replication_job", func(t *testing.T) {
		needStandin(t)
		pass := needle{"A's stanza passphrase", keyForms(platformSecret(t, A, "backup.cipher_pass"))}
		switchWAL(t, A)
		job, resume := catchJob(t, A.Ref, "replicate", 4*time.Minute)
		defer resume()
		for _, n := range append([]needle{pass}, s3KeyNeedles(t)...) {
			if where := envHolds(t, job, n); where != "" {
				t.Errorf("a replication job holds %s in %s", n.name, where)
			}
		}
		if envHolds(t, job, needle{"its bucket", [][]byte{[]byte("SUPAPACE_S3_BUCKET=sp-projects")}}) == "" {
			t.Error("control: the replication job's environment was not read")
		}
	})
}

// backupDeadline is a full backup's deadline at a disk quota (and the equal
// repository quota) of qd MiB.
func backupDeadline(qd int) time.Duration {
	d, err := bklimit.Deadline("backup", qd, qd)
	if err != nil {
		panic(err)
	}
	return d
}

// restoredSet restores p's set label by hand into a fresh directory (the
// passphrase through the environment) and returns the directory.
func restoredSet(t testing.TB, p Project, label string) string {
	t.Helper()
	out := handRepo(t, p)
	pass := string(platformSecret(t, p, "backup.cipher_pass"))
	b := backups(t, p.Ref)
	r := workerRun(t, p.UID, []string{repoDir(p.Ref) + ":/repo:ro", out + ":/out"},
		[]string{"PGBACKREST_STANZA=" + b.Stanza, "PGBACKREST_REPO1_PATH=/repo", "PGBACKREST_CONFIG=/dev/null",
			"PGBACKREST_REPO1_CIPHER_TYPE=aes-256-cbc", "PGBACKREST_REPO1_CIPHER_PASS=" + pass, "PGBACKREST_PG1_PATH=/out",
			"PGBACKREST_LOCK_PATH=/tmp/lock", "PGBACKREST_LOG_PATH=/tmp/log", "PGBACKREST_LOG_LEVEL_FILE=off"},
		"pgbackrest", "restore", "--set="+label, "--type=none")
	if r.code != 0 {
		t.Fatalf("restoring set %s of %s by hand: exit %d: %s", label, p.Ref, r.code, redact(brief(r.stderr)))
	}
	return out
}

// tenantTrees uses one scratch project S throughout: links and crafted names
// in its spool, in its restore spool and in its data directory.
func tenantTrees(t *testing.T, bCanary string, bNeedle needle) {
	S := fixtureScratch(t)
	stanza := backups(t, S.Ref).Stanza

	// Fails if a push follows a link in the spool or pushes a crafted name;
	// the links must be set aside, unfollowed, and the crafted names left.
	t.Run("spool_links_and_names", func(t *testing.T) {
		const seg, hist = "00000001000000FF000000FE", "00000001.history"
		mustUID(t, S, `cd `+spoolInPG+` && ln -s /proc/self/environ "$1" && ln -s /proc/self/environ "$2" && printf x > --config=x && printf x > 00000001000000ff000000fe`, seg, hist)
		waitPush(t, S.Ref)
		es, files := spool(t, S.Ref), repoFiles(t, S.Ref)
		for _, n := range []string{seg, hist} {
			if slices.ContainsFunc(es, func(e spoolEntry) bool { return e.name == n }) || archived(files, stanza, n) != "" {
				t.Errorf("the linked spool entry %s is still under its name or in the repository", n)
			}
		}
		links := 0
		for _, e := range quarantined(es) {
			if e.link == "/proc/self/environ" {
				links++
			}
		}
		if links != 2 {
			t.Errorf("%d links set aside under a name outside the pattern, want 2", links)
		}
		for _, n := range []string{"--config=x", "00000001000000ff000000fe"} {
			if !slices.ContainsFunc(es, func(e spoolEntry) bool { return e.name == n && string(e.data) == "x" }) {
				t.Errorf("the crafted name %s was not left as it was", n)
			}
		}
		for _, f := range files {
			if strings.Contains(f, "config") || strings.Contains(f, "ff000000fe") {
				t.Errorf("a crafted name reached the repository: %s", f)
			}
		}
	})

	// Fails if an option-shaped restore request is accepted by the archive
	// binary, or if links in the restore spool stop the restore or are
	// followed; control: a WAL name is requested (its answer then waits).
	t.Run("restore_spool", func(t *testing.T) {
		const wal = "000000010000000000000099"
		get := func(name string) string {
			r := asUID(t, S, `timeout -s KILL 3 `+archInPG+` get "$1" /tmp/reach-out; echo "exit $?"; ls -A `+rspoolInPG+`/req; rm -f `+rspoolInPG+`/req/`+wal, name)
			return r.stdout
		}
		if out := get(wal); !strings.Contains(out, "exit 137") || !strings.Contains(out, wal) {
			t.Fatalf("control: a WAL name was not requested: %q", brief(out))
		}
		if out := get("--config=/job/input.json"); !strings.Contains(out, "exit 201") || strings.Contains(out, "config") {
			t.Errorf("an option-shaped restore request: %q, want exit 201 and no request", brief(out))
		}
		// req/ replaced by a link to a decoy holding an option-shaped request
		// (the serve job would remove it, were the link followed), and a link
		// at the serve job's temporary pattern in out/ pointing into the
		// job's own writable mount.
		const tmpName = ".tmp-" + wal + "-0123456789abcdef"
		mustUID(t, S, `cd `+rspoolInPG+` && mkdir decoy && printf x > 'decoy/--config=x' && rm -rf req && ln -s decoy req && ln -s /rspool/reach-through "out/`+tmpName+`"`)
		op, code := restore(t, S.Ref, "--to", "latest")
		if code != 0 || op.State != "done" {
			t.Fatalf("restore with links in the restore spool: exit %d, %s at step %q: %s", code, op.State, op.Step, op.LastError)
		}
		rs := filepath.Join(paths.ProjectDir(S.Ref), "rspool")
		for _, d := range []string{"req", "out"} {
			if fi, err := os.Lstat(filepath.Join(rs, d)); err != nil || !fi.IsDir() {
				t.Errorf("%s/ of the restore spool is not a directory after the restore (%v)", d, err)
			}
		}
		if b, err := os.ReadFile(filepath.Join(rs, "decoy", "--config=x")); err != nil || string(b) != "x" {
			t.Errorf("the decoy behind the req/ link was touched (%q, %v): the link was followed", b, err)
		}
		// The serve job removes old temporaries by name, unfollowed, when it
		// starts: the planted link is gone and nothing was written through it.
		if _, err := os.Lstat(filepath.Join(rs, "out", tmpName)); err == nil {
			t.Error("the link planted at a temporary name in out/ is still there: the serve job did not clear it at its start")
		}
		if _, err := os.Lstat(filepath.Join(rs, "reach-through")); err == nil {
			t.Error("something was written through the link at a temporary name in out/")
		}
	})

	// Fails if a link to B's tree gets anything of B into a backup made without
	// the pre-check: mount isolation alone must keep it out. Control: the same
	// run stores the target of a link to its own environment.
	t.Run("hand_run_without_the_precheck", func(t *testing.T) {
		mark := needle{"the run's marker", [][]byte{[]byte("reach-mark-" + randHex(8))}}
		mustUID(t, S, `ln -sfn /proc/self/environ /var/lib/postgresql/data/reach-env`)
		repo := handRepo(t, S)
		if r := handBackup(t, S, repo, "REACH_MARK="+string(mark.b[0])); r.code != 0 {
			t.Fatalf("control: the backup run by hand failed: exit %d: %s", r.code, brief(r.stderr))
		}
		if len(treeHolds(t, repo, mark)) == 0 {
			t.Fatal("control: a backup without the pre-check did not store its own environment; the link case proves nothing")
		}
		mustUID(t, S, `rm -f /var/lib/postgresql/data/reach-env && ln -s "$1" /var/lib/postgresql/data/reach-b`, bCanary)
		repo = handRepo(t, S)
		r := handBackup(t, S, repo)
		t.Logf("a backup run by hand over a link to B's tree: exit %d", r.code)
		if hits := treeHolds(t, repo, bNeedle); len(hits) != 0 {
			t.Errorf("B's canary was stored at %v", hits)
		}
		mustUID(t, S, `rm -f /var/lib/postgresql/data/reach-b`)
	})

	// Fails if the platform's backup stores what a link in the data directory
	// names: the pre-check must refuse it, and no set is added.
	t.Run("link_to_the_job_environment", func(t *testing.T) {
		mustUID(t, S, `ln -s /proc/self/environ /var/lib/postgresql/data/reach-env`)
		before := backups(t, S.Ref).Sets
		labels := func() []string {
			ents, _ := os.ReadDir(filepath.Join(repoDir(S.Ref), "backup", stanza))
			var l []string
			for _, e := range ents {
				l = append(l, e.Name())
			}
			return l
		}
		dirs := labels()
		res := deleteResult(t, S)
		if res.FinalBackup != "symlink" {
			t.Errorf("final backup over a link to the job's environment: %q, want symlink", res.FinalBackup)
		}
		if after := backups(t, S.Ref).Sets; len(after) != len(before) || !slices.Equal(labels(), dirs) {
			t.Errorf("a set was added: %d sets before, %d after; directories %v → %v", len(before), len(after), dirs, labels())
		}
	})
}

// hostileServer: a scratch project's socket is taken by a fake server that
// never answers; its delete's final backup job then talks to the fake. While
// that job runs: its user, flags, mounts and missing network are as the
// platform made them; it reaches nothing (control: the node reaches the
// gateway); its environment holds the passphrase and no object-store key; no
// environment file is on disk and no host file S's uid can read holds the
// passphrase. The daemon is then killed: the job outlives it (control), and
// the next job of S starts only after that container is gone; no two jobs of
// S overlap; the next job ends within its deadline.
// ponytail: the silent server (stall) only — the mode bounded by the deadline
// alone; the other modes of test 9 end sooner and cost one project each.
func hostileServer(t *testing.T) {
	const quota = 1024
	S := fixtureScratch(t, "--disk-quota", "1g")
	pass := needle{"S's stanza passphrase", keyForms(platformSecret(t, S, "backup.cipher_pass"))}
	marker := needle{"S's marker", [][]byte{[]byte("reach-marker-" + randHex(8))}}
	mustUID(t, S, `printf %s "$1" > /var/lib/postgresql/data/reach-marker`, string(marker.b[0]))
	mustUID(t, S, `cd /var/run/postgresql && mv .s.PGSQL.5432 .reach-real`)
	fakeInContainer(t, pgName(S), fmt.Sprintf("%d:%d", S.UID, S.UID), "--socket", sockInPG, "--log", "/tmp/fake-stall.log", "--mode", "stall")
	since := time.Now()
	out, code := cli(t, "project", "delete", S.Ref, "--no-wait")
	var m mutationJSON
	decode(t, "project delete", out, &m)
	if code != 0 {
		t.Fatalf("delete --no-wait: exit %d", code)
	}
	first := waitJob(t, S.Ref, "backup", 5*time.Minute)
	job := jobName(S.Ref, "backup")
	for deadline := time.Now().Add(time.Minute); len(fakeConns(t, pgName(S), "/tmp/fake-stall.log")) == 0; time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("control: the backup job never reached the fake server")
		}
	}

	// Posture.
	f := containerFlags(t, job)
	if f.User != fmt.Sprintf("%d:%d", S.UID, S.UID) || !slices.Equal(f.CapDrop, []string{"ALL"}) || !f.NoNewPrivs || !f.ReadOnly ||
		f.Privileged || len(f.CapAdd) != 0 || f.RestartPolicy != "no" && f.RestartPolicy != "" || f.Tmpfs["/tmp"] == "" {
		t.Errorf("job flags: %+v", f)
	}
	if nm := strings.TrimSpace(docker(t, "inspect", "-f", "{{.HostConfig.NetworkMode}}", job)); nm != "none" {
		t.Errorf("job network mode %q, want none", nm)
	}
	pd, rd := paths.ProjectDir(S.Ref), repoDir(S.Ref)
	want := map[string]struct {
		src string
		rw  bool
	}{
		"/var/lib/postgresql/data": {pd + "/data", false}, "/var/run/postgresql": {pd + "/sock", true},
		"/spool": {pd + "/spool", true}, "/repo": {rd, true}, "/supapaced": {"", false}, "/job": {"", false},
	}
	ms := containerMounts(t, job)
	for dst, mt := range ms {
		w, ok := want[dst]
		if !ok || mt.Type != "bind" || mt.RW != w.rw || w.src != "" && mt.Source != w.src {
			t.Errorf("job mount %s: %+v", dst, mt)
		}
	}
	if len(ms) != len(want) {
		t.Errorf("job mounts %d, want %d", len(ms), len(want))
	}
	for _, a := range nsAddrs(t, job) {
		if a.Ifname != "lo" {
			t.Errorf("the job's namespace has %s on %s", a.Addr, a.Ifname)
		}
	}
	gw := gatewayAt(t).addr.String()
	wantVerdict(t, "control: the node reaches the gateway", "", "connected", "tcp", gw)
	if v := probeVerdict(t, job, "tcp", gw); strings.HasPrefix(v, "connected") {
		t.Errorf("the job reached the gateway: %s", v)
	}
	if envHolds(t, job, pass) == "" {
		t.Error("control: the backup job's environment was not read (no passphrase found)")
	}
	for _, n := range s3KeyNeedles(t) {
		if where := envHolds(t, job, n); where != "" {
			t.Errorf("the backup job holds %s in %s", n.name, where)
		}
	}
	ents, _ := os.ReadDir(paths.JobsDir())
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".env") {
			t.Errorf("an environment file is on disk while its job runs: %s", e.Name())
		}
	}
	// Host paths, traversed from the root; and the trees S's uid reaches
	// through its containers' mounts (P itself is root's 0700, so a walk
	// from the root would find nothing there). Control: a marker S planted in
	// its data directory is found by the same search of the mounted trees.
	hits, err := secretsReadableBy(S.UID, S.UID, []string{"/etc/supapace", "/run/supapace", paths.PlatformDir(), "/tmp", "/var/tmp"}, false, []needle{pass})
	if err != nil || len(hits) != 0 {
		t.Errorf("host files S's uid can read hold the passphrase: %v (%v)", hits, err)
	}
	mounted := []string{pd + "/data", pd + "/sock", pd + "/spool", pd + "/rspool", rd}
	if hits, err := secretsReadableBy(S.UID, S.UID, mounted, true, []needle{pass}); err != nil || len(hits) != 0 {
		t.Errorf("files below S's mounts hold the passphrase: %v (%v)", hits, err)
	}
	if hits, _ := secretsReadableBy(S.UID, S.UID, mounted, true, []needle{marker}); len(hits) == 0 {
		t.Error("control: the search of S's mounted trees did not find the marker S planted in its data directory")
	}

	// The daemon dies while the job runs.
	release := holdDaemon(t)
	if jobRunning(t, job) != first {
		t.Fatal("control: the job did not outlive the daemon; the ordering below proves nothing")
	}
	conns := len(fakeConns(t, pgName(S), "/tmp/fake-stall.log"))
	release()
	second := ""
	for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(time.Second) {
		if id := jobRunning(t, job); id != "" && id != first {
			second = id
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no new backup job of S within 5 minutes of the daemon's return")
		}
	}
	// Else the deadline below would be met by a job that never met the fake.
	for deadline := time.Now().Add(time.Minute); len(fakeConns(t, pgName(S), "/tmp/fake-stall.log")) <= conns; time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("control: the next backup job never reached the fake server")
		}
	}
	for deadline := time.Now().Add(backupDeadline(quota) + time.Minute); jobRunning(t, job) != ""; time.Sleep(5 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("the backup job against a silent server still runs past its deadline of %v", backupDeadline(quota))
		}
	}
	evs := jobEvents(t, S.Ref, since)
	at := func(id, action string) int64 {
		for _, e := range evs {
			if e.id == id && e.action == action {
				return e.at
			}
		}
		t.Fatalf("no %s event of job container %s", action, id[:12])
		return 0
	}
	if gone, next := at(first, "destroy"), at(second, "start"); gone > next {
		t.Errorf("the next job of S started %v before the left-over container was removed", time.Duration(gone-next))
	}
	if d := time.Duration(at(second, "die") - at(second, "start")); d > backupDeadline(quota)+30*time.Second {
		t.Errorf("the backup job against a silent server ran %v, deadline %v", d, backupDeadline(quota))
	}
	if o := overlaps(evs); o != "" {
		t.Errorf("job containers of S overlap: %s", o)
	}
	op := waitOp(t, m.OperationID)
	var full resultOp
	out, _ = cli(t, "op", "show", strconv.FormatInt(op.ID, 10))
	decode(t, "op show", out, &full)
	var res deleteResultJSON
	if op.State != "done" || json.Unmarshal(full.Result, &res) != nil || res.FinalBackup == "ok" {
		t.Errorf("delete against a silent server: %s, result %s", op.State, full.Result)
	}
}

// ───────── test 26 ─────────

// TestReach26_BackupRole: on a fresh cluster the backup role logs in by peer
// from the project's uid only — not from another uid, not over TCP — is not a
// superuser and cannot read a user table (control: the owner reads it); the
// create's backup and check ran as that role with archive checking on, so the
// set is recorded and its WAL is in the repository.
func TestReach26_BackupRole(t *testing.T) {
	needBackups(t)
	S := fixtureScratch(t)
	login := func(uid int, host, sql string) result {
		return inAt(t, pgName(S), uid, `psql -X -w -q -t -A -v ON_ERROR_STOP=1 -h "$1" -U `+backupRole+` -d postgres -c "$2"`, host, sql)
	}
	if r := login(S.UID, "/var/run/postgresql", "select current_user, rolsuper from pg_roles where rolname = current_user"); r.code != 0 ||
		strings.TrimSpace(r.stdout) != backupRole+"|f" {
		t.Fatalf("peer login from S's uid: exit %d %q %s", r.code, r.stdout, brief(r.stderr))
	}
	for _, c := range []struct {
		uid  int
		host string
	}{{S.UID + 1, "/var/run/postgresql"}, {S.UID, "127.0.0.1"}} {
		// The refusal must be the server's authentication, not a client fault.
		if r := login(c.uid, c.host, "select 1"); r.code == 0 || !strings.Contains(r.stderr, "authentication failed") &&
			!strings.Contains(r.stderr, "no pg_hba.conf entry") && !strings.Contains(r.stderr, "no password supplied") {
			t.Errorf("the backup role from uid %d over %s: exit %d %s", c.uid, c.host, r.code, brief(r.stderr))
		}
	}
	mustSQL(t, S, "postgres", "create table public.reach_private(x int); insert into public.reach_private values (1)")
	if got := mustSQL(t, S, "postgres", "select x from public.reach_private"); got != "1" {
		t.Fatalf("control: the owner reads %q", got)
	}
	if r := login(S.UID, "/var/run/postgresql", "select x from public.reach_private"); r.code == 0 || !strings.Contains(r.stderr, "permission denied") {
		t.Errorf("the backup role read a user table: exit %d %s", r.code, brief(r.stderr))
	}
	b := backups(t, S.Ref)
	if len(b.Sets) == 0 {
		t.Fatal("no backup set after the create")
	}
	if s := b.Sets[len(b.Sets)-1]; s.Timeline != 1 || archived(repoFiles(t, S.Ref), b.Stanza, s.StopSegment) == "" {
		t.Errorf("the create's set %+v: its stop segment is not in the repository", s)
	}
}

// ───────── test 28 ─────────

// TestReach28_Quarantine: a spool entry the repository refuses is renamed out
// of the pattern (its bytes kept), recorded as a gap and noticed, never pushed;
// later segments still reach the repository; one forced full backup follows,
// and after a second refusal the same day none does. A history file and a
// segment of a timeline the project never recorded are set aside and noticed
// the same way.
func TestReach28_Quarantine(t *testing.T) {
	needBackups(t)
	S := fixtureScratch(t)
	b0 := backups(t, S.Ref)
	plant := func(name, cmd string) []byte {
		t.Helper()
		// Written aside, then renamed in: a push never sees a half-written entry.
		return []byte(mustUID(t, S, `cd `+spoolInPG+` && `+cmd+` > /tmp/reach-plant && cp /tmp/reach-plant .reach && mv .reach "$1" && cat /tmp/reach-plant`, name))
	}
	setAside := func(name string, data []byte, b backupsJSON) {
		t.Helper()
		es := spool(t, S.Ref)
		if spoolHas(es, name) || archived(repoFiles(t, S.Ref), b.Stanza, name) != "" {
			t.Errorf("%s is still spooled or in the repository", name)
		}
		if !slices.ContainsFunc(quarantined(es), func(e spoolEntry) bool { return string(e.data) == string(data) }) {
			t.Errorf("%s was not renamed out of the pattern with its bytes", name)
		}
	}
	notices := func(b backupsJSON) int64 {
		for _, n := range b.Notices {
			if n.Code == "quarantine" {
				return n.Count
			}
		}
		return 0
	}

	bad := "0000000100000000000000F0"
	data := plant(bad, "head -c 65536 /dev/urandom")
	start := time.Now()
	b := waitPush(t, S.Ref)
	setAside(bad, data, b)
	if len(b.Gaps) != len(b0.Gaps)+1 || b.Gaps[0].Cause != "quarantine" || notices(b) <= notices(b0) {
		t.Errorf("after a quarantine: gaps %+v, quarantine notices %d", b.Gaps, notices(b))
	}
	seg := switchWAL(t, S)
	b = waitPush(t, S.Ref)
	if spoolHas(spool(t, S.Ref), seg) || archived(repoFiles(t, S.Ref), b.Stanza, seg) == "" {
		t.Errorf("segment %s after the quarantine did not reach the repository", seg)
	}
	for deadline := time.Now().Add(10 * time.Minute); len(backups(t, S.Ref).Sets) != len(b0.Sets)+1; time.Sleep(5 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("no forced full backup within 10 minutes of a quarantine")
		}
	}
	took, day := time.Since(start), time.Now().UTC().Format(time.DateOnly)

	data = plant("0000000100000000000000F1", "head -c 65536 /dev/urandom")
	b = waitPush(t, S.Ref)
	setAside("0000000100000000000000F1", data, b)
	time.Sleep(max(3*time.Minute, took)) // the first full came within took
	if n := len(backups(t, S.Ref).Sets); time.Now().UTC().Format(time.DateOnly) != day {
		t.Log("the UTC day changed during the wait; a second forced full is allowed then")
	} else if n != len(b0.Sets)+1 {
		t.Errorf("a second quarantine the same day was followed by another full backup (%d sets, want %d)", n, len(b0.Sets)+1)
	}

	// A timeline the project never recorded.
	before := notices(b)
	hist := plant("00000002.history", `printf '1\t0/3000000\tno recovery target specified\n'`)
	segData := plant("000000020000000000000005", "head -c 65536 /dev/urandom")
	b = waitPush(t, S.Ref)
	setAside("00000002.history", hist, b)
	setAside("000000020000000000000005", segData, b)
	if notices(b) <= before {
		t.Error("the unrecorded timeline's entries were not noticed")
	}
	if len(b.Timelines) != 1 || b.Timelines[0].Timeline != 1 {
		t.Errorf("timelines after an unrecorded history: %+v", b.Timelines)
	}
}
