//go:build !reach

package reach

// Self-tests of the backup helpers, with a stand-in CLI and sp-probe: no
// daemon, node or store is needed.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// recT records how a helper ended: Skip and Fatal end the goroutine.
type recT struct {
	mainT
	skipped bool
	msg     string
}

func (r *recT) Skip(a ...any)            { r.skipped, r.msg = true, fmt.Sprint(a...); runtime.Goexit() }
func (r *recT) Skipf(f string, a ...any) { r.Skip(fmt.Sprintf(f, a...)) }
func (r *recT) Fatal(a ...any)           { r.msg = fmt.Sprint(a...); r.mainT.Fatal(a...) }
func (r *recT) Fatalf(f string, a ...any) {
	r.msg = fmt.Sprintf(f, a...)
	r.mainT.Fatalf(f, a...)
}

// ran runs f with a recorder; it reports skipped, failed and the last message.
func ran(f func(testing.TB)) (skipped, failed bool, msg string) {
	r := &recT{mainT: mainT{out: io.Discard}}
	done := make(chan struct{})
	go func() { defer close(done); f(r) }()
	<-done
	r.mainT.cleanup()
	return r.skipped, r.failed, r.msg
}

// stubCLI points cliBin at a shell script whose `case "$1 $2"` arms are body.
func stubCLI(t *testing.T, body string) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "supapace")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ncase \"$1 $2\" in\n"+body+"\n*) exit 2 ;;\nesac\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := cliBin
	cliBin = stub
	t.Cleanup(func() { cliBin = old })
}

// withFixtureA makes fixture A (and B) the self-test's ref.
func withFixtureA(t *testing.T) {
	old1, old2 := fixA, fixB
	fixA, fixB = &Project{Ref: selfRef}, &Project{Ref: selfRef}
	t.Cleanup(func() { fixA, fixB = old1, old2 })
}

const backupsDoc = `{"ref":"` + selfRef + `","stanza":"` + selfRef + `-1","incarnation":"1","layout":2,
 "sets":[{"label":"20261118-104332F","timeline":1,"start":"…","stop":"…","start_segment":"…","stop_segment":"…","replicated":true,"listed_at":"…"}],
 "window":{"from":"…","to":"…"},
 "push":{"last_ok":"…","lag_seconds":42,"spool_entries":0,"spool_bytes":0,"spool_oldest":null,"newest_segment":"…"},
 "quota":{"at":"…","disk_used_mb":412,"disk_quota_mb":8192,"repo_used_mb":37,"repo_quota_mb":8192},
 "replication":{"declared":"declared","last_ok":"…","lag_seconds":70,"paused_until":null,"rebuilding":false,
                "bytes_today":0,"bytes_budget":17179869184,"objects_today":0,"objects_budget":32768,"objects_recorded":1013},
 "info_versions":[{"name":"backup.info","version_id":"…","at":"…","sha256":"…"}],
 "timelines":[{"timeline":1,"state":"recorded","operation_id":null}],
 "gaps":[{"cause":"quarantine","first_segment":"…","last_segment":"…","at":"…","detail":"…"}],
 "notices":[{"code":"unlisted-entry","count":3,"first_at":"…","last_at":"…","detail":"…"}],
 "restores":[{"operation_id":7,"state":"done","to":"…","from":"local","new_timeline":2,"finished_at":"…"}]}`

const restoreResultDoc = `{"to":"…","from":"local","set":"…","mode":"none","reached_segment":"…","new_timeline":2,
 "previous_timeline":1,"previous_newest_segment":"…","seeded":false,
 "shortfall":null,"steps":[{"step":"T4p","seconds":3}]}`

// TestBackuphelp_GoldenShapes: the documented backups document, a restore's
// and a delete's result decode with no member left over and encode back to
// the same document, so every member has a field under its own name.
func TestBackuphelp_GoldenShapes(t *testing.T) {
	for _, c := range []struct {
		name, doc string
		v         any
	}{
		{"backups", backupsDoc, &backupsJSON{}},
		{"restore result", restoreResultDoc, &restoreResultJSON{}},
		{"restore result with a shortfall", strings.Replace(restoreResultDoc, `"shortfall":null`,
			`"shortfall":{"expected":"000000010000000000000009","reached":"000000010000000000000007","segments":2}`, 1), &restoreResultJSON{}},
		{"restore result not checked", strings.Replace(restoreResultDoc, `"shortfall":null`, `"shortfall":"not checked"`, 1), &restoreResultJSON{}},
		{"delete result", `{"final_backup":"ok","final_push":"skipped","final_replication":"interrupted_limit"}`, &deleteResultJSON{}},
		{"operation with a result", `{"id":12,"ref":"` + selfRef + `","kind":"restore","state":"done","step":"T11","attempts":1,
  "generation":3,"last_error":"","result":` + restoreResultDoc + `}`, &resultOp{}},
	} {
		d := json.NewDecoder(strings.NewReader(c.doc))
		d.DisallowUnknownFields()
		if err := d.Decode(c.v); err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		var want, got any
		json.Unmarshal([]byte(c.doc), &want)
		b, _ := json.Marshal(c.v)
		json.Unmarshal(b, &got)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s: encodes back as\n%s", c.name, b)
		}
	}
	// A layout-1 project answers with empty lists, never null.
	var b backupsJSON
	if err := json.Unmarshal([]byte(`{"ref":"r","layout":1,"sets":[],"gaps":[],"notices":[],"restores":[],"timelines":[],"info_versions":[]}`), &b); err != nil ||
		b.Layout != 1 || b.Sets == nil || len(b.Sets) != 0 {
		t.Errorf("layout-1 document: %v %+v", err, b)
	}
}

// TestBackuphelp_AdminAPIGoldens: the admin API's own golden documents (the
// backups document at both layouts, a restore's result) decode into the
// helper's types with no member left over, so a renamed member fails here.
func TestBackuphelp_AdminAPIGoldens(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "adminapi", "testdata")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("%s absent: the admin API's documents are not in this tree", name)
		}
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	strict := func(name string, b []byte, v any) {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, f := range []string{"backups.json", "backups_layout1.json"} {
		strict(f, read(f), &backupsJSON{})
	}
	var op struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(read("operation_result.json"), &op); err != nil || len(op.Result) == 0 {
		t.Fatalf("operation_result.json: %v", err)
	}
	strict("operation_result.json result", op.Result, &restoreResultJSON{})
}

// TestBackuphelp_LayoutAndNeedBackups: an absent layout is 1, a written one
// 2, anything else fails; needBackups passes at 2, skips below it, and fails
// below it when SUPAPACE_BACKUP=1.
func TestBackuphelp_LayoutAndNeedBackups(t *testing.T) {
	withFixtureA(t)
	for _, c := range []struct {
		config, env     string
		layout          int // 0: layoutOf fails
		skipped, failed bool
	}{
		{`{"disk_quota_mb":8192}`, "", 1, true, false},
		{`{"disk_quota_mb":8192}`, "1", 1, false, true},
		{`{"disk_quota_mb":8192}`, "0", 1, true, false},
		{`{"layout":2}`, "", 2, false, false},
		{`{"layout":2}`, "1", 2, false, false},
		{`{"layout":3}`, "", 0, false, true},
	} {
		stubCLI(t, `"project show") echo '{"ref":"`+selfRef+`","config":`+c.config+`}' ;;`)
		t.Setenv(backupEnv, c.env)
		var got int
		if _, failed, _ := ran(func(tb testing.TB) { got = nodeLayout(tb) }); failed != (c.layout == 0) || (c.layout != 0 && got != c.layout) {
			t.Errorf("config %s: nodeLayout %d failed %v, want %d", c.config, got, failed, c.layout)
		}
		skipped, failed, msg := ran(func(tb testing.TB) { needBackups(tb) })
		if skipped != c.skipped || failed != c.failed {
			t.Errorf("config %s, %s=%q: needBackups skipped %v failed %v (%s)", c.config, backupEnv, c.env, skipped, failed, msg)
		}
		if (skipped || failed) && c.layout == 1 && !strings.Contains(msg, "layout 1") {
			t.Errorf("config %s: the message does not name the layout: %q", c.config, msg)
		}
	}
	stubCLI(t, `"project show") echo '{"ref":"other"}' ;;`)
	if _, failed, _ := ran(func(tb testing.TB) { layoutOf(tb, selfRef) }); !failed {
		t.Error("a document of another ref was taken")
	}
}

// TestBackuphelp_NeedStandin: no endpoint file skips, or fails with
// SUPAPACE_STANDIN=1; with the file the test runs.
func TestBackuphelp_NeedStandin(t *testing.T) {
	old := s3Dir
	s3Dir = t.TempDir()
	t.Cleanup(func() { s3Dir = old })
	for _, c := range []struct {
		file            bool
		env             string
		skipped, failed bool
	}{{false, "", true, false}, {false, "1", false, true}, {true, "", false, false}, {true, "1", false, false}} {
		os.Remove(filepath.Join(s3Dir, "endpoint"))
		if c.file {
			os.WriteFile(filepath.Join(s3Dir, "endpoint"), []byte("https://s3.sp.test:9443\n"), 0o400)
		}
		t.Setenv(standinEnv, c.env)
		if skipped, failed, msg := ran(func(tb testing.TB) { needStandin(tb) }); skipped != c.skipped || failed != c.failed {
			t.Errorf("endpoint %v, %s=%q: skipped %v failed %v (%s)", c.file, standinEnv, c.env, skipped, failed, msg)
		}
	}
}

// TestBackuphelp_S3: the connection comes from the harness's files (endpoint,
// every declared address on the endpoint's port, CA, the role's keys and
// bucket); the verdict and the exit status must agree; an error fails.
func TestBackuphelp_S3(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldProbe := s3Dir, probeBin
	s3Dir = dir
	t.Cleanup(func() { s3Dir, probeBin = oldDir, oldProbe })
	os.WriteFile(filepath.Join(dir, "endpoint"), []byte("https://s3.sp.test:9443\n"), 0o400)
	os.WriteFile(filepath.Join(dir, "addrs"), []byte("10.215.9.10\n10.215.9.138\n"), 0o400)
	argsFile := filepath.Join(dir, "args")
	stub := func(script string) {
		probeBin = filepath.Join(t.TempDir(), "sp-probe")
		os.WriteFile(probeBin, []byte("#!/bin/sh\necho \"$@\" > "+argsFile+"\n"+script+"\n"), 0o755)
	}
	stub(`echo "object 3 abc v1"; exit 0`)
	var line string
	var code int
	if _, failed, msg := ran(func(tb testing.TB) { line, code = s3(tb, "cp-read", "head", "cp-1/x") }); failed || code != 0 || line != "object 3 abc v1" {
		t.Fatalf("head: %q %d failed %v (%s)", line, code, failed, msg)
	}
	got, _ := os.ReadFile(argsFile)
	want := "s3 head cp-1/x --endpoint https://s3.sp.test:9443 --keys " + dir + "/cp-read.keys --ca " + dir +
		"/ca.pem --timeout 30s --addr 10.215.9.10:9443 --addr 10.215.9.138:9443 --bucket sp-cp\n"
	if string(got) != want {
		t.Errorf("argv\n%s want\n%s", got, want)
	}
	ran(func(tb testing.TB) { s3(tb, "admin", "versions", "--bucket", "sp-cp") })
	if got, _ := os.ReadFile(argsFile); strings.Count(string(got), "--bucket") != 1 {
		t.Errorf("a --bucket of the caller was doubled: %s", got)
	}
	for _, c := range []struct {
		script string
		code   int // -1: the helper fails
	}{
		{`echo denied; exit 1`, 1},
		{`echo 'version "a" v1 latest'; echo not-found; exit 1`, 1},
		{`echo timeout; exit 2`, 2},
		{`echo denied; exit 0`, -1},
		{`echo "object 1 a b"; exit 1`, -1},
		{`echo "error tls"; exit 3`, -1},
		{`exit 0`, -1},
	} {
		stub(c.script)
		_, failed, _ := ran(func(tb testing.TB) { _, code = s3(tb, "projects-read", "head", "k") })
		if failed != (c.code < 0) || (c.code >= 0 && code != c.code) {
			t.Errorf("%q: code %d failed %v, want %d", c.script, code, failed, c.code)
		}
	}
	// versions: every line comes back; no line at all is an empty listing.
	stub(`echo 'version "k" v2 latest'; echo 'version "k" v1 noncurrent'; exit 0`)
	if _, failed, _ := ran(func(tb testing.TB) { line, code = s3(tb, "admin", "versions", "k") }); failed || code != 0 ||
		line != "version \"k\" v2 latest\nversion \"k\" v1 noncurrent" {
		t.Errorf("versions: %q %d failed %v", line, code, failed)
	}
	stub(`exit 0`)
	if _, failed, _ := ran(func(tb testing.TB) { line, code = s3(tb, "admin", "versions", "none/") }); failed || code != 0 || line != "" {
		t.Errorf("an empty listing: %q %d failed %v", line, code, failed)
	}
}

// TestBackuphelp_BackupsRestoreWaitPush: backups and restore read the CLI's
// documents (a document of another ref fails); waitPush returns only for a
// complete push that ended after the call, and fails at its deadline.
func TestBackuphelp_BackupsRestoreWaitPush(t *testing.T) {
	dir := t.TempDir()
	lastOK := filepath.Join(dir, "last_ok")
	stubCLI(t, `"project backups") printf '{"ref":"%s","layout":2,"push":{"last_ok":%s}}' "$3" "$(cat `+lastOK+`)" ;;
"project restore") echo "$@" > `+dir+`/restore; echo '{"id":9,"ref":"`+selfRef+`","kind":"restore","state":"done","result":`+strings.ReplaceAll(restoreResultDoc, "\n", "")+`}' ;;`)
	os.WriteFile(lastOK, []byte("null"), 0o600)
	if _, failed, _ := ran(func(tb testing.TB) { backups(tb, selfRef) }); failed {
		t.Error("backups failed on its own ref")
	}
	stubCLI(t, `"project backups") echo '{"ref":"other"}' ;;`)
	if _, failed, _ := ran(func(tb testing.TB) { backups(tb, selfRef) }); !failed {
		t.Error("backups took a document of another ref")
	}
	stubCLI(t, `"project backups") printf '{"ref":"%s","layout":2,"push":{"last_ok":%s}}' "$3" "$(cat `+lastOK+`)" ;;
"project restore") echo "$@" > `+dir+`/restore; echo '{"id":9,"ref":"`+selfRef+`","kind":"restore","state":"done","result":`+strings.ReplaceAll(restoreResultDoc, "\n", "")+`}' ;;`)
	var op resultOp
	ran(func(tb testing.TB) { op, _ = restore(tb, selfRef, "--to", "latest", "--from", "offsite") })
	var res restoreResultJSON
	if args, _ := os.ReadFile(dir + "/restore"); string(args) != "project restore "+selfRef+" --to latest --from offsite\n" ||
		op.Kind != "restore" || json.Unmarshal(op.Result, &res) != nil || res.NewTimeline != 2 {
		t.Errorf("restore: argv %q, op %+v, result %+v", args, op.Op, res)
	}

	oldWait := pushWait
	pushWait = 3 * time.Second
	t.Cleanup(func() { pushWait = oldWait })
	// A push before the call never counts.
	os.WriteFile(lastOK, []byte(`"`+time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)+`"`), 0o600)
	start := time.Now()
	if _, failed, _ := ran(func(tb testing.TB) { waitPush(tb, selfRef) }); !failed || time.Since(start) < pushWait {
		t.Errorf("waitPush with an old push: failed %v after %v", failed, time.Since(start))
	}
	pushAt := func(after time.Duration) {
		time.Sleep(after)
		os.WriteFile(lastOK, []byte(`"`+time.Now().UTC().Format(time.RFC3339Nano)+`"`), 0o600)
	}
	// One push after the call may have listed the spool before it: not enough.
	go pushAt(1500 * time.Millisecond)
	if _, failed, _ := ran(func(tb testing.TB) { waitPush(tb, selfRef) }); !failed {
		t.Error("waitPush returned after a single push that may have started before the call")
	}
	go func() { pushAt(1500 * time.Millisecond); pushAt(1500 * time.Millisecond) }()
	var b backupsJSON
	start = time.Now()
	if _, failed, msg := ran(func(tb testing.TB) { b = waitPush(tb, selfRef) }); failed || b.Push.LastOK == nil || time.Since(start) < 3*time.Second {
		t.Errorf("waitPush with two new pushes: failed %v after %v (%s)", failed, time.Since(start), msg)
	}
}

// TestBackuphelp_HoldDaemon: the hold file exists before the daemon is
// killed; holdDaemon returns once no daemon runs; cleanup removes the file and
// waits for the daemon to answer again.
func TestBackuphelp_HoldDaemon(t *testing.T) {
	oldFile, oldProcs, oldUp := holdFile, daemonProcs, daemonUp
	holdFile = filepath.Join(t.TempDir(), "sp-hold")
	t.Cleanup(func() { holdFile, daemonProcs, daemonUp = oldFile, oldProcs, oldUp })
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	heldAtFirstLook := false
	looked := false
	daemonProcs = func() []int {
		if !looked {
			_, err := os.Stat(holdFile)
			heldAtFirstLook, looked = err == nil, true
		}
		select {
		case <-exited:
			return nil
		default:
			return []int{cmd.Process.Pid}
		}
	}
	up := make(chan struct{})
	daemonUp = func() bool {
		select {
		case <-up:
			return true
		default:
			return false
		}
	}
	r := &recT{mainT: mainT{out: io.Discard}}
	r.run(func(tb testing.TB) { holdDaemon(tb) })
	if r.failed || !heldAtFirstLook {
		t.Fatalf("holdDaemon failed %v (%s); hold file present before the kill: %v", r.failed, r.msg, heldAtFirstLook)
	}
	select {
	case <-exited:
	default:
		t.Fatal("the daemon still runs after holdDaemon returned")
	}
	if st := cmd.ProcessState; st == nil || st.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("the daemon ended with %v, want SIGKILL", st)
	}
	go func() { time.Sleep(500 * time.Millisecond); close(up) }()
	start := time.Now()
	r.cleanup()
	if _, err := os.Stat(holdFile); err == nil || r.failed || time.Since(start) < 400*time.Millisecond {
		t.Fatalf("cleanup: hold file left %v, failed %v, returned after %v (before the daemon answered)", err == nil, r.failed, time.Since(start))
	}
}

// TestBackuphelp_SecretsReadableBy: a file holding the needle is reported
// when the uid can read it and every directory above it, and only then.
func TestBackuphelp_SecretsReadableBy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files other owners")
	}
	const uid, other = 64001, 64002
	root := t.TempDir()
	for _, d := range []string{root, filepath.Dir(root)} {
		os.Chmod(d, 0o755)
	}
	if !readableBy(uid, uid, filepath.Dir(root), "/") {
		t.Skipf("a directory above %s is not traversable by an unprivileged uid", root)
	}
	secret := []byte("reach-passphrase-0123456789")
	write := func(rel string, mode os.FileMode, owner int) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, append([]byte("x="), secret...), mode)
		os.Chmod(p, mode)
		os.Chown(p, owner, owner)
	}
	write("world", 0o644, 0)
	write("own", 0o600, uid)
	write("group", 0o640, other)
	write("root-only", 0o600, 0)
	write("closed/inner", 0o644, 0)
	write("closed/open/mounted", 0o600, uid)
	os.Chmod(filepath.Join(root, "closed"), 0o700)
	os.Symlink(filepath.Join(root, "world"), filepath.Join(root, "link"))
	hits, err := secretsReadableBy(uid, uid, []string{root, filepath.Join(root, "absent")}, false, []needle{{"pass", keyForms(secret)}})
	var names []string
	for _, h := range hits {
		names = append(names, strings.TrimPrefix(strings.Fields(h)[0], root+"/"))
	}
	if err != nil || !slices.Equal(names, []string{"own", "world"}) {
		t.Fatalf("hits %v, err %v; want own and world", names, err)
	}
	// Control: the group bit counts for the group.
	if hits, _ := secretsReadableBy(other+1, other, []string{root}, false, []needle{{"pass", [][]byte{secret}}}); !slices.ContainsFunc(hits, func(h string) bool { return strings.Contains(h, "/group ") }) {
		t.Errorf("a group-readable file was not found for the group: %v", hits)
	}
	if hits, _ := secretsReadableBy(uid, uid, []string{root}, false, []needle{{"none", [][]byte{[]byte("absent-bytes")}}}); len(hits) != 0 {
		t.Errorf("an absent needle matched %v", hits)
	}
	// A mount source behind a closed directory is still reached through the
	// mount: searched as mounted, the uid's own file there is found.
	open := filepath.Join(root, "closed", "open")
	if hits, _ := secretsReadableBy(uid, uid, []string{open}, true, []needle{{"pass", [][]byte{secret}}}); len(hits) != 1 ||
		!strings.HasPrefix(hits[0], filepath.Join(open, "mounted")+" ") {
		t.Errorf("searched as mounted: %v, want the file below the mount source", hits)
	}
	if hits, _ := secretsReadableBy(other, other, []string{open}, true, []needle{{"pass", [][]byte{secret}}}); len(hits) != 0 {
		t.Errorf("searched as mounted, another uid's 0600 file was reported: %v", hits)
	}
}

// TestBackuphelp_ArchivedAndQuarantined: archived finds a segment, a label and
// a history file of the stanza by their repository names only; quarantined
// keeps entries outside the pattern that are not temporaries.
func TestBackuphelp_ArchivedAndQuarantined(t *testing.T) {
	const st = "abcdefghij0123456789-1"
	seg := "000000010000000000000003"
	files := []string{
		"archive/" + st + "/archive.info",
		"archive/" + st + "/17-1/0000000100000000/" + seg + "-0123456789abcdef0123456789abcdef01234567.zst",
		"archive/" + st + "/17-1/0000000100000000/000000010000000000000004.00000028.backup",
		"archive/" + st + "/17-1/00000002.history",
		"archive/other-1/17-1/0000000100000000/000000010000000000000005-0123456789abcdef0123456789abcdef01234567.zst",
		"backup/" + st + "/20261118-104332F/pg_data/pg_wal/000000010000000000000005", // a set file of that name is not archived WAL
	}
	for name, want := range map[string]string{
		seg: files[1], "000000010000000000000004.00000028.backup": files[2], "00000002.history": files[3],
		"000000010000000000000005": "", "000000010000000000000006": "",
	} {
		if got := archived(files, st, name); got != want {
			t.Errorf("archived %s = %q, want %q", name, got, want)
		}
	}
	es := []spoolEntry{{name: seg}, {name: "00000002.history"}, {name: ".tmp-" + seg + "-0123456789abcdef"},
		{name: seg + ".quarantine"}, {name: "--config=x"}, {name: strings.ToLower("0000000A0000000000000001")}}
	var got []string
	for _, e := range quarantined(es) {
		got = append(got, e.name)
	}
	if want := []string{seg + ".quarantine", "--config=x", "0000000a0000000000000001"}; !slices.Equal(got, want) {
		t.Errorf("quarantined %v, want %v", got, want)
	}
}
