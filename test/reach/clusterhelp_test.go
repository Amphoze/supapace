package reach

// Helpers of the cluster and saga tests that need no daemon: the project
// check document, the fake backend's log and what a client sent it, the
// verdicts expected from an untrusted database server, the user quota report,
// a container log's bound and tail, the agent's state file, processes by executable, and writers that run in the
// background. Untagged like helpers_test.go; self-tests are below each part.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/routes"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/jackc/pgx/v5"
)

// ───────── admin API documents ─────────

// checkJSON is the answer of `project check` (POST /v1/projects/{ref}/check).
type checkJSON struct {
	OK      bool        `json:"ok"`
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Drift   []driftJSON `json:"drift"`
}

type driftJSON struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

// driftNames is the sorted set of the check names in c's drift list.
func (c checkJSON) driftNames() []string {
	var n []string
	for _, d := range c.Drift {
		n = append(n, d.Name)
	}
	slices.Sort(n)
	return slices.Compact(n)
}

// placementJSON is a project's state and placement with null kept apart from
// 0: a purged or aborted project has no subnet index, and index 0 is a real
// slice.
type placementJSON struct {
	Ref         string `json:"ref"`
	State       string `json:"state"`
	UID         *int   `json:"uid"`
	SubnetIndex *int   `json:"subnet_index"`
}

// errorJSON is a synchronous error body of the admin API.
type errorJSON struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func TestClusterhelp_DecodeCheckAndPlacement(t *testing.T) {
	var ok, bad checkJSON
	if err := json.Unmarshal([]byte(`{"ok":true,"drift":[]}`), &ok); err != nil || !ok.OK || ok.Code != "" || len(ok.driftNames()) != 0 {
		t.Fatalf("ok document: %v %+v", err, ok)
	}
	doc := `{"ok":false,"code":"peer","message":"m","drift":[{"name":"superuser","detail":"a"},{"name":"event-triggers","detail":"b"},{"name":"superuser","detail":"c"}]}`
	if err := json.Unmarshal([]byte(doc), &bad); err != nil || bad.OK || bad.Code != "peer" || bad.Message != "m" {
		t.Fatalf("failed document: %v %+v", err, bad)
	}
	if got := bad.driftNames(); !slices.Equal(got, []string{"event-triggers", "superuser"}) {
		t.Fatalf("drift names %v", got)
	}
	var purged, placed placementJSON
	json.Unmarshal([]byte(`{"ref":"r","state":"purged","uid":700002,"subnet_index":null}`), &purged)
	json.Unmarshal([]byte(`{"ref":"r","state":"active","uid":700002,"subnet_index":0}`), &placed)
	if purged.UID == nil || *purged.UID != 700002 || purged.SubnetIndex != nil {
		t.Fatalf("purged: %+v", purged)
	}
	if placed.SubnetIndex == nil || *placed.SubnetIndex != 0 {
		t.Fatalf("index 0 must not read as null: %+v", placed)
	}
	var e errorJSON
	if json.Unmarshal([]byte(`{"code":"bad_ref","message":"x"}`), &e) != nil || e.Code != "bad_ref" {
		t.Fatalf("error body: %+v", e)
	}
}

// ───────── psql inside a cluster container ─────────

// psqlArgv is the docker command that runs sql in the cluster of ref as role,
// with the password (if any) taken from PGPASSWORD in the caller's
// environment and env as further variables passed by name.
func psqlArgv(ref, role, sql string, env ...string) []string {
	argv := []string{"docker", "exec", "-e", "PGPASSWORD"}
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		argv = append(argv, "-e", name)
	}
	return append(argv, "pg-"+ref, "psql", "-X", "-w", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
		"-h", psqlHost(role), "-U", role, "-d", "postgres", "-c", sql)
}

func TestClusterhelp_PsqlHostPerRole(t *testing.T) {
	// The rendered pg_hba admits the administrative role over the socket only;
	// a loopback login of it is rejected, so sqlAs must not send it there.
	if psqlHost("supabase_admin") != "/var/run/postgresql" {
		t.Fatalf("supabase_admin goes to %q", psqlHost("supabase_admin"))
	}
	for _, r := range []string{"postgres", "authenticator", "anon"} {
		if psqlHost(r) != "127.0.0.1" {
			t.Fatalf("%s goes to %q", r, psqlHost(r))
		}
	}
	a := psqlArgv("abcdefghij0123456789", "supabase_admin", "select 1", "PGOPTIONS=-c role=none")
	s := strings.Join(a, " ")
	if !strings.Contains(s, "-e PGPASSWORD -e PGOPTIONS pg-abcdefghij0123456789 psql") || !strings.Contains(s, "-h /var/run/postgresql -U supabase_admin") {
		t.Fatalf("argv %q", a)
	}
	if strings.Contains(s, "role=none") {
		t.Fatalf("an environment value reached argv: %q", a)
	}
}

// ───────── the fake backend's log ─────────

// parseFakeLog splits a fakepg log ("conn N LEN\n" + LEN bytes, repeated)
// into the bytes each connection sent, in order. A record cut short or a
// malformed header is an error: the log is read by its LEN fields only.
func parseFakeLog(b []byte) (map[int][]byte, error) {
	out := map[int][]byte{}
	for len(b) > 0 {
		line, rest, ok := bytes.Cut(b, []byte("\n"))
		f := strings.Fields(string(line))
		if !ok || len(f) != 3 || f[0] != "conn" {
			return nil, fmt.Errorf("malformed record header %q", brief(string(line)))
		}
		n, err1 := strconv.Atoi(f[1])
		l, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil || n < 1 || l < 0 || l > len(rest) {
			return nil, fmt.Errorf("record header %q: bad numbers or %d bytes left", brief(string(line)), len(rest))
		}
		out[n] = append(out[n], rest[:l]...)
		b = rest[l:]
	}
	return out, nil
}

// frontendMsg is one message a client sent: typ 0 for the untyped packets of
// the start (encryption requests, startup packet).
type frontendMsg struct {
	typ  byte
	body []byte
}

const (
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
)

// frontendMessages parses what one connection sent: encryption requests and
// the startup packet, then typed messages. A message cut at the end of the
// stream (the client went away, or the fake stopped logging) is returned with
// its partial body and cut set.
func frontendMessages(s []byte) (msgs []frontendMsg, cut bool) {
	for len(s) >= 8 {
		n := binary.BigEndian.Uint32(s)
		code := binary.BigEndian.Uint32(s[4:])
		if n < 8 {
			return msgs, true
		}
		if int64(n) > int64(len(s)) {
			return append(msgs, frontendMsg{0, s[4:]}), true
		}
		msgs = append(msgs, frontendMsg{0, s[4:n]})
		s = s[n:]
		if n != 8 || code != sslRequestCode && code != gssEncRequestCode {
			break // that was the startup packet
		}
	}
	if len(msgs) == 0 && len(s) > 0 {
		return nil, true
	}
	for len(s) > 0 {
		if len(s) < 5 {
			return append(msgs, frontendMsg{s[0], nil}), true
		}
		n := binary.BigEndian.Uint32(s[1:])
		if n < 4 {
			return append(msgs, frontendMsg{s[0], nil}), true
		}
		if int64(n)+1 > int64(len(s)) {
			return append(msgs, frontendMsg{s[0], s[5:]}), true
		}
		msgs = append(msgs, frontendMsg{s[0], s[5 : n+1]})
		s = s[n+1:]
	}
	return msgs, false
}

// passwordMessages checks the password-class ('p') messages of one
// connection: only a SCRAM-SHA-256 initial response and then one client-final
// message may appear — never a cleartext or MD5 password. It returns how many
// there were and every problem found.
func passwordMessages(stream []byte) (n int, problems []string) {
	msgs, _ := frontendMessages(stream)
	for _, m := range msgs {
		if m.typ != 'p' {
			continue
		}
		switch n++; {
		case n == 1 && bytes.HasPrefix(m.body, []byte("SCRAM-SHA-256\x00")):
		case n == 2 && bytes.HasPrefix(m.body, []byte("c=")) && bytes.Contains(m.body, []byte(",p=")):
		default:
			problems = append(problems, fmt.Sprintf("password message %d is not a SCRAM client message (%d bytes)", n, len(m.body)))
		}
	}
	return n, problems
}

// hasControl reports a control character (C0, DEL, C1) or invalid UTF-8 in s.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r <= 0x9f || r == utf8.RuneError {
			return true
		}
	}
	return false
}

// fe frames a typed frontend message.
func fe(typ byte, body string) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{typ}, uint32(4+len(body))), body...)
}

// startupPacket is a minimal startup packet (protocol 3.0, user u).
func startupPacket(u string) []byte {
	body := append(binary.BigEndian.AppendUint32(nil, 196608), "user\x00"+u+"\x00\x00"...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(4+len(body))), body...)
}

func sslRequest() []byte {
	return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), sslRequestCode)
}

func TestClusterhelp_FakeLogAndPasswordMessages(t *testing.T) {
	scram := slices.Concat(sslRequest(), startupPacket("supabase_admin"),
		fe('p', "SCRAM-SHA-256\x00\x00\x00\x00\x20n,,n=,r=abc"), fe('p', "c=biws,r=abcdef,p=proof"), fe('Q', "select 1\x00"))
	// The same bytes split over records of two connections, one record
	// carrying text shaped like a header.
	log := fmt.Appendf(nil, "conn 1 %d\n", 10)
	log = append(log, scram[:10]...)
	log = append(fmt.Appendf(log, "conn 2 %d\n", 12), "conn 9 99\nxx"...)
	log = append(fmt.Appendf(log, "conn 1 %d\n", len(scram)-10), scram[10:]...)
	conns, err := parseFakeLog(log)
	if err != nil || len(conns) != 2 || !bytes.Equal(conns[1], scram) || string(conns[2]) != "conn 9 99\nxx" {
		t.Fatalf("parse: %v %q", err, conns)
	}
	if n, p := passwordMessages(conns[1]); n != 2 || len(p) != 0 {
		t.Fatalf("SCRAM exchange: %d messages, problems %v", n, p)
	}
	for name, s := range map[string][]byte{
		"cleartext":      slices.Concat(startupPacket("u"), fe('p', "secret\x00")),
		"md5":            slices.Concat(startupPacket("u"), fe('p', "md5abcdef\x00")),
		"third":          slices.Concat(startupPacket("u"), fe('p', "SCRAM-SHA-256\x00x"), fe('p', "c=biws,p=x"), fe('p', "c=biws,p=y")),
		"cut_password":   slices.Concat(startupPacket("u"), fe('p', "secret\x00")[:7]),
		"final_no_proof": slices.Concat(startupPacket("u"), fe('p', "SCRAM-SHA-256\x00x"), fe('p', "c=biws,r=x")),
	} {
		if _, p := passwordMessages(s); len(p) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
	if n, _ := passwordMessages(slices.Concat(startupPacket("u"), fe('p', "SCRAM-SHA-256\x00x"))); n != 1 {
		t.Errorf("client-first only: %d password messages", n)
	}
	for _, bad := range []string{"conn 1 5\nabc", "conn x 1\na", "garbage\n", "conn 1 1", "conn 0 1\na", "conn 1 -1\n", "con 1 1\na"} {
		if _, err := parseFakeLog([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !hasControl("a\x1b[2J") || !hasControl("a\nb") || !hasControl("a\x7f") || !hasControl("\xc2\x9b") || !hasControl("\xff") || hasControl("fake-marker plain é") {
		t.Error("hasControl")
	}
}

// ───────── an untrusted database server: expected verdicts ─────────

// hostileMode is one behaviour of the fake backend run as a cluster
// container's init, and what `project check` must answer: one of codes within
// the bound. postAuth modes complete a real SCRAM exchange first. "peer" is
// never right: the suite records the fake as the postmaster, so the peer check
// passes and a peer code would mean the fake was never the server.
type hostileMode struct {
	mode     string
	postAuth bool
	codes    []string
	within   time.Duration
}

var (
	codeTimeout, codeInternal, codeEither = []string{"timeout"}, []string{"internal"}, []string{"timeout", "internal"}
)

var hostileModes = []hostileMode{
	{"huge", false, codeTimeout, 15 * time.Second},
	// The platform's guard refuses a message before authentication (internal)
	// unless the budget ends it first (timeout).
	{"flood", false, codeEither, 15 * time.Second},
	{"stall", false, codeTimeout, 15 * time.Second},
	{"trickle", false, codeTimeout, 15 * time.Second},
	{"cleartext", false, codeInternal, 5 * time.Second},
	{"md5", false, codeInternal, 5 * time.Second},
	{"authok", false, codeInternal, 5 * time.Second},
	{"sasl-iter", false, codeEither, 2 * time.Second},
	{"row-huge", true, codeTimeout, 15 * time.Second},
	{"rows-endless", true, codeTimeout, 15 * time.Second},
	{"stall-auth", true, codeTimeout, 15 * time.Second},
	{"escapes", true, codeInternal, 15 * time.Second},
}

// hostileProblems lists every way res, the time it took and what the fake
// received (by connection) miss the expectation for m: the check fails with
// one of m's codes within m's bound; its message is at most 1 KiB without control
// characters (for escapes it carries the fake's marker); no password other
// than SCRAM client messages reached the fake; for sasl-iter no client-final
// message (nothing was derived from the password); and the fake was reached
// at all (else the check never met it).
func hostileProblems(m hostileMode, res checkJSON, elapsed time.Duration, conns map[int][]byte) []string {
	var p []string
	if res.OK {
		p = append(p, `"ok":true`)
	}
	if !slices.Contains(m.codes, res.Code) {
		p = append(p, fmt.Sprintf("code %q, want one of %q", res.Code, m.codes))
	}
	if elapsed > m.within {
		p = append(p, fmt.Sprintf("answered after %v, bound %v", elapsed.Round(time.Millisecond), m.within))
	}
	if len(res.Message) > 1024 || hasControl(res.Message) {
		p = append(p, fmt.Sprintf("message of %d bytes, control characters %v", len(res.Message), hasControl(res.Message)))
	}
	if m.mode == "escapes" && !strings.Contains(res.Message, "fake-marker") {
		p = append(p, "message does not carry the fake's marker: the server's error text was not relayed")
	}
	if len(conns) == 0 {
		p = append(p, "the fake received no connection")
	}
	for c, s := range conns {
		n, probs := passwordMessages(s)
		for _, q := range probs {
			p = append(p, fmt.Sprintf("connection %d: %s", c, q))
		}
		if m.mode == "sasl-iter" && n > 1 {
			p = append(p, fmt.Sprintf("connection %d: a client-final message was sent (key derivation ran)", c))
		}
	}
	return p
}

func TestClusterhelp_HostileProblems(t *testing.T) {
	firstOnly := map[int][]byte{1: slices.Concat(startupPacket("supabase_admin"), fe('p', "SCRAM-SHA-256\x00x"))}
	full := map[int][]byte{1: slices.Concat(startupPacket("supabase_admin"), fe('p', "SCRAM-SHA-256\x00x"), fe('p', "c=biws,r=x,p=y"), fe('Q', "select 1\x00"))}
	clearPw := map[int][]byte{1: slices.Concat(startupPacket("supabase_admin"), fe('p', "secret\x00"))}
	mode := func(name string) hostileMode {
		i := slices.IndexFunc(hostileModes, func(m hostileMode) bool { return m.mode == name })
		return hostileModes[i]
	}
	timeout := checkJSON{Code: "timeout", Message: "session budget exceeded"}
	for _, c := range []struct {
		name    string
		m       hostileMode
		res     checkJSON
		elapsed time.Duration
		conns   map[int][]byte
		bad     bool
	}{
		{"huge_ok", mode("huge"), timeout, 6 * time.Second, map[int][]byte{1: startupPacket("supabase_admin")}, false},
		{"huge_late", mode("huge"), timeout, 16 * time.Second, map[int][]byte{1: startupPacket("supabase_admin")}, true},
		{"huge_wrong_code", mode("huge"), checkJSON{Code: "internal"}, time.Second, map[int][]byte{1: startupPacket("u")}, true},
		{"passed", mode("stall"), checkJSON{OK: true}, time.Second, map[int][]byte{1: startupPacket("u")}, true},
		{"never_reached", mode("stall"), timeout, time.Second, nil, true},
		{"cleartext_refused", mode("cleartext"), checkJSON{Code: "internal"}, time.Second, map[int][]byte{1: startupPacket("u")}, false},
		{"cleartext_sent", mode("cleartext"), checkJSON{Code: "internal"}, time.Second, clearPw, true},
		{"sasl_iter_first_only", mode("sasl-iter"), checkJSON{Code: "internal"}, time.Second, firstOnly, false},
		{"sasl_iter_derived", mode("sasl-iter"), checkJSON{Code: "internal"}, time.Second, full, true},
		{"row_huge", mode("row-huge"), timeout, 10 * time.Second, full, false},
		{"escapes_marker", mode("escapes"), checkJSON{Code: "internal", Message: "fake-marker red"}, time.Second, full, false},
		{"escapes_no_marker", mode("escapes"), checkJSON{Code: "internal", Message: "error"}, time.Second, full, true},
		{"escapes_raw", mode("escapes"), checkJSON{Code: "internal", Message: "fake-marker \x1b[2J"}, time.Second, full, true},
		{"peer_is_never_right", mode("sasl-iter"), checkJSON{Code: "peer"}, time.Second, firstOnly, true},
		{"long_message", mode("stall"), checkJSON{Code: "timeout", Message: strings.Repeat("x", 1025)}, time.Second, firstOnly, true},
	} {
		if got := hostileProblems(c.m, c.res, c.elapsed, c.conns); (len(got) > 0) != c.bad {
			t.Errorf("%s: problems %q, want problems: %v", c.name, got, c.bad)
		}
	}
	if len(hostileModes) != 12 {
		t.Fatalf("the hostile list has %d modes, want 12", len(hostileModes))
	}
}

// ───────── user quota ─────────

// userQuota is a user's XFS quota as `xfs_quota -x -c 'report -u -n -N -b -i'`
// reports it: blocks in KiB, inodes in files.
type userQuota struct {
	BlocksUsed, BlocksHard, InodesUsed, InodesHard int64
}

// parseQuotaReport finds uid's line ("#<uid> used soft hard warn [grace] used
// soft hard warn [grace]"; a grace field may hold spaces).
func parseQuotaReport(out string, uid int) (userQuota, error) {
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "#"+strconv.Itoa(uid) {
			continue
		}
		var nums []int64
		for i := 1; i < len(f); i++ {
			if strings.HasPrefix(f[i], "[") {
				for !strings.HasSuffix(f[i], "]") && i+1 < len(f) {
					i++
				}
				continue
			}
			n, err := strconv.ParseInt(f[i], 10, 64)
			if err != nil {
				return userQuota{}, fmt.Errorf("quota line %q: field %q", strings.TrimSpace(line), f[i])
			}
			nums = append(nums, n)
		}
		if len(nums) != 8 {
			return userQuota{}, fmt.Errorf("quota line %q: %d numbers, want 8", strings.TrimSpace(line), len(nums))
		}
		return userQuota{nums[0], nums[2], nums[4], nums[6]}, nil
	}
	return userQuota{}, fmt.Errorf("no quota line for uid %d", uid)
}

// quotaOf reads uid's user quota on the projects filesystem.
func quotaOf(t testing.TB, uid int) userQuota {
	t.Helper()
	r, err := run(cmdTimeout, []string{"LC_ALL=C"}, "xfs_quota", "-x", "-c", "report -u -n -N -b -i", paths.ProjectsDir())
	if err != nil || r.code != 0 || strings.TrimSpace(r.stderr) != "" {
		t.Fatalf("xfs_quota report: %v exit %d %s", err, r.code, brief(r.stderr))
	}
	q, err := parseQuotaReport(r.stdout, uid)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestClusterhelp_ParseQuotaReport(t *testing.T) {
	out := `#0                   0          0          0     00 [--------]          3          0          0     00 [--------]
#700002          61444          0    1048576     00 [--------]       1032          0     262144     00 [--------]
#700003        1048576    1048576    1048576     00 [7 days]        262144          0     262144     00 [6 days 23:59]
`
	q, err := parseQuotaReport(out, 700002)
	if err != nil || q != (userQuota{61444, 1048576, 1032, 262144}) {
		t.Fatalf("700002: %+v %v", q, err)
	}
	if q, err := parseQuotaReport(out, 700003); err != nil || q != (userQuota{1048576, 1048576, 262144, 262144}) {
		t.Fatalf("700003 (grace with spaces): %+v %v", q, err)
	}
	if _, err := parseQuotaReport(out, 7000); err == nil {
		t.Fatal("a missing uid was found")
	}
	if _, err := parseQuotaReport("#5 1 2\n", 5); err == nil {
		t.Fatal("a short line was accepted")
	}
}

// ───────── the agent's state file ─────────

// setStatePeer rewrites the postmaster identity (pm_pid, pm_start) in the
// agent's state file of a project, keeping every other member, atomically
// (temporary file, then rename, root 0600).
func setStatePeer(path string, pid int, start uint64) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("state file: %v", err)
	}
	if _, ok := m["pm_pid"]; !ok {
		return errors.New("state file has no pm_pid")
	}
	m["pm_pid"] = json.RawMessage(strconv.Itoa(pid))
	m["pm_start"] = json.RawMessage(strconv.FormatUint(start, 10))
	out, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := path + ".reach-tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// statePeer reads pm_pid and pm_start from the agent's state file.
func statePeer(path string) (pid int, start uint64, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	var s struct {
		Pid   *int    `json:"pm_pid"`
		Start *uint64 `json:"pm_start"`
	}
	if err := json.Unmarshal(b, &s); err != nil || s.Pid == nil || s.Start == nil {
		return 0, 0, fmt.Errorf("state file: pm_pid or pm_start missing (%v)", err)
	}
	return *s.Pid, *s.Start, nil
}

func TestClusterhelp_StatePeer(t *testing.T) {
	f := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(f, []byte(`{"epoch":1,"generation":3,"phase":"B","pm_pid":10,"pm_start":20,"listener_pid":0,"listener_start":0}`), 0o600)
	if err := setStatePeer(f, 4242, 123456789012); err != nil {
		t.Fatal(err)
	}
	pid, start, err := statePeer(f)
	if err != nil || pid != 4242 || start != 123456789012 {
		t.Fatalf("read back %d %d %v", pid, start, err)
	}
	var m map[string]any
	b, _ := os.ReadFile(f)
	json.Unmarshal(b, &m)
	if m["phase"] != "B" || m["generation"] != float64(3) || len(m) != 7 {
		t.Fatalf("other members changed: %v", m)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	os.WriteFile(f, []byte(`{"phase":"B"}`), 0o600)
	if setStatePeer(f, 1, 1) == nil {
		t.Fatal("a state file without pm_pid was rewritten")
	}
	os.WriteFile(f, []byte(`{"phase":"B","pm_pid":10}`), 0o600)
	if _, _, err := statePeer(f); err == nil {
		t.Fatal("a state file without pm_start was read")
	}
}

// ───────── processes ─────────

// procsOf lists the pids whose executable is exe and whose arguments include
// arg ("" any), sorted.
func procsOf(exe, arg string) []int {
	var out []int
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err != nil || l != exe {
			continue
		}
		cl, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if arg == "" || slices.Contains(strings.Split(string(cl), "\x00"), arg) {
			out = append(out, pid)
		}
	}
	slices.Sort(out)
	return out
}

// rssKiB is a process's resident set (VmRSS) in KiB.
func rssKiB(pid int) (int64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			return strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		}
	}
	return 0, errors.New("no VmRSS")
}

func TestClusterhelp_ProcsOf(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(procsOf(self, ""), os.Getpid()) {
		t.Fatalf("procsOf(%s) does not list this process", self)
	}
	if slices.Contains(procsOf(self, "no-such-argument"), os.Getpid()) {
		t.Fatal("the argument filter matched nothing it should")
	}
	if n, err := rssKiB(os.Getpid()); err != nil || n <= 0 {
		t.Fatalf("rss %d %v", n, err)
	}
}

// ───────── background writers ─────────

// repeatWhile calls fn every interval in its own goroutine until the returned
// function is called (also a cleanup); that function fails the test unless fn
// ran at least three times and succeeded each time. It calls no testing
// method from the goroutine.
func repeatWhile(t testing.TB, what string, interval time.Duration, fn func() error) func() {
	t.Helper()
	var mu sync.Mutex
	n, bad := 0, []string{}
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			err := fn()
			mu.Lock()
			n++
			if err != nil {
				bad = append(bad, redact(brief(err.Error())))
			}
			mu.Unlock()
			select {
			case <-quit:
				return
			case <-time.After(interval):
			}
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(quit)
			<-done
			if n < 3 || len(bad) > 0 {
				t.Errorf("%s: %d runs, failures %q", what, n, bad[:min(len(bad), 5)])
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// inBackground runs fn in its own goroutine and returns a function that waits
// at most within for its result (false if it has not ended by then); a
// cleanup waits up to backgroundBound, so no failure path leaves fn running
// into the next step. fn must end by itself (its commands have deadlines)
// and call no testing method.
func inBackground[T any](t testing.TB, fn func() T) func(within time.Duration) (T, bool) {
	t.Helper()
	ch := make(chan T, 1)
	go func() { ch <- fn() }()
	var mu sync.Mutex
	var got T
	done := false
	wait := func(within time.Duration) (T, bool) {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			select {
			case got = <-ch:
				done = true
			case <-time.After(within):
			}
		}
		return got, done
	}
	t.Cleanup(func() {
		if _, ok := wait(backgroundBound); !ok {
			t.Errorf("a background step did not end within %v", backgroundBound)
		}
	})
	return wait
}

// backgroundBound bounds the cleanup's wait of inBackground: longer than any
// command's deadline. A variable for the self-test.
var backgroundBound = cliTimeout + time.Minute

// commandOK is a repeatWhile function that runs argv (env added to the
// environment) and wants exit status 0.
func commandOK(env []string, argv ...string) func() error {
	return func() error {
		r, err := run(cmdTimeout, env, argv...)
		if err == nil && r.code != 0 {
			err = fmt.Errorf("exit %d: %s", r.code, brief(r.stderr))
		}
		return err
	}
}

// writesThroughout inserts a row into a table of p as postgres every 500 ms
// (repeatWhile); the table is created first and dropped in cleanup.
func writesThroughout(t testing.TB, p Project) func() {
	t.Helper()
	if _, err := sqlAs(t, p, "postgres", "create table if not exists public.reach_writes(at timestamptz default now(), pad text)"); err != nil {
		t.Fatalf("writer table in %s: %v", p.Ref, err)
	}
	t.Cleanup(func() { sqlAs(t, p, "postgres", "drop table if exists public.reach_writes") })
	return repeatWhile(t, "writes into "+p.Ref, 500*time.Millisecond, commandOK([]string{"PGPASSWORD=" + p.PostgresPassword},
		psqlArgv(p.Ref, "postgres", "insert into public.reach_writes(pad) select repeat('w', 4096) from generate_series(1, 16)")...))
}

// cpWrite commits one write in the control-plane database, reached the way
// the daemon reaches it (its socket, as root by peer authentication): a
// temporary table is a catalog write that leaves nothing behind.
func cpWrite() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return err
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User = filepath.Join(paths.CPDir(), "sock"), 5432, "supapaced", "supapaced"
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close(context.Background())
	_, err = c.Exec(ctx, "create temp table reach_cp_probe(x text); insert into reach_cp_probe values ('x')")
	return err
}

// ───────── node state read by the saga tests ─────────

// projectDEK unwraps p's data key as the daemon does (control-plane store
// over its socket as root, KEK). The caller clears it.
func projectDEK(t testing.TB, p Project) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(paths.CPDir(), "sock"))
	if err != nil {
		t.Fatalf("data key: %v", err)
	}
	defer st.Close()
	kek, err := secrets.LoadKEK(paths.KEK())
	if err != nil {
		t.Fatalf("data key: %v", err)
	}
	defer clear(kek[:])
	nonce, wrapped, err := st.GetDEK(ctx, p.Ref)
	if err != nil {
		t.Fatalf("data key of %s: %v", p.Ref, err)
	}
	dek, err := secrets.UnwrapDEK(kek, p.Ref, nonce, wrapped)
	if err != nil {
		t.Fatalf("data key of %s: %v", p.Ref, err)
	}
	return dek
}

// routeStates maps each ref of the gateway's route file to its state.
func routeStates(t testing.TB) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(paths.GatewayDir(), "routes.json"))
	if err != nil {
		t.Fatalf("route file: %v", err)
	}
	f, err := routes.Parse(b)
	if err != nil {
		t.Fatalf("route file: %v", err)
	}
	out := map[string]string{}
	for ref, p := range f.Projects {
		out[ref] = p.State
	}
	return out
}

// containerState is a container's id and start time as docker reports them.
func containerState(t testing.TB, name string) string {
	t.Helper()
	return strings.TrimSpace(docker(t, "inspect", "-f", "{{.Id}} {{.State.StartedAt}}", name))
}

// dockerRoot is Docker's data root, read once (docker info, bounded).
var (
	dockerRoot     string
	dockerRootOnce sync.Once
)

// dockerLogBytes is the size of every log file Docker keeps for a container:
// the local log driver's directory under Docker's data root, rotated files
// included.
func dockerLogBytes(t testing.TB, container string) int64 {
	t.Helper()
	dockerRootOnce.Do(func() {
		dockerRoot = strings.TrimSpace(docker(t, "info", "--format", "{{.DockerRootDir}}"))
	})
	if !filepath.IsAbs(dockerRoot) {
		t.Fatalf("docker info: data root %q", dockerRoot)
	}
	id := strings.TrimSpace(docker(t, "inspect", "-f", "{{.Id}}", container))
	dir := filepath.Join(dockerRoot, "containers", id, "local-logs")
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("log files of %s: %v (none found under %s)", container, err, dir)
	}
	var n int64
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		n += fi.Size()
	}
	return n
}

// logBound is the most a container's log driver keeps by its options:
// max-size (Docker's binary units: a number with k, m or g, b optional)
// times max-file. Both must be set.
func logBound(opts map[string]string) (int64, error) {
	size, files := opts["max-size"], opts["max-file"]
	if size == "" || files == "" {
		return 0, fmt.Errorf("log options %v: max-size and max-file must both be set", opts)
	}
	num := strings.TrimSuffix(strings.ToLower(size), "b")
	if num == "" {
		return 0, fmt.Errorf("log options %v: max-size has no number", opts)
	}
	mult := int64(1)
	if k := strings.IndexByte("kmg", num[len(num)-1]); k >= 0 {
		mult, num = int64(1)<<(10*(k+1)), num[:len(num)-1]
	}
	n, err := strconv.ParseInt(num, 10, 64)
	f, ferr := strconv.ParseInt(files, 10, 64)
	if err != nil || ferr != nil || n <= 0 || f <= 0 {
		return 0, fmt.Errorf("log options %v: max-size or max-file is not a positive number", opts)
	}
	return n * mult * f, nil
}

// logTail reads a log stream to its end and reports whether a line holding
// marker was seen, how many bytes follow the end of the last such line, and
// how many lines of at least long bytes the stream held. Memory is bounded by
// one buffer, whatever the line length.
func logTail(r io.Reader, marker string, long int) (found bool, after int64, longLines int, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var total, lineLen int64
	hit := false
	for {
		chunk, err := br.ReadSlice('\n')
		total += int64(len(chunk))
		lineLen += int64(len(chunk))
		hit = hit || bytes.Contains(chunk, []byte(marker))
		if err == bufio.ErrBufferFull {
			continue
		}
		if len(chunk) > 0 && (err == nil || err == io.EOF) {
			if hit {
				found, after = true, total
			}
			if lineLen >= int64(long) {
				longLines++
			}
			hit, lineLen = false, 0
		}
		if err == io.EOF {
			return found, total - after, longLines, nil
		}
		if err != nil {
			return found, 0, longLines, err
		}
	}
}

func TestClusterhelp_LogBoundAndTail(t *testing.T) {
	for opts, want := range map[[2]string]int64{{"10m", "3"}: 30 << 20, {"512k", "2"}: 1 << 20, {"1G", "1"}: 1 << 30, {"100", "1"}: 100, {"10mb", "3"}: 30 << 20} {
		if got, err := logBound(map[string]string{"max-size": opts[0], "max-file": opts[1]}); err != nil || got != want {
			t.Errorf("%v: %d %v, want %d", opts, got, err, want)
		}
	}
	for _, bad := range []map[string]string{{}, {"max-size": "10m"}, {"max-file": "3"}, {"max-size": "m", "max-file": "3"}, {"max-size": "b", "max-file": "3"}, {"max-size": "10m", "max-file": "0"}, {"max-size": "-1m", "max-file": "3"}} {
		if _, err := logBound(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	flood := strings.Repeat("f", 200<<10) + "\n"
	in := "start\n" + flood + flood + "LOG:  reach-marker\n" + "after 1\nafter 2\n"
	found, after, long, err := logTail(strings.NewReader(in), "reach-marker", 100<<10)
	if err != nil || !found || after != int64(len("after 1\nafter 2\n")) || long != 2 {
		t.Fatalf("found %v after %d long %d %v", found, after, long, err)
	}
	// The last occurrence counts; a stream without a final newline ends a line.
	found, after, _, _ = logTail(strings.NewReader("reach-marker\nx\nreach-marker y"), "reach-marker", 1)
	if !found || after != 0 {
		t.Fatalf("last occurrence: found %v after %d", found, after)
	}
	if found, _, long, _ := logTail(strings.NewReader(flood+"no marker\n"), "reach-marker", 100<<10); found || long != 1 {
		t.Fatalf("absent marker: found %v long %d", found, long)
	}
	// A line longer than the buffer is one line; a short line after it is
	// read whole (bufio moves unread data to the front before refilling).
	in = strings.Repeat("x", 100<<10+7) + "\n" + strings.Repeat("y", 64<<10-200) + "reach-marker\n"
	if found, after, long, _ := logTail(strings.NewReader(in), "reach-marker", 64<<10); !found || after != 0 || long != 1 {
		t.Fatalf("after a long line: found %v after %d long %d", found, after, long)
	}
}

// ───────── a tree a tenant left behind ─────────

// countTree counts dir and every entry below it without following links. It
// walks by descriptor (openat), so a tree nested deeper than a path can name
// is counted too.
func countTree(dir string) (int, error) {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", dir, err)
	}
	return countAt(fd)
}

// countAt counts the directory open at fd and everything below it; it closes fd.
func countAt(fd int) (int, error) {
	f := os.NewFile(uintptr(fd), "dir")
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return 0, err
	}
	n := 1
	for _, e := range ents {
		if !e.IsDir() {
			n++
			continue
		}
		c, err := syscall.Openat(fd, e.Name(), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return 0, fmt.Errorf("%q: %w", e.Name(), err)
		}
		m, err := countAt(c)
		if err != nil {
			return 0, err
		}
		n += m
	}
	return n, nil
}

func TestClusterhelp_CountTreeDeeperThanAPath(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	for _, f := range []string{"a", "b"} {
		os.WriteFile(filepath.Join(outside, f), nil, 0o600)
	}
	os.Symlink(outside, filepath.Join(root, "link")) // one entry; not followed
	os.WriteFile(filepath.Join(root, "file"), nil, 0o600)
	// 2,000 nested directories: about 10,000 bytes of path, past PATH_MAX.
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 2000 {
		if err := syscall.Mkdirat(fd, "deep", 0o700); err != nil {
			t.Fatal(err)
		}
		next, err := syscall.Openat(fd, "deep", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		syscall.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		fd = next
	}
	syscall.Close(fd)
	n, err := countTree(root)
	if err != nil || n != 1+2+2000 {
		t.Fatalf("counted %d (%v), want %d", n, err, 1+2+2000)
	}
	if _, err := countTree(filepath.Join(root, "link")); err == nil {
		t.Fatal("a link to a directory was followed")
	}
	// t.TempDir's removal handles the deep tree (os.RemoveAll works by descriptor).
}
