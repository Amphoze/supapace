//go:build reach

// Bare-node proof, run as root on a node started with `make node-bare` into which
// the dashboard's database client image and the proxy's image have been loaded
// (the cluster image is in every node). On scratch networks the dashboard's
// database client reaches a cluster of the platform's image through the built
// proxy; what the client sees at each of the proxy's refusals is recorded, and
// the fake backend's hostile modes run against the built image.
package pgcap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	proxyImage = "supapace-pgcap:local"
	scratch    = "sp-test-pgcap-"
	// The scratch layout: the platform network, and three slices of the block —
	// 3 with a cluster of the platform's image, 7 with nothing at the cluster's
	// address, 9 with the fake backend.
	platNet = "10.212.0.0/24"
	proxyIP = "10.212.0.6"
	clientA = "10.212.0.4" // the client against the cluster
	clientB = "10.212.0.5" // the client against the fake or nothing
)

// reach is the proof's arrangement on the node.
type reach struct {
	t        *testing.T
	ctx      context.Context
	dir      string // the proxy's table, the fake's log and password
	password string
	salt     []byte
	tb       Table
}

func (r *reach) docker(args ...string) string {
	r.t.Helper()
	out, err := dockerx.Run(r.ctx, args...)
	if err != nil {
		r.t.Fatalf("docker %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(out)
}

func (r *reach) rm(names ...string) {
	for _, n := range names {
		dockerx.Run(context.Background(), "rm", "-f", "-v", scratch+n)
	}
}

func (r *reach) network(name, subnet, gateway string) {
	dockerx.Run(context.Background(), "network", "rm", scratch+name)
	r.docker("network", "create", "--label", "supapace.test=1", "--subnet", subnet, "--gateway", gateway, scratch+name)
	r.t.Cleanup(func() { dockerx.Run(context.Background(), "network", "rm", scratch+name) })
}

// slice returns slice i's network name, subnet and gateway.
func sliceNet(i int) (name, subnet, gw string) {
	b := netip.MustParsePrefix("10.213.0.0/16").Addr().As4()
	n := binary.BigEndian.Uint32(b[:]) + uint32(i)<<6
	return "s" + strconv.Itoa(i), addr4(n).String() + "/26", addr4(n + 1).String()
}

// writeTable writes the proxy's table in Marshal's form, by rename, readable by
// the proxy's user.
func (r *reach) writeTable(tb Table) {
	r.t.Helper()
	b, err := tb.Marshal()
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := ParseTable(b); err != nil {
		r.t.Fatal(err)
	}
	tmp := filepath.Join(r.dir, "table", ".new")
	if err := os.WriteFile(tmp, b, 0o444); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(r.dir, "table", "pgcap.json")); err != nil {
		r.t.Fatal(err)
	}
	r.tb = tb
	time.Sleep(2500 * time.Millisecond) // the proxy looks at the file every second
}

// defaultTable is the dashboard's class at its figures, its peers the two
// clients, with slices 3, 7 and 9.
func defaultTable() Table {
	tb, err := ParseTable([]byte(metaJSON(`{"3":{"meta":5},"7":{"meta":5},"9":{"meta":5}}`)))
	if err != nil {
		panic(err)
	}
	// The node's defaults: a pool of both instances' connections, the ceiling
	// that covers it, and a burst of two pages' worth refilled at one a second.
	tb.MaxConns, tb.Classes[0].RefusalsMax = 80, 32
	tb.Classes[0].ConnsPerSecond, tb.Classes[0].ConnsBurst = 30, 60
	return tb
}

// proxy starts the proxy's container on the platform network and attaches it at
// the proxy's address of each slice given.
func (r *reach) proxy(slices ...int) {
	r.rm("proxy")
	r.docker("run", "-d", "--name", scratch+"proxy", "--label", "supapace.test=1", "--network", scratch+"plat", "--ip", proxyIP,
		"--memory", "64m", "--memory-swap", "64m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"-v", filepath.Join(r.dir, "table")+":/etc/pgcap:ro", proxyImage)
	for _, i := range slices {
		name, _, _ := sliceNet(i)
		from, _ := sliceAddrs(&r.tb, i)
		r.docker("network", "connect", "--ip", from.String(), scratch+name, scratch+"proxy")
	}
}

// client (re)starts a postgres-meta instance at ip whose connection string
// names the proxy's port of slice i, with query appended to the string.
func (r *reach) client(name, ip string, i int, query string) {
	r.rm(name)
	url := fmt.Sprintf("postgresql://postgres:%s@%s:%d/postgres%s", r.password, proxyIP, 20000+i, query)
	r.docker("run", "-d", "--name", scratch+name, "--label", "supapace.test=1", "--network", scratch+"plat", "--ip", ip,
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-e", "PG_META_PORT=8080", "-e", "PG_META_DB_URL="+url, pgMetaImage)
	hc := &http.Client{Timeout: 5 * time.Second}
	for deadline := time.Now().Add(120 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		if resp, err := hc.Get("http://" + ip + ":8080/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("postgres-meta at %s did not become healthy", ip)
		}
	}
}

// query posts one statement to the postgres-meta instance at ip.
func query1(ip, sql string) (int, string, time.Duration) {
	t0 := time.Now()
	b, _ := json.Marshal(map[string]string{"query": sql})
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Post("http://"+ip+":8080/query", "application/json", bytes.NewReader(b))
	if err != nil {
		return 0, err.Error(), time.Since(t0)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body), time.Since(t0)
}

// fake (re)starts the fake backend at slice 9's cluster address in mode.
func (r *reach) fake(mode string) {
	r.rm("fake")
	os.Remove(filepath.Join(r.dir, "fake", "log"))
	_, to := sliceAddrs(&r.tb, 9)
	args := []string{"run", "-d", "--name", scratch + "fake", "--label", "supapace.test=1", "--network", scratch + "s9", "--ip", to.Addr().String(),
		"--user", "0", "-v", probeBin + ":/sp-probe:ro", "-v", filepath.Join(r.dir, "fake") + ":/fake", "--entrypoint", "/sp-probe", proxyImage,
		"fakepg", "--listen", to.String(), "--log", "/fake/log", "--mode", mode}
	if saltModes(mode) {
		args = append(args, "--salt", hex.EncodeToString(r.salt))
	}
	if postAuthMode(mode) {
		args = append(args, "--password-file", "/fake/pw")
	}
	r.docker(args...)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if strings.Contains(r.docker("logs", scratch+"fake"), "listening") {
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("the fake backend did not start: %s", r.docker("logs", scratch+"fake"))
		}
	}
}

func postAuthMode(m string) bool {
	return m == "escapes" || m == "rows-endless" || m == "copy-both" || m == "param-flood"
}
func saltModes(m string) bool { return postAuthMode(m) || m == "sasl-iter" || m == "scram-low" }

// proxyLog is what the proxy logged since t0.
func (r *reach) proxyLog(t0 time.Time) string {
	out, errOut, _ := dockerx.RunOutput(r.ctx, "logs", "--since", t0.Format(time.RFC3339Nano), scratch+"proxy")
	return out + errOut
}

// memory reads the proxy container's cgroup: memory.current and the socket
// buffers' share of it.
func (r *reach) memory() (current, sock int64) {
	r.t.Helper()
	id := r.docker("inspect", "-f", "{{.Id}}", scratch+"proxy")
	for _, pat := range []string{"/sys/fs/cgroup/docker/" + id, "/sys/fs/cgroup/system.slice/docker-" + id + ".scope", "/sys/fs/cgroup/*/docker/" + id} {
		ms, _ := filepath.Glob(pat)
		for _, d := range ms {
			b, err := os.ReadFile(filepath.Join(d, "memory.current"))
			if err != nil {
				continue
			}
			current, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
			st, _ := os.ReadFile(filepath.Join(d, "memory.stat"))
			for _, l := range strings.Split(string(st), "\n") {
				if v, ok := strings.CutPrefix(l, "sock "); ok {
					sock, _ = strconv.ParseInt(v, 10, 64)
				}
			}
			return current, sock
		}
	}
	r.t.Fatalf("no cgroup for the proxy's container %s", id)
	return 0, 0
}

func TestRelay_RealClientLibrary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	r := &reach{t: t, ctx: ctx, dir: t.TempDir(), password: rand.Text(), salt: make([]byte, 16), tb: defaultTable()}
	rand.Read(r.salt)
	for _, d := range []string{"table", "fake"} {
		if err := os.MkdirAll(filepath.Join(r.dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.Chmod(r.dir, 0o755)
	if err := os.WriteFile(filepath.Join(r.dir, "fake", "pw"), []byte(r.password), 0o644); err != nil {
		t.Fatal(err)
	}
	r.network("plat", platNet, "10.212.0.1")
	for _, i := range []int{3, 7, 9} {
		r.network(sliceNet(i))
	}
	// Registered after the networks' cleanups, so it runs before them.
	t.Cleanup(func() { r.rm("proxy", "pgmeta-a", "pgmeta-b", "cluster", "fake") })

	// The cluster at slice 3, the platform's image, its password set for the
	// client's role (the image keeps a SCRAM verifier, 4,096 iterations).
	images, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	_, cl := sliceAddrs(&r.tb, 3)
	r.rm("cluster")
	r.docker("run", "-d", "--name", scratch+"cluster", "--label", "supapace.test=1", "--network", scratch+"s3", "--ip", cl.Addr().String(),
		"-e", "POSTGRES_PASSWORD="+r.password, images.Postgres)
	psql := func(sql string) string {
		out, err := dockerx.Run(ctx, "exec", scratch+"cluster", "psql", "-U", "supabase_admin", "-h", "127.0.0.1", "-d", "postgres", "-tAc", sql)
		if err != nil {
			return "error: " + err.Error()
		}
		return strings.TrimSpace(out)
	}
	for deadline := time.Now().Add(5 * time.Minute); psql("select 1") != "1"; time.Sleep(2 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("the cluster did not start: %s", r.docker("logs", "--tail", "30", scratch+"cluster"))
		}
	}
	time.Sleep(5 * time.Second) // past the image's own first restart, if it has one
	for psql("select 1") != "1" {
		time.Sleep(time.Second)
	}
	if got := psql("alter role postgres with login password '" + r.password + "'"); got != "ALTER ROLE" {
		t.Fatalf("set the password: %s", got)
	}

	r.writeTable(defaultTable())
	r.proxy(3, 7, 9)
	r.client("pgmeta-a", clientA, 3, "")

	t.Run("a statement returns its rows", func(t *testing.T) {
		status, body, _ := query1(clientA, "select 1 as n")
		t.Logf("answer %d: %s", status, body)
		if status != 200 || !strings.Contains(body, `"n":1`) {
			t.Fatalf("answer %d %s", status, body)
		}
	})
	t.Run("statements per connection", func(t *testing.T) {
		pids := map[string]int{}
		for range 10 {
			_, body, _ := query1(clientA, "select pg_backend_pid() as pid")
			pids[body]++
		}
		t.Logf("ten statements in a row were served by %d connections: %v", len(pids), pids)
	})
	// A page's worth — thirty statements in two seconds, five at a time — with
	// the default table, then with its rate out of the way and with its
	// allowance out of the way, so that a refusal is put down to its cause.
	page := func(t *testing.T) map[int]int {
		var mu sync.Mutex
		statuses := map[int]int{}
		t0 := time.Now()
		for wave := range 6 {
			var wg sync.WaitGroup
			for range 5 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					status, _, _ := query1(clientA, "select pg_sleep(0.05), 1 as n")
					mu.Lock()
					statuses[status]++
					mu.Unlock()
				}()
			}
			wg.Wait()
			time.Sleep(time.Until(t0.Add(time.Duration(wave+1) * 333 * time.Millisecond)))
		}
		time.Sleep(time.Second)
		t.Logf("thirty statements in %v: answers %v; proxy: %s", time.Since(t0), statuses, strings.TrimSpace(r.proxyLog(t0)))
		return statuses
	}
	t.Run("a page's worth is not refused by the default rate", func(t *testing.T) {
		for _, c := range []struct {
			name string
			edit func(*Table)
		}{
			{"the rate out of the way", func(tb *Table) { tb.Classes[0].ConnsPerSecond, tb.Classes[0].ConnsBurst = 1000, 1000 }},
			{"the allowance out of the way", func(tb *Table) { tb.Slices["3"]["meta"] = 16 }},
		} {
			tb := defaultTable()
			c.edit(&tb)
			r.writeTable(tb)
			t.Logf("%s:", c.name)
			page(t)
		}
		r.writeTable(defaultTable())
		time.Sleep(time.Second) // a full bucket
		if statuses := page(t); statuses[200] != 30 {
			t.Errorf("the default table refused part of a page's worth: %v", statuses)
		}
	})
	t.Run("the client's pooling", func(t *testing.T) {
		ip, _ := sliceAddrs(&r.tb, 3)
		count := func() string {
			return psql("select count(*) from pg_stat_activity where client_addr = '" + ip.String() + "'")
		}
		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() { defer wg.Done(); query1(clientA, "select pg_sleep(0.5), 1 as n") }()
		}
		wg.Wait()
		t.Logf("after five statements at once, the cluster has %s connections from the proxy", count())
		time.Sleep(10 * time.Second)
		t.Logf("10 s after the last statement: %s (one project of one instance; the proxy's own count of the slice: see its table)", count())
	})
	t.Run("the per-project cap reached", func(t *testing.T) {
		tb := defaultTable()
		tb.Slices["3"]["meta"] = 1
		r.writeTable(tb)
		defer r.writeTable(defaultTable())
		answers := parallel(clientA, "select pg_sleep(2), 1 as n", 3)
		t.Logf("three statements at once with an allowance of one: %q", answers)
	})
	t.Run("the rate exceeded", func(t *testing.T) {
		tb := defaultTable()
		tb.Classes[0].ConnsPerSecond, tb.Classes[0].ConnsBurst = 1, 1
		r.writeTable(tb)
		defer r.writeTable(defaultTable())
		answers := parallel(clientA, "select pg_sleep(1), 1 as n", 4)
		t.Logf("four statements at once at a rate of one a second: %q", answers)
	})
	t.Run("the dial fails", func(t *testing.T) {
		r.client("pgmeta-b", clientB, 7, "")
		status, body, d := query1(clientB, "select 1")
		t.Logf("nothing at the cluster's address: answer %d after %v: %s", status, d, body)
		t.Logf("proxy: %s", r.proxyLog(time.Now().Add(-d-time.Second)))
	})
	t.Run("the startup the client sends", func(t *testing.T) {
		r.fake("escapes")
		r.client("pgmeta-b", clientB, 9, "")
		status, body, _ := query1(clientB, "select 1")
		t.Logf("answer %d: %.200s", status, body)
		first, params, encryption := clientStartup(t, filepath.Join(r.dir, "fake", "log"))
		t.Logf("one statement: %d connections reached the fake", fakeConns(t, filepath.Join(r.dir, "fake", "log")))
		t.Logf("encryption requests before it: %d; protocol code %d; parameters %q", encryption, first, params)
		if first != 196608 || strings.Contains(params, "_pq_.") {
			t.Fatalf("the client asked for protocol code %d with parameters %q: want 3.0 and no protocol option", first, params)
		}
	})
	t.Run("the encryption answer N", func(t *testing.T) {
		r.fake("escapes")
		r.client("pgmeta-b", clientB, 9, "?sslmode=prefer")
		status, body, _ := query1(clientB, "select 1")
		_, _, encryption := clientStartup(t, filepath.Join(r.dir, "fake", "log"))
		t.Logf("with sslmode=prefer: %d encryption requests reached the fake; answer %d: %.300s", encryption, status, body)
	})
	t.Run("hostile modes against the built image", func(t *testing.T) {
		for _, c := range []struct{ mode, reason string }{
			{"authok", "authentication request 0 refused"},
			{"sasl-iter", "SCRAM iteration count 10000000 outside"},
			{"scram-low", "SCRAM iteration count 1024 outside"},
			{"copy-both", "copy-both refused by the class"},
			{"param-flood", "parameter-status messages over the cap"}, // the first response may answer the statement
			{"stall", ""}, // the client gives up first or the authentication deadline ends it
		} {
			r.fake(c.mode)
			r.client("pgmeta-b", clientB, 9, "")
			t0 := time.Now()
			status, body, d := query1(clientB, "select 1")
			time.Sleep(time.Second)
			log := r.proxyLog(t0.Add(-time.Second))
			t.Logf("%s: answer %d after %v: %.300s; proxy: %s", c.mode, status, d, body, strings.TrimSpace(log))
			if status == 200 && c.mode != "param-flood" || c.reason != "" && !strings.Contains(log, c.reason) {
				t.Errorf("%s: answer %d, proxy log %q: want an error and %q", c.mode, status, log, c.reason)
			}
		}
	})
	t.Run("memory", func(t *testing.T) { r.memoryProof(t) })
}

// parallel posts n statements at once and returns their answers.
func parallel(ip, sql string, n int) []string {
	var mu sync.Mutex
	var out []string
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, body, d := query1(ip, sql)
			mu.Lock()
			out = append(out, fmt.Sprintf("%d after %v: %.200s", status, d.Round(time.Millisecond), body))
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// clientStartup reads the fake's log and returns the protocol code and the
// parameters of the first connection's startup packet, and how many encryption
// requests came before it.
func clientStartup(t *testing.T, logFile string) (code uint32, params string, encryption int) {
	t.Helper()
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	var s []byte
	for len(raw) > 0 {
		head, rest, _ := bytes.Cut(raw, []byte("\n"))
		var n, size int
		if _, err := fmt.Sscanf(string(head), "conn %d %d", &n, &size); err != nil || size > len(rest) {
			t.Fatalf("bad log record %q", head)
		}
		if n == 1 {
			s = append(s, rest[:size]...)
		}
		raw = rest[size:]
	}
	for len(s) >= 8 {
		size := int(binary.BigEndian.Uint32(s))
		code = binary.BigEndian.Uint32(s[4:8])
		if size < 8 || size > len(s) {
			t.Fatalf("startup length %d", size)
		}
		if size == 8 && (code == 80877103 || code == 80877104) {
			encryption++
			s = s[8:]
			continue
		}
		params = strings.ReplaceAll(string(s[8:size]), "\x00", " ")
		return code, params, encryption
	}
	return 0, "", encryption
}

// memoryProof re-creates the proxy with 1,024 slices in its table and two
// peer addresses the test owns, measures it idle, then holds 32 connections
// whose client reads nothing while the cluster streams, and 32 silent sockets
// in the preamble — 64 of the 80 units — and measures it again. A cancel to a
// live cluster ends at once and is not held here; the rule counts each at a
// connection's figure.
func (r *reach) memoryProof(t *testing.T) {
	plat := r.docker("network", "inspect", "-f", "{{.Id}}", scratch+"plat")
	dev := "br-" + plat[:12]
	peers := []string{"10.212.0.7", "10.212.0.8"}
	for _, p := range peers {
		if out, err := nodeCmd(r.ctx, "ip", "addr", "add", p+"/32", "dev", dev); err != nil {
			t.Fatalf("add %s: %v %s", p, err, out)
		}
		t.Cleanup(func() { nodeCmd(context.Background(), "ip", "addr", "del", p+"/32", "dev", dev) })
	}
	tb := defaultTable()
	tb.Classes[0].Peers = []netip.Addr{netip.MustParseAddr(peers[0]), netip.MustParseAddr(peers[1])}
	tb.PreambleMS = 60000
	tb.Slices = map[string]map[string]int{}
	for i := range 1024 {
		tb.Slices[strconv.Itoa(i)] = map[string]int{"meta": 5}
	}
	tb.Slices["9"]["meta"] = 32 // every connection of the measurement goes to the fake
	tb.Classes[0].ConnsPerSecond, tb.Classes[0].ConnsBurst = 1000, 1000
	r.writeTable(tb)
	r.proxy(9)
	time.Sleep(3 * time.Second)
	idle, idleSock := r.memory()
	t.Logf("1,024 slices in the table, idle: memory.current %d KiB, of it socket buffers %d KiB", idle>>10, idleSock>>10)

	r.fake("rows-endless")
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for n := range 32 {
		cfg, err := pgconn.ParseConfig(fmt.Sprintf("postgres://postgres:%s@%s:%d/postgres?sslmode=disable", r.password, proxyIP, 20009))
		if err != nil {
			t.Fatal(err)
		}
		cfg.DialFunc = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(peers[n%2])}}).DialContext
		pc, err := pgconn.ConnectConfig(r.ctx, cfg)
		if err != nil {
			t.Fatalf("connection %d: %v", n, err)
		}
		c := pc.Conn()
		c.Write(append([]byte{'Q'}, append(binary.BigEndian.AppendUint32(nil, 4+9), "select 1\x00"...)...))
		conns = append(conns, c) // never read: the buffers fill
	}
	for n := range 32 {
		c, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(peers[n%2])}}).Dial("tcp4", net.JoinHostPort(proxyIP, strconv.Itoa(20000+100+n)))
		if err != nil {
			t.Fatalf("silent socket %d: %v", n, err)
		}
		conns = append(conns, c)
	}
	time.Sleep(5 * time.Second) // the streams fill every buffer on the way
	full, fullSock := r.memory()
	figure := int64(32+16)*r.tb.Classes[0].ConnBytes() + 32*r.tb.Classes[0].ConnBytes()/2
	t.Logf("32 stalled streams and 32 silent sockets: memory.current %d KiB, of it socket buffers %d KiB; "+
		"the rule's figure for every term at the ceiling %d KiB plus 16 MiB fixed, within 80 %% of 64 MiB (%d KiB)",
		full>>10, fullSock>>10, figure>>10, 64<<10*8/10)
	if full > 64<<20*8/10 {
		t.Fatalf("memory.current %d bytes over 80 %% of the limit", full)
	}
	extra, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(peers[0])}}).Dial("tcp4", net.JoinHostPort(proxyIP, strconv.Itoa(20000+200)))
	if err == nil {
		extra.SetDeadline(time.Now().Add(10 * time.Second))
		b, err := io.ReadAll(extra)
		t.Logf("a socket over the class's pool: %d bytes, %v", len(b), err)
		extra.Close()
	}
}

// nodeCmd runs a command of the node.
func nodeCmd(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// fakeConns counts the connections in the fake's log.
func fakeConns(t *testing.T, logFile string) int {
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for len(raw) > 0 {
		head, rest, _ := bytes.Cut(raw, []byte("\n"))
		var n, size int
		if _, err := fmt.Sscanf(string(head), "conn %d %d", &n, &size); err != nil || size > len(rest) {
			t.Fatalf("bad log record %q", head)
		}
		seen[n] = true
		raw = rest[size:]
	}
	return len(seen)
}
