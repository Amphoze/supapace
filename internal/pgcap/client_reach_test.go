//go:build reach

// Bare-node proof, run as root on a node started with `make node-bare` into which
// the dashboard's database client image has been loaded. It records what that
// client does when the server's final SCRAM signature is wrong: the request ends
// in an error, the control with the right signature runs the statement, and the
// messages the server received after the startup packet are logged, so that a
// new image shows any change.
package pgcap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
)

const (
	pgMetaImage = "public.ecr.aws/supabase/postgres-meta:v0.100.0"
	probeBin    = "/opt/supapace/bin/sp-probe"
)

func TestNode_ClientAfterWrongServerSignature(t *testing.T) {
	for _, c := range []struct {
		name, mode string
		control    bool
	}{
		{"wrong signature", "scram-bad-signature", false},
		{"control: right signature", "escapes", true}, // the same exchange; the answer carries a marker
	} {
		t.Run(c.name, func(t *testing.T) {
			status, body, conns := pgMetaAgainstFake(t, c.mode)
			t.Logf("postgres-meta answered %d: %s", status, body)
			exchanges := 0
			for n, types := range conns {
				t.Logf("connection %d: client messages after the startup packet: %q", n, types)
				if strings.Count(types, "p") >= 2 {
					exchanges++
				}
			}
			if exchanges == 0 {
				t.Fatal("no connection completed the client's side of a SCRAM exchange: the proof proves nothing")
			}
			if c.control {
				if !strings.Contains(body, "fake-marker") {
					t.Fatalf("answer %d %q does not carry the server's answer to the statement", status, body)
				}
				return
			}
			if status/100 == 2 || strings.Contains(body, "fake-marker") || !strings.Contains(body, "signature") {
				t.Fatalf("answer %d %q: want an error naming the server signature", status, body)
			}
		})
	}
}

// pgMetaAgainstFake runs the fake backend in mode on a loopback port of this
// namespace and postgres-meta beside it with every capability dropped, posts one
// query, and returns the HTTP answer and, per connection the fake saw, the types
// of the client's messages after its startup packet.
func pgMetaAgainstFake(t *testing.T, mode string) (int, string, map[int]string) {
	dir := t.TempDir()
	password, salt := rand.Text(), make([]byte, 16)
	rand.Read(salt)
	pwFile, logFile := filepath.Join(dir, "pw"), filepath.Join(dir, "log")
	if err := os.WriteFile(pwFile, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := exec.Command(probeBin, "fakepg", "--listen", "127.0.0.1:0", "--log", logFile, "--mode", mode,
		"--password-file", pwFile, "--salt", hex.EncodeToString(salt))
	out, err := fake.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Process.Kill(); fake.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	fakeAddr, ok := strings.CutPrefix(strings.TrimSpace(line), "listening ")
	if err != nil || !ok {
		t.Fatalf("fake: %q %v", line, err)
	}
	go io.Copy(io.Discard, out)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpAddr := l.Addr().String()
	l.Close()
	_, httpPort, _ := net.SplitHostPort(httpAddr)
	name := "sp-test-pgmeta-" + mode
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rm := func() { dockerx.Run(context.Background(), "rm", "-f", "-v", name) }
	rm()
	t.Cleanup(rm)
	if _, err := dockerx.Run(ctx, "run", "-d", "--name", name, "--label", "supapace.test=1",
		"--network", "host", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"-e", "PG_META_HOST=127.0.0.1", "-e", "PG_META_PORT="+httpPort,
		"-e", "PG_META_DB_URL=postgresql://postgres:"+password+"@"+fakeAddr+"/postgres",
		pgMetaImage); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for deadline := time.Now().Add(90 * time.Second); ; {
		r, err := client.Get("http://" + httpAddr + "/health")
		if err == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			logs, _ := dockerx.Run(ctx, "logs", "--tail", "20", name)
			t.Fatalf("postgres-meta did not become healthy: %v\n%s", err, logs)
		}
		time.Sleep(500 * time.Millisecond)
	}
	r, err := client.Post("http://"+httpAddr+"/query", "application/json", strings.NewReader(`{"query":"select 1"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	r.Body.Close()
	rm() // nothing more reaches the fake; its log is complete
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	conns, err := clientMessageTypes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r.StatusCode, string(b), conns
}

// clientMessageTypes reads the fake's log ("conn N LEN" + LEN bytes, repeated)
// and returns, per connection, the type bytes of the messages the client sent
// after its startup packet (8-byte encryption requests before it skipped).
func clientMessageTypes(log []byte) (map[int]string, error) {
	streams := map[int][]byte{}
	for len(log) > 0 {
		head, rest, ok := bytes.Cut(log, []byte("\n"))
		var n, size int
		if _, err := fmt.Sscanf(string(head), "conn %d %d", &n, &size); !ok || err != nil || size > len(rest) {
			return nil, fmt.Errorf("bad log record %q", head)
		}
		streams[n] = append(streams[n], rest[:size]...)
		log = rest[size:]
	}
	out := map[int]string{}
	for n, s := range streams {
		for len(s) >= 8 { // startup packet, after any encryption request
			size := int(binary.BigEndian.Uint32(s))
			if size < 8 || size > len(s) {
				return nil, fmt.Errorf("connection %d: startup length %d", n, size)
			}
			code := binary.BigEndian.Uint32(s[4:8])
			s = s[size:]
			if size != 8 || code != 80877103 && code != 80877104 {
				break
			}
		}
		var types []byte
		for len(s) >= 5 {
			size := int(binary.BigEndian.Uint32(s[1:5]))
			if size < 4 || 1+size > len(s) {
				return nil, fmt.Errorf("connection %d: message %q of length %d", n, s[0], size)
			}
			types = append(types, s[0])
			s = s[1+size:]
		}
		out[n] = string(types)
	}
	return out, nil
}
