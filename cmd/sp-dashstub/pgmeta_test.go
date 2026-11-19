package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// cryptoFixture was made outside Go, in the format the pinned Studio's
// encryptString writes (crypto-js passphrase AES: OpenSSL's salted format with
// an MD5-derived key), by
//
//	printf '%s' "$plaintext" | openssl enc -aes-256-cbc -md md5 -salt -base64 -A -pass "pass:$key"
type cryptoFixture struct {
	Key, Plaintext, Ciphertext string
	NoPortPlaintext            string `json:"no_port_plaintext"`
	NoPortCiphertext           string `json:"no_port_ciphertext"`
}

func loadCrypto(t *testing.T) cryptoFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/crypto.json")
	if err != nil {
		t.Fatal(err)
	}
	var f cryptoFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

type pgmetaHarness struct {
	t   *testing.T
	url string
}

// startPgMeta serves the stub on loopback with the key file holding key and
// extra flags appended.
func startPgMeta(t *testing.T, key string, extra ...string) *pgmetaHarness {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "crypto.key"), key)
	args := append([]string{"--listen", "127.0.0.1:0", "--crypto-key-file", filepath.Join(dir, "crypto.key")}, extra...)
	var errb bytes.Buffer
	s, addr, err := newPgMetaStub(args, &errb)
	if err != nil {
		t.Fatalf("newPgMetaStub: %v (%s)", err, errb.String())
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(s)
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return &pgmetaHarness{t: t, url: srv.URL}
}

func (h *pgmetaHarness) do(method, path, body string, header map[string]string) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.url+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, b
}

func (h *pgmetaHarness) seen() []seenRequest {
	h.t.Helper()
	status, b := h.do("GET", "/_seen", "", nil)
	if status != 200 {
		h.t.Fatalf("/_seen: %d %s", status, b)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out []seenRequest
	if err := dec.Decode(&out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

type metaAnswer struct {
	Login string `json:"login"`
	Port  int    `json:"port"`
	N     int    `json:"n"`
}

func decodeAnswer(t *testing.T, b []byte) metaAnswer {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var a []metaAnswer
	if err := dec.Decode(&a); err != nil || len(a) != 1 {
		t.Fatalf("answer %q: %v", b, err)
	}
	if dec.More() {
		t.Fatalf("answer %q: trailing data", b)
	}
	return a[0]
}

func TestPgMetaStub_DecryptsWhatStudioEncrypts(t *testing.T) {
	f := loadCrypto(t)
	got, err := decryptHeader([]byte(f.Key), f.Ciphertext)
	if err != nil || got != f.Plaintext {
		t.Fatalf("decrypt = %q, %v", got, err)
	}

	h := startPgMeta(t, f.Key)
	hdr := map[string]string{"x-connection-encrypted": f.Ciphertext}
	for i, p := range []string{"/query", "/generators/typescript"} {
		status, b := h.do("POST", p, `{"query":"select 1"}`, hdr)
		if status != 200 {
			t.Fatalf("%s: %d %s", p, status, b)
		}
		if a := decodeAnswer(t, b); a != (metaAnswer{"supabase_read_only_user", 20003, i + 1}) {
			t.Errorf("%s: %+v", p, a)
		}
	}

	// Refused: another key, a changed byte, no salt header, a cut block, no
	// header. The control above used the same paths.
	raw, _ := base64.StdEncoding.DecodeString(f.Ciphertext)
	flip := bytes.Clone(raw)
	flip[len(flip)-1] ^= 0x55
	// The last plaintext byte, a pad of 2, turned into 3 through the block
	// before it: a pad value in range whose bytes disagree.
	badPad := bytes.Clone(raw)
	badPad[len(badPad)-17] ^= 0x01
	noSalt := append([]byte("Unsalted"), raw[8:]...)
	for name, ct := range map[string]string{
		"changed byte":  base64.StdEncoding.EncodeToString(flip),
		"pad bytes":     base64.StdEncoding.EncodeToString(badPad),
		"no salt label": base64.StdEncoding.EncodeToString(noSalt),
		"cut block":     base64.StdEncoding.EncodeToString(raw[:len(raw)-5]),
		"header only":   base64.StdEncoding.EncodeToString(raw[:16]),
		"not base64":    "@@@",
	} {
		if s, err := decryptHeader([]byte(f.Key), ct); err == nil {
			t.Errorf("%s: decrypted to %q", name, s)
		}
	}
	if s, err := decryptHeader([]byte(f.Key[1:]), f.Ciphertext); err == nil && s == f.Plaintext {
		t.Error("another key decrypted the fixture")
	}
	if status, b := h.do("POST", "/query", "", map[string]string{"x-connection-encrypted": base64.StdEncoding.EncodeToString(flip)}); status != 400 {
		t.Errorf("changed byte over HTTP: %d %s", status, b)
	}
	if status, b := h.do("POST", "/query", "", nil); status != 400 {
		t.Errorf("no header: %d %s", status, b)
	}
	// A string that decrypts but names no port is not answered.
	if s, err := decryptHeader([]byte(f.Key), f.NoPortCiphertext); err != nil || s != f.NoPortPlaintext {
		t.Fatalf("no-port fixture: %q, %v", s, err)
	}
	if status, b := h.do("POST", "/query", "", map[string]string{"x-connection-encrypted": f.NoPortCiphertext}); status != 400 {
		t.Errorf("no port: %d %s", status, b)
	}
	// The key file's bytes are the key as they are: a file ending in a line end
	// decrypts only a header encrypted with that line end, and the file
	// without it does not.
	padded := append([]byte(f.Plaintext), bytes.Repeat([]byte{byte(16 - len(f.Plaintext)%16)}, 16-len(f.Plaintext)%16)...)
	withLF := map[string]string{"x-connection-encrypted": seal(f.Key+"\n", padded)}
	hLF := startPgMeta(t, f.Key+"\n")
	if status, b := hLF.do("POST", "/query", "", withLF); status != 200 || decodeAnswer(t, b).Port != 20003 {
		t.Errorf("key with line end, header with line end: %d %s", status, b)
	}
	if status, b := hLF.do("POST", "/query", "", hdr); status != 400 {
		t.Errorf("key with line end, header without: %d %s", status, b)
	}
	if status, b := h.do("POST", "/query", "", withLF); status != 400 {
		t.Errorf("key without line end, header with: %d %s", status, b)
	}
	hOther := startPgMeta(t, "another-key")
	if status, b := hOther.do("POST", "/query", "", hdr); status != 400 {
		t.Errorf("another key over HTTP: %d %s", status, b)
	}
}

func TestPgMetaStub_SeenListsHeadersOldestFirst(t *testing.T) {
	h := startPgMeta(t, "k")
	h.do("POST", "/query", "12345", map[string]string{"X-Probe": "one", "x-connection-encrypted": "a"})
	h.do("GET", "/generators/typescript?included_schemas=public", "", map[string]string{"x-probe": "two"})
	if status, _ := h.do("DELETE", "/elsewhere", "", map[string]string{"X-Probe": "three"}); status != 404 {
		t.Errorf("other path: %d", status)
	}
	seen := h.seen()
	if len(seen) != 3 {
		t.Fatalf("seen = %+v", seen)
	}
	for i, want := range []struct {
		method, path, probe string
		body                int
	}{
		{"POST", "/query", "one", 5},
		{"GET", "/generators/typescript", "two", 0},
		{"DELETE", "/elsewhere", "three", 0},
	} {
		s := seen[i]
		if s.N != i+1 || s.Method != want.method || s.Path != want.path || s.BodyBytes != want.body ||
			!reflect.DeepEqual(s.Headers["x-probe"], []string{want.probe}) {
			t.Errorf("seen[%d] = %+v, want %+v", i, s, want)
		}
	}
	if !reflect.DeepEqual(seen[0].Headers["x-connection-encrypted"], []string{"a"}) {
		t.Errorf("seen[0] headers = %v", seen[0].Headers)
	}
	// /_seen itself is not recorded.
	if len(h.seen()) != 3 {
		t.Fatal("/_seen recorded itself")
	}

	// At most the last 1,000, oldest first.
	for range 1000 {
		h.do("GET", "/query", "", nil)
	}
	seen = h.seen()
	if len(seen) != 1000 || seen[0].N != 4 || seen[999].N != 1003 {
		t.Fatalf("after 1003 requests: %d kept, first %d, last %d", len(seen), seen[0].N, seen[len(seen)-1].N)
	}
}

func TestPgMetaStub_DelaySizeStatus(t *testing.T) {
	f := loadCrypto(t)
	hdr := map[string]string{"x-connection-encrypted": f.Ciphertext}

	h := startPgMeta(t, f.Key, "--delay-ms", "300", "--size", "4096", "--status", "503")
	start := time.Now()
	status, b := h.do("POST", "/query", "", hdr)
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Errorf("answered after %v, want at least 300ms", el)
	}
	if status != 503 || len(b) != 4096 {
		t.Errorf("status %d, %d bytes", status, len(b))
	}
	if a := decodeAnswer(t, b); a.Login != "supabase_read_only_user" || a.N != 1 {
		t.Errorf("padded answer = %+v", a)
	}

	// A size below the answer's length leaves it whole; the defaults are 200
	// and no padding.
	h2 := startPgMeta(t, f.Key, "--size", "10")
	status, b = h2.do("POST", "/query", "", hdr)
	want := fmt.Sprintf(`[{"login":"supabase_read_only_user","port":20003,"n":1}]`)
	if status != 200 || string(b) != want {
		t.Errorf("small size: %d %q", status, b)
	}
	h3 := startPgMeta(t, f.Key)
	if status, b = h3.do("POST", "/query", "", hdr); status != 200 || string(b) != want {
		t.Errorf("defaults: %d %q", status, b)
	}
}

func TestPgMetaStub_Usage(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "k"), "key")
	write(t, filepath.Join(dir, "empty"), "")
	base := []string{"pgmeta", "--listen", "127.0.0.1:0", "--crypto-key-file", filepath.Join(dir, "k")}
	for name, args := range map[string][]string{
		"no flags":       {"pgmeta"},
		"no key file":    {"pgmeta", "--listen", "127.0.0.1:0"},
		"no listen":      {"pgmeta", "--crypto-key-file", filepath.Join(dir, "k")},
		"absent key":     {"pgmeta", "--listen", "127.0.0.1:0", "--crypto-key-file", filepath.Join(dir, "absent")},
		"empty key":      {"pgmeta", "--listen", "127.0.0.1:0", "--crypto-key-file", filepath.Join(dir, "empty")},
		"negative delay": append(base, "--delay-ms", "-1"),
		"negative size":  append(base, "--size", "-1"),
		"status 99":      append(base, "--status", "99"),
		"status 600":     append(base, "--status", "600"),
		"extra argument": append(base, "x"),
	} {
		if _, _, err := newPgMetaStub(args[1:], io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if code, out, errs := runOut("pgmeta", "--size", "-1"); code != 2 || out != "" || !strings.Contains(errs, "usage") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	// Control: the same flags parse.
	var errb bytes.Buffer
	if _, _, err := newPgMetaStub(base[1:], &errb); err != nil {
		t.Fatalf("control: %v %s", err, errb.String())
	}
}
