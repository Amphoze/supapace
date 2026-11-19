package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashsock"
	"github.com/Amphoze/supapace/internal/dashtok"
)

// A second set of vectors, made with openssl enc -aes-256-cbc -md md5 under a
// passphrase with non-ASCII and URL-ish characters: a plaintext of exactly two
// blocks (a whole block of padding follows), one of exactly one block, and an
// empty one.
func TestPgMetaStub_SecondVectors(t *testing.T) {
	key := "pässphrase with spaces+/=é"
	for plain, ct := range map[string]string{
		"postgresql://u:pw@h:5/abcdefghij": "U2FsdGVkX18uXGJxs9owVuCruectLw3ZvYoDItOL3tYj57291fJ/qYA1iIYS90KmG3TCp6DIUnCqhyXtzWmAWw==",
		"0123456789abcdef":                 "U2FsdGVkX1/jHxY56nxxU9+U2Iv2R/pX1X0vcZRCDNvhlx70/2BMcSmkgBf+d0xA",
		"":                                 "U2FsdGVkX18iAkUR4Dwn3TmdZuxEWpA1JPEPzh7rF1c=",
	} {
		if got, err := decryptHeader([]byte(key), ct); err != nil || got != plain {
			t.Errorf("decrypt %q = %q, %v", plain, got, err)
		}
		// Control: the wrong passphrase never yields the plaintext.
		if got, err := decryptHeader([]byte(key+"x"), ct); err == nil && got == plain {
			t.Errorf("wrong key decrypted %q", plain)
		}
	}
}

func FuzzDecryptHeader(f *testing.F) {
	f.Add("U2FsdGVkX18iAkUR4Dwn3TmdZuxEWpA1JPEPzh7rF1c=")
	f.Add("")
	f.Add("U2FsdGVkX1")
	f.Fuzz(func(t *testing.T, h string) {
		decryptHeader([]byte("k"), h) // must not panic
	})
}

// The server refuses a client that never finishes its header, and keeps one
// that finishes it within the bound.
func TestSocketStub_HeaderReadTimeout(t *testing.T) {
	h := startSocket(t, stubTable())
	dial := func() net.Conn {
		c, err := net.Dial("unix", h.sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	tok := h.assertion(dashtok.Assertion{Sub: "u-owner", Ref: refA, Role: "owner"})
	full := "POST /v1/keys HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n" + dashsock.HeaderAssertion + ": " + tok + "\r\n\r\n"
	// Control: a header finished after a second is answered.
	c := dial()
	io.WriteString(c, full[:20])
	time.Sleep(time.Second)
	io.WriteString(c, full[20:])
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(io.LimitReader(c, 12))
	if !strings.HasPrefix(string(b), "HTTP/1.1 200") {
		t.Fatalf("slow but in-bound header: %q", b)
	}
	// A header that stops short is closed by the server well before the client gives up.
	c = dial()
	io.WriteString(c, full[:len(full)-2])
	start := time.Now()
	c.SetReadDeadline(start.Add(8 * time.Second))
	_, err := io.Copy(io.Discard, c)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server held a half header for %v", time.Since(start))
	}
	if d := time.Since(start); d < time.Second || d > 6*time.Second {
		t.Fatalf("closed after %v, want about 2 s", d)
	}
}

// A client that leaves ends the delay: the handler returns, so the server is
// not held up.
func TestPgMetaStub_DelayEndsWhenClientLeaves(t *testing.T) {
	f := loadCrypto(t)
	dir := t.TempDir()
	write(t, filepath.Join(dir, "k"), f.Key)
	s, _, err := newPgMetaStub([]string{"--listen", "x", "--crypto-key-file", filepath.Join(dir, "k"), "--delay-ms", "60000"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/query", strings.NewReader("{}"))
	req.Header.Set("x-connection-encrypted", f.Ciphertext)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("answered before the delay")
	}
	start := time.Now()
	srv.Close() // waits for handlers: returns at once only if the delay was cut short
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("handler still held after the client left: %v", d)
	}
}

// RED until the stub orders a refusal mode as the socket does: a refusal of
// check 3, 4 or 5 or a store failure comes after check 2, so a request with no
// valid assertion is 401 whatever the mode. (peer, check 1, has no stub check and
// stays first.)
func TestSocketStub_RefuseModeAfterAssertion(t *testing.T) {
	for _, code := range []string{"rate_limited", "not_here", "not_a_member", "unavailable"} {
		h := startSocket(t, stubTable(), "--mode", "refuse:"+code)
		st, body := h.do("POST", "/v1/resolve", "", "")
		wantCode(t, code+" without an assertion", st, body, 401, "bad_assertion")
	}
	h := startSocket(t, stubTable(), "--mode", "refuse:peer")
	st, body := h.do("POST", "/v1/resolve", "", "")
	wantCode(t, "peer without an assertion", st, body, 403, "peer")
}

// seal encrypts whole blocks as they are, with no padding added, under the
// salted MD5 format, so that a test can write any padding it likes.
func seal(passphrase string, blocks []byte) string {
	salt := []byte("saltsalt")
	var kiv, prev []byte
	for len(kiv) < 48 {
		d := md5.Sum(append(append(append([]byte{}, prev...), passphrase...), salt...))
		prev = d[:]
		kiv = append(kiv, prev...)
	}
	b, _ := aes.NewCipher(kiv[:32])
	ct := make([]byte, len(blocks))
	cipher.NewCBCEncrypter(b, kiv[32:48]).CryptBlocks(ct, blocks)
	return base64.StdEncoding.EncodeToString(append(append([]byte("Salted__"), salt...), ct...))
}

func TestPgMetaStub_PaddingEdges(t *testing.T) {
	blk := func(tail ...byte) []byte {
		return append(bytes.Repeat([]byte("x"), 16-len(tail)), tail...)
	}
	for name, c := range map[string]struct {
		blocks []byte
		want   string
		ok     bool
	}{
		"one byte of padding":      {blk('a', 1), "xxxxxxxxxxxxxxa", true},
		"a whole block of padding": {bytes.Repeat([]byte{16}, 16), "", true},
		"padding byte zero":        {blk('a', 0), "", false},
		"padding byte 17":          {append(bytes.Repeat([]byte("y"), 15), 17), "", false},
		"padding byte 255":         {append(bytes.Repeat([]byte("y"), 15), 255), "", false},
		"padding run disagrees":    {blk(3, 2, 3), "", false},
		"padding run too short":    {blk(2, 2, 3), "", false},
	} {
		got, err := decryptHeader([]byte("k"), seal("k", c.blocks))
		if (err == nil) != c.ok || (c.ok && got != c.want) {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

// A restarted stub keeps the lines of the run before it.
func TestSocketStub_LogSurvivesRestart(t *testing.T) {
	h := startSocket(t, stubTable())
	h.post("/v1/resolve", "u-owner", "owner", "")
	args := []string{"--listen", h.sock, "--public", filepath.Join(h.dir, "assert.pub"),
		"--node", node1, "--table", filepath.Join(h.dir, "table.json")}
	s, _, err := newSocketStub(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	s.write(socketLogLine{Path: "/v1/keys", Status: 1})
	s.log.Close()
	if got := h.logLines(); len(got) != 2 || got[0].Status != 200 {
		t.Fatalf("log after restart: %+v", got)
	}
}
