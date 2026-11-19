package main

// sp-dashstub pgmeta --listen ADDR --crypto-key-file FILE [--delay-ms N] [--size BYTES] [--status CODE]
//
// A stand-in for postgres-meta's /query and /generators/typescript: it
// decrypts the x-connection-encrypted header and answers
// [{"login":…,"port":…,"n":…}] for the connection string it was handed,
// padded with spaces to --size bytes. GET /_seen lists the last 1,000
// requests it received, oldest first.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() { subcommands["pgmeta"] = pgmeta }

const seenMax = 1000

type seenRequest struct {
	N         int                 `json:"n"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Headers   map[string][]string `json:"headers"` // names in lower case
	BodyBytes int                 `json:"body_bytes"`
}

type pgmetaStub struct {
	key          []byte
	delay        time.Duration
	size, status int
	mu           sync.Mutex
	n            int
	seen         []seenRequest
}

func pgmeta(args []string, stdout, stderr io.Writer) int {
	s, addr, err := newPgMetaStub(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "sp-dashstub pgmeta:", err)
		fmt.Fprintln(stderr, "usage: sp-dashstub pgmeta --listen ADDR --crypto-key-file FILE [--delay-ms N] [--size BYTES] [--status CODE]")
		return 2
	}
	srv := &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintln(stderr, "sp-dashstub pgmeta: serving", addr)
	fmt.Fprintln(stderr, "sp-dashstub pgmeta:", srv.ListenAndServe())
	return 1
}

func newPgMetaStub(args []string, stderr io.Writer) (*pgmetaStub, string, error) {
	fl := flag.NewFlagSet("pgmeta", flag.ContinueOnError)
	fl.SetOutput(stderr)
	listen := fl.String("listen", "", "TCP address")
	keyFile := fl.String("crypto-key-file", "", "the header encryption key file")
	delay := fl.Int("delay-ms", 0, "milliseconds before each answer")
	size := fl.Int("size", 0, "pad each answer to this many bytes")
	status := fl.Int("status", 200, "status of each answer")
	if err := fl.Parse(args); err != nil {
		return nil, "", err
	}
	if fl.NArg() > 0 || *listen == "" || *keyFile == "" {
		return nil, "", errors.New("--listen and --crypto-key-file are required, and nothing else")
	}
	if *delay < 0 || *size < 0 || *status < 100 || *status > 599 {
		return nil, "", errors.New("--delay-ms and --size must be >= 0, --status 100 to 599")
	}
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		return nil, "", err
	}
	// The key is the file's bytes as they are, a line end included.
	key := b
	if len(key) == 0 {
		return nil, "", fmt.Errorf("%s: empty key", *keyFile)
	}
	return &pgmetaStub{key: key, delay: time.Duration(*delay) * time.Millisecond, size: *size, status: *status}, *listen, nil
}

func (s *pgmetaStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/_seen" {
		s.mu.Lock()
		b, _ := json.Marshal(s.seen)
		s.mu.Unlock()
		w.Write(b)
		return
	}
	body, _ := io.Copy(io.Discard, r.Body)
	h := map[string][]string{}
	for k, v := range r.Header {
		h[strings.ToLower(k)] = v
	}
	s.mu.Lock()
	s.n++
	n := s.n
	s.seen = append(s.seen, seenRequest{N: n, Method: r.Method, Path: r.URL.Path, Headers: h, BodyBytes: int(body)})
	if len(s.seen) > seenMax {
		s.seen = slices.Clone(s.seen[len(s.seen)-seenMax:])
	}
	s.mu.Unlock()

	if r.URL.Path != "/query" && r.URL.Path != "/generators/typescript" {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	dsn, err := decryptHeader(s.key, r.Header.Get("x-connection-encrypted"))
	var u *url.URL
	var port int
	if err == nil {
		if u, err = url.Parse(dsn); err == nil {
			port, err = strconv.Atoi(u.Port())
		}
	}
	if err != nil {
		http.Error(w, `{"error":"connection string not readable"}`, 400)
		return
	}
	b, _ := json.Marshal([]struct {
		Login string `json:"login"`
		Port  int    `json:"port"`
		N     int    `json:"n"`
	}{{u.User.Username(), port, n}})
	if pad := s.size - len(b); pad > 0 {
		b = append(b, bytes.Repeat([]byte(" "), pad)...)
	}
	select {
	case <-time.After(s.delay):
	case <-r.Context().Done():
		return
	}
	w.WriteHeader(s.status)
	w.Write(b)
}

// decryptHeader reverses crypto-js's AES.encrypt with a passphrase, the
// function the pinned Studio encrypts the header with: base64 of "Salted__",
// an 8-byte salt and AES-256-CBC ciphertext with PKCS#7 padding, whose key and
// IV are OpenSSL's EVP_BytesToKey over MD5, one round.
func decryptHeader(passphrase []byte, header string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return "", err
	}
	if len(raw) < 32 || string(raw[:8]) != "Salted__" || (len(raw)-16)%aes.BlockSize != 0 {
		return "", errors.New("not a salted ciphertext")
	}
	salt, ct := raw[8:16], raw[16:]
	var kiv, prev []byte
	for len(kiv) < 48 {
		d := md5.Sum(append(append(prev, passphrase...), salt...))
		prev = d[:]
		kiv = append(kiv, prev...)
	}
	block, _ := aes.NewCipher(kiv[:32])
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, kiv[32:48]).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > aes.BlockSize || !bytes.Equal(pt[len(pt)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return "", errors.New("bad padding")
	}
	return string(pt[:len(pt)-pad]), nil
}
