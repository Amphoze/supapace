package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	refA = "aaaaaaaaaaaaaaaaaaaa"
	refB = "bbbbbbbbbbbbbbbbbbbb"
)

// asOwner lets LoadKEK accept files owned by the test user instead of root.
func asOwner(t *testing.T) {
	t.Helper()
	old := kekOwner
	kekOwner = os.Getuid()
	t.Cleanup(func() { kekOwner = old })
}

func testDEK(t *testing.T) []byte {
	t.Helper()
	return bytes.Repeat([]byte{0x5a}, 32)
}

// rawOpen decrypts with plain AES-256-GCM and an explicit AAD.
func rawOpen(t *testing.T, key, aad, nonce, ct []byte) []byte {
	t.Helper()
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	return p
}

func TestGenerateKEK_ModeAndExclusive(t *testing.T) {
	asOwner(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "kek")
	k, err := GenerateKEK(path)
	if err != nil {
		t.Fatal(err)
	}
	if k == (KEK{}) {
		t.Fatal("zero KEK")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != 0o400 || fi.Size() != 32 {
		t.Fatalf("mode %v size %d", fi.Mode(), fi.Size())
	}
	onlyEntry(t, dir, "kek")
	if _, err := GenerateKEK(path); err == nil {
		t.Fatal("second GenerateKEK on the same path succeeded")
	}
	onlyEntry(t, dir, "kek")
	got, err := LoadKEK(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Fatal("loaded KEK differs from generated KEK")
	}
}

func writeKEK(t *testing.T, b []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadKEK_RejectsLooseMode(t *testing.T) {
	asOwner(t)
	key := bytes.Repeat([]byte{1}, 32)
	for _, m := range []os.FileMode{0o440, 0o404, 0o600, 0o444, 0o500} {
		if _, err := LoadKEK(writeKEK(t, key, m)); err == nil {
			t.Errorf("mode %o accepted", m)
		}
	}
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := LoadKEK(writeKEK(t, bytes.Repeat([]byte{1}, n), 0o400)); err == nil {
			t.Errorf("size %d accepted", n)
		}
	}
	// A symlink to a valid KEK is refused.
	good := writeKEK(t, key, 0o400)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKEK(link); err == nil {
		t.Error("symlink accepted")
	}
	if _, err := LoadKEK(good); err != nil {
		t.Errorf("valid KEK refused: %v", err)
	}
	// Owner other than the required one is refused.
	kekOwner = os.Getuid() + 1
	if _, err := LoadKEK(good); err == nil {
		t.Error("foreign owner accepted")
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	dek := testDEK(t)
	for _, plain := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("p"), 4096)} {
		nonce, ct, err := Seal(dek, refA, "pg.postgres.password", plain)
		if err != nil {
			t.Fatal(err)
		}
		if len(nonce) != 12 {
			t.Fatalf("nonce length %d", len(nonce))
		}
		got, err := Open(dek, refA, "pg.postgres.password", nonce, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatal("round trip mismatch")
		}
	}
}

func TestOpen_RejectsWrongAAD(t *testing.T) {
	dek := testDEK(t)
	nonce, ct, err := Seal(dek, refA, "x", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dek, refB, "x", nonce, ct); err == nil {
		t.Error("opened under another ref")
	}
	if _, err := Open(dek, refA, "y", nonce, ct); err == nil {
		t.Error("opened under another name")
	}
	if _, err := Open(dek, refA, "x", nonce, ct); err != nil {
		t.Errorf("correct AAD refused: %v", err)
	}
	if got := rawOpen(t, dek, []byte(refA+"\x00x"), nonce, ct); string(got) != "secret" {
		t.Error("AAD is not ref || 0x00 || name")
	}
	other := bytes.Repeat([]byte{0x11}, 32)
	if _, err := Open(other, refA, "x", nonce, ct); err == nil {
		t.Error("opened under another DEK")
	}
	if _, _, err := Seal(dek, "a\x00b", "x", nil); err == nil {
		t.Error("ref with NUL accepted")
	}
}

func TestUnwrapDEK_RejectsWrongRef(t *testing.T) {
	var k KEK
	k[0] = 7
	dek := testDEK(t)
	nonce, wrapped, err := WrapDEK(k, refA, dek)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 12 {
		t.Fatalf("nonce length %d", len(nonce))
	}
	if _, err := UnwrapDEK(k, refB, nonce, wrapped); err == nil {
		t.Error("unwrapped under another ref")
	}
	got, err := UnwrapDEK(k, refA, nonce, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrap mismatch")
	}
	if got := rawOpen(t, k[:], []byte("dek\x00"+refA), nonce, wrapped); !bytes.Equal(got, dek) {
		t.Error("wrap AAD is not \"dek\" || 0x00 || ref")
	}
	if _, _, err := WrapDEK(k, refA, dek[:16]); err == nil {
		t.Error("short DEK wrapped")
	}
}

func TestSeal_NonceUnique(t *testing.T) {
	dek := testDEK(t)
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		nonce, _, err := Seal(dek, refA, "x", []byte("p"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(nonce)] {
			t.Fatalf("nonce repeated after %d seals", i)
		}
		seen[string(nonce)] = true
	}
}

func TestEscrowText_IsHex(t *testing.T) {
	var k KEK
	for i := range k {
		k[i] = byte(i)
	}
	s := EscrowText(k)
	if !strings.Contains(s, hex.EncodeToString(k[:])) {
		t.Fatalf("escrow text does not carry the key: %q", s)
	}
}

func TestErrors_CarryNoSecret(t *testing.T) {
	asOwner(t)
	var k KEK
	for i := range k {
		k[i] = byte(0xa0 + i%16)
	}
	dek := bytes.Repeat([]byte{0xc3}, 32)
	plain := []byte("hunter2-plaintext")
	nonce, ct, err := Seal(dek, refA, "x", plain)
	if err != nil {
		t.Fatal(err)
	}
	wn, wrapped, err := WrapDEK(k, refA, dek)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := writeKEK(t, append(k[:], 0), 0o400)
	loose := writeKEK(t, k[:], 0o440)

	var errs []error
	collect := func(err error) {
		if err == nil {
			t.Fatal("expected an error")
		}
		errs = append(errs, err)
	}
	_, err = Open(dek, refB, "x", nonce, ct)
	collect(err)
	_, err = Open(dek[:5], refA, "x", nonce, ct)
	collect(err)
	_, err = Open(dek, refA, "x", nonce[:3], ct)
	collect(err)
	_, _, err = Seal(dek[:31], refA, "x", plain)
	collect(err)
	_, err = UnwrapDEK(k, refB, wn, wrapped)
	collect(err)
	_, err = UnwrapDEK(k, refA, wn[:1], wrapped)
	collect(err)
	_, _, err = WrapDEK(k, refA, dek[:3])
	collect(err)
	_, err = LoadKEK(keyFile)
	collect(err)
	_, err = LoadKEK(loose)
	collect(err)
	_, err = GenerateKEK(loose)
	collect(err)

	var needles []string
	for _, b := range [][]byte{k[:], dek, plain, ct, wrapped} {
		needles = append(needles, string(b), hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b),
			base64.RawURLEncoding.EncodeToString(b))
	}
	for _, e := range errs {
		msg := e.Error()
		lower := strings.ToLower(msg)
		for _, n := range needles {
			if strings.Contains(msg, n) || strings.Contains(lower, strings.ToLower(n)) {
				t.Errorf("error %q carries secret material", msg)
			}
		}
		// Byte-slice formatting (%v / %x of the key) would show these runs.
		if strings.Contains(msg, "160 161 162") || strings.Contains(msg, "195 195 195") {
			t.Errorf("error %q carries formatted key bytes", msg)
		}
	}
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// Every authentication failure is the same error, whatever its cause.
func TestOpen_TamperAnyByte(t *testing.T) {
	dek := randBytes(t, 32)
	plain := []byte("synthetic secret value")
	nonce, ct, err := Seal(dek, refA, "x", plain)
	if err != nil {
		t.Fatal(err)
	}
	for i := range nonce {
		n := bytes.Clone(nonce)
		n[i] ^= 0x01
		if _, err := Open(dek, refA, "x", n, ct); !errors.Is(err, errCrypto) {
			t.Fatalf("nonce byte %d: %v", i, err)
		}
	}
	for i := range ct { // ciphertext body and the 16-byte tag
		c := bytes.Clone(ct)
		c[i] ^= 0x80
		if _, err := Open(dek, refA, "x", nonce, c); !errors.Is(err, errCrypto) {
			t.Fatalf("ct byte %d: %v", i, err)
		}
	}
	for n := 0; n < len(ct); n++ {
		if _, err := Open(dek, refA, "x", nonce, ct[:n]); !errors.Is(err, errCrypto) {
			t.Fatalf("truncated to %d: %v", n, err)
		}
	}
	if _, err := Open(dek, refA, "x", nonce, append(bytes.Clone(ct), 0)); !errors.Is(err, errCrypto) {
		t.Fatalf("extended: %v", err)
	}
	// Wrong key, wrong ref, wrong name and tampering are indistinguishable.
	_, e1 := Open(randBytes(t, 32), refA, "x", nonce, ct)
	_, e2 := Open(dek, refB, "x", nonce, ct)
	_, e3 := Open(dek, refA, "y", nonce, ct)
	if !errors.Is(e1, errCrypto) || !errors.Is(e2, errCrypto) || !errors.Is(e3, errCrypto) {
		t.Fatalf("non-uniform errors: %v / %v / %v", e1, e2, e3)
	}
}

func TestOpen_SwappedNonces(t *testing.T) {
	dek := randBytes(t, 32)
	n1, c1, _ := Seal(dek, refA, "x", []byte("one"))
	n2, c2, _ := Seal(dek, refA, "x", []byte("two"))
	if _, err := Open(dek, refA, "x", n2, c1); err == nil {
		t.Error("c1 opened under n2")
	}
	if _, err := Open(dek, refA, "x", n1, c2); err == nil {
		t.Error("c2 opened under n1")
	}
}

func TestSealOpen_EdgePlaintexts(t *testing.T) {
	dek := randBytes(t, 32)
	for _, p := range [][]byte{{}, randBytes(t, 16<<20)} {
		n, c, err := Seal(dek, refA, "x", p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(dek, refA, "x", n, c)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("len %d: %v", len(p), err)
		}
	}
}

// Refs are exactly 20 characters of [a-z0-9], so the first NUL of the AAD
// ends the ref: names may hold NUL without making two (ref, name) pairs
// collide. Malformed refs and empty names are refused on every entry point.
func TestAAD_NoBoundaryCollision(t *testing.T) {
	dek := randBytes(t, 32)
	n, c, err := Seal(dek, refA, "b\x00c", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dek, refA, "b", n, c); err == nil {
		t.Error("prefix name accepted")
	}
	if _, err := Open(dek, refA+"\x00b", "c", n, c); err == nil {
		t.Error("NUL-split ref accepted")
	}
	for _, ref := range []string{"", "a", "dek", "a\x00b", refA[:19], refA + "a",
		"AAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaa-", "aaaaaaaaaaaaaaaaaaa\x00",
		"aaaaaaaaaaaaaaaaaa\u00e9"} {
		if _, _, err := Seal(dek, ref, "x", nil); err == nil {
			t.Errorf("seal ref %q accepted", ref)
		}
		if _, err := Open(dek, ref, "x", n, c); !errors.Is(err, errRef) {
			t.Errorf("open ref %q: %v, want the invalid-ref error", ref, err)
		}
		if _, _, err := WrapDEK(KEK{}, ref, dek); err == nil {
			t.Errorf("wrap ref %q accepted", ref)
		}
		_, err := UnwrapDEK(KEK{}, ref, make([]byte, 12), make([]byte, 48))
		if !errors.Is(err, errRef) {
			t.Errorf("unwrap ref %q: %v, want the invalid-ref error", ref, err)
		} else if len(ref) >= 19 && strings.Contains(err.Error(), ref[:19]) {
			t.Errorf("error %q echoes the ref", err)
		}
	}
	if _, _, err := Seal(dek, refA, "", []byte("p")); err == nil {
		t.Error("empty name sealed")
	}
	if _, err := Open(dek, refA, "", n, c); err == nil {
		t.Error("empty name opened")
	}
}

func TestCrossProjectMove(t *testing.T) {
	var k KEK
	copy(k[:], randBytes(t, 32))
	dekA, dekB := randBytes(t, 32), randBytes(t, 32)
	wn, w, _ := WrapDEK(k, refA, dekA)
	if _, err := UnwrapDEK(k, refB, wn, w); err == nil {
		t.Error("A's wrapped DEK unwrapped as B's")
	}
	var k2 KEK
	copy(k2[:], randBytes(t, 32))
	if _, err := UnwrapDEK(k2, refA, wn, w); err == nil {
		t.Error("unwrapped under another KEK")
	}
	n, c, _ := Seal(dekA, refA, "x", []byte("p"))
	if _, err := Open(dekB, refB, "x", n, c); err == nil {
		t.Error("A's secret opened as B's")
	}
	if _, err := Open(dekA, refB, "x", n, c); err == nil {
		t.Error("A's secret opened under A's DEK as B's")
	}
	// A wrapped value tampered or truncated is refused.
	for i := range w {
		x := bytes.Clone(w)
		x[i] ^= 1
		if _, err := UnwrapDEK(k, refA, wn, x); !errors.Is(err, errCrypto) {
			t.Fatalf("wrapped byte %d: %v", i, err)
		}
	}
	if _, err := UnwrapDEK(k, refA, wn, w[:len(w)-1]); err == nil {
		t.Error("truncated wrap accepted")
	}
}

func TestWrongLengths(t *testing.T) {
	good := randBytes(t, 32)
	n, c, _ := Seal(good, refA, "x", []byte("p"))
	for _, l := range []int{0, 16, 24, 31, 33, 64} {
		if _, _, err := Seal(make([]byte, l), refA, "x", nil); err == nil {
			t.Errorf("seal key len %d accepted", l)
		}
		if _, err := Open(make([]byte, l), refA, "x", n, c); err == nil {
			t.Errorf("open key len %d accepted", l)
		}
		if _, _, err := WrapDEK(KEK{}, refA, make([]byte, l)); err == nil {
			t.Errorf("wrap DEK len %d accepted", l)
		}
	}
	for _, l := range []int{0, 8, 11, 13, 16, 24} {
		if _, err := Open(good, refA, "x", make([]byte, l), c); err == nil {
			t.Errorf("nonce len %d accepted", l)
		}
		if _, err := UnwrapDEK(KEK{}, refA, make([]byte, l), c); err == nil {
			t.Errorf("wrap nonce len %d accepted", l)
		}
	}
	// A 16-byte value wrapped as a raw GCM payload under the right AAD is refused on unwrap.
	var k KEK
	copy(k[:], randBytes(t, 32))
	a, _ := gcm(k[:])
	wn := randBytes(t, 12)
	short := a.Seal(nil, wn, make([]byte, 16), []byte("dek\x00"+refA))
	if _, err := UnwrapDEK(k, refA, wn, short); err == nil {
		t.Error("16-byte DEK unwrapped")
	}
}

func TestSeal_Concurrent(t *testing.T) {
	dek := randBytes(t, 32)
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				n, c, err := Seal(dek, refA, "x", []byte("p"))
				if err != nil {
					t.Error(err)
					return
				}
				if p, err := Open(dek, refA, "x", n, c); err != nil || string(p) != "p" {
					t.Error("concurrent round trip failed")
					return
				}
				mu.Lock()
				if seen[string(n)] {
					t.Error("nonce repeated")
				}
				seen[string(n)] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

// The link step, not the file's permission bits, must stop the overwrite:
// root ignores 0400.
func TestGenerateKEK_NeverOverwritesWritableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kek")
	orig := randBytes(t, 32)
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKEK(path); err == nil {
		t.Fatal("existing file overwritten")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, orig) {
		t.Fatal("existing file changed or removed")
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode() != 0o600 {
		t.Fatal("existing file mode changed")
	}
	onlyEntry(t, dir, "kek")
}

// onlyEntry fails unless dir holds exactly the one entry name.
func onlyEntry(t *testing.T, dir, name string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != name {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %q, want only %q", names, name)
	}
}

func TestGenerateKEK_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "kek")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKEK(link); err == nil {
		t.Fatal("dangling symlink followed")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("symlink target created")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("symlink removed by a failed GenerateKEK")
	}
}

func TestGenerateKEK_Race(t *testing.T) {
	asOwner(t)
	path := filepath.Join(t.TempDir(), "kek")
	const n = 16
	keys := make([]KEK, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys[i], errs[i] = GenerateKEK(path)
		}(i)
	}
	wg.Wait()
	won := -1
	for i, err := range errs {
		if err == nil {
			if won >= 0 {
				t.Fatal("two GenerateKEK calls both succeeded")
			}
			won = i
		}
	}
	if won < 0 {
		t.Fatal("no GenerateKEK call succeeded")
	}
	got, err := LoadKEK(path)
	if err != nil || got != keys[won] {
		t.Fatalf("file does not hold the winner's KEK: %v", err)
	}
}

func TestGenerateKEK_ExactModeUnderAnyUmask(t *testing.T) {
	for _, mask := range []int{0, 0o022, 0o477, 0o777} {
		dir := t.TempDir() // before the umask, so cleanup can remove it
		path := filepath.Join(dir, "kek")
		old := syscall.Umask(mask)
		_, err := GenerateKEK(path)
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %o: %v", mask, err)
		}
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode() != 0o400 {
			t.Fatalf("umask %o: mode %v: %v", mask, fi.Mode(), err)
		}
		onlyEntry(t, dir, "kek")
	}
}

func TestLoadKEK_RefusesDirectory(t *testing.T) {
	asOwner(t)
	dir := filepath.Join(t.TempDir(), "kek")
	if err := os.Mkdir(dir, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKEK(dir); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestLoadKEK_RefusesDevice(t *testing.T) {
	old := kekOwner
	kekOwner = 0
	defer func() { kekOwner = old }()
	if _, err := LoadKEK("/dev/zero"); err == nil {
		t.Fatal("device accepted")
	}
}

// A FIFO at the KEK path must be refused, not block the caller forever.
func TestLoadKEK_RefusesFIFOWithoutBlocking(t *testing.T) {
	asOwner(t)
	path := filepath.Join(t.TempDir(), "kek")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadKEK(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(2 * time.Second):
		// Release the blocked open so the goroutine can finish.
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		<-done
		t.Fatal("LoadKEK blocked on a FIFO")
	}
}

// A failed directory sync after the link leaves no key behind, so the next
// call starts afresh instead of failing on an existing file.
func TestGenerateKEK_SyncFailureRemovesKey(t *testing.T) {
	asOwner(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "kek")
	orig := syncDir
	syncDir = func(string) error { return errors.New("injected sync failure") }
	_, err := GenerateKEK(path)
	syncDir = orig
	if err == nil {
		t.Fatal("GenerateKEK succeeded despite a failed directory sync")
	}
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Fatalf("directory not empty after the failure: %v %v", ents, err)
	}
	k, err := GenerateKEK(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadKEK(path)
	if err != nil || got != k {
		t.Fatalf("retry key not read back: %v", err)
	}
	onlyEntry(t, dir, "kek")
}
