// Package secrets holds the node key-encryption key (KEK) and the envelope
// encryption of per-project secrets: a per-project data-encryption key (DEK)
// wrapped by the KEK, and each secret sealed by the DEK. Both layers are
// AES-256-GCM with a 12-byte random nonce and bound associated data, so a
// ciphertext cannot be moved to another project or another secret name.
//
// Errors never carry key bytes, plaintext or ciphertext.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// KEK is the node key-encryption key. Its value must never be formatted,
// printed or logged; the init command shows it once, through EscrowText.
type KEK [32]byte

// kekOwner is the uid a KEK file must belong to; tests substitute their own.
var kekOwner = 0

var (
	errCrypto = errors.New("secrets: authentication failed")
	errRef    = errors.New("secrets: invalid ref")
)

// GenerateKEK writes a fresh random KEK to path with mode 0400. The key is
// written and synced in a temporary file in the same directory, then linked to
// path; the link fails when path exists, so an existing file of any mode,
// size or owner is never modified. On failure the temporary file is
// removed, and so is path when the failure came after the link and path is
// still the file just linked, so a retry generates a fresh key. A crash
// between the link and the removal of the temporary file can leave a
// ".<base>.tmp-*" hard link to the key in the same directory; the caller that
// owns the directory removes such leftovers before generating.
func GenerateKEK(path string) (KEK, error) {
	var k KEK
	var suffix [8]byte
	if _, err := rand.Read(k[:]); err != nil {
		return KEK{}, fmt.Errorf("secrets: generate KEK: %w", err)
	}
	if _, err := rand.Read(suffix[:]); err != nil {
		return KEK{}, fmt.Errorf("secrets: generate KEK: %w", err)
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(suffix[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o400)
	if err != nil {
		return KEK{}, fmt.Errorf("secrets: create KEK file: %w", err)
	}
	defer os.Remove(tmp) // after a successful link, only the second name goes
	var fi os.FileInfo
	err = f.Chmod(0o400) // exact mode, whatever the umask
	if err == nil {
		_, err = f.Write(k[:])
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		fi, err = f.Stat()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return KEK{}, fmt.Errorf("secrets: write KEK file: %w", err)
	}
	if err := os.Link(tmp, path); err != nil {
		return KEK{}, fmt.Errorf("secrets: install KEK file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		if st, serr := os.Lstat(path); serr == nil && os.SameFile(st, fi) {
			os.Remove(path)
		}
		return KEK{}, fmt.Errorf("secrets: sync KEK directory %s: %w", dir, err)
	}
	return k, nil
}

// syncDir makes a new directory entry durable; tests substitute a failure.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// LoadKEK reads the KEK from path. It refuses a symlink, anything but a
// regular file, an owner other than root, a mode other than 0400 and a size
// other than 32 bytes. The open never blocks (a FIFO is refused, not waited
// on). Only the final path component is protected against symlinks: the
// caller must keep the key in a directory that only root can write.
func LoadKEK(path string) (KEK, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return KEK{}, fmt.Errorf("secrets: open KEK file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return KEK{}, fmt.Errorf("secrets: stat KEK file %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return KEK{}, fmt.Errorf("secrets: KEK file %s is not a regular file", path)
	case !ok || int(st.Uid) != kekOwner:
		return KEK{}, fmt.Errorf("secrets: KEK file %s is not owned by uid %d", path, kekOwner)
	case fi.Mode() != 0o400:
		return KEK{}, fmt.Errorf("secrets: KEK file %s has mode %v, want 0400", path, fi.Mode().Perm())
	case fi.Size() != int64(len(KEK{})):
		return KEK{}, fmt.Errorf("secrets: KEK file %s has size %d, want %d", path, fi.Size(), len(KEK{}))
	}
	var k KEK
	// One byte past the key detects a file that grew after the stat.
	buf := make([]byte, len(k)+1)
	n, err := io.ReadFull(f, buf)
	if err != io.ErrUnexpectedEOF || n != len(k) {
		clear(buf)
		return KEK{}, fmt.Errorf("secrets: KEK file %s changed while reading", path)
	}
	copy(k[:], buf)
	clear(buf)
	return k, nil
}

// EscrowText is the KEK as lowercase hex, for offline escrow.
func EscrowText(k KEK) string {
	return hex.EncodeToString(k[:])
}

// WrapDEK encrypts a 32-byte DEK under the KEK with AAD "dek" || 0x00 || ref.
func WrapDEK(k KEK, ref string, dek []byte) (nonce, wrapped []byte, err error) {
	if len(dek) != 32 {
		return nil, nil, fmt.Errorf("secrets: DEK must be 32 bytes, got %d", len(dek))
	}
	if err := checkAAD(ref, "dek"); err != nil {
		return nil, nil, err
	}
	return seal(k[:], []byte("dek\x00"+ref), dek)
}

// UnwrapDEK reverses WrapDEK; any mismatch of KEK, ref, nonce or ciphertext
// fails.
func UnwrapDEK(k KEK, ref string, nonce, wrapped []byte) ([]byte, error) {
	if err := checkAAD(ref, "dek"); err != nil {
		return nil, err
	}
	dek, err := open(k[:], []byte("dek\x00"+ref), nonce, wrapped)
	if err != nil {
		return nil, err
	}
	if len(dek) != 32 {
		clear(dek)
		return nil, errors.New("secrets: unwrapped DEK has the wrong length")
	}
	return dek, nil
}

// Seal encrypts plain under the DEK with AAD ref || 0x00 || name.
func Seal(dek []byte, ref, name string, plain []byte) (nonce, ct []byte, err error) {
	if err := checkAAD(ref, name); err != nil {
		return nil, nil, err
	}
	return seal(dek, []byte(ref+"\x00"+name), plain)
}

// Open reverses Seal; any mismatch of DEK, ref, name, nonce or ciphertext
// fails.
func Open(dek []byte, ref, name string, nonce, ct []byte) ([]byte, error) {
	if err := checkAAD(ref, name); err != nil {
		return nil, err
	}
	return open(dek, []byte(ref+"\x00"+name), nonce, ct)
}

// checkAAD refuses a ref outside ^[a-z0-9]{20}$ and an empty name. A ref
// holds no NUL, so the first NUL of the AAD always ends it. The error never
// echoes either value.
func checkAAD(ref, name string) error {
	if len(ref) != 20 {
		return errRef
	}
	for i := 0; i < len(ref); i++ {
		if c := ref[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return errRef
		}
	}
	if name == "" {
		return errors.New("secrets: empty name")
	}
	return nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secrets: key must be 32 bytes, got %d", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("secrets: cipher setup failed")
	}
	a, err := cipher.NewGCM(b) // 12-byte nonce, 16-byte tag
	if err != nil {
		return nil, errors.New("secrets: cipher setup failed")
	}
	return a, nil
}

func seal(key, aad, plain []byte) (nonce, ct []byte, err error) {
	a, err := gcm(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("secrets: nonce: %w", err)
	}
	return nonce, a.Seal(nil, nonce, plain, aad), nil
}

func open(key, aad, nonce, ct []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("secrets: nonce must be %d bytes, got %d", a.NonceSize(), len(nonce))
	}
	plain, err := a.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errCrypto
	}
	return plain, nil
}

// SealNode encrypts a node-level secret file under the KEK: the 12-byte nonce
// followed by the AES-256-GCM ciphertext, with AAD "node" || 0x00 || name, so
// a sealed file cannot be read back under another name.
func SealNode(k KEK, name string, plain []byte) ([]byte, error) {
	if name == "" {
		return nil, errors.New("secrets: empty name")
	}
	nonce, ct, err := seal(k[:], []byte("node\x00"+name), plain)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// OpenNode reverses SealNode; any mismatch of KEK, name or bytes fails.
func OpenNode(k KEK, name string, sealed []byte) ([]byte, error) {
	if name == "" {
		return nil, errors.New("secrets: empty name")
	}
	if len(sealed) < 12 {
		return nil, errCrypto
	}
	return open(k[:], []byte("node\x00"+name), sealed[:12], sealed[12:])
}
