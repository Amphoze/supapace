package pgsock

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
)

// scramIterations is the iteration count of every verifier the platform sets;
// a server asking for another count is refused before any key is derived.
const scramIterations = 4096

const scramSaltLen = 16

// ScramSalt derives the SCRAM salt of a role from the project's data key:
// HMAC-SHA-256(dek, "supapace-scram-salt" 0x00 len(ref) ref len(role) role)
// truncated to 16 bytes, each length a 4-byte big-endian count. The cluster
// never sees the key; the salt is unique per project and role and says
// nothing about the password. An empty key is refused.
func ScramSalt(dek []byte, ref, role string) ([]byte, error) {
	if len(dek) == 0 {
		return nil, errors.New("pgsock: empty data key")
	}
	m := hmac.New(sha256.New, dek)
	m.Write([]byte("supapace-scram-salt\x00"))
	m.Write(binary.BigEndian.AppendUint32(nil, uint32(len(ref))))
	m.Write([]byte(ref))
	m.Write(binary.BigEndian.AppendUint32(nil, uint32(len(role))))
	m.Write([]byte(role))
	return m.Sum(nil)[:scramSaltLen], nil
}

// ScramVerifier returns the SCRAM-SHA-256 verifier
// "SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>" for password and salt,
// to be set with ALTER ROLE … PASSWORD so the password never reaches a server.
// The password must be printable ASCII (SASLprep leaves it unchanged, so the
// client computes the same keys) and the salt 16 bytes.
func ScramVerifier(password string, salt []byte) (string, error) {
	if password == "" {
		return "", errors.New("pgsock: empty password")
	}
	for i := 0; i < len(password); i++ {
		if password[i] < 0x20 || password[i] > 0x7e {
			return "", errors.New("pgsock: password is not printable ASCII")
		}
	}
	if len(salt) != scramSaltLen {
		return "", errors.New("pgsock: salt is not 16 bytes")
	}
	sp, err := pbkdf2.Key(sha256.New, password, salt, scramIterations, sha256.Size)
	if err != nil {
		return "", errors.New("pgsock: key derivation failed")
	}
	ck := hmac.New(sha256.New, sp)
	ck.Write([]byte("Client Key"))
	stored := sha256.Sum256(ck.Sum(nil))
	sk := hmac.New(sha256.New, sp)
	sk.Write([]byte("Server Key"))
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$" + strconv.Itoa(scramIterations) + ":" + b64(salt) + "$" + b64(stored[:]) + ":" + b64(sk.Sum(nil)), nil
}
