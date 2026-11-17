package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// Request codes a client may send before its startup packet; a backend without
// TLS or GSSAPI declines each with 'N'.
const (
	sslRequest    = 80877103
	gssEncRequest = 80877104
)

// fakePG listens on a Unix socket like a Postgres backend: it answers each
// client's startup packet with the authentication request of mode — SASL
// (SCRAM-SHA-256) or cleartext password — and appends every byte any client sends
// to logFile. It never authenticates anyone.
//
// The log is a series of chunks, each the header line "conn N LEN" (N numbers the
// connections from 1) followed by the LEN bytes as received. It is created once
// the socket is bound, and "listening" is printed after both. A reader takes a
// header line, then exactly LEN bytes, and repeats; the payload is client data
// and may itself contain text shaped like a header.
func fakePG(socket, mode, logFile string, stdout io.Writer) error {
	l, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer l.Close()
	// Any local user may connect, as to a real backend's socket.
	if err := os.Chmod(socket, 0o777); err != nil {
		return err
	}
	logf, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	auth := binary.BigEndian.AppendUint32(nil, 3)
	if mode == "sasl" {
		auth = append(binary.BigEndian.AppendUint32(nil, 10), "SCRAM-SHA-256\x00\x00"...)
	}
	auth = append(binary.BigEndian.AppendUint32([]byte{'R'}, uint32(4+len(auth))), auth...)
	fmt.Fprintln(stdout, "listening", socket)
	var mu sync.Mutex
	for n := 1; ; n++ {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go serveFake(c, io.TeeReader(c, &chunkLog{f: logf, mu: &mu, conn: n}), auth)
	}
}

// chunkLog writes each chunk a connection sends as one framed record.
type chunkLog struct {
	f    *os.File
	mu   *sync.Mutex
	conn int
}

func (w *chunkLog) Write(p []byte) (int, error) {
	rec := append(fmt.Appendf(nil, "conn %d %d\n", w.conn, len(p)), p...)
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(rec); err != nil {
		return 0, err
	}
	return len(p), nil
}

func serveFake(c net.Conn, r io.Reader, auth []byte) {
	defer c.Close()
	// Whatever happens below, everything the client sent reaches the log.
	defer io.Copy(io.Discard, r)
	for {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr)
		if n < 8 || n > 10000 {
			break
		}
		if _, err := io.CopyN(io.Discard, r, int64(n-8)); err != nil {
			return
		}
		if code := binary.BigEndian.Uint32(hdr[4:]); n != 8 || code != sslRequest && code != gssEncRequest {
			break
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return
		}
	}
	c.Write(auth)
}
