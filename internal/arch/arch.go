// Package arch is the archive and restore command a cluster runs: push copies
// a finished WAL file into the spool, get asks the restore spool for a file
// during recovery and waits for the answer. It runs inside the cluster's
// container with the project's rights; its checks keep a confused or hostile
// spool from turning into a wrong archive entry or a wrong recovery, not the
// cluster out of anything it could reach anyway. It reads no environment.
//
//	supapace-arch push <path> <name>   exit 0 archived (or a .partial segment
//	                                   discarded), 1 refused or failed, 2 usage
//	supapace-arch get <name> <dest>    exit 0 served, 1 not in the archive,
//	                                   200 timeout, 201 any other error
//
// get exits 1 only when the restore spool holds the explicit "not in the
// archive" marker: the server reads any exit at or below 125 as the end of the
// archive and may end recovery, so a refused name, a usage error, a timeout
// and every other failure exit above 125 and the server stops instead.
package arch

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/walname"
)

// GetTimeout bounds one get; then it exits 200.
const GetTimeout = 120 * time.Second

const (
	maxAnswer = 16<<20 + 1<<10 // the largest answer get accepts: a segment and some slack
	pollEvery = 100 * time.Millisecond
	maxDraws  = 8 // temporary names tried before giving up
)

var (
	errRefused      = errors.New("refused name")
	errNotInArchive = errors.New("not in the archive")
	errTimeout      = errors.New("timed out")
)

// The fixed mount points inside the cluster, and seams; tests replace them.
var (
	spoolDir  = "/opt/supapace/spool"
	rspoolDir = "/opt/supapace/rspool"
	fsync     = func(f *os.File) error { return f.Sync() }
	randHex   = func() (string, error) {
		b := make([]byte, 8)
		_, err := rand.Read(b)
		return hex.EncodeToString(b), err
	}
	beforeLink = func() {}
	getTimeout = GetTimeout
)

// Main runs the command line args (args[0] is the program name) and returns
// the exit code.
func Main(args []string, stderr io.Writer) int {
	switch {
	case len(args) == 4 && args[1] == "push":
		if err := push(spoolDir, args[2], args[3]); err != nil {
			fmt.Fprintf(stderr, "supapace-arch: push %q: %v\n", args[3], err)
			return 1
		}
		return 0
	case len(args) >= 2 && args[1] == "get":
		if len(args) != 4 {
			fmt.Fprintln(stderr, "supapace-arch: usage: get <name> <dest>")
			return 201
		}
		err := get(rspoolDir, args[2], args[3], getTimeout)
		if err == nil {
			return 0
		}
		fmt.Fprintf(stderr, "supapace-arch: get %q: %v\n", args[2], err)
		switch {
		case errors.Is(err, errNotInArchive):
			return 1
		case errors.Is(err, errTimeout):
			return 200
		}
		return 201
	}
	fmt.Fprintln(stderr, "usage: supapace-arch push <path> <name> | get <name> <dest>")
	return 2
}

// push archives the file at path into spool under name.
func push(spool, path, name string) error {
	// Acknowledged and discarded before anything is opened; see walname.Partial.
	if walname.Partial(name) {
		return nil
	}
	if _, _, ok := walname.Spool(name); !ok {
		return errRefused
	}
	// Never blocks on a FIFO or reads a device: only a regular file is archived.
	src, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	if fi, err := src.Stat(); err != nil || !fi.Mode().IsRegular() {
		return errors.New("source is not a regular file")
	}
	tmp, err := copyToTemp(spool, ".tmp-"+name+"-", src, -1)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	beforeLink()
	target := filepath.Join(spool, name)
	if err := os.Link(tmp, target); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := sameRegularSynced(target, tmp); err != nil {
			return err
		}
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	d, err := os.OpenFile(spool, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	return fsync(d)
}

// sameRegularSynced fails unless target is a regular file with the bytes of
// tmp, and then fsyncs it through the descriptor it compared.
func sameRegularSynced(target, tmp string) error {
	t, err := os.OpenFile(target, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("already in the spool, unreadable: %w", err)
	}
	defer t.Close()
	if fi, err := t.Stat(); err != nil || !fi.Mode().IsRegular() {
		return errors.New("already in the spool and not a regular file")
	}
	m, err := os.Open(tmp)
	if err != nil {
		return err
	}
	defer m.Close()
	a, b := make([]byte, 64<<10), make([]byte, 64<<10)
	for {
		n, errA := io.ReadFull(t, a)
		k, errB := io.ReadFull(m, b)
		if !bytes.Equal(a[:n], b[:k]) {
			return errors.New("already in the spool with other content")
		}
		// Equal reads of equal length: either both filled the buffer or both ended.
		if errA == nil && errB == nil {
			continue
		}
		for _, e := range []error{errA, errB} {
			if e != io.EOF && e != io.ErrUnexpectedEOF {
				return e
			}
		}
		return fsync(t)
	}
}

// get asks the restore spool for name, waits up to timeout for the answer and
// puts it at dest.
func get(rspool, name, dest string, timeout time.Duration) error {
	if _, _, ok := walname.Request(name); !ok {
		return errRefused
	}
	deadline := time.Now().Add(timeout)
	req := filepath.Join(rspool, "req", name)
	out := filepath.Join(rspool, "out", name)
	f, err := os.OpenFile(req, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	switch {
	case err == nil:
		f.Close()
	case !errors.Is(err, os.ErrExist):
		return err
	}
	tick := time.NewTicker(pollEvery) // panics on a zero interval: never a busy loop
	defer tick.Stop()
	for {
		if _, err := os.Lstat(out + ".none"); err == nil {
			os.Remove(req)
			os.Remove(out + ".none")
			return errNotInArchive
		}
		done, err := serve(out, dest)
		if err != nil {
			return err
		}
		if done {
			// The file is in place; a leftover request or answer is harmless.
			// The request goes first, so it is never seen without its answer.
			os.Remove(req)
			os.Remove(out)
			return nil
		}
		if !time.Now().Before(deadline) {
			return errTimeout
		}
		<-tick.C
	}
}

// serve copies the answer at out to dest if out is a regular file. Anything
// else at out (nothing, a link, a FIFO, a directory) is not an answer yet.
func serve(out, dest string) (bool, error) {
	f, err := os.OpenFile(out, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ELOOP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return false, err
	}
	dir := filepath.Dir(dest)
	tmp, err := copyToTemp(dir, "."+filepath.Base(dest)+".tmp-", f, maxAnswer)
	if err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// copyToTemp writes r into dir under prefix plus 16 random hex digits, created
// exclusively and never through a link, and fsyncs it. max >= 0 bounds the
// size: more is an error and nothing is left behind.
func copyToTemp(dir, prefix string, r io.Reader, max int64) (string, error) {
	var f *os.File
	var name string
	for i := 0; ; i++ {
		h, err := randHex()
		if err != nil {
			return "", err
		}
		name = filepath.Join(dir, prefix+h)
		f, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) || i+1 == maxDraws {
			return "", err
		}
	}
	err := func() error {
		defer f.Close()
		if max >= 0 {
			r = io.LimitReader(r, max+1)
		}
		n, err := io.Copy(f, r)
		if err != nil {
			return err
		}
		if max >= 0 && n > max {
			return fmt.Errorf("answer larger than %d bytes", max)
		}
		return fsync(f)
	}()
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}
