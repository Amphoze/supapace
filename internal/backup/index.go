package backup

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/store"
)

// The replicator's index file of a subject is the record's rows, one
// jobio.IndexRow a line: root-owned, mode 0444, in a root 0700 directory,
// mounted read-only into the subject's replication jobs. The runner is its
// only writer and writes it only for a subject whose job slot it holds, so
// two writes of one file never meet.

// ensureIndex makes the subject's index file hold as many rows as the record
// and returns that count: a file that is missing, not the daemon's regular
// 0444 file, holds a line jobio does not read back (the job then fails with
// code index), ends inside a line or holds another number of lines is
// rebuilt.
func (r *Runner) ensureIndex(ctx context.Context, subject string) (int64, error) {
	n, err := r.st.ObjectCount(ctx, subject)
	if err != nil {
		return 0, err
	}
	if lines, err := r.checkIndex(r.p.IndexFile(subject)); err == nil && lines == n {
		return n, nil
	}
	return n, r.rebuildIndex(ctx, subject)
}

// fileID is what tells one state of a file from another: its inode, size and
// modification time.
type fileID struct{ ino, size, mtimeNS int64 }

func idOf(fi os.FileInfo) fileID {
	return fileID{int64(fi.Sys().(*syscall.Stat_t).Ino), fi.Size(), fi.ModTime().UnixNano()}
}

type knownKey struct {
	r    *Runner
	path string
}

type knownFile struct {
	id    fileID
	lines int64
}

// known holds, per runner and index file, the file as the runner last wrote
// or read it whole, and its line count: such a file is not read again.
//
// ponytail: a file changed in place to the same size and modification time
// (only root can) is taken as known; compare a checksum if that ever matters.
var known = struct {
	sync.Mutex
	m map[knownKey]knownFile
}{m: map[knownKey]knownFile{}}

func (r *Runner) remember(path string, lines int64) {
	known.Lock()
	defer known.Unlock()
	if fi, err := os.Lstat(path); err == nil {
		known.m[knownKey{r, path}] = knownFile{idOf(fi), lines}
	} else {
		delete(known.m, knownKey{r, path})
	}
}

func (r *Runner) forget(path string) {
	known.Lock()
	delete(known.m, knownKey{r, path})
	known.Unlock()
}

func (r *Runner) recall(path string) (knownFile, bool) {
	known.Lock()
	defer known.Unlock()
	k, ok := known.m[knownKey{r, path}]
	return k, ok
}

// checkIndex returns the line count of the index file at path. It is opened
// without following a link or blocking (a FIFO); anything but the daemon's
// own regular 0444 file — one an interrupted append left writable, say — is
// an error. A file the runner did not write or read in this state is read
// whole, and a line jobio does not read back, or a last line without its
// newline, is an error.
func (r *Runner) checkIndex(path string) (int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o444 || int(fi.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return 0, errors.New("the index file is not the daemon's regular 0444 file")
	}
	if k, ok := r.recall(path); ok && k.id == idOf(fi) {
		return k.lines, nil
	}
	var n int64
	br := bufio.NewReaderSize(f, 64<<10) // a line is at most about 1.1 KiB
	for {
		line, err := br.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("index line %d: %w", n+1, err)
		}
		if _, err := jobio.ParseIndexRow(line); err != nil {
			return 0, fmt.Errorf("index line %d: %w", n+1, err)
		}
		n++
	}
	known.Lock()
	known.m[knownKey{r, path}] = knownFile{idOf(fi), n}
	known.Unlock()
	return n, nil
}

// indexRow is a record row as an index line's fields.
func indexRow(o store.ObjectRow) jobio.IndexRow {
	return jobio.IndexRow{Key: o.Key, Size: o.Size, Ino: o.Ino, CtimeNS: o.CtimeNS, SHA256: hex.EncodeToString(o.SHA256)}
}

// rebuildIndex writes the subject's index file from the record, by rename: a
// row that would not read back fails the write and leaves the old file.
func (r *Runner) rebuildIndex(ctx context.Context, subject string) error {
	path := r.p.IndexFile(subject)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	// A temporary a stop left behind is this subject's (its name says so) and
	// nothing else writes one now: the subject's slot is held.
	stale, _ := filepath.Glob(filepath.Join(dir, "."+filepath.Base(path)+"-*"))
	for _, s := range stale {
		os.Remove(s)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	w := bufio.NewWriterSize(tmp, 1<<20)
	var line []byte
	var n int64
	err = r.st.ObjectRows(ctx, subject, func(o store.ObjectRow) error {
		var err error
		if line, err = jobio.AppendIndexRow(line[:0], indexRow(o)); err == nil {
			_, err = w.Write(line)
			n++
		}
		return err
	})
	if err == nil {
		err = w.Flush()
	}
	if err == nil {
		err = tmp.Chmod(0o444)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	r.remember(path, n)
	return nil
}

// appendIndex appends rows to the subject's index file, all or none: a row
// that would not read back fails the call before anything is written. Any
// failure rebuilds the file from the record, so it is never left short.
func (r *Runner) appendIndex(ctx context.Context, subject string, rows []jobio.IndexRow) error {
	var buf []byte
	var err error
	for _, row := range rows {
		if buf, err = jobio.AppendIndexRow(buf, row); err != nil {
			break
		}
	}
	path := r.p.IndexFile(subject)
	if err == nil {
		// A file known before the append stays known after it.
		k, ok := r.recall(path)
		fi, serr := os.Lstat(path)
		ok = ok && serr == nil && idOf(fi) == k.id
		if err = appendFile(path, buf); err == nil && ok {
			r.remember(path, k.lines+int64(len(rows)))
		} else if err == nil {
			r.forget(path)
		}
	}
	if err != nil {
		r.log.Warn("rebuilding an index file", "subject", subject, "err", clean(err.Error()))
		return r.rebuildIndex(ctx, subject)
	}
	return nil
}

// appendFile appends b to the 0444 file at path, writable for the moment of
// the write only (its directory is root's, 0700).
func appendFile(path string, b []byte) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Chmod(0o444); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
