package repl

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"sort"

	"github.com/Amphoze/supapace/internal/jobio"
)

// index is the daemon's record of the subject, as the index file holds it,
// at 40 bytes a row: a 64-bit hash of the key, the row's offset in the file,
// size, inode and ctime. A hit is confirmed by reading the key at its offset,
// so two keys on one hash are never taken for each other. Rows are kept in
// fixed chunks, so loading never copies them to a larger array.
type index struct {
	chunks [][]irow
	n      int
	file   io.ReaderAt
}

type irow struct {
	hash    uint64
	off     int64 // offset of the line; bit 63 set: the row has no hash
	size    int64
	ino     int64
	ctimeNS int64
}

const (
	noHash    = int64(-1) << 63
	chunkBits = 16
	chunkLen  = 1 << chunkBits
)

type hit struct {
	size, ino, ctimeNS int64
	hasHash            bool
}

// ErrIndex is an index file that does not read: the daemon writes it again.
var ErrIndex = errors.New("repl: the index file")

var seed = maphash.MakeSeed()

// keyHash is a seam: a test forces collisions through it.
var keyHash = func(k string) uint64 { return maphash.String(seed, k) }

func (ix *index) at(i int) *irow { return &ix.chunks[i>>chunkBits][i&(chunkLen-1)] }

// sort.Interface, by hash.
func (ix *index) Len() int           { return ix.n }
func (ix *index) Less(i, j int) bool { return ix.at(i).hash < ix.at(j).hash }
func (ix *index) Swap(i, j int)      { a, b := ix.at(i), ix.at(j); *a, *b = *b, *a }

// loadIndex reads the index file once. A malformed line is an error: the job
// fails and the daemon writes the file again.
func loadIndex(r io.Reader) (*index, error) {
	ra, ok := r.(io.ReaderAt)
	if !ok {
		return nil, fmt.Errorf("%w must be readable at an offset", ErrIndex)
	}
	ix := &index{file: ra}
	br := bufio.NewReaderSize(r, 4096)
	var off int64
	for {
		line, err := br.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: line at byte %d unterminated or longer than 4 KiB", ErrIndex, off)
		}
		row, err := jobio.ParseIndexRow(line)
		if err != nil {
			return nil, fmt.Errorf("%w: line at byte %d: %w", ErrIndex, off, err)
		}
		o := off
		if row.SHA256 == "" {
			o |= noHash
		}
		if ix.n&(chunkLen-1) == 0 {
			ix.chunks = append(ix.chunks, make([]irow, chunkLen))
		}
		*ix.at(ix.n) = irow{keyHash(row.Key), o, row.Size, row.Ino, row.CtimeNS}
		ix.n++
		off += int64(len(line))
	}
	sort.Sort(ix)
	return ix, nil
}

// lookup finds key, confirming each row of its hash by the key at its offset.
func (ix *index) lookup(key string) (hit, bool, error) {
	h := keyHash(key)
	buf := make([]byte, len(key)+1)
	for i := sort.Search(ix.n, func(i int) bool { return ix.at(i).hash >= h }); i < ix.n && ix.at(i).hash == h; i++ {
		r := ix.at(i)
		n, err := ix.file.ReadAt(buf, r.off&^noHash)
		if n < len(buf) && err != nil && err != io.EOF {
			return hit{}, false, fmt.Errorf("repl: index: %w", err)
		}
		if n == len(buf) && bytes.Equal(buf[:len(key)], []byte(key)) && buf[len(key)] == '\t' {
			return hit{r.size, r.ino, r.ctimeNS, r.off&noHash == 0}, true, nil
		}
	}
	return hit{}, false, nil
}
