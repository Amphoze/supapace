package bkjob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/rmtree"
)

// The seed job's failure code.
const seedFailed = "seed"

// seedSync makes a copied file or directory durable before the job reports
// done: a crash after the seed is recorded must not leave the repository
// short. Tests record the calls.
var seedSync = func(fd int, _ string) error { return syscall.Fsync(fd) }

// seedDepthMax bounds how deep fetch/ may go: the repository's deepest path,
// a set's file below pg_data/, is far above it only by a crafted tree.
const seedDepthMax = 32

// seedNameRE is one name of a path the repository uses.
var seedNameRE = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,255}$`)

// Seed makes repo a copy of fetch: it checks the whole of fetch first —
// directories and regular files only, never through a link, names of the
// repository's characters, at most 32 levels — then empties repo (every
// directory removed with rmtree, every other entry unlinked by name) and
// copies fetch into it by descriptor, relative paths kept, directories 0750
// and files 0640 (the repository's modes, which the replicator reads by its
// group). It runs at the project's uid: what it writes is the project's and
// counts against its repository quota. Nothing is followed in either tree.
func Seed(ctx context.Context, repo, fetch string) (jobio.SeedResult, error) {
	res := jobio.SeedResult{OK: true}
	if !filepath.IsAbs(repo) || filepath.Clean(repo) != repo {
		return res, fmt.Errorf("bkjob: seed: repository path %q is not absolute and clean", repo)
	}
	src, err := openDirNoFollow(-100, fetch)
	if err != nil {
		return res, fail(seedFailed, "opening the fetched tree: %v", err)
	}
	defer syscall.Close(src)
	if err := seedWalk(ctx, src, -1, ".", 0, nil); err != nil {
		return res, fail(seedFailed, "the fetched tree: %v", err)
	}
	if err := seedEmpty(repo); err != nil {
		return res, fail(seedFailed, "emptying the repository: %v", err)
	}
	dst, err := openDirNoFollow(-100, repo)
	if err != nil {
		return res, fail(seedFailed, "opening the repository: %v", err)
	}
	defer syscall.Close(dst)
	if err := seedWalk(ctx, src, dst, ".", 0, &res); err != nil {
		return res, fail(seedFailed, "copying: %v", err)
	}
	if err := seedSync(dst, "."); err != nil {
		return res, fail(seedFailed, "syncing the repository: %v", err)
	}
	return res, nil
}

// openDirNoFollow opens directory name of dirfd, never through a link.
func openDirNoFollow(dirfd int, name string) (int, error) {
	return syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
}

// seedWalk checks the tree of src (rel is its path in fetch/) and, when dst
// is a descriptor, copies it there; res counts the files copied.
func seedWalk(ctx context.Context, src, dst int, rel string, depth int, res *jobio.SeedResult) error {
	d, err := dirFile(src, rel)
	if err != nil {
		return err
	}
	defer d.Close()
	for {
		ents, rerr := d.ReadDir(256)
		for _, e := range ents {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := e.Name()
			p := filepath.Join(rel, name)
			if !seedNameRE.MatchString(name) || name == "." || name == ".." {
				return fmt.Errorf("a name outside the repository's characters at %s", quoteName(p))
			}
			var st syscall.Stat_t
			if err := statNoFollow(src, name, &st); err != nil {
				return err
			}
			switch st.Mode & syscall.S_IFMT {
			case syscall.S_IFDIR:
				if depth+1 > seedDepthMax {
					return fmt.Errorf("deeper than %d levels at %s", seedDepthMax, quoteName(p))
				}
				if err := seedDir(ctx, src, dst, name, p, depth+1, res); err != nil {
					return err
				}
			case syscall.S_IFREG:
				if dst >= 0 {
					n, err := seedFile(src, dst, name)
					if err != nil {
						return fmt.Errorf("%s: %w", quoteName(p), err)
					}
					res.Files++
					res.Bytes += n
				}
			default:
				return fmt.Errorf("a link or special file at %s", quoteName(p))
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// seedDir walks the directory name of src and, when copying, makes it in dst.
func seedDir(ctx context.Context, src, dst int, name, p string, depth int, res *jobio.SeedResult) error {
	sub, err := openDirNoFollow(src, name)
	if err != nil {
		return fmt.Errorf("%s: %w", quoteName(p), err)
	}
	defer syscall.Close(sub)
	dsub := -1
	if dst >= 0 {
		if err := syscall.Mkdirat(dst, name, 0o750); err != nil {
			return fmt.Errorf("%s: %w", quoteName(p), err)
		}
		if dsub, err = openDirNoFollow(dst, name); err != nil {
			return fmt.Errorf("%s: %w", quoteName(p), err)
		}
		defer syscall.Close(dsub)
		if err := syscall.Fchmod(dsub, 0o750); err != nil {
			return err
		}
	}
	if err := seedWalk(ctx, sub, dsub, p, depth, res); err != nil {
		return err
	}
	if dsub >= 0 {
		return seedSync(dsub, p)
	}
	return nil
}

// seedFile copies the regular file name of src to a new file of dst.
func seedFile(src, dst int, name string) (int64, error) {
	sfd, err := syscall.Openat(src, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	r := os.NewFile(uintptr(sfd), name)
	defer r.Close()
	if fi, err := r.Stat(); err != nil || !fi.Mode().IsRegular() {
		return 0, errors.Join(err, errors.New("not a regular file"))
	}
	dfd, err := syscall.Openat(dst, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o640)
	if err != nil {
		return 0, err
	}
	w := os.NewFile(uintptr(dfd), name)
	n, err := io.Copy(w, r)
	if err == nil {
		err = w.Chmod(0o640)
	}
	if err == nil {
		err = seedSync(int(w.Fd()), name)
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// seedEmpty removes every entry of the directory repo: directories with
// rmtree (which never follows a link), anything else unlinked by name. repo
// must be empty afterwards.
func seedEmpty(repo string) error {
	fd, err := openDirNoFollow(-100, repo)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	for pass := 0; ; pass++ {
		d, err := dirFile(fd, repo)
		if err != nil {
			return err
		}
		seen := 0
		for err == nil {
			var names []string
			names, err = d.Readdirnames(1024)
			seen += len(names)
			if pass == 2 && len(names) > 0 {
				d.Close()
				return fmt.Errorf("entries are left, %s among them", quoteName(names[0]))
			}
			for _, name := range names {
				var st syscall.Stat_t
				if serr := statNoFollow(fd, name, &st); serr != nil {
					d.Close()
					return serr
				}
				rerr := error(nil)
				if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
					rerr = rmtree.Remove(filepath.Join(repo, name))
				} else {
					rerr = syscall.Unlinkat(fd, name)
				}
				if rerr != nil {
					d.Close()
					return rerr
				}
			}
		}
		d.Close()
		if !errors.Is(err, io.EOF) {
			return err
		}
		// Removals while a directory is read may hide entries from the read:
		// it is read again until a pass finds nothing.
		if seen == 0 {
			return nil
		}
	}
}
