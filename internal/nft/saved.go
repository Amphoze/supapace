package nft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
)

// One lock, Paths.NftLock(), serialises every writer of the ruleset file, the
// addresses file and the tables with every check, in every process: Load,
// InstallSet and EnsureRules take it exclusive; Check, SavedSet and RenderSaved
// shared. Without it a check could see a new file over the old tables (drift),
// and a renderer that read the saved set before another process's install
// could write the old set back. The functions ending in Locked expect the
// caller to hold it: a second request on a new descriptor would block the
// very process that holds it.

// lockRetry is how often a held lock is tried again.
const lockRetry = 10 * time.Millisecond

// savedWait bounds the wait for the lock of SavedSet and RenderSaved, which
// take no context.
var savedWait = 30 * time.Second

// maxAddrsFile bounds the addresses file that SavedSet reads.
const maxAddrsFile = 64 << 10

// maxElements bounds the off-site set: its addresses file (at most 22 bytes a
// line) then always stays far below maxAddrsFile, so InstallSet never saves a
// set SavedSet refuses.
const maxElements = 256

// testHook is called at named points: "busy" when a lock is first found
// held, "saved" when EnsureRules has read the saved set, "addresses" when
// InstallSet has written the addresses file. Tests only.
var testHook = func(string) {}

// lock takes an flock (how: LOCK_SH or LOCK_EX) on the lock file, creating it
// 0600 when absent and never through a link. It does not block: a held lock
// is tried again until ctx ends, and then the context's error is returned.
func lock(ctx context.Context, p nodecfg.Paths, how int) (unlock func(), err error) {
	// Never blocks on a FIFO or a device and takes no terminal; anything but a
	// regular file is refused.
	f, err := os.OpenFile(p.NftLock(), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("nft: lock: %w", err)
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("nft: lock: %s is not a regular file", p.NftLock())
	}
	busy := false
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("nft: lock: %w", err)
		}
		if !busy {
			busy = true
			testHook("busy")
		}
		t := time.NewTimer(lockRetry)
		select {
		case <-ctx.Done():
			t.Stop()
			f.Close()
			return nil, fmt.Errorf("nft: lock %s not obtained: %w", p.NftLock(), ctx.Err())
		case <-t.C:
		}
	}
}

// normalize checks that every element is an IPv4 address with a port other
// than 0 and returns the elements sorted, without duplicates.
func normalize(set []netip.AddrPort) ([]netip.AddrPort, error) {
	if len(set) > maxElements {
		return nil, fmt.Errorf("nft: %d off-site elements, at most %d", len(set), maxElements)
	}
	out := make([]netip.AddrPort, 0, len(set))
	for _, e := range set {
		if !e.IsValid() || !e.Addr().Is4() || e.Port() == 0 {
			return nil, fmt.Errorf("nft: off-site element %q is not an IPv4 address and port", e)
		}
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return slices.Compact(out), nil
}

// SavedSet returns the set of the addresses file: the set the loaded tables
// hold. No file: none. A file that is not one "ip:port" per line, each an IPv4
// address with a port other than 0, is refused.
func SavedSet(p nodecfg.Paths) ([]netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(context.Background(), savedWait)
	defer cancel()
	unlock, err := lock(ctx, p, syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return savedSetLocked(p)
}

// RenderSaved is RenderWith(c, SavedSet(p)), under one hold of the lock.
func RenderSaved(c nodecfg.Config, p nodecfg.Paths) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), savedWait)
	defer cancel()
	unlock, err := lock(ctx, p, syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer unlock()
	set, err := savedSetLocked(p)
	if err != nil {
		return nil, err
	}
	return RenderWith(c, set)
}

func savedSetLocked(p nodecfg.Paths) ([]netip.AddrPort, error) {
	path := p.OffsiteAddrs()
	// O_NONBLOCK: a FIFO in its place must not block the open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("nft: %w", err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !ownRegular(fi) {
		return nil, fmt.Errorf("nft: %s is not a regular file of mode 0600 owned by uid %d", path, os.Geteuid())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAddrsFile+1))
	if err != nil {
		return nil, fmt.Errorf("nft: %w", err)
	}
	if len(b) > maxAddrsFile {
		return nil, fmt.Errorf("nft: %s is larger than %d bytes", path, maxAddrsFile)
	}
	if len(b) == 0 {
		return nil, nil
	}
	if b[len(b)-1] != '\n' {
		return nil, fmt.Errorf("nft: %s does not end with a newline", path)
	}
	var set []netip.AddrPort
	for i, l := range strings.Split(string(b[:len(b)-1]), "\n") {
		e, err := netip.ParseAddrPort(l)
		if err != nil || e.String() != l || !e.Addr().Is4() || e.Port() == 0 {
			return nil, fmt.Errorf("nft: %s line %d: %q is not an IPv4 address and port", path, i+1, l)
		}
		set = append(set, e)
	}
	return set, nil
}

// InstallSet makes set the off-site set of the tables and of both files.
// Under the exclusive lock: render, write the ruleset file when it differs,
// load it, and only after a successful load write the addresses file, then
// the checksum. A failure at the load or after it puts both files back as
// they were (and, after the load, loads the previous ruleset again), so the
// files always describe the tables that are loaded.
func InstallSet(ctx context.Context, p nodecfg.Paths, c nodecfg.Config, set []netip.AddrPort) error {
	set, err := normalize(set)
	if err != nil {
		return err
	}
	rules, err := RenderWith(c, set)
	if err != nil {
		return err
	}
	var addrs []byte
	for _, e := range set {
		addrs = append(addrs, e.String()+"\n"...)
	}
	unlock, err := lock(ctx, p, syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlock()
	return installSetLocked(ctx, p, rules, addrs)
}

func installSetLocked(ctx context.Context, p nodecfg.Paths, rules, addrs []byte) error {
	prevRules, hadRules, err := readFile(p.NftFile())
	if err != nil {
		return err
	}
	wroteRules := !hadRules || !bytes.Equal(prevRules, rules)
	if wroteRules {
		if err := writeEtc(p, p.NftFile(), rules); err != nil {
			return err
		}
	}
	// putBack restores what was written, oldest state first; after the load
	// it loads the previous ruleset again. The restore load runs even when
	// ctx has ended, bounded by its own deadline.
	var wroteAddrs, hadAddrs bool
	var prevAddrs []byte
	putBack := func(cause error, reload bool) error {
		errs := []error{cause}
		// An addresses file that cannot be put back ends the put-back: the
		// files and tables stay at the new set under the old checksum, so Check
		// reports drift and EnsureRules converges, instead of the saved set
		// naming addresses the tables do not hold while Check passes.
		if wroteAddrs {
			if err := restore(p, p.OffsiteAddrs(), prevAddrs, hadAddrs); err != nil {
				return errors.Join(cause, err)
			}
		}
		if wroteRules {
			errs = append(errs, restore(p, p.NftFile(), prevRules, hadRules))
		}
		if reload && hadRules {
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			if _, err := nft(rctx, prevRules, "-f", "-"); err != nil {
				errs = append(errs, fmt.Errorf("nft: loading the previous ruleset again: %w", err))
			}
		}
		return errors.Join(errs...)
	}
	// A failed transaction changes no table.
	if _, err := nft(ctx, rules, "-f", "-"); err != nil {
		return putBack(fmt.Errorf("nft: load: %w", err), false)
	}
	listing, err := listTables(ctx)
	if err != nil {
		return putBack(fmt.Errorf("nft: load: %w", err), true)
	}
	if prevAddrs, hadAddrs, err = readAddrs(p.OffsiteAddrs()); err != nil {
		return putBack(err, true)
	}
	if !hadAddrs || !bytes.Equal(prevAddrs, addrs) || !ownFile(p.OffsiteAddrs()) {
		wroteAddrs = true
		if err := writeEtc(p, p.OffsiteAddrs(), addrs); err != nil {
			return putBack(err, true)
		}
		testHook("addresses")
	}
	if err := writeFile(p.NftSum(), sums(rules, listing)); err != nil {
		return putBack(err, true)
	}
	return EnsureBridgeNF()
}

// EnsureRules renders the ruleset from the saved set and writes the file when
// it differs (content, mode or owner); it reports whether it wrote. With load
// it then loads when the file changed or the check fails, and checks again: a
// check that still fails is its error. All under the exclusive lock. It is the
// one way the ruleset file is written outside a set change.
func EnsureRules(ctx context.Context, p nodecfg.Paths, c nodecfg.Config, load bool) (changed bool, err error) {
	unlock, err := lock(ctx, p, syscall.LOCK_EX)
	if err != nil {
		return false, err
	}
	defer unlock()
	return ensureRules(ctx, p, c, load)
}

func ensureRules(ctx context.Context, p nodecfg.Paths, c nodecfg.Config, load bool) (bool, error) {
	set, err := savedSetLocked(p)
	if err != nil {
		return false, err
	}
	testHook("saved")
	want, err := RenderWith(c, set)
	if err != nil {
		return false, err
	}
	have, had, err := readFile(p.NftFile())
	if err != nil {
		return false, err
	}
	changed := !had || !bytes.Equal(have, want) || !ownFile(p.NftFile())
	if changed {
		if err := writeEtc(p, p.NftFile(), want); err != nil {
			return false, err
		}
	}
	if !load || !changed && checkLocked(ctx, p) == nil {
		return changed, nil
	}
	if err := loadLocked(ctx, p); err != nil {
		return changed, err
	}
	return changed, checkLocked(ctx, p)
}

// readFile returns the file's content and whether it exists.
func readFile(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("nft: %w", err)
	}
	return b, true, nil
}

// readAddrs reads the previous addresses file for the comparison and the
// put-back, opened as savedSetLocked opens it: no link followed, never
// blocking, at most maxAddrsFile bytes. A link, FIFO, socket or device at the
// path is removed without being read, and a file over the bound is not kept:
// every reader refuses both, so they hold no set and read as absent — the
// put-back then leaves no file (none). A directory stays an error.
func readAddrs(path string) ([]byte, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOCTTY, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENXIO): // a link; a socket
		return nil, false, unlinkAddrs(path)
	case err != nil:
		return nil, false, fmt.Errorf("nft: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("nft: %w", err)
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return nil, false, unlinkAddrs(path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAddrsFile+1))
	if err != nil {
		return nil, false, fmt.Errorf("nft: %w", err)
	}
	if len(b) > maxAddrsFile {
		return nil, false, nil
	}
	return b, true, nil
}

// unlinkAddrs removes what is not a regular file at path, so that the write
// (which refuses to replace one) can put a file there; never a directory.
func unlinkAddrs(path string) error {
	if err := syscall.Unlink(path); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("nft: removing %s: %w", path, err)
	}
	return nil
}

// ownFile reports whether path is a regular file, 0600, owned by this process's uid.
func ownFile(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && ownRegular(fi)
}

func ownRegular(fi os.FileInfo) bool {
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// writeEtc replaces a file of the configuration directory, 0600, through
// nodefs.WriteFile (no link followed; its temporary name is the one init
// clears after an interruption).
func writeEtc(p nodecfg.Paths, path string, data []byte) error {
	return nodefs.WriteFile(p, filepath.Dir(path), filepath.Base(path), data, 0o600, os.Geteuid(), os.Getegid())
}

// restore puts a file back to prev, or removes it when it did not exist.
func restore(p nodecfg.Paths, path string, prev []byte, existed bool) error {
	if existed {
		return writeEtc(p, path, prev)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("nft: %w", err)
	}
	return nil
}
