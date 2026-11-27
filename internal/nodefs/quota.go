package nodefs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// SetQuota sets the user-quota hard limits of uid on the projects mount to
// quotaMB MiB of blocks and max(65536, 256·quotaMB) inodes; 0 clears both.
// No project limit is ever set: a file's owner may give it any project id, so
// a project limit could be consumed by another tenant. The project id stays
// usage accounting only. A non-zero limit is refused with errQuotaNotEnforced
// unless user-quota enforcement is on. xfs_quota is given ids and the mount
// point and opens nothing below it. It reports many failures on standard
// error with exit status 0, so any output there is an error, and the limits
// are read back.
func SetQuota(p nodecfg.Paths, uid, quotaMB int) error {
	if !projectID(uid) {
		return fmt.Errorf("nodefs: invalid project uid %d", uid)
	}
	return setQuotaAt(p.ProjectsDir(), uid, quotaMB)
}

// SetQuotaAt is SetQuota on any XFS mount (a root-owned directory writable
// by no one else), for a project id, exactly the control plane's or the
// replicator's id, or Studio's (dashcfg.StudioUID, for its data volume on the
// projects filesystem); every other id, 0 included, is refused.
func SetQuotaAt(mount string, id, quotaMB int) error {
	if !quotaID(id) && id != dashcfg.StudioUID {
		return fmt.Errorf("nodefs: invalid quota id %d", id)
	}
	return setQuotaAt(mount, id, quotaMB)
}

// quotaID accepts the ids that may carry a user quota: a project id, or
// exactly one of the two platform ids.
func quotaID(id int) bool {
	return projectID(id) || id == nodecfg.ControlPlaneUID || id == nodecfg.ReplicatorUID
}

func setQuotaAt(mount string, uid, quotaMB int) error {
	if quotaMB < 0 || quotaMB > 1<<30 {
		return fmt.Errorf("nodefs: invalid disk quota %d MiB", quotaMB)
	}
	fd, err := openTrustedDir(mount, "")
	if err != nil {
		return err
	}
	var sfs syscall.Statfs_t
	err = syscall.Fstatfs(fd, &sfs)
	syscall.Close(fd)
	if err != nil {
		return err
	}
	if sfs.Type != xfsSuperMagic {
		return fmt.Errorf("nodefs: %s is not XFS", mount)
	}
	inodes := 0
	if quotaMB > 0 {
		state, err := xfsQuota(context.Background(), mount, "state -u")
		if err != nil {
			return err
		}
		if !bytes.Contains(state, []byte("Accounting: ON")) || !bytes.Contains(state, []byte("Enforcement: ON")) {
			return fmt.Errorf("%w (%s)", errQuotaNotEnforced, mount)
		}
		inodes = max(minInodes, quotaMB*inodesPerMB)
	}
	if _, err := xfsQuota(context.Background(), mount, fmt.Sprintf("limit -u bhard=%dm ihard=%d %d", quotaMB, inodes, uid)); err != nil {
		return err
	}
	recs, err := readLimits(mount, uid)
	if err != nil {
		return err
	}
	want := [2]int{quotaMB * 1024, inodes}
	// A cleared quota with no usage prints no record.
	if len(recs) == 1 && recs[0] == want || len(recs) == 0 && quotaMB == 0 {
		return nil
	}
	return fmt.Errorf("nodefs: quota of %d on %s reads %v, want one record of %d KiB / %d inodes", uid, mount, recs, want[0], want[1])
}

// The user quota also caps inodes: XFS does not charge an inode to the block
// quota, so without an inode limit a tenant could fill the filesystem with
// empty files. One inode per 4 KiB of block quota (256 per MiB), at least
// 65,536, bounds that uncharged inode space (512 bytes each) to about an
// eighth of the block quota.
const (
	minInodes   = 65536
	inodesPerMB = 256
)

// Project uids and gids lie within [minProjectID, maxProjectID]: system
// accounts, the usual nobody/nonroot ids and the overflow id are below it,
// and ids from 2^31 on are not portable.
const (
	minProjectID = 1 << 16
	maxProjectID = 1<<31 - 1
)

func projectID(id int) bool { return id >= minProjectID && id <= maxProjectID }

var errQuotaNotEnforced = errors.New("nodefs: user quota is not enforced on the mount")

var bracketRE = regexp.MustCompile(`\[[^\]]*\]`)

// DiskUsage returns the bytes of blocks the user quota of uid charges on the
// projects mount: the quota's own accounting of every file the uid owns
// there, the figure its block limit is enforced against. A uid with neither
// usage nor limits has no record and uses 0 bytes.
func DiskUsage(ctx context.Context, p nodecfg.Paths, uid int) (int64, error) {
	if !projectID(uid) {
		return 0, fmt.Errorf("nodefs: invalid project uid %d", uid)
	}
	recs, err := readQuota(ctx, p.ProjectsDir(), uid)
	switch {
	case err != nil:
		return 0, err
	case len(recs) == 0:
		return 0, nil
	case len(recs) > 1:
		return 0, fmt.Errorf("nodefs: %d quota records for %d on %s, want one", len(recs), uid, p.ProjectsDir())
	}
	return int64(recs[0][0]) << 10, nil
}

// QuotaUsage returns the KiB of blocks the user quota of id charges on mount
// and its block hard limit in KiB (0: none), for the ids SetQuotaAt accepts.
// An id with neither usage nor limits has no record: 0, 0. The quota tool is
// killed, with what it started, when ctx ends; the error is then ctx's.
func QuotaUsage(ctx context.Context, mount string, id int) (usedKB, hardKB int64, err error) {
	if !quotaID(id) && id != dashcfg.StudioUID {
		return 0, 0, fmt.Errorf("nodefs: invalid quota id %d", id)
	}
	if !filepath.IsAbs(mount) {
		return 0, 0, fmt.Errorf("nodefs: mount %q is not absolute", mount)
	}
	recs, err := readQuota(ctx, mount, id)
	switch {
	case err != nil && ctx.Err() != nil:
		return 0, 0, fmt.Errorf("nodefs: quota of %d on %s: %w", id, mount, ctx.Err())
	case err != nil:
		return 0, 0, err
	case len(recs) == 0:
		return 0, 0, nil
	case len(recs) > 1:
		return 0, 0, fmt.Errorf("nodefs: %d quota records for %d on %s, want one", len(recs), id, mount)
	}
	return int64(recs[0][0]), int64(recs[0][1]), nil
}

// readLimits returns the (block hard limit in KiB, inode hard limit) of each
// user-quota record xfs_quota prints for uid on mount. A quota with neither
// limits nor usage prints no record.
func readLimits(mount string, uid int) ([][2]int, error) {
	recs, err := readQuota(context.Background(), mount, uid)
	var out [][2]int
	for _, r := range recs {
		out = append(out, [2]int{r[1], r[2]})
	}
	return out, err
}

// maxUsedKiB bounds a parsed usage (1 PiB, far above any quota) so that its
// bytes, and the MiB rounding of callers, stay within int64.
const maxUsedKiB = 1 << 40

// readQuota returns the (blocks used in KiB, block hard limit in KiB, inode
// hard limit) of each user-quota record xfs_quota prints for uid on mount.
func readQuota(ctx context.Context, mount string, uid int) ([][3]int, error) {
	out, err := xfsQuota(ctx, mount, fmt.Sprintf("quota -v -N -b -i -u %d", uid))
	if err != nil {
		return nil, err
	}
	// A device name too long for its column goes on a line of its own,
	// the numbers on the next, indented one.
	out = bytes.ReplaceAll(out, []byte("\n "), []byte(" "))
	var recs [][3]int
	for _, l := range strings.Split(string(out), "\n") {
		// device, used, soft, hard, warn, [grace], used, soft, hard, warn, [grace], mount
		f := strings.Fields(bracketRE.ReplaceAllString(l, " "))
		if len(f) == 0 {
			continue
		}
		if len(f) != 10 {
			return nil, fmt.Errorf("nodefs: unexpected quota record %q", l)
		}
		u, err0 := strconv.Atoi(f[1])
		b, err1 := strconv.Atoi(f[3])
		i, err2 := strconv.Atoi(f[7])
		if err0 != nil || err1 != nil || err2 != nil || u < 0 || u > maxUsedKiB {
			return nil, fmt.Errorf("nodefs: unexpected quota record %q", l)
		}
		recs = append(recs, [3]int{u, b, i})
	}
	return recs, nil
}

func xfsQuota(ctx context.Context, mount string, cmds ...string) ([]byte, error) {
	args := []string{"-x"}
	for _, c := range cmds {
		args = append(args, "-c", c)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "xfs_quota", append(args, mount)...)
	// A context that ends kills the tool and anything it started.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	// Its messages are translated; the state check needs the C locale.
	cmd.Env = []string{"LC_ALL=C", "PATH=" + os.Getenv("PATH")}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil && stderr.Len() > 0 {
		err = errors.New("error output")
	}
	if err != nil {
		return nil, fmt.Errorf("nodefs: xfs_quota %q: %w: %s", cmds, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// CheckRange returns an error when [base, base+count) contains a uid or gid
// of passwd or group, or intersects a range of subuid or subgid (nil subuid
// or subgid readers stand for absent files), and when the range does not lie
// within [65536, 2^31-1]. A malformed line is an error.
func CheckRange(base, count int, passwd, group, subuid, subgid io.Reader) error {
	if count <= 0 || !projectID(base) || !projectID(base+count-1) {
		return fmt.Errorf("nodefs: id range %d+%d is not within [65536, 2^31-1]", base, count)
	}
	if passwd == nil || group == nil {
		return errors.New("nodefs: passwd and group are required")
	}
	lo, hi := uint64(base), uint64(base)+uint64(count)
	inside := func(file string, n int, v uint64) error {
		if v >= lo && v < hi {
			return fmt.Errorf("nodefs: %s line %d: id %d is inside the reserved range [%d, %d)", file, n, v, lo, hi)
		}
		return nil
	}
	ids := func(file string, r io.Reader, minFields int, cols ...int) error {
		return eachLine(file, r, minFields, func(n int, f []uint64) error {
			for _, c := range cols {
				if err := inside(file, n, f[c]); err != nil {
					return err
				}
			}
			return nil
		}, cols...)
	}
	sub := func(file string, r io.Reader) error {
		return eachLine(file, r, 3, func(n int, f []uint64) error {
			if start, cnt := f[1], f[2]; cnt > 0 && start < hi && start+cnt > lo {
				return fmt.Errorf("nodefs: %s line %d: [%d, %d) intersects the reserved range [%d, %d)", file, n, start, start+cnt, lo, hi)
			}
			return nil
		}, 1, 2)
	}
	if err := ids("passwd", passwd, 7, 2, 3); err != nil {
		return err
	}
	if err := ids("group", group, 4, 2); err != nil {
		return err
	}
	if err := sub("subuid", subuid); err != nil {
		return err
	}
	return sub("subgid", subgid)
}

// eachLine calls fn for every non-blank, non-comment line of a colon-separated
// file with at least minFields fields, the columns in cols parsed as 32-bit
// unsigned integers (other columns are zero).
func eachLine(file string, r io.Reader, minFields int, fn func(n int, f []uint64) error, cols ...int) error {
	if r == nil {
		return nil
	}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < minFields {
			return fmt.Errorf("nodefs: %s line %d: malformed", file, n)
		}
		f := make([]uint64, len(parts))
		for _, c := range cols {
			v, err := strconv.ParseUint(parts[c], 10, 32)
			if err != nil {
				return fmt.Errorf("nodefs: %s line %d: malformed id", file, n)
			}
			f[c] = v
		}
		if err := fn(n, f); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("nodefs: read %s: %w", file, err)
	}
	return nil
}
