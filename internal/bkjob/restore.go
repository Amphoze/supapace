package bkjob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/walname"
)

// The restore job's failure codes.
const (
	restoreTablespace = "tablespace"       // the set holds a tablespace or a link: refused before anything is written
	restoreHistory    = "history_mismatch" // the tool's 58: the set's timeline does not lead to the target timeline
	restoreSetInvalid = "set_invalid"      // the tool's 75 or a signal, or a manifest that cannot be read or is refused
	restoreTool       = "pgbackrest"       // any other failure of the restore
)

// restoreData is the data directory the restore writes (PGBACKREST_PG1_PATH).
var restoreData = "/var/lib/postgresql/data"

// Restore restores set in.Set into the empty data directory: it reads the
// set's manifest first and refuses a tablespace, a link or a path outside the
// data directory's form before anything is written (checkManifest); then the
// tool's restore --set=<label> --type=none, or for the one standby retry
// --type=standby --target-timeline=<n>; then recovery.signal — written by the
// job for none, put in place of the tool's standby.signal for standby — so
// that the recovery start replays to the target the command line pins.
//
// A failed or stopped restore leaves the data directory as the tool left it,
// without recovery.signal: the operation wipes it before the next restore, and
// a restore into a directory that is not empty is refused before the tool
// runs. No message carries the passphrase.
func Restore(ctx context.Context, in jobio.Input) (jobio.RestoreResult, error) {
	if k, _, _, ok := walname.RepoPath(in.Stanza, "backup/"+in.Stanza+"/"+in.Set+"/backup.manifest"); !ok || k != walname.SetManifest {
		return jobio.RestoreResult{}, fmt.Errorf("bkjob: restore: set %q of stanza %q is not a set label", in.Set, in.Stanza)
	}
	args := []string{"restore", "--set=" + in.Set}
	switch {
	case in.Mode == "none" && in.TargetTimeline == 0:
		args = append(args, "--type=none")
	case in.Mode == "standby" && in.TargetTimeline > 0 && uint64(in.TargetTimeline) <= math.MaxUint32:
		args = append(args, "--type=standby", "--target-timeline="+strconv.Itoa(in.TargetTimeline))
	default:
		return jobio.RestoreResult{}, fmt.Errorf("bkjob: restore: mode %q with target timeline %d", in.Mode, in.TargetTimeline)
	}
	empty, err := emptyDir(restoreData)
	if err != nil {
		return jobio.RestoreResult{}, failQuiet(restoreTool, "reading the data directory: %v", err)
	}
	if !empty {
		return jobio.RestoreResult{}, failQuiet(restoreTool, "the data directory is not empty")
	}
	setKey, err := checkManifest(ctx, in.Stanza, in.Set)
	if err != nil {
		return jobio.RestoreResult{}, err
	}
	r, err := restoreRun(ctx, in, args)
	return r, hide(err, setKey)
}

// restoreRun runs the restore and puts the recovery signal in place.
func restoreRun(ctx context.Context, in jobio.Input, args []string) (jobio.RestoreResult, error) {
	exit, out, err := Run(ctx, args...)
	var ee *exec.ExitError
	switch {
	case err != nil && errors.As(err, &ee):
		return jobio.RestoreResult{}, failQuiet(restoreSetInvalid, "restore of set %s: %v", in.Set, ee)
	case err != nil:
		return jobio.RestoreResult{}, err
	case exit == 58:
		return jobio.RestoreResult{}, failQuiet(restoreHistory, "restore of set %s: %s", in.Set, errorLine(out))
	case exit == 75:
		return jobio.RestoreResult{}, failQuiet(restoreSetInvalid, "restore of set %s: %s", in.Set, errorLine(out))
	case exit != 0:
		return jobio.RestoreResult{}, failQuiet(restoreTool, "restore of set %s: exit %d: %s", in.Set, exit, errorLine(out))
	}
	if err := recoverySignal(in.Mode == "standby"); err != nil {
		return jobio.RestoreResult{}, failQuiet(restoreTool, "the recovery signal: %v", err)
	}
	return jobio.RestoreResult{OK: true, Mode: in.Mode}, nil
}

// emptyDir reports whether dir, opened without following a link, has no entry.
func emptyDir(dir string) (bool, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if len(names) > 0 {
		return false, nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return true, nil
}

// recoverySignal puts recovery.signal into the data directory: for standby,
// the tool's standby.signal renamed to it (a standby signal left beside it
// would keep the server in standby); else a new empty file. Never through a
// link.
func recoverySignal(standby bool) error {
	d, err := syscall.Open(restoreData, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(d)
	if standby {
		var st syscall.Stat_t
		if err := statNoFollow(d, "standby.signal", &st); err != nil {
			return fmt.Errorf("the tool wrote no standby.signal: %w", err)
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return errors.New("standby.signal is not a regular file")
		}
		return syscall.Renameat(d, "standby.signal", d, "recovery.signal")
	}
	fd, err := syscall.Openat(d, "recovery.signal", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}

// failQuiet is fail with the passphrase, should a message ever carry it,
// replaced: tool output and manifest names reach the message.
func failQuiet(code, format string, a ...any) error {
	m := fmt.Sprintf(format, a...)
	if p := os.Getenv(PassName); p != "" {
		m = strings.ReplaceAll(m, p, "[passphrase]")
	}
	return fail(code, "%s", m)
}

// hide replaces secret in the message of a job failure err.
func hide(err error, secret string) error {
	var e *Error
	if secret == "" || !errors.As(err, &e) {
		return err
	}
	m := strings.ReplaceAll(e.Message, secret, "[set key]")
	// The message was cut to its bound before: a key cut there leaves its start.
	for i := len(secret) - 1; i > 0; i-- {
		if strings.HasSuffix(m, secret[:i]) {
			m = strings.TrimSuffix(m, secret[:i])
			break
		}
	}
	return fail(e.Code, "%s", m)
}
