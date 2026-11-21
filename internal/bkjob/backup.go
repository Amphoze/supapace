package bkjob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// The failure codes of stanza-create, backup and check. A push nested in one
// of them never passes its own code on: its failure is one of these, the
// push's code in the message.
const (
	CodeLogin          = "login"           // the server refused the backup role's login
	CodeArchiveTimeout = "archive_timeout" // the tool's exit 82: its WAL was not pushed in time
	CodePgbackrest     = "pgbackrest"      // any other failure of the tool or of a push
	CodeTablespace     = "tablespace"      // the data directory holds a tablespace
	CodeSymlink        = "symlink"         // the data directory holds a link, or could not be walked whole
)

var (
	// dataRoot and spoolRoot are where the job mounts the data directory
	// (read-only) and the spool.
	dataRoot  = "/var/lib/postgresql/data"
	spoolRoot = "/spool"
	// pushEvery is the pause between two passes of the push loop.
	pushEvery = 500 * time.Millisecond
)

// StanzaCreate creates the stanza — again without harm when it exists — and
// then pushes the spool once. No push runs before: there is no stanza yet.
func StanzaCreate(ctx context.Context, in jobio.Input) (jobio.CheckJobResult, error) {
	p, err := withPush(ctx, in, false, "stanza-create")
	if err != nil {
		return jobio.CheckJobResult{}, err
	}
	return jobio.CheckJobResult{OK: true, Push: &p}, nil
}

// Check runs the tool's check, which waits for a segment it has the server
// switch to reach the repository: the spool is pushed meanwhile.
func Check(ctx context.Context, in jobio.Input) (jobio.CheckJobResult, error) {
	p, err := withPush(ctx, in, true, "check")
	if err != nil {
		return jobio.CheckJobResult{}, err
	}
	return jobio.CheckJobResult{OK: true, Push: &p}, nil
}

// Backup takes a full backup, the spool pushed meanwhile (the tool waits for
// the backup's last segment), and reads the new set from the tool's info
// answer: the newest label, checked for its form like everything else taken
// from it.
func Backup(ctx context.Context, in jobio.Input) (jobio.BackupResult, error) {
	if in.Type != "full" {
		return jobio.BackupResult{}, refuse(CodePgbackrest, "backup type %q: only full", in.Type)
	}
	p, err := withPush(ctx, in, true, "backup", "--type=full")
	if err != nil {
		return jobio.BackupResult{}, err
	}
	// The answer grows with every set the repository keeps: it is read under a
	// bound of its own. Its peak cost is a few times the bound — the kept
	// bytes, their string, the decoded sets — well inside the job's 512 MiB.
	exit, out, err := run(ctx, infoMax, "info", "--output=json")
	pre := unlisted(len(p.Quarantined))
	switch {
	case err != nil:
		return jobio.BackupResult{}, refuse(CodePgbackrest, pre+"info: %v", err)
	case len(out) >= infoMax:
		return jobio.BackupResult{}, refuse(CodePgbackrest,
			pre+"the repository holds too many sets for this version: the info answer is above %d MiB", infoMax>>20)
	case exit != 0:
		return jobio.BackupResult{}, refuse(CodePgbackrest, pre+"info: exit %d: %s", exit, errorLine(out))
	}
	r, err := newestSet(in.Stanza, out)
	if err != nil {
		return jobio.BackupResult{}, refuse(CodePgbackrest, pre+"info: %v", err)
	}
	r.Push = &p
	return r, nil
}

// withPush runs the tree pre-check, then the tool with args — with the push
// loop beside it when loop is set — and, once the tool succeeded, the final
// push, whose result it returns.
//
// The loop is stopped by a flag between two passes and waited for before the
// final push starts: a pass is never cut short, so no archive-push is killed
// half-way and no two ever run at once.
func withPush(ctx context.Context, in jobio.Input, loop bool, args ...string) (jobio.PushResult, error) {
	if err := precheck(dataRoot); err != nil {
		return jobio.PushResult{}, err
	}
	stop, done := make(chan struct{}), make(chan pushLog, 1)
	if loop {
		go pushLoop(ctx, in, stop, done)
	} else {
		done <- pushLog{}
	}
	exit, out, err := Run(ctx, args...)
	close(stop)
	lg := <-done
	switch {
	case err != nil:
		return jobio.PushResult{}, refuse(CodePgbackrest, unlisted(lg.set)+"%s: %v", args[0], err)
	case exit != 0:
		return jobio.PushResult{}, toolFailure(args[0], exit, out, lg)
	}
	p, err := Push(ctx, in, spoolRoot)
	if err != nil {
		return jobio.PushResult{}, refuse(CodePgbackrest, unlisted(lg.set)+"%s succeeded, the push after it failed: %s",
			args[0], pushText(err))
	}
	// What the loop's passes set aside is listed with the final pass's, so that
	// the record sees every entry renamed during the job (at most the list's
	// bound; the final pass's own come first).
	for _, q := range lg.quarantined {
		if len(p.Quarantined) == quarantinedMax {
			break
		}
		p.Quarantined = append(p.Quarantined, q)
	}
	return p, nil
}

// quarantinedMax is the bound of a push result's quarantined list
// (bklimit.PushMaxEntries).
const quarantinedMax = 56

// pushLog is what the loop's passes leave: the failure of the last pass, if
// it failed, the entries they set aside (at most the list's bound) and how
// many they set aside in all.
type pushLog struct {
	last        error
	quarantined []jobio.Quarantined
	set         int
}

func pushLoop(ctx context.Context, in jobio.Input, stop <-chan struct{}, done chan<- pushLog) {
	var lg pushLog
	defer func() { done <- lg }()
	for {
		p, err := Push(ctx, in, spoolRoot)
		lg.last, lg.set = err, lg.set+len(p.Quarantined)
		if len(lg.quarantined) < quarantinedMax {
			lg.quarantined = append(lg.quarantined, p.Quarantined[:min(len(p.Quarantined), quarantinedMax-len(lg.quarantined))]...)
		}
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-time.After(pushEvery):
		}
	}
}

// connectFailed starts the tool's warning for a connection check that could
// not connect (2.58, src/db/helper.c); the tool then ends with 56 (backup,
// stanza-create: no primary) or 27 (check: no database). It is printed
// before any file is listed, so only the tool's own line starts so.
const connectFailed = "WARN: unable to check pg1: [DbConnectError] "

// toolFailure is the failure of the tool's exit: a refused login (exit 56 or
// 27 with the tool's connection warning at the start of a line — never the
// marker inside other text, which file names and server messages can carry),
// the archive timeout (82, with the loop's last push failure, which names its
// cause), or the tool's own failure.
func toolFailure(cmd string, exit int, out string, lg pushLog) error {
	line, pre := errorLine(out), unlisted(lg.set)
	switch {
	case (exit == 56 || exit == 27) && strings.Contains("\n"+out, "\n"+connectFailed):
		return refuse(CodeLogin, pre+"%s: the server refused the login: exit %d: %s", cmd, exit, line)
	case exit == 82:
		why := "the pushes succeeded: the lane was late"
		if lg.last != nil {
			why = "the last push failed: " + pushText(lg.last)
		}
		return refuse(CodeArchiveTimeout, pre+"%s: its WAL was not pushed in time (%s): %s", cmd, why, line)
	}
	return refuse(CodePgbackrest, pre+"%s: exit %d: %s", cmd, exit, line)
}

// infoMax bounds what the job keeps of the tool's info answer, which grows by
// about 650 bytes a set: some 12,900 sets.
const infoMax = 8 << 20

// unlisted starts a failure's message when the push loop's passes set entries
// aside: the failure document cannot list them, so their number is said ("" when
// none).
func unlisted(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d entries set aside by the push meanwhile, unlisted; ", n)
}

// pushText names a push's failure: its code and message.
func pushText(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code + ": " + e.Message
	}
	return err.Error()
}

// refuse is a failure of these kinds. Its message may carry the tool's or
// the server's text and the names of tenant-written entries: the stanza's
// passphrase is cut out of it, control and formatting characters removed,
// and it is bounded at 256 bytes.
func refuse(code, format string, a ...any) error {
	m := fmt.Sprintf(format, a...)
	if pass := os.Getenv(PassName); pass != "" {
		m = strings.ReplaceAll(m, pass, "<redacted>")
	}
	return &Error{Code: code, Message: pgsock.Sanitize(m, 256)}
}

var (
	labelRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}F$`)
	segRE   = regexp.MustCompile(`^[0-9A-F]{24}$`)
	lsnRE   = regexp.MustCompile(`^[0-9A-F]{1,8}/[0-9A-F]{1,8}$`)
)

// infoStanza is the part of the tool's info answer a backup reads.
type infoStanza struct {
	Name   string `json:"name"`
	Backup []struct {
		Label   string `json:"label"`
		Type    string `json:"type"`
		Archive struct {
			Start string `json:"start"`
			Stop  string `json:"stop"`
		} `json:"archive"`
		LSN struct {
			Start string `json:"start"`
			Stop  string `json:"stop"`
		} `json:"lsn"`
		Timestamp struct {
			Start int64 `json:"start"`
			Stop  int64 `json:"stop"`
		} `json:"timestamp"`
	} `json:"backup"`
}

// newestSet reads the newest set of stanza from the tool's info answer (the
// last line of out that is a JSON array; a warning may precede it). The tool
// refuses a new label that is not later than the latest, so the newest is
// the one just taken. Every value is checked for its form.
func newestSet(stanza, out string) (jobio.BackupResult, error) {
	var doc string
	for l := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(l, "[") {
			doc = l
		}
	}
	var info []infoStanza
	if err := json.NewDecoder(strings.NewReader(doc)).Decode(&info); err != nil {
		return jobio.BackupResult{}, fmt.Errorf("the answer is not the tool's document: %v", err)
	}
	if len(info) != 1 || info[0].Name != stanza || len(info[0].Backup) == 0 {
		return jobio.BackupResult{}, fmt.Errorf("the answer does not hold one stanza %s with a set", stanza)
	}
	sets := info[0].Backup
	b := sets[0]
	for _, s := range sets[1:] {
		if s.Label > b.Label {
			b = s
		}
	}
	tli, err := strconv.ParseUint(b.Archive.Start[:min(8, len(b.Archive.Start))], 16, 32)
	switch {
	case !labelRE.MatchString(b.Label) || b.Type != "full":
		return jobio.BackupResult{}, fmt.Errorf("the newest set's label %q (%q) is not a full set's", b.Label, b.Type)
	case !segRE.MatchString(b.Archive.Start) || !segRE.MatchString(b.Archive.Stop) || err != nil || tli < 1 || tli > 1<<31-1 ||
		b.Archive.Stop[:8] != b.Archive.Start[:8]:
		return jobio.BackupResult{}, fmt.Errorf("set %s: segments %q to %q", b.Label, b.Archive.Start, b.Archive.Stop)
	case !lsnRE.MatchString(b.LSN.Start) || !lsnRE.MatchString(b.LSN.Stop):
		return jobio.BackupResult{}, fmt.Errorf("set %s: positions %q to %q", b.Label, b.LSN.Start, b.LSN.Stop)
	case b.Timestamp.Start <= 0 || b.Timestamp.Stop < b.Timestamp.Start:
		return jobio.BackupResult{}, fmt.Errorf("set %s: times %d to %d", b.Label, b.Timestamp.Start, b.Timestamp.Stop)
	}
	return jobio.BackupResult{OK: true, Label: b.Label, Timeline: uint32(tli),
		Start: time.Unix(b.Timestamp.Start, 0).UTC(), Stop: time.Unix(b.Timestamp.Stop, 0).UTC(),
		StartSegment: b.Archive.Start, StopSegment: b.Archive.Stop, StartLSN: b.LSN.Start, StopLSN: b.LSN.Stop}, nil
}
