package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

func init() { offsiteCommands["rebuild-continue"] = offsiteRebuildContinue }

var subjectRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// offsiteRebuildContinue is `supapaced offsite rebuild-continue --subject S`:
// the way on for a subject whose record rebuild stopped at its page cap. It
// sets the subject's page count back to 0 through the store's guarded reset
// — only for a subject that is at the cap with its record not yet rebuilt —
// and clears the alert the refusal raised. The markers are kept, so the next
// replication of the subject continues the listing where it stopped. It
// installs nothing and starts no job; the control-plane database must be up,
// with the daemon running or stopped.
func offsiteRebuildContinue(args []string) int {
	fl := flag.NewFlagSet("offsite rebuild-continue", flag.ContinueOnError)
	fl.SetOutput(stderr)
	subject := fl.String("subject", "", "a project ref, or cp for the control plane (required)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 0 || *subject != nodecfg.ControlPlaneSubject && !subjectRE.MatchString(*subject) {
		fmt.Fprintln(stderr, "usage: supapaced offsite rebuild-continue --subject <project ref or cp>")
		return 2
	}
	if rootOnly && os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "supapaced offsite rebuild-continue: must run as root")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	line, err := continueRebuild(ctx, *subject)
	if err != nil {
		fmt.Fprintf(stderr, "supapaced offsite rebuild-continue: %s\n", clean(err))
		return 1
	}
	fmt.Fprintln(stdout, line)
	return 0
}

func continueRebuild(ctx context.Context, subject string) (string, error) {
	st, err := openCPStore(ctx)
	if err != nil {
		return "", err
	}
	defer st.Close()
	pages, err := st.ContinueRebuild(ctx, subject, bklimit.RebuildMaxPages)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", fmt.Errorf("%s has no backup state", subject)
	case errors.Is(err, store.ErrConflict):
		return "", fmt.Errorf("the record rebuild of %s is not stopped at its page cap (%d pages): nothing to continue", subject, bklimit.RebuildMaxPages)
	case err != nil:
		return "", err
	}
	if err := st.ClearAlert(ctx, subject, "rebuild-page-cap"); err != nil {
		return "", fmt.Errorf("the rebuild of %s continues, but its alert was not cleared: %w", subject, err)
	}
	bs, err := st.GetBackupState(ctx, subject)
	if err != nil {
		return "", fmt.Errorf("the rebuild of %s continues, but its markers could not be read: %w", subject, err)
	}
	return fmt.Sprintf("supapaced offsite rebuild-continue: %s: %d pages merged so far; the rebuild continues at the subject's next replication after key marker %q, version marker %q",
		subject, pages, bs.RebuildKeyMarker, bs.RebuildVersionMarker), nil
}
