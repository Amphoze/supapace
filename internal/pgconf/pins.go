package pgconf

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ArchiveCommand and RestoreCommand are the archiving and restore commands of
// every project's cluster. The comment in ArchiveCommand is part of the value.
const (
	ArchiveCommand = "/opt/supapace/tools/supapace-arch push %p %f # pgbackrest"
	RestoreCommand = "/opt/supapace/tools/supapace-arch get %f %p"
)

// commandLineOnly are the override-file settings that Pins passes on the
// command line instead.
var commandLineOnly = []string{"archive_mode", "archive_command", "max_connections", "superuser_reserved_connections", "reserved_connections"}

// maxMemMB is the largest container memory Overrides accepts.
const maxMemMB = 1 << 30

// OverridesPinned is Overrides without the lines of archive_mode,
// archive_command, max_connections, superuser_reserved_connections and
// reserved_connections, which Pins sets on the command line. The checks are
// those of Overrides.
func OverridesPinned(gucs map[string]string, memMB int) ([]byte, error) {
	b, err := Overrides(gucs, memMB)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if name, _, _ := strings.Cut(l, " = "); !slices.Contains(commandLineOnly, name) {
			out = append(out, l...)
		}
	}
	return out, nil
}

// Pins returns the -c flags (each flag and each name=value its own element)
// that set archiving, the restore command and the connection limits on the
// command line, where no configuration file the database server can write
// moves them: archive_mode, archive_command, restore_command, max_connections
// (the default merged with gucs), superuser_reserved_connections and
// reserved_connections, in that order.
//
// gucs is checked as Overrides checks it. The bounds relative to the
// container's memory are not known here: OverridesPinned checks them.
func Pins(gucs map[string]string) ([]string, error) {
	if _, err := Overrides(gucs, maxMemMB); err != nil {
		return nil, err
	}
	mc, ok := gucs["max_connections"]
	if !ok {
		mc = defaultValue("max_connections")
	}
	return []string{
		"-c", "archive_mode=on",
		"-c", "archive_command=" + ArchiveCommand,
		"-c", "restore_command=" + RestoreCommand,
		"-c", "max_connections=" + mc,
		"-c", "superuser_reserved_connections=" + defaultValue("superuser_reserved_connections"),
		"-c", "reserved_connections=" + defaultValue("reserved_connections"),
	}, nil
}

func defaultValue(name string) string {
	for _, d := range defaults {
		if d[0] == name {
			return d[1]
		}
	}
	panic("pgconf: no default for " + name)
}

// PinnedNames returns the settings a cluster of the given layout takes from
// the command line: layout 1 the two preload lists, layout 2 also the six
// names of Pins. Any other layout has none (nil).
func PinnedNames(layout int) []string {
	l1 := []string{"session_preload_libraries", "shared_preload_libraries"}
	switch layout {
	case 1:
		return l1
	case 2:
		return append(l1, "archive_mode", "archive_command", "restore_command", "max_connections",
			"superuser_reserved_connections", "reserved_connections")
	}
	return nil
}

// RecoveryTarget is where a restore stops: at Time, at the position LSN
// ("hex/hex"), or — both unset — at the end of the archive. Timeline is
// "latest" or a decimal timeline id for the end of the archive (the end of
// that timeline's archive), "current" or a decimal timeline id otherwise.
type RecoveryTarget struct {
	Time     time.Time
	LSN      string
	Timeline string
}

// RecoveryPins returns the -c flags of a recovery start. The order is
// load-bearing: the server applies command-line settings in order and refuses
// to start when any recovery target setting, an empty one too, follows one
// that is set ("multiple recovery targets specified"). So every target the
// restore does not use comes first, emptied (a configuration file may have set
// it); then the settings that make recovery promote at the target without
// delay or extra commands; the chosen target, if any, last.
func RecoveryPins(t RecoveryTarget) ([]string, error) {
	hasTime, hasLSN := !t.Time.IsZero(), t.LSN != ""
	bad := func(why string) ([]string, error) {
		// Quoted and cut: the fields are operator input and the text reaches logs.
		return nil, fmt.Errorf("%w: recovery target (time %v, position %.40q, timeline %.40q): %s",
			ErrGUCValue, t.Time.UTC(), t.LSN, t.Timeline, why)
	}
	switch {
	case hasTime && hasLSN:
		return bad("a time and a position")
	case hasTime && (t.Time.UTC().Year() < 1 || t.Time.UTC().Year() > 9999):
		return bad("want a year 1 to 9999")
	case !hasTime && !hasLSN && t.Timeline != "latest" && !timelineID(t.Timeline):
		return bad("no target needs timeline latest or a decimal id 1–4294967295")
	case (hasTime || hasLSN) && t.Timeline != "current" && !timelineID(t.Timeline):
		return bad("want timeline current or a decimal id 1–4294967295")
	case hasLSN && !lsn(t.LSN):
		return bad("want a position hex/hex, at most 8 digits each")
	}
	out := []string{"-c", "recovery_target=", "-c", "recovery_target_name=", "-c", "recovery_target_xid="}
	if !hasTime {
		out = append(out, "-c", "recovery_target_time=")
	}
	if !hasLSN {
		out = append(out, "-c", "recovery_target_lsn=")
	}
	out = append(out,
		"-c", "recovery_target_inclusive=on",
		"-c", "recovery_target_action=promote",
		"-c", "recovery_target_timeline="+t.Timeline,
		"-c", "recovery_min_apply_delay=0",
		"-c", "recovery_end_command=",
		"-c", "archive_cleanup_command=")
	switch {
	case hasTime:
		out = append(out, "-c", "recovery_target_time="+t.Time.UTC().Format("2006-01-02 15:04:05.999999+00"))
	case hasLSN:
		out = append(out, "-c", "recovery_target_lsn="+t.LSN)
	}
	return out, nil
}

// timelineID: decimal digits (ParseUint takes no sign) without a leading
// zero (the server reads "0…" as octal or hex), 1 to 2^32-1.
func timelineID(s string) bool {
	if s == "" || s[0] == '0' {
		return false
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// lsn: 1–8 hexadecimal digits, a slash, 1–8 hexadecimal digits; not 0/0,
// which is no position.
func lsn(s string) bool {
	hi, lo, _ := strings.Cut(s, "/")
	isHex := func(h string) bool {
		return h != "" && len(h) <= 8 && strings.Trim(h, "0123456789abcdefABCDEF") == ""
	}
	return isHex(hi) && isHex(lo) && strings.Trim(hi+lo, "0") != ""
}

// RecoveryExtensionPins returns the -c flags that switch off, for a project's
// recovery start, three settings of extensions the image preloads; only the
// command line can set them there. A restored database may have registered a
// login check (it would refuse the platform's login after promotion), a
// password check (it runs inside each password statement and is handed its
// text) or scheduled jobs (they start at promotion, beside the platform's
// session). The project's recovery start puts these before RecoveryPins, so
// that the chosen target stays last.
func RecoveryExtensionPins() []string {
	return []string{"-c", "pgtle.enable_clientauth=off", "-c", "pgtle.enable_password_check=off", "-c", "cron.launch_active_jobs=off"}
}
