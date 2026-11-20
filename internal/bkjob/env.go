// Package bkjob is what runs inside a backup job container: the tool's
// environment, the one way the tool is run, and the job programs. Everything
// a job reads from the spool or the repository is the project's to write; a
// name is used only once it passes walname, and a file only once it was opened
// without following a link and checked.
package bkjob

import (
	"maps"
	"slices"
	"strings"

	"github.com/Amphoze/supapace/internal/pgsock"
)

// PassName is the variable that carries the stanza's passphrase. It reaches a
// job through its container's environment, never through Env.
const PassName = "PGBACKREST_REPO1_CIPHER_PASS"

// passKinds are the kinds whose tool uses the stanza's encryption: only they
// are handed the passphrase.
var passKinds = map[string]bool{"push": true, "stanza-create": true, "backup": true, "check": true, "restore": true, "serve": true}

// Env is the tool's environment for a job of kind, without the passphrase.
// Every option is pinned here, and PGBACKREST_CONFIG=/dev/null keeps any
// configuration file from supplying one this list forgot. A control-plane job
// logs in as the control plane's superuser through its existing map.
func Env(stanza, kind string, controlPlane bool) map[string]string {
	e := map[string]string{
		"PGBACKREST_STANZA":            stanza,
		"PGBACKREST_REPO1_PATH":        "/repo",
		"PGBACKREST_REPO1_CIPHER_TYPE": "aes-256-cbc",
		"PGBACKREST_LOCK_PATH":         "/tmp/lock",
		"PGBACKREST_LOG_PATH":          "/tmp/log",
		"PGBACKREST_SPOOL_PATH":        "/tmp/spool",
		"PGBACKREST_LOG_LEVEL_FILE":    "off",
		"PGBACKREST_LOG_LEVEL_CONSOLE": "warn",
		"PGBACKREST_COMPRESS_TYPE":     "zst",
		"PGBACKREST_PROCESS_MAX":       "1",
		"PGBACKREST_START_FAST":        "y",
		"PGBACKREST_REPO1_BUNDLE":      "n",
		"PGBACKREST_REPO1_BLOCK":       "n",
		"PGBACKREST_RESUME":            "n",
		"PGBACKREST_REPO1_HARDLINK":    "n",
		"PGBACKREST_ARCHIVE_COPY":      "n",
		// The default, pinned: the replicator reads the repository through
		// its group, which rests on 0640 files and 0750 directories.
		"PGBACKREST_NEUTRAL_UMASK": "y",
		"PGBACKREST_CONFIG":        "/dev/null",
	}
	switch kind {
	case "stanza-create", "backup", "check":
		user := "supapace_backup"
		if controlPlane {
			user = "supapaced"
		}
		e["PGBACKREST_PG1_SOCKET_PATH"] = "/var/run/postgresql"
		e["PGBACKREST_PG1_USER"] = user
		e["PGOPTIONS"] = pgOptions(pgsock.StartupParams(false))
		fallthrough
	case "restore", "serve":
		e["PGBACKREST_PG1_PATH"] = "/var/lib/postgresql/data"
	}
	return e
}

// Environ is Env with the passphrase pass for the six kinds that take one; an
// empty pass is not set.
func Environ(stanza, kind string, controlPlane bool, pass string) map[string]string {
	e := Env(stanza, kind, controlPlane)
	if passKinds[kind] && pass != "" {
		e[PassName] = pass
	}
	return e
}

// optEscape escapes what the server splits PGOPTIONS on: white space, and the
// backslash that escapes it.
var optEscape = strings.NewReplacer(`\`, `\\`, " ", `\ `)

// pgOptions renders parameters as "-c name=value" pairs joined by single
// spaces, in name order; an empty value is "-c name=".
func pgOptions(params map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(params)) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("-c " + optEscape.Replace(k) + "=" + optEscape.Replace(params[k]))
	}
	return b.String()
}
