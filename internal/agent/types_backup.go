package agent

import (
	"fmt"
	"io"
	"net/netip"
	"time"
)

// JobSpec is one backup job container. Kind is one of push, stanza-create,
// backup, check, restore, serve, seed, replicate, fetch, probe.
type JobSpec struct {
	ID            int64
	Subject, Kind string
	UID, GID      int               // owner of the tree: the project's ids, or the control plane's
	Env           map[string]string // passed through the job's environment file
	SecretEnv     map[string]string `json:"-"` // the stanza passphrase and nothing else
	Cred          []byte            `json:"-"` // replicate, fetch, probe: the credential file's content; nil otherwise
	Input         []byte            // becomes /job/input.json
	Files         map[string][]byte // further read-only files in /job; never a secret
	Addrs         []netip.AddrPort  // replicate, fetch, probe
	MemMB         int               // replicate only; 0: the kind's fixed figure
	Deadline      time.Duration
}

// String, GoString and Format keep SecretEnv and Cred out of every fmt verb
// and log line; JSON leaves them out. A JobSpec held in an unexported field of
// a printed struct is printed by reflection, raw: never print such a struct.
func (j JobSpec) String() string {
	return fmt.Sprintf("agent.JobSpec{ID:%d Subject:%s Kind:%s}", j.ID, j.Subject, j.Kind)
}

func (j JobSpec) GoString() string { return j.String() }

func (j JobSpec) Format(f fmt.State, _ rune) { io.WriteString(f, j.String()) }

// JobResult is what a job container left: its exit code, its last result line
// (empty when it wrote none that fits), the tail of its standard error, and
// whether it was killed at its deadline.
type JobResult struct {
	ExitCode int
	Result   []byte
	Stderr   string
	TimedOut bool
}

// QuotaUse is a project's use of its two quotas, from the host's quota report.
type QuotaUse struct{ DiskUsedKB, DiskHardKB, RepoUsedKB, RepoHardKB int64 }

// HostState is what the host holds of a project, read without entering its tree.
type HostState struct{ ProjectDir, StateFile, ClusterRunning, QuotaFull bool }
