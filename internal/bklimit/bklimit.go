// Package bklimit holds every figure that sizes a backup job, a loop, a budget or
// a lag. Each is a constant or a function of the node's quotas, never of a size a
// project's tree or repository reports: a project chooses those.
package bklimit

import (
	"fmt"
	"math"
	"time"
)

const (
	PushInterval  = 60 * time.Second
	SchedulerTick = 5 * time.Second

	PushMaxEntries = 56 // spool entries one push job takes: 896 MiB of segments
	ReplMaxFiles   = 2048
	ReplMaxBytes   = 1280 << 20
	ReplMaxEntries = 250000 // entries one replication walk visits

	RebuildPageRows = 4000 // listed versions one rebuild job returns
	RebuildMaxPages = 2048

	PartSize        = 32 << 20          // multipart part size, and the largest single upload
	GetTimeout      = 120 * time.Second // one restore request of the archive binary; equals its own constant
	ServeMaxAnswers = 8                 // answers a serve job gives one name

	PushLagShown = 300 * time.Second
	ReplLagShown = 600 * time.Second

	DrainPushWait     = 60 * time.Second
	RecordHorizonDays = 90

	JobRowAge  = 48 * time.Hour
	PruneBatch = 10000
	PruneEvery = time.Hour

	ResultMax = 1 << 20 // one job's result line
)

// Object bounds: a segment, a small file (info, history, label), a set file.
const (
	SegmentMax = 16<<20 + 1<<10
	SmallMax   = 1 << 20
	SetFileMax = 1<<30 + 16<<20
)

// WholeArchive is what FetchMargin returns once the margin has been doubled three
// times: no time limit, the whole recorded archive.
const WholeArchive = time.Duration(math.MaxInt64)

func ceilDiv(a, b int64) int64 { return (a + b - 1) / b }

// Deadline is the deadline of one job of kind at disk quota diskMB and
// repository quota repoMB. A serve job runs inside a recover job and has its
// deadline. An unknown kind or a negative quota is an error.
func Deadline(kind string, diskMB, repoMB int) (time.Duration, error) {
	if diskMB < 0 || repoMB < 0 {
		return 0, fmt.Errorf("bklimit: negative quota %d/%d MiB", diskMB, repoMB)
	}
	qd, qr := int64(diskMB), int64(repoMB)
	var s int64
	switch kind {
	case "push", "probe":
		s = 120
	case "replicate":
		s = 300
	case "stanza-create", "check":
		s = 180
	case "backup", "restore":
		s = 300 + ceilDiv(qd, 20) // 20 MiB/s
	case "fetch":
		s = 300 + ceilDiv(qr, 4) // 4 MiB/s from the store
	case "seed":
		s = 120 + ceilDiv(qr, 50) // 50 MiB/s local copy
	case "recover", "serve":
		s = 600 + ceilDiv(qr*11, 16) // 16 MiB/s of raw WAL, 11 raw bytes per archived byte
	default:
		return 0, fmt.Errorf("bklimit: unknown job kind %q", kind)
	}
	return time.Duration(s) * time.Second, nil
}

// PushLoopMax bounds the push jobs one step submits to empty the spool: the
// spool lies inside the disk quota, so it holds at most that many jobs' worth
// of segments.
func PushLoopMax(diskMB int) int { return int(ceilDiv(int64(diskMB), PushMaxEntries*16)) + 2 }

// ReplLoopMax bounds the copy jobs one step submits to replicate until complete.
func ReplLoopMax(repoMB int) int { return 2*int(ceilDiv(int64(repoMB), ReplMaxBytes>>20)) + 4 }

// Budgets is a project's daily upload budget: overrideMB MiB, else twice the
// repository quota; overrideObjects objects, else one per 0.5 MiB of the byte
// budget and at least 7,500.
func Budgets(repoMB, overrideMB, overrideObjects int) (bytes int64, objects int) {
	bytes = 2 * int64(repoMB) << 20
	if overrideMB > 0 {
		bytes = int64(overrideMB) << 20
	}
	objects = overrideObjects
	if objects <= 0 {
		objects = int(max(7500, bytes/(512<<10)))
	}
	return bytes, objects
}

// ReplMemMB is a replication job's memory limit for an index of rows rows.
func ReplMemMB(rows int64) int { return int(max(256, 128+ceilDiv(max(rows, 0), 20000))) }

// FetchMargin is how far past a time target a fetch plan reaches: the
// project's archive timeout and the two lags shown, doubled extra times; above
// three doublings, WholeArchive.
func FetchMargin(archiveTimeout time.Duration, extra int) time.Duration {
	if extra > 3 {
		return WholeArchive
	}
	return (archiveTimeout + PushLagShown + ReplLagShown) << max(extra, 0)
}
