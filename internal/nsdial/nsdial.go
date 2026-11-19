// Package nsdial makes one TCP connection from inside another process's
// network namespace — a container's — without returning the thread that
// entered it to the Go scheduler.
package nsdial

import "errors"

// Target is a container's init process: the pid Docker's inspection reports
// and that process's start time in clock ticks (field 22 of /proc/<pid>/stat).
type Target struct {
	PID        int
	StartTicks uint64
}

// ErrChanged reports that the process behind a Target is not the one the
// caller inspected: it exited, or its pid now names another process.
var ErrChanged = errors.New("nsdial: the container changed between inspection and entry")
