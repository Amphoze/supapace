// Package testdocker keeps the containers and volumes a test process starts
// from outliving it when it is killed. Labels marks them as this process's
// and starts a watchdog that removes them once the process is gone; Bounded
// gives a container a lifetime of its own, a backstop should the watchdog be
// killed too. Tests only.
package testdocker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Lifetime is how long a container started with Bounded runs at most: longer
// than any run of a test binary (a -count run lasts hours).
const Lifetime = 4 * time.Hour

// OwnerLabel names the label whose value is this process's own.
const OwnerLabel = "supapace.test.owner"

var (
	once     sync.Once
	owner    string
	startErr error
)

// watchdog waits until the process $1 that started at $3 (its start time in
// /proc) is gone, then removes every container and volume labelled $2, a value
// no other process holds: at once, and again after 5 s and 30 s for a docker
// run that was still under way when the process ended. Nothing else ends the
// wait: not an age, not a label, not a pid taken by another process later.
const watchdog = `alive() {
	start=$2
	s=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
	set -- ${s##*) }
	[ "${20}" = "$start" ]
}
while alive "$1" "$3"; do sleep 1; done
for d in 0 5 25; do
	sleep "$d"
	docker ps -aq --filter "label=$2" | xargs -r docker rm -f -v >/dev/null 2>&1
	docker volume ls -q --filter "label=$2" | xargs -r docker volume rm -f >/dev/null 2>&1
done`

func start() {
	b := make([]byte, 8)
	rand.Read(b)
	owner = hex.EncodeToString(b)
	// This process's start time: field 22 of its stat line, the 20th after
	// the name in parentheses, which may hold anything.
	stat, err := os.ReadFile("/proc/self/stat")
	i := bytes.LastIndex(stat, []byte(") "))
	if err != nil || i < 0 || len(bytes.Fields(stat[i+2:])) < 20 {
		startErr = fmt.Errorf("reading this process's start time: %v", err)
		return
	}
	started := string(bytes.Fields(stat[i+2:])[19])
	// In a session of its own, with no stream of the test's: neither the
	// test's end nor a signal to its process group ends it, and go test does
	// not wait for it.
	w := exec.Command("sh", "-c", watchdog, "sh", strconv.Itoa(os.Getpid()), OwnerLabel+"="+owner, started)
	w.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if startErr = w.Start(); startErr == nil {
		w.Process.Release()
	}
}

// Labels returns the docker options that mark a container or a volume as a
// test's (supapace.test=1) and as this process's. The first call starts the
// watchdog.
func Labels(t testing.TB) []string {
	t.Helper()
	once.Do(start)
	if startErr != nil {
		t.Fatalf("starting the test containers' watchdog: %v", startErr)
	}
	return []string{"--label", "supapace.test=1", "--label", OwnerLabel + "=" + owner}
}

// bounded runs its arguments as the container's first process (sh execs
// them, so that process keeps the pid) beside a child that sends it SIGINT
// after $0 seconds.
const bounded = `(sleep "$0" && kill -INT 1) >/dev/null 2>&1 & exec "$@"`

// Bounded returns docker run's arguments from the entrypoint option on: image
// run with cmd (the image's entrypoint and its arguments) as the container's
// first process, which receives SIGINT after Lifetime. cmd must end on
// SIGINT, as postgres does.
func Bounded(image string, cmd ...string) []string { return boundedFor(Lifetime, image, cmd...) }

func boundedFor(d time.Duration, image string, cmd ...string) []string {
	return append([]string{"--entrypoint", "sh", image, "-c", bounded, strconv.Itoa(int(d / time.Second))}, cmd...)
}
