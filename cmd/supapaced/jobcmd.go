package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Amphoze/supapace/internal/bkjob"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

func init() { commands["job"] = jobCmd }

// The fixed paths of a job container (tests substitute their own).
var (
	jobInput = "/job/input.json"
	jobSpool = "/spool"
)

// jobKinds are the job programs this binary runs. A kind is added here with
// its program; any other is a usage error.
var jobKinds = map[string]func(ctx context.Context, in jobio.Input) (any, error){
	"push": func(ctx context.Context, in jobio.Input) (any, error) { return bkjob.Push(ctx, in, jobSpool) },
}

// jobCmd runs one job program inside its job container: supapaced job KIND.
// It reads /job/input.json, gives the tool its environment — every PG*
// variable replaced by exactly bkjob.Environ's, the passphrase taken from the
// container's environment — runs the program and prints its result as the
// one line of standard output. Exit 0 with a result, 1 with a failure
// document, 2 usage (no result line); 3 an error the program could not name
// (no result line: the runner records the job crashed).
func jobCmd(args []string) int {
	if len(args) != 1 || jobKinds[args[0]] == nil {
		fmt.Fprintln(stderr, "usage: supapaced job push")
		return 2
	}
	b, err := os.ReadFile(jobInput)
	var in jobio.Input
	if err == nil {
		in, err = jobio.ParseInput(b)
	}
	if err == nil && in.Kind != args[0] {
		err = fmt.Errorf("the input is for a job of kind %q", in.Kind)
	}
	if err != nil {
		fmt.Fprintf(stderr, "supapaced job: %v\n", err)
		return 2
	}
	setToolEnv(in)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	v, err := jobKinds[in.Kind](ctx, in)
	code := 0
	if err != nil {
		var e *bkjob.Error
		if !errors.As(err, &e) {
			fmt.Fprintf(stderr, "supapaced job %s: %v\n", in.Kind, err)
			return 3
		}
		v, code = jobio.Failure{Code: e.Code, Message: e.Message}, 1
	}
	line, err := jobio.MarshalResult(v)
	if err != nil {
		fmt.Fprintf(stderr, "supapaced job %s: %v\n", in.Kind, err)
		return 3
	}
	stdout.Write(line)
	return code
}

// setToolEnv replaces every PG* variable of this process — the tool and the
// libpq it links read them — by the job's environment.
func setToolEnv(in jobio.Input) {
	pass := os.Getenv(bkjob.PassName)
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "PG") {
			os.Unsetenv(k)
		}
	}
	for k, v := range bkjob.Environ(in.Stanza, in.Kind, in.Subject == nodecfg.ControlPlaneSubject, pass) {
		os.Setenv(k, v)
	}
}
