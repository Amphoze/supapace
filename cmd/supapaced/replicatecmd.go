package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/repl"
	"github.com/Amphoze/supapace/internal/s3x"
)

func init() { commands["replicate"] = replicateCmd }

// The paths a replication job is given (the launcher's mount targets) and
// the client constructor: seams for the tests.
var (
	replJobDir = "/job"
	replCred   = "/cred"
	replRepo   = "/repo"
	replIndex  = "/index"
	replEnv    = os.Environ
	replBound  = repl.Bound
	newS3      = s3x.New
)

// replicateCmd is `supapaced replicate copy|rebuild|probe`, the program of a
// replication or probe job: it reads its credential file once, then its
// input, runs the mode and prints the one result line. Exit 0 with a result,
// 1 with a failure document, 2 for a usage error — an empty address set among
// them, refused before any client is made.
func replicateCmd(args []string) int {
	if len(args) != 1 || args[0] != "copy" && args[0] != "rebuild" && args[0] != "probe" {
		fmt.Fprintln(stderr, "usage: supapaced replicate copy|rebuild|probe")
		return 2
	}
	mode := args[0]
	env, err := repl.ReadEnv(replEnv())
	if errors.Is(err, repl.ErrNoAddrs) {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err != nil {
		return replFail("input", err)
	}
	pairs := 1
	if mode == "probe" {
		pairs = 2
	}
	keys, err := repl.ReadCred(replCred, pairs)
	if err != nil {
		return replFail("credential", err)
	}
	replKeys = keys
	defer func() { replKeys = nil }()
	repl.Warn = func(s string) { fmt.Fprintln(stderr, "replicate: "+cleanText(scrub(s))) }
	in, err := replInput(mode)
	if err != nil {
		return replFail("input", err)
	}
	ca, err := repl.ReadCA(replJobDir + "/ca.pem")
	if err != nil {
		return replFail("input", fmt.Errorf("the CA bundle: %w", err))
	}
	write, err := newS3(env.Config(env.Bucket, keys[0], ca))
	if err != nil {
		return replFail("input", err)
	}
	st := repl.NewBucket(write, env.Prefix)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	// The program's own bound, below its job's deadline: it always ends with a
	// result line that records what it did.
	ctx, cancel := context.WithTimeout(ctx, replBound(mode))
	defer cancel()
	var res jobio.ReplResult
	switch mode {
	case "copy":
		fd, oerr := syscall.Open(replIndex, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if oerr != nil {
			return replFail("index", oerr)
		}
		idx := os.NewFile(uintptr(fd), replIndex)
		defer idx.Close()
		if fi, serr := idx.Stat(); serr != nil || !fi.Mode().IsRegular() {
			return replFail("index", errors.New("the index is not a regular file"))
		}
		res, err = repl.Copy(ctx, in, replRepo, idx, st)
	case "rebuild":
		res, err = repl.Rebuild(ctx, in, st)
	case "probe":
		res, err = replProbe(ctx, in, env, keys, ca, write)
	}
	if errors.Is(err, repl.ErrInput) {
		return replFail("input", err)
	}
	if errors.Is(err, repl.ErrIndex) {
		return replFail("index", err)
	}
	if err != nil {
		return replFail(map[string]string{"copy": "repository", "rebuild": "store", "probe": "store"}[mode], err)
	}
	line, err := jobio.MarshalResult(res)
	if err != nil {
		return replFail("result", err)
	}
	stdout.Write(line)
	return 0
}

func replProbe(ctx context.Context, in jobio.Input, env repl.Env, keys []repl.Keys, ca string, write *s3x.Client) (jobio.ReplResult, error) {
	read, err := newS3(env.Config(env.Bucket, keys[1], ca))
	if err != nil {
		return jobio.ReplResult{}, err
	}
	t := repl.ProbeTargets{Write: repl.NewBucket(write, env.Prefix), Read: repl.NewBucket(read, env.Prefix)}
	if env.OtherBucket != "" {
		other, err := newS3(env.Config(env.OtherBucket, keys[0], ca))
		if err != nil {
			return jobio.ReplResult{}, err
		}
		t.Other = repl.NewBucket(other, env.Prefix)
	}
	u, err := url.Parse(env.Endpoint)
	if err != nil {
		return jobio.ReplResult{}, err
	}
	s := repl.NewSigner(write.HTTPClient(), u.Host, env.Bucket, env.Region, env.PathStyle, keys[0], env.Prefix)
	t.Raw = s
	return repl.Probe(ctx, in, t, s)
}

// replInput reads /job/input.json (at most 1 MiB, a regular file) and
// checks it is an input of this mode.
func replInput(mode string) (jobio.Input, error) {
	f, err := os.OpenFile(replJobDir+"/input.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return jobio.Input{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return jobio.Input{}, errors.New("the input is not a regular file of at most 1 MiB")
	}
	b := make([]byte, fi.Size())
	if _, err := f.ReadAt(b, 0); err != nil {
		return jobio.Input{}, err
	}
	in, err := jobio.ParseInput(b)
	if err != nil {
		return jobio.Input{}, err
	}
	kind := "replicate"
	if mode == "probe" {
		kind = "probe"
	}
	if in.Kind != kind || in.Repl == nil || in.Repl.Mode != mode {
		return jobio.Input{}, fmt.Errorf("the input is not of kind %s, mode %s", kind, mode)
	}
	return in, nil
}

// replKeys are the job's keys, scrubbed from every text it prints: a store
// may echo the access key it was sent.
var replKeys []repl.Keys

// A key, and every beginning of it of at least scrubMin bytes (an echo the
// client cut), is replaced. Known limit: a key echoed in pieces shorter than
// that, or transformed, is not recognised.
func scrub(s string) string {
	for _, k := range replKeys {
		for _, v := range []string{k.Access, k.Secret} {
			for n := len(v); n >= scrubMin; n-- {
				s = strings.ReplaceAll(s, v[:n], "[key]")
			}
		}
	}
	return s
}

const scrubMin = 8

// cleanText keeps printable ASCII, other bytes as "?", at most 256 bytes.
func cleanText(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) > 256 {
		b = b[:256]
	}
	return string(b)
}

// replFail prints a failure document: the message cleaned and cut to 256
// bytes. No error of the program carries a key: Keys never prints.
func replFail(code string, err error) int {
	line, merr := jobio.MarshalResult(jobio.Failure{Code: code, Message: cleanText(scrub(err.Error()))})
	if merr != nil {
		fmt.Fprintln(stderr, merr)
		return 1
	}
	stdout.Write(line)
	return 1
}
