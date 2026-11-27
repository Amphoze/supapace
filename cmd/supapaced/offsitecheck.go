package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/pgsock"
)

func init() { offsiteCommands["check"] = offsiteCheck }

// checkAgent is what `offsite check` needs from *agent.Agent.
type checkAgent interface {
	EnsureBackupNetwork(context.Context) error
	RunJob(context.Context, agent.JobSpec) (agent.JobResult, error)
}

// The resolver, the ruleset's set installer and the agent: the tests' seams.
var (
	resolveEndpoint = offsite.Resolve
	installSet      = nft.InstallSet
	newCheckAgent   = func(c nodecfg.Config) checkAgent { return agent.New(c, paths) }
)

// maxProbeRows bounds the rows one probe's result may carry into the record.
const maxProbeRows = 32

// probeRowRE is a row's name; "probe" is the row of a probe without a usable
// result.
var probeRowRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// checkRow and checkDoc are the record of a check: written by this command
// only, read by the daemon's node check. OK is null only for a probe job
// that left no result; a row the probe could not decide is false.
type checkRow struct {
	Bucket string `json:"bucket"` // projects or cp
	Name   string `json:"name"`
	OK     *bool  `json:"ok"`
	Detail string `json:"detail"`
}

type checkDoc struct {
	At       string     `json:"at"`
	Endpoint string     `json:"endpoint"`
	Rows     []checkRow `json:"rows"`
}

// offsiteCheck is `supapaced offsite check`: it resolves the declared
// endpoint, installs the address set in the node's ruleset, runs one probe
// job per bucket and prints and stores what they report. The check passed
// when every row is ok; a record is written whether it passed or not, and
// the exit status is 1 when it did not. It works with the daemon running or
// stopped: a probe is named, labelled and filed apart from every subject's
// jobs.
func offsiteCheck(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: supapaced offsite check")
		return 2
	}
	if rootOnly && os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "supapaced offsite check: must run as root")
		return 1
	}
	// A signal stops the running probe through its context; the launcher then
	// removes the probe's container and its credential file.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	doc, err := runCheck(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "supapaced offsite check: %s\n", clean(err))
		return 1
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	b = append(b, '\n')
	path := paths.OffsiteCheck()
	if err := nodefs.WriteFile(paths, filepath.Dir(path), filepath.Base(path), b, 0o600, os.Geteuid(), os.Getegid()); err != nil {
		fmt.Fprintf(stderr, "supapaced offsite check: %s\n", clean(err))
		return 1
	}
	stdout.Write(b)
	bad := 0
	for _, r := range doc.Rows {
		if r.OK == nil || !*r.OK {
			bad++
		}
	}
	if bad > 0 {
		fmt.Fprintf(stderr, "supapaced offsite check: not passed: %d of %d rows are not ok\n", bad, len(doc.Rows))
		return 1
	}
	return 0
}

func runCheck(ctx context.Context) (checkDoc, error) {
	cfg, err := nodecfg.Load(paths.NodeJSON())
	if err != nil {
		return checkDoc{}, err
	}
	k, err := loadKEK(paths.KEK())
	if err != nil {
		return checkDoc{}, err
	}
	d, state, err := offsite.Load(paths, k)
	clear(k[:])
	if err != nil {
		return checkDoc{}, err
	}
	if state != offsite.StateDeclared {
		return checkDoc{}, fmt.Errorf("the off-site store is not declared (it is %s): run supapaced offsite set first", state)
	}
	set, err := resolveAndInstall(ctx, d, cfg)
	if err != nil {
		return checkDoc{}, err
	}
	ag := newCheckAgent(cfg)
	if err := ag.EnsureBackupNetwork(ctx); err != nil {
		return checkDoc{}, err
	}
	doc := checkDoc{At: now().UTC().Format(time.RFC3339), Endpoint: d.Endpoint}
	for _, b := range []struct {
		role        string
		this, other offsite.Bucket
	}{{"projects", d.Projects, d.ControlPlane}, {nodecfg.ControlPlaneSubject, d.ControlPlane, d.Projects}} {
		doc.Rows = append(doc.Rows, probe(ctx, ag, d, b.role, b.this, b.other.Name, set)...)
		if ctx.Err() != nil {
			return checkDoc{}, errors.New("interrupted by a signal: no record was written; run the check again")
		}
	}
	return doc, nil
}

// resolveAndInstall resolves the endpoint and installs the answer as the
// ruleset's set, under the lock every process shares: what a job can reach
// is that set and nothing else. A load that failed is never reported as a
// busy lock.
func resolveAndInstall(ctx context.Context, d offsite.Declaration, cfg nodecfg.Config) ([]netip.AddrPort, error) {
	rctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	set, err := resolveEndpoint(rctx, d, cfg)
	if err != nil {
		return nil, err
	}
	switch err := installSet(rctx, paths, cfg, set); {
	case errors.Is(err, nft.ErrUnverified):
		return nil, fmt.Errorf("the ruleset could not be loaded: %w", err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return nil, fmt.Errorf("the ruleset lock is busy: %w", err)
	case err != nil:
		return nil, err
	}
	return set, nil
}

// storeEnv is the environment of a job that talks to bucket b of the
// declared store through the addresses of set; it holds no secret.
func storeEnv(endpoint, region string, pathStyle bool, bucket, prefix string, set []netip.AddrPort) map[string]string {
	list := make([]string, len(set))
	for i, a := range set {
		list[i] = a.String()
	}
	style := "0"
	if pathStyle {
		style = "1"
	}
	return map[string]string{"SUPAPACE_S3_ENDPOINT": endpoint, "SUPAPACE_S3_REGION": region, "SUPAPACE_S3_BUCKET": bucket,
		"SUPAPACE_S3_PREFIX": prefix, "SUPAPACE_S3_PATH_STYLE": style, "SUPAPACE_S3_ADDRS": strings.Join(list, ",")}
}

func caFile(pem string) map[string][]byte {
	if pem == "" {
		return nil
	}
	return map[string][]byte{"ca.pem": []byte(pem)}
}

// probe runs the probe job of one bucket and returns its rows for the
// record. The job holds the write and the read-only credential of that
// bucket and no other; its subject is the bucket's role, by which the
// launcher names it.
func probe(ctx context.Context, ag checkAgent, d offsite.Declaration, role string, b offsite.Bucket, other string, set []netip.AddrPort) []checkRow {
	one := func(ok *bool, detail string) []checkRow {
		return []checkRow{{Bucket: role, Name: "probe", OK: ok, Detail: pgsock.Sanitize(detail, 256)}}
	}
	no := false
	in, err := jobio.MarshalInput(jobio.Input{Kind: "probe", Subject: role, Repl: &jobio.ReplInput{Mode: "probe"}})
	if err != nil {
		return one(nil, err.Error())
	}
	deadline, err := bklimit.Deadline("probe", 0, 0)
	if err != nil {
		return one(nil, err.Error())
	}
	env := storeEnv(d.Endpoint, d.Region, d.PathStyle, b.Name, b.Prefix, set)
	if other != b.Name { // one bucket for both uses has no other to try the credential on
		env["SUPAPACE_S3_OTHER_BUCKET"] = other
	}
	res, err := ag.RunJob(ctx, agent.JobSpec{Subject: role, Kind: "probe", Env: env, Files: caFile(d.CAPEM), Addrs: set, Input: in, Deadline: deadline,
		Cred: []byte(b.Write.AccessKey + "\n" + b.Write.SecretKey + "\n" + b.Read.AccessKey + "\n" + b.Read.SecretKey)})
	switch {
	case err != nil:
		return one(nil, "the probe job left no result: "+err.Error())
	case len(res.Result) == 0:
		return one(nil, fmt.Sprintf("the probe job left no result (exit %d)", res.ExitCode))
	}
	v, fail, err := jobio.ParseResult("probe", res.Result)
	switch {
	case err != nil:
		return one(&no, "the probe's result is refused: "+err.Error())
	case fail != nil:
		return one(&no, fail.Code+": "+fail.Message)
	}
	pr := v.(jobio.ReplResult).ProbeRows
	if len(pr) > maxProbeRows {
		return one(&no, fmt.Sprintf("the probe's result is refused: it holds more than %d rows", maxProbeRows))
	}
	rows := make([]checkRow, len(pr))
	seen := map[string]bool{}
	for i, r := range pr {
		if !probeRowRE.MatchString(r.Name) || r.Name == "probe" || seen[r.Name] {
			return one(&no, "the probe's result is refused: a row's name is malformed or repeated")
		}
		seen[r.Name] = true
		ok := r.OK
		rows[i] = checkRow{Bucket: role, Name: r.Name, OK: &ok, Detail: pgsock.Sanitize(r.Detail, 256)}
	}
	return rows
}
