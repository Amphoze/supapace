package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/store"
)

// The replication and fetch halves of launching and recording, assigned by
// the files that implement them. While one is nil, a job of its kind ends
// failed with code internal.
//
// A builder completes the job's input and spec from the job row (the mode
// and markers, the memory, the plan, the replicator's quota); a recorder
// writes what the job's parsed result says and returns the document stored
// as the job's result. Each is handed the job row.
var (
	buildReplicate, buildFetch func(ctx context.Context, r *Runner, j store.Job, in *jobio.Input, spec *agent.JobSpec) error
	recordReplicate            func(ctx context.Context, r *Runner, j store.Job, v jobio.ReplResult) (json.RawMessage, error)
	recordFetch                func(ctx context.Context, r *Runner, j store.Job, v jobio.FetchResult) (json.RawMessage, error)
)

// jobError is a refusal to launch, with the code the job ends with.
type jobError struct{ code, msg string }

func (e *jobError) Error() string { return e.code + ": " + e.msg }

// jobErr is how a builder refuses a launch with a code of its own
// (record_not_rebuilt, fetch_too_large).
func jobErr(code, msg string) error { return &jobError{code, msg} }

func specFailure(err error) outcome {
	var je *jobError
	if errors.As(err, &je) {
		return failed(je.code, je.msg)
	}
	return failed("internal", err.Error())
}

// subject is what a job needs of its subject.
type subject struct {
	name           string
	uid, gid       int
	stanza, pass   string
	diskMB, repoMB int
	spec           agent.Spec // a project's; zero for the control plane
	admitted       []uint32   // the timelines a project admits; nil for the control plane (every one)
}

// subjectOf reads the subject: a project's spec, or the control plane's
// fixed ids, its stanza and its sealed passphrase.
func (r *Runner) subjectOf(ctx context.Context, name string) (subject, error) {
	if name == nodecfg.ControlPlaneSubject {
		bs, err := r.st.GetBackupState(ctx, name)
		if err != nil {
			return subject{}, err
		}
		// The passphrase is made once by init; a missing file is never made here.
		if _, err := os.Lstat(r.p.CPStanzaSealed()); err != nil {
			return subject{}, fmt.Errorf("the control plane's passphrase: %w", err)
		}
		pass, err := offsite.EnsureControlPlanePass(r.p, r.kek)
		if err != nil {
			return subject{}, err
		}
		disk, repo := nodecfg.CPQuotas(r.cfg, r.p)
		return subject{name: name, uid: nodecfg.ControlPlaneUID, gid: nodecfg.ControlPlaneUID,
			stanza: name + "-" + bs.Incarnation, pass: pass, diskMB: disk, repoMB: repo}, nil
	}
	sp, err := r.pr.SpecFor(ctx, name)
	if err != nil {
		return subject{}, err
	}
	if sp.Stanza == "" || sp.StanzaPass == "" {
		return subject{}, fmt.Errorf("project %s has no stanza or passphrase", name)
	}
	tls, err := r.st.Timelines(ctx, name)
	if err != nil {
		return subject{}, err
	}
	admitted := make([]uint32, 0, len(tls)) // never nil: an empty list admits none
	for _, t := range tls {
		admitted = append(admitted, uint32(t.TLI))
	}
	return subject{name: name, uid: sp.UID, gid: sp.GID, stanza: sp.Stanza, pass: sp.StanzaPass,
		diskMB: sp.DiskQuotaMB, repoMB: sp.DiskQuotaMB, spec: sp, admitted: admitted}, nil
}

// passKinds are the kinds that take the stanza passphrase. seed, replicate,
// fetch and probe never do.
var passKinds = map[string]bool{"push": true, "stanza-create": true, "backup": true, "check": true, "restore": true, "serve": true}

// jobSpec builds the container of job j: its input, its ids, its deadline,
// and the secrets by kind — the passphrase in the environment for the six
// kinds that take one, for replicate the write and for fetch the read-only
// credential of the subject's own bucket as a file, never both, never a
// passphrase beside a credential — and for those two the loaded address set,
// whole.
func (r *Runner) jobSpec(ctx context.Context, j store.Job, s subject) (agent.JobSpec, error) {
	in := jobio.Input{Job: j.ID, Kind: j.Kind, Subject: s.name, Stanza: s.stanza, UID: s.uid}
	if s.name != nodecfg.ControlPlaneSubject { // the control plane admits every timeline
		tls, err := r.st.Timelines(ctx, s.name)
		if err != nil {
			return agent.JobSpec{}, err
		}
		in.Timelines = make([]uint32, 0, len(tls))
		for _, t := range tls {
			in.Timelines = append(in.Timelines, uint32(t.TLI))
		}
	}
	spec := agent.JobSpec{ID: j.ID, Subject: s.name, Kind: j.Kind, UID: s.uid, GID: s.gid,
		Deadline: time.Duration(j.DeadlineS) * time.Second}
	if passKinds[j.Kind] {
		spec.SecretEnv = map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": s.pass}
	}
	switch j.Kind {
	case "push":
		in.MaxEntries = bklimit.PushMaxEntries
	case "backup":
		in.Type = "full"
	case "serve":
		in.MaxAnswers = bklimit.ServeMaxAnswers
	case "restore":
		p, err := parseRestoreParams(j.Params)
		if err != nil {
			return agent.JobSpec{}, err
		}
		in.Set, in.Mode, in.TargetTimeline = p.Set, p.Mode, p.TargetTimeline
	case "replicate", "fetch":
		build := buildReplicate
		if j.Kind == "fetch" {
			build = buildFetch
		}
		if build == nil {
			return agent.JobSpec{}, jobErr("internal", "this node does not run "+j.Kind+" jobs yet")
		}
		if err := r.networked(&spec, j.Kind, s.name); err != nil {
			return agent.JobSpec{}, err
		}
		if err := build(ctx, r, j, &in, &spec); err != nil {
			return agent.JobSpec{}, err
		}
	}
	b, err := jobio.MarshalInput(in)
	if err != nil {
		return agent.JobSpec{}, err
	}
	spec.Input = b
	return spec, nil
}

// networked gives a replicate or fetch job its credential, the endpoint and
// the loaded address set. The subject's bucket only: the control plane's
// for "cp", the projects' for a project.
func (r *Runner) networked(spec *agent.JobSpec, kind, subj string) error {
	d, st, addrs := r.offsite()
	if st != offsite.StateDeclared {
		return jobErr("internal", "the off-site store is not declared")
	}
	b := d.Projects
	if subj == nodecfg.ControlPlaneSubject {
		b = d.ControlPlane
	}
	c := b.Write
	if kind == "fetch" {
		c = b.Read
	}
	spec.Cred = []byte(c.AccessKey + "\n" + c.SecretKey)
	spec.Addrs = addrs
	list := make([]string, len(addrs))
	for i, a := range addrs {
		list[i] = a.String()
	}
	style := "0"
	if d.PathStyle {
		style = "1"
	}
	spec.Env = map[string]string{"SUPAPACE_S3_ENDPOINT": d.Endpoint, "SUPAPACE_S3_REGION": d.Region,
		"SUPAPACE_S3_BUCKET": b.Name, "SUPAPACE_S3_PREFIX": b.Prefix, "SUPAPACE_S3_PATH_STYLE": style,
		"SUPAPACE_S3_ADDRS": strings.Join(list, ",")}
	if d.CAPEM != "" {
		spec.Files = map[string][]byte{"ca.pem": []byte(d.CAPEM)}
	}
	return nil
}

// strictObject decodes b, one JSON object, into v when its member names are
// exactly among names and each appears once: encoding/json alone folds case,
// keeps the last of two equal names and ignores unknown members.
func strictObject(b []byte, v any, names ...string) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := t.(string)
		if seen[k] || !slices.Contains(names, k) {
			return fmt.Errorf("member %.32q", k)
		}
		seen[k] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
	}
	return json.Unmarshal(b, v) // it also refuses anything after the object
}

// restoreParams are a restore job's parameters, written by the restore:
// {"set":"<label>","mode":"none"|"standby","target_timeline":N}, the target
// timeline with standby only.
type restoreParams struct {
	Set            string `json:"set"`
	Mode           string `json:"mode"`
	TargetTimeline int    `json:"target_timeline"`
}

func parseRestoreParams(b []byte) (restoreParams, error) {
	var p restoreParams
	if err := strictObject(b, &p, "set", "mode", "target_timeline"); err != nil {
		return p, fmt.Errorf("restore job parameters: %w", err)
	}
	if !labelRE.MatchString(p.Set) || (p.Mode != "none" || p.TargetTimeline != 0) && (p.Mode != "standby" || p.TargetTimeline < 1) {
		return p, errors.New("restore job parameters: set, mode or target timeline out of shape")
	}
	return p, nil
}

var (
	paramLSNRE      = regexp.MustCompile(`^[0-9A-Fa-f]{1,8}/[0-9A-Fa-f]{1,8}$`)
	paramTimelineRE = regexp.MustCompile(`^(latest|current|[1-9][0-9]{0,9})$`)
)

// parseRecoverParams reads a recover job's parameters, written by the
// restore: {"target":{"time":"<RFC 3339>","lsn":"<hex>/<hex>","timeline":
// "latest"|"current"|"<decimal>"}}, time and lsn omitted when unset.
func parseRecoverParams(b []byte) (pgconf.RecoveryTarget, error) {
	var outer struct {
		Target json.RawMessage `json:"target"`
	}
	var t struct {
		Time     *time.Time `json:"time"`
		LSN      *string    `json:"lsn"`
		Timeline string     `json:"timeline"`
	}
	err := strictObject(b, &outer, "target")
	// A missing or null target is no object: the nested call refuses it.
	if err == nil {
		err = strictObject(outer.Target, &t, "time", "lsn", "timeline")
	}
	if err == nil && (!paramTimelineRE.MatchString(t.Timeline) || t.LSN != nil && !paramLSNRE.MatchString(*t.LSN) || t.Time != nil && t.Time.IsZero()) {
		err = errors.New("target out of shape")
	}
	if err != nil {
		return pgconf.RecoveryTarget{}, fmt.Errorf("recover job parameters: %w", err)
	}
	rt := pgconf.RecoveryTarget{Timeline: t.Timeline}
	if t.Time != nil {
		rt.Time = *t.Time
	}
	if t.LSN != nil {
		rt.LSN = *t.LSN
	}
	return rt, nil
}
