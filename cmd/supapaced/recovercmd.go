package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/Amphoze/supapace/internal/walname"
)

func init() { commands["recover"] = recoverCmd }

// recoverAgent is what a recovery needs from *agent.Agent; the tests use a fake.
type recoverAgent interface {
	checkAgent
	EnsureImageFiles(context.Context) error
	KillJobs(context.Context, string) error
	PrepareControlPlaneRestore(context.Context) error
	SetReplicatorQuota(context.Context, int) error
	EnsureControlPlaneRecovery(context.Context, pgconf.RecoveryTarget) error
	ControlPlaneRecoveryState(context.Context) (promoted, exited bool, systemID string, err error)
	StopControlPlaneRecovery(context.Context) error
	FinishControlPlaneRestore(context.Context) error
}

// recoveredStore is the restored database as a recovery uses it.
type recoveredStore interface {
	Migrate(context.Context) error
	ListProjects(context.Context) ([]store.Project, error)
	EnterNewEpoch(context.Context, int) (int64, error)
	Close()
}

// What a recovery reaches outside its own files: the tests' seams.
var (
	newRecoverAgent = func(c nodecfg.Config) recoverAgent { return agent.New(c, paths) }
	openRecovered   = func(ctx context.Context) (recoveredStore, error) {
		st, err := dialCPStore(ctx)
		if err != nil {
			return nil, err
		}
		return st, nil
	}
	inspectContainer = dockerx.InspectContainer
	loadImage        = func(ctx context.Context, archive string) error {
		_, err := dockerx.Run(ctx, "load", "--input", archive)
		return err
	}
	// ownerUID is the uid that owns path, not following a link.
	ownerUID = func(path string) (int, error) {
		fi, err := os.Lstat(path)
		if err != nil {
			return 0, err
		}
		return owner(fi), nil
	}
	recoverTools = jobPrograms
	recoverPoll  = 2 * time.Second
)

var (
	setLabelRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}F$`)
	segmentRE  = regexp.MustCompile(`^[0-9A-F]{24}$`)
)

// files collects a flag given more than once.
type files []string

func (f *files) String() string     { return fmt.Sprint(*f) }
func (f *files) Set(s string) error { *f = append(*f, s); return nil }

// recoverCmd is `supapaced recover --escrow F [--escrow F2]
// [--worker-image-archive F] [--accept-shortfall]`: on a node that holds
// nothing, it brings the control-plane database back from the escrow set and
// the object store alone. It runs as root, before init and with no daemon
// running, and refuses before it writes anything when the node is not such a
// node or the set is not usable. Exit 0 recovered, 1 refused or stopped, 2
// usage.
func recoverCmd(args []string) int {
	fl := flag.NewFlagSet("recover", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var escrow files
	fl.Var(&escrow, "escrow", "an escrow file: the whole set, or one of its two parts (give both)")
	archive := fl.String("worker-image-archive", "", "the worker image's archive, loaded when the image is not present")
	accept := fl.Bool("accept-shortfall", false, "finish although recovery did not reach the newest fetched segment: every later change is lost")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	bad := fl.NArg() != 0 || len(escrow) < 1 || len(escrow) > 2
	for _, f := range escrow {
		bad = bad || f == ""
	}
	if bad {
		fmt.Fprintln(stderr, "usage: supapaced recover --escrow F [--escrow F2] [--worker-image-archive F] [--accept-shortfall]")
		return 2
	}
	if rootOnly && os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "supapaced recover: must run as root")
		return 1
	}
	// A closed output is a signal like the others: the run ends with its
	// clean-up instead of being killed at its next line.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGPIPE)
	defer stop()
	if err := recoverNode(ctx, escrow, *archive, *accept); err != nil {
		fmt.Fprintf(stderr, "supapaced recover: %s\n", clean(err))
		return 1
	}
	return 0
}

// recovery is one run: the escrow document, the node's default
// configuration (there is no node.json yet) and the agent made with it.
type recovery struct {
	e              offsite.Escrow
	cfg            nodecfg.Config
	ag             recoverAgent
	diskMB, repoMB int
	set            []netip.AddrPort
	// The uid range a surviving owner is looked for in: the defaults', or
	// that of a node.json left on the node.
	uidBase, uidCount int
	keepDeclaration   bool // the node holds its own full declaration of the document's location
}

// scrub replaces every form of a secret of the escrow document in a text the
// command is about to print: a job's or a tool's message is printed as it
// came, and none of them should hold one. A beginning of a secret of at
// least scrubMin bytes is replaced too: a message's bound may have cut it.
func (r *recovery) scrub(s string) string {
	o, k := r.e.Offsite.Read, r.e.KEK
	for _, secret := range []string{r.e.ControlPlane.CipherPass, o.SecretKey, o.AccessKey,
		base64.StdEncoding.EncodeToString(k[:]), hex.EncodeToString(k[:]), string(k[:])} {
		for n := len(secret); n >= scrubMin; n-- {
			s = strings.ReplaceAll(s, secret[:n], "[secret]")
		}
	}
	return s
}

func (r *recovery) say(format string, args ...any) {
	fmt.Fprintln(stdout, r.scrub("supapaced recover: "+fmt.Sprintf(format, args...)))
}

func recoverNode(ctx context.Context, escrow []string, archive string, accept bool) (err error) {
	var parts [][]byte
	defer func() {
		for _, p := range parts {
			clear(p)
		}
	}()
	for _, f := range escrow {
		b, err := readRegular(f)
		if err != nil {
			return err
		}
		parts = append(parts, b)
	}
	// It refuses a key that is not the one its kek_id names, before anything else.
	e, err := offsite.ParseEscrow(parts...)
	if err != nil {
		return err
	}
	r := &recovery{e: e, cfg: nodecfg.Defaults()}
	clear(e.KEK[:])
	defer func() {
		if err != nil {
			err = errors.New(r.scrub(err.Error()))
			if ctx.Err() != nil { // whatever failed then failed because of it
				err = errors.New("interrupted by a signal; the recovery start and the control plane's job containers are removed and a restore that was marked stays marked: run recover again")
			}
		}
		clear(r.e.KEK[:])
	}()
	r.diskMB, r.repoMB = nodecfg.CPQuotas(r.cfg, paths)
	r.uidBase, r.uidCount = r.cfg.UIDBase, r.cfg.UIDCount
	if err := r.refusals(ctx, archive); err != nil {
		return err
	}
	// The daemon must not run: the recovery start listens on its socket path.
	// Held until the run ends, the lock also keeps a daemon — and a second
	// recovery — from starting.
	lock, err := claimRunDir(paths.AdminSock())
	if err != nil {
		if strings.Contains(err.Error(), "is locked") {
			return fmt.Errorf("a daemon or another recover is running on this node (%s is locked)", filepath.Join(filepath.Dir(paths.AdminSock()), "serve.lock"))
		}
		return err
	}
	defer lock.Close()
	// A node.json that survived is the daemon's: this run does not read its
	// subnets, quotas or images, and says so.
	if exists(paths.NodeJSON()) {
		r.say("%s exists and is not read: this run uses the defaults for the subnets, the quotas and the images; the daemon's first start applies the file", paths.NodeJSON())
		if c, err := nodecfg.Load(paths.NodeJSON()); err == nil {
			r.uidBase, r.uidCount = c.UIDBase, c.UIDCount
		}
	}
	if err := r.install(); err != nil {
		return err
	}
	r.ag = newRecoverAgent(r.cfg)
	if err := r.prepare(ctx); err != nil {
		return err
	}
	// From here the recovery start may exist, and a job container: neither
	// outlives a run that did not finish. A database nothing has checked does
	// not stay up, and no container stays whose configuration holds the
	// passphrase — a signal can end the run between a job's creation and the
	// launcher's own removal.
	finished := false
	defer func() {
		if finished {
			return
		}
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if err := r.ag.KillJobs(sctx, nodecfg.ControlPlaneSubject); err != nil {
			fmt.Fprintf(stderr, "supapaced recover: removing the control plane's job containers: %s\n", r.scrub(clean(err)))
		}
		if err := r.ag.StopControlPlaneRecovery(sctx); err != nil {
			fmt.Fprintf(stderr, "supapaced recover: stopping the recovery start: %s\n", r.scrub(clean(err)))
		}
	}()
	fetched, reached, served, err := r.restore(ctx)
	if err != nil {
		return err
	}
	if err := r.shortfall(fetched.NewestSegment, reached, served, accept); err != nil {
		return err
	}
	epoch, undone, err := r.newEpoch(ctx)
	if err != nil {
		return err
	}
	if err := r.ag.KillJobs(ctx, nodecfg.ControlPlaneSubject); err != nil {
		return err
	}
	if err := r.ag.FinishControlPlaneRestore(ctx); err != nil {
		return err
	}
	finished = true // the recovery start is stopped and removed

	r.say("recovered point: set %s, reached segment %s, new epoch %d", fetched.NewestSet, reached, epoch)
	r.say("memberships, session revocations and service keys are as of the recovered point")
	for _, ref := range undone {
		// The document carries the control-plane bucket's location only: the
		// place is named relative to the projects bucket's own prefix.
		r.say("project %s: its create was undone; the off-site purge will destroy what is under %s/ below the projects bucket's prefix", ref, ref)
	}
	r.say("next: run supapaced init, start the daemon, run supapaced offsite set with all four credentials, then restore each project")
	return nil
}

// refusals are the checks a recovery makes before it writes anything: the
// document against this build, and the node against a node that holds no
// control plane of its own.
func (r *recovery) refusals(ctx context.Context, archive string) error {
	cp := r.e.ControlPlane
	if v := store.SchemaVersion(); cp.SchemaVersion > v {
		return fmt.Errorf("the escrow document's schema version %d is above this build's (%d): use a newer supapaced", cp.SchemaVersion, v)
	}
	if cp.Image != r.cfg.Images.ControlPlane {
		return errors.New("the control-plane image of the escrow document is not this build's: use the supapaced version the document names")
	}
	// A key or a passphrase already here must be the document's: another one
	// is another node's, and installing over it would orphan what it sealed.
	if exists(paths.KEK()) {
		k, err := loadKEK(paths.KEK())
		if err != nil {
			return fmt.Errorf("the key file %s cannot be read: %w", paths.KEK(), err)
		}
		same := k == r.e.KEK
		clear(k[:])
		if !same {
			return fmt.Errorf("the key file %s holds another key than the escrow document: this node has its own key", paths.KEK())
		}
	}
	if exists(paths.CPStanzaSealed()) {
		if pass, err := offsite.EnsureControlPlanePass(paths, r.e.KEK); err != nil || pass != cp.CipherPass {
			return fmt.Errorf("the sealed passphrase %s is not the escrow document's: this node has its own control plane", paths.CPStanzaSealed())
		}
	}
	// So must a declaration: one that names another place for the control
	// plane's copy is another node's. The node's own full declaration of the
	// document's location is kept as it is — a recovery does not take the
	// other credentials away; a partial one is written again.
	if exists(paths.OffsiteSealed()) {
		d, state, err := offsite.Load(paths, r.e.KEK)
		if err != nil {
			return fmt.Errorf("the declaration %s does not open with the escrow document's key: this node has its own", paths.OffsiteSealed())
		}
		want := r.declaration()
		if d.Endpoint != want.Endpoint || d.Region != want.Region || d.PathStyle != want.PathStyle || d.CAPEM != want.CAPEM ||
			d.ControlPlane.Name != want.ControlPlane.Name || d.ControlPlane.Prefix != want.ControlPlane.Prefix {
			return fmt.Errorf("the declaration %s names another control-plane location than the escrow document: this node has its own store", paths.OffsiteSealed())
		}
		r.keepDeclaration = state == offsite.StateDeclared
	}
	c, err := inspectContainer(ctx, cpContainer)
	if err != nil {
		return err
	}
	if c != nil {
		return fmt.Errorf("the container %s exists: this node has a control-plane database", cpContainer)
	}
	if old := filepath.Join(paths.CPDir(), "data"); exists(old) {
		return fmt.Errorf("%s holds a database of an older build: this node has a control-plane database", old)
	}
	// A restore already marked is a run that did not finish: its trees are
	// emptied by the preparation. Without the marker they may be the node's
	// newest copy.
	if !exists(paths.CPRestoring()) {
		for dir, what := range map[string]string{filepath.Join(paths.CPProjectDir(), "data"): "database",
			filepath.Join(paths.RepoDir(nodecfg.ControlPlaneSubject), "repo"): "repository"} {
			ents, err := os.ReadDir(dir)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if len(ents) > 0 {
				return fmt.Errorf("%s holds a %s and no restore is marked: this node has a control plane; move it aside first if it is to be replaced", dir, what)
			}
		}
	}
	etc := filepath.Dir(paths.NodeJSON())
	if fi, err := os.Lstat(etc); err == nil {
		if !fi.IsDir() || owner(fi) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must be a real directory of uid %d that no one else can write", etc, os.Geteuid())
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := recoverTools(); err != nil {
		return err
	}
	// The worker image by its recorded id. Absent, or present under the name
	// with another id, it is loaded from the archive when one is given: the
	// load only moves the name to the archive's image — the other image stays
	// in Docker's store, unnamed — and the id is compared again afterwards.
	ref, want := r.cfg.Images.Worker, r.e.WorkerImage.ID
	id, err := imageID(ctx, ref)
	switch {
	case err == nil && id == want:
		return nil
	case err != nil && !errors.Is(err, errNoImage):
		return fmt.Errorf("the worker image %s could not be inspected: %w", ref, err)
	case archive == "" && err != nil:
		return fmt.Errorf("the worker image %s is not loaded: pass --worker-image-archive", ref)
	case archive == "":
		return fmt.Errorf("the worker image %s has id %s, the escrow document records %s: pass --worker-image-archive to load the recorded one under that name", ref, id, want)
	}
	if err := loadImage(ctx, archive); err != nil {
		return fmt.Errorf("loading the worker image: %w", err)
	}
	if id, err = imageID(ctx, ref); err != nil {
		return fmt.Errorf("the archive did not load the worker image %s: %w", ref, err)
	}
	if id != want {
		return fmt.Errorf("the archive loaded an image with id %s, the escrow document records %s", id, want)
	}
	return nil
}

// jobPrograms checks what a job container is started from, as the launcher
// will: this executable, which must be root's, and the archive binary beside
// it.
func jobPrograms() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(exe); err != nil || !fi.Mode().IsRegular() || owner(fi) != os.Geteuid() || int(fi.Sys().(*syscall.Stat_t).Gid) != os.Getegid() {
		return fmt.Errorf("the executable %s must be a regular file of root's: no job is started from another owner's program", exe)
	}
	arch := filepath.Join(filepath.Dir(exe), "supapace-arch")
	if fi, err := os.Lstat(arch); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("the archive binary %s must lie beside the executable", arch)
	}
	return nil
}

// install writes the node directory and what the document holds for it: the
// key with its marker (init then neither shows it again nor makes another),
// the control plane's passphrase sealed under the key, and a declaration of
// the control plane's bucket with its read-only credential — the store is
// then partly declared until `offsite set` names every credential. A file
// already in place was checked against the document and is left as it is,
// the node's own full declaration of the same location among them.
func (r *recovery) install() error {
	etc := filepath.Dir(paths.NodeJSON())
	uid, gid := os.Geteuid(), os.Getegid()
	if err := os.Mkdir(etc, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	write := func(path string, data []byte, mode os.FileMode) error {
		if exists(path) {
			return nil
		}
		return nodefs.WriteFile(paths, etc, filepath.Base(path), data, mode, uid, gid)
	}
	if err := write(paths.KEK(), r.e.KEK[:], 0o400); err != nil {
		return err
	}
	if err := write(filepath.Join(etc, kekEscrowName), nil, 0o600); err != nil {
		return err
	}
	sealed, err := secrets.SealNode(r.e.KEK, "cp-stanza", []byte(r.e.ControlPlane.CipherPass))
	if err != nil {
		return err
	}
	if err := write(paths.CPStanzaSealed(), sealed, 0o600); err != nil {
		return err
	}
	// Read back as every later reader will: under the key, by its name.
	if pass, err := offsite.EnsureControlPlanePass(paths, r.e.KEK); err != nil || pass != r.e.ControlPlane.CipherPass {
		return fmt.Errorf("the sealed passphrase %s does not open to the escrow document's", paths.CPStanzaSealed())
	}
	if r.keepDeclaration {
		return nil
	}
	return offsite.Save(paths, r.e.KEK, r.declaration())
}

// declaration is the store as the document names it: the control plane's
// bucket and how to read it. A recovery never holds a write credential.
func (r *recovery) declaration() offsite.Declaration {
	o := r.e.Offsite
	return offsite.Declaration{Endpoint: o.Endpoint, Region: o.Region, PathStyle: o.PathStyle, CAPEM: o.CAPEM,
		ControlPlane: offsite.Bucket{Name: o.Bucket, Prefix: o.Prefix, Read: o.Read}}
}

// prepare readies the node for the jobs. The image files come first: a
// second preparation runs removal tasks under the seccomp profile. No job of
// the control plane may run while its trees are emptied. The fetch job's
// only way out of its network is the set installed here.
func (r *recovery) prepare(ctx context.Context) error {
	if err := r.ag.EnsureImageFiles(ctx); err != nil {
		return err
	}
	if err := r.ag.KillJobs(ctx, nodecfg.ControlPlaneSubject); err != nil {
		return err
	}
	if err := r.ag.PrepareControlPlaneRestore(ctx); err != nil {
		return err
	}
	if err := r.ag.SetReplicatorQuota(ctx, 2*r.repoMB); err != nil {
		return err
	}
	if err := r.ag.EnsureBackupNetwork(ctx); err != nil {
		return err
	}
	set, err := resolveAndInstall(ctx, r.declaration(), r.cfg)
	r.set = set
	return err
}

// job runs one job of the control plane to its result. Only the fetch job
// holds a credential and addresses, only restore and serve the passphrase.
func (r *recovery) job(ctx context.Context, id int64, kind string, in jobio.Input) (any, error) {
	cp := nodecfg.ControlPlaneSubject
	in.Job, in.Kind, in.Subject, in.Stanza, in.UID = id, kind, cp, r.e.ControlPlane.Stanza, nodecfg.ControlPlaneUID
	spec := agent.JobSpec{ID: id, Subject: cp, Kind: kind, UID: nodecfg.ControlPlaneUID, GID: nodecfg.ControlPlaneUID}
	switch kind {
	case "fetch":
		// The byte limit and the deadline come from one figure, the repository quota.
		in.MaxBytes, in.ListCurrent = int64(r.repoMB)<<20, true
		o := r.e.Offsite
		spec.Cred = []byte(o.Read.AccessKey + "\n" + o.Read.SecretKey)
		spec.Env, spec.Files, spec.Addrs = storeEnv(o.Endpoint, o.Region, o.PathStyle, o.Bucket, o.Prefix, r.set), caFile(o.CAPEM), r.set
	case "restore", "serve":
		spec.SecretEnv = map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": r.e.ControlPlane.CipherPass}
	}
	var err error
	if spec.Deadline, err = bklimit.Deadline(kind, r.diskMB, r.repoMB); err != nil {
		return nil, err
	}
	if spec.Input, err = jobio.MarshalInput(in); err != nil {
		return nil, err
	}
	res, err := r.ag.RunJob(ctx, spec)
	switch {
	case err != nil && len(res.Result) == 0:
		return nil, fmt.Errorf("the %s job: %w", kind, err)
	case res.TimedOut:
		return nil, fmt.Errorf("the %s job ran past its deadline of %v", kind, spec.Deadline)
	case len(res.Result) == 0:
		return nil, fmt.Errorf("the %s job left no result (exit %d)", kind, res.ExitCode)
	}
	v, fail, err := jobio.ParseResult(kind, res.Result)
	switch {
	case err != nil:
		return nil, fmt.Errorf("the %s job: %w", kind, err)
	case fail != nil:
		return nil, fmt.Errorf("the %s job failed: %s: %s", kind, fail.Code, fail.Message)
	case res.ExitCode != 0:
		return nil, fmt.Errorf("the %s job ended with status %d", kind, res.ExitCode)
	}
	return v, nil
}

// denied is what follows every stop the store itself causes by what it holds
// or withholds: it is no shortfall, and accepting one does not pass it.
const denied = "the store denies this recovery: this is not a shortfall, and --accept-shortfall does not pass it; nothing was written to the restored database"

var historyRE = regexp.MustCompile(`^([0-9A-F]{8})\.history$`)

// fetchedHistories lists the timelines whose history file the fetch took:
// the names in fetch/archive/<stanza>/<archive id>/, two listings deep, no
// file opened and no link followed. The fetch job wrote them, each name
// checked against the stanza's layout; their content is whatever the store
// held under those names.
func fetchedHistories(stanza string) ([]uint32, error) {
	dir := filepath.Join(paths.RepoDir(nodecfg.ControlPlaneSubject), "fetch", "archive", stanza)
	ids, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var tls []uint32
	for _, id := range ids {
		if !id.IsDir() {
			continue
		}
		ents, err := os.ReadDir(filepath.Join(dir, id.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if m := historyRE.FindStringSubmatch(e.Name()); m != nil {
				t, _ := strconv.ParseUint(m[1], 16, 32)
				tls = append(tls, uint32(t))
			}
		}
	}
	return tls, nil
}

// restoreTimeline is the timeline the restore job is told to follow, from
// names alone: the highest fetched history that is not above the timeline of
// the newest fetched segment, else 1. The archive tool then opens that
// history and no other: left to itself it opens the highest history of the
// archive, and a history above every segment — one the replicator never put
// there — would stop the restore, or steer it. The recovery start still
// follows the archive as far as it is served.
//
// Both figures are names the store lists, and a store can offer names the
// replicator never wrote; what was followed is therefore judged afterwards,
// from the history the promotion writes (replayEnd).
//
// A history of the very next timeline, with no segment of that timeline, is
// refused. The recovery start would ask for it: one the archive tool can
// read is followed, and the promotion takes the timeline after it; one it
// cannot read is never answered, and the server stops. A node lost after
// its promotion's history was uploaded and before the first segment of that
// timeline leaves the same names, so the refusal says what was found, not
// who put it there.
func restoreTimeline(newest string, histories []uint32) (int, error) {
	t, _ := strconv.ParseUint(newest[:8], 16, 32)
	target := 1
	for _, h := range histories {
		switch {
		case uint64(h) == t+1:
			return 0, fmt.Errorf("the store holds a history of timeline %d and no segment of that timeline (the newest fetched segment is on timeline %d): "+
				"a store that holds a promotion's history without a segment of it is refused, whether a node lost right after a recovery left it or it was put there; "+
				"this release has no way past it, --accept-shortfall does not pass it, and nothing was restored or changed in the store", h, t)
		case uint64(h) <= t && int(h) > target:
			target = int(h)
		}
	}
	return target, nil
}

// restore fetches the escrowed stanza's two trees, seeds the repository,
// restores the newest set the fetch named and recovers to the end of the
// archive in a container of its own, a serve job beside it, until promotion.
// It returns what was fetched, the segment replay ended in, and whether the
// serve job left a result. The restored database must be the escrowed one.
func (r *recovery) restore(ctx context.Context) (fetched jobio.FetchResult, reached string, served bool, err error) {
	v, err := r.job(ctx, 1, "fetch", jobio.Input{})
	if err != nil {
		return fetched, "", false, err
	}
	fetched = v.(jobio.FetchResult)
	// The names are a job's words about what a store listed.
	if !setLabelRE.MatchString(fetched.NewestSet) {
		return fetched, "", false, errors.New("the fetch found no backup set of the escrowed stanza: nothing to restore")
	}
	if !segmentRE.MatchString(fetched.NewestSegment) {
		return fetched, "", false, fmt.Errorf("the fetch took no segment of the archive, or named one that is no segment: a set cannot be recovered without its segments; %s", denied)
	}
	r.say("fetched %d files, %d bytes: newest set %s, newest segment %s", fetched.Files, fetched.Bytes, fetched.NewestSet, fetched.NewestSegment)
	histories, err := fetchedHistories(r.e.ControlPlane.Stanza)
	if err != nil {
		return fetched, "", false, err
	}
	timeline, err := restoreTimeline(fetched.NewestSegment, histories)
	if err != nil {
		return fetched, "", false, err
	}
	if _, err := r.job(ctx, 2, "seed", jobio.Input{}); err != nil {
		return fetched, "", false, err
	}
	if _, err := r.job(ctx, 3, "restore", jobio.Input{Set: fetched.NewestSet, Mode: "standby", TargetTimeline: timeline}); err != nil {
		return fetched, "", false, fmt.Errorf("%w; if the archive tool could not read an object of the set or the history of timeline %d, %s", err, timeline, denied)
	}
	r.say("restored set %s; recovering to the end of the archive", fetched.NewestSet)

	deadline, err := bklimit.Deadline("serve", r.diskMB, r.repoMB)
	if err != nil {
		return fetched, "", false, err
	}
	if err := r.ag.EnsureControlPlaneRecovery(ctx, pgconf.RecoveryTarget{Timeline: "latest"}); err != nil {
		return fetched, "", false, err
	}
	sctx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	result := make(chan *jobio.ServeResult, 1)
	go func() {
		// Stopped at promotion, the job still leaves its result.
		v, err := r.job(sctx, 4, "serve", jobio.Input{MaxAnswers: bklimit.ServeMaxAnswers})
		if sv, ok := v.(jobio.ServeResult); ok && err == nil {
			result <- &sv
			return
		}
		result <- nil
	}()
	systemID, err := r.awaitPromotion(ctx, result, time.Now().Add(deadline))
	stopServe()
	sv := <-result
	if errors.Is(err, errNotPromoted) {
		// The serve job records the requests it answered, never one it could
		// not: what stopped the server is what it asked for after the last.
		at := "the serve job answered no request it can name"
		if sv != nil {
			if _, _, ok := walname.Request(sv.Last); ok {
				at = "the last request the serve job answered was " + sv.Last +
					"; what the server asked for after it is what the archive does not hold in a form the archive tool can read"
			}
		}
		return fetched, "", false, fmt.Errorf("%w: %s; %s", err, at, denied)
	}
	if err != nil {
		return fetched, "", false, err
	}
	if systemID != r.e.ControlPlane.Incarnation {
		return fetched, "", false, fmt.Errorf("the restored database has system identifier %s, the escrow document names %s: the bucket gave another database; nothing was written to it",
			pgsock.Sanitize(systemID, 32), r.e.ControlPlane.Incarnation)
	}
	if reached, err = replayEnd(); err != nil {
		return fetched, "", false, err
	}
	r.say("recovery promoted; replay ended in segment %s", reached)
	return fetched, reached, sv != nil, nil
}

var errNotPromoted = errors.New("the recovery start exited before it promoted")

// awaitPromotion polls the recovery start until it has promoted and returns
// the database's system identifier. A recovery start that exits, a serve job
// that ends first and the serve job's deadline each end the wait.
func (r *recovery) awaitPromotion(ctx context.Context, result chan *jobio.ServeResult, deadline time.Time) (string, error) {
	for {
		promoted, exited, systemID, err := r.ag.ControlPlaneRecoveryState(ctx)
		switch {
		case err != nil:
			return "", err
		case promoted:
			return systemID, nil
		case exited:
			return "", errNotPromoted
		case time.Now().After(deadline):
			return "", errors.New("the recovery did not promote within its deadline")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case sv := <-result:
			result <- sv
			return "", errors.New("the serve job ended before the recovery promoted")
		case <-time.After(recoverPoll):
		}
	}
}

// walSegmentBits: a segment is 16 MiB, the size the control-plane image
// initialises its database with.
const walSegmentBits = 24

var switchRE = regexp.MustCompile(`^([0-9]{1,10})\s+([0-9A-Fa-f]{1,8})/([0-9A-Fa-f]{1,8})(\s|$)`)

// replayEnd is the segment replay ended in, read from what the server wrote
// at promotion: the history of the new timeline, the newest in the data
// directory's WAL directory. Its last line names the timeline replay ended
// on and the position the new timeline forks at; the segment holding the
// byte before that position is the last one replayed. A segment the serve
// job handed over and the server did not use is not counted: only this is.
// The same history shows which timelines replay went through.
func replayEnd() (string, error) {
	dir := filepath.Join(paths.CPProjectDir(), "data", "pg_wal")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	name := ""
	for _, e := range ents {
		if historyRE.MatchString(e.Name()) && e.Name() > name {
			name = e.Name()
		}
	}
	if name == "" {
		return "", errors.New("the promoted database has no history of a new timeline: where replay ended is not known")
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return "", err
	}
	var m []string
	inOrder, lines := true, uint64(0)
	for _, line := range strings.Split(string(b), "\n") {
		if s := switchRE.FindStringSubmatch(strings.TrimSpace(line)); s != nil {
			m = s // the last line that is a switch: this timeline's own
			lines++
			inOrder = inOrder && s[1] == strconv.FormatUint(lines, 10)
		}
	}
	if m == nil {
		return "", fmt.Errorf("the history %s names no switch point: where replay ended is not known", name)
	}
	// The control plane's timelines arise one after the other, each at the
	// end of the one before: the history of timeline N names 1 to N-1, once
	// each and in order. One that does not shows that replay followed a
	// history which leaves out a timeline the archive holds — offered under a
	// later name than the one it was written for — and so never read that
	// timeline. What it restored is no end of the archive, however far its
	// segments are numbered.
	if own, _ := strconv.ParseUint(name[:8], 16, 32); !inOrder || lines != own-1 {
		return "", fmt.Errorf("the history the promotion wrote (%s) does not name every timeline below its own, once and in order: "+
			"replay followed a history that leaves out a timeline of the archive; %s", name, denied)
	}
	tli, _ := strconv.ParseUint(m[1], 10, 32)
	hi, _ := strconv.ParseUint(m[2], 16, 32)
	lo, _ := strconv.ParseUint(m[3], 16, 32)
	lsn := hi<<32 | lo
	if tli == 0 || lsn == 0 {
		return "", fmt.Errorf("the history %s names no usable switch point: where replay ended is not known", name)
	}
	lsn-- // a fork at a segment's first byte: replay ended in the segment before
	return fmt.Sprintf("%08X%08X%08X", tli, lsn>>32, (lsn&0xFFFFFFFF)>>walSegmentBits), nil
}

// segNum is a segment's number, whatever its timeline: of its last 16 hex
// digits the first 8 count 4 GiB each — 256 segments — and the last 8 the
// segments within.
func segNum(seg string) uint64 {
	hi, _ := strconv.ParseUint(seg[8:16], 16, 32)
	lo, _ := strconv.ParseUint(seg[16:], 16, 32)
	return hi<<(32-walSegmentBits) | lo
}

// shortfall stops a recovery whose replay ended before the newest segment
// the fetch took, compared by segment number — on the control plane
// timelines arise only at the end of its archive, so numbers rise across
// them. A serve job that left no result counts as one: never a silent pass.
// This is the one restore whose shortfall would lose every project's later
// keys.
func (r *recovery) shortfall(newest, reached string, served, accept bool) error {
	var what string
	switch {
	case segNum(reached) < segNum(newest):
		what = fmt.Sprintf("replay ended in segment %s, the fetch took segments through %s: %d segments were not replayed", reached, newest, segNum(newest)-segNum(reached))
	case !served:
		what = fmt.Sprintf("the serve job left no result, so what recovery asked for and was not given is not known; replay ended in segment %s, the fetch took segments through %s", reached, newest)
	default:
		return nil
	}
	const lost = "every change after the reached position is lost, creates and their keys included, so those projects' off-site backups cannot be opened"
	if accept {
		r.say("shortfall accepted: %s; %s", what, lost)
		return nil
	}
	return fmt.Errorf("shortfall: %s; %s; nothing was written to the restored database; run recover again with --accept-shortfall to accept the loss", what, lost)
}

// newEpoch is the one transaction that makes the restored database this
// node's: a new epoch, the uid counter above every owner left on disk, the
// lost node's jobs and open operations ended. The creates it aborts are read
// first — the transaction leaves no trace of which they were: the projects
// still being provisioned whose layout has an off-site prefix.
func (r *recovery) newEpoch(ctx context.Context) (epoch int64, undone []string, err error) {
	st, err := openRecovered(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer st.Close()
	// A database of an older build is brought to this build's schema, which
	// the transaction is written for.
	if err := st.Migrate(ctx); err != nil {
		return 0, nil, err
	}
	ps, err := st.ListProjects(ctx)
	if err != nil {
		return 0, nil, err
	}
	for _, p := range ps {
		if p.State == "provisioning" && p.Config.Layout == 2 {
			undone = append(undone, p.Ref)
		}
	}
	floor, err := uidFloor(r.uidBase, r.uidCount)
	if err != nil {
		return 0, nil, err
	}
	epoch, err = st.EnterNewEpoch(ctx, floor)
	return epoch, undone, err
}

// uidFloor is one above the highest project uid that owns an entry of the
// projects directory or a repo directory below an entry of the repository
// root; 0 when there is none. A tree that survived keeps its owner: the
// filesystem would charge its bytes to a new project given that uid. Root's
// own directories are listed, one lstat an entry; no tree is entered.
func uidFloor(base, count int) (int, error) {
	floor := 0
	for dir, sub := range map[string]string{paths.ProjectsDir(): "", paths.RepoRoot(): "repo"} {
		ents, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return 0, err
		}
		for _, e := range ents {
			uid, err := ownerUID(filepath.Join(dir, e.Name(), sub))
			switch {
			case errors.Is(err, fs.ErrNotExist):
			case err != nil:
				return 0, err
			case uid >= base && uid < base+count:
				floor = max(floor, uid+1)
			}
		}
	}
	return floor, nil
}
