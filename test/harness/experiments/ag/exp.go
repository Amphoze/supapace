//go:build supapace_exp

// exp.go — the experiments' command, `supapaced exp …`. It is never part of a
// product build: ag/lab.sh compiles it INTO cmd/supapaced with `go build
// -overlay -tags supapace_exp`, so the binary is the daemon itself plus this
// one command. Each subcommand is one call (or a short sequence) of the
// platform's own packages — internal/agent (layout-2 projects, job containers,
// the recovery start, the re-key, the control-plane database), internal/nft
// (the node ruleset and its address set), internal/s3x — and a job it starts
// runs this same binary as its program (`supapaced job …`, `supapaced
// replicate …`, `supapaced rmtree …`), exactly as the daemon's jobs do.
//
// It runs as root inside a bare test node (no daemon). State between calls
// lives in $SUPAPACE_EXP_DIR (root 0700): a random lab seed and one small file
// per project. Every password, salt, data key and passphrase is derived from
// the seed (lab values, never real ones) and never printed.
//
//	exp node [-offsite]                 platform networks, image files, the node
//	                                    ruleset loaded; -offsite: its address set
//	                                    is the stand-in's two addresses; the backup
//	                                    network
//	exp set ADDR:PORT…|none             the ruleset's address set (nft.InstallSet)
//	exp up REF UID SLICE DISKMB REPOMB  a layout-2 project: directories, quotas,
//	                                    network, first boot, networked start
//	exp stop|start|wipe|rmfetch|down REF
//	                                    StopCluster | EnsureCluster | WipeData |
//	                                    RemoveFetch | everything of REF removed
//	exp quota REF DISKMB REPOMB         new quotas (SetQuota)
//	exp sql [-trust | -bare] [-gen N] REF SQL
//	                                    one superuser session: SCRAM with the
//	                                    password of the current generation (or N),
//	                                    or (-trust) without one as the recovery
//	                                    start allows; -bare: without the platform's
//	                                    startup list either (a control), with -set
//	                                    parameters only; rows a|b
//	exp job REF KIND [-tl 1,2] [-set L] [-mode none|standby] [-target N]
//	        [-role R] [-prefix P] [-addrs A,B] [-maxbytes N] [-from SEG]
//	                                    one job by agent.RunJob; prints
//	                                    "exit N", the result line, the stderr tail.
//	                                    serve runs until this process is stopped.
//	exp recover REF [-time T | -lsn L] [-timeline TL] [-wait S]
//	                                    EnsureRecovery, then RecoveryState once a
//	                                    second: "promoted after N s", "exited
//	                                    after N s" or "not promoted after N s"
//	exp rekey REF                       the next generation's passwords; Rekey
//	exp cp ensure|prepare|recover|state|finish|migrate|stop
//	                                    the control-plane database (internal/agent)
//	exp cp sql SQL                      root's session to it (peer, role supapaced)
//	exp mpu ROLE KEY N                  N multipart uploads of KEY completed at
//	                                    once with the conditional create
//	exp nftcheck                         nft.Check (10 s for its lock)
//	exp rquota MB                        the replicator's quota on the repository
//	                                    filesystem (SetReplicatorQuota; 0 clears it)
//	exp pass REF FILE                   the stanza passphrase into FILE (0600), for a
//	                                    pgBackRest command no platform job runs
//	exp downall                         every project of the directory, the
//	                                    control plane, the networks, the ruleset
//
// Exit 0 success, 1 a call failed (one line on stderr), 2 usage.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/s3x"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/Amphoze/supapace/internal/walname"
	"github.com/jackc/pgx/v5"
)

func init() { commands["exp"] = expCmd }

type xUsage string

func (e xUsage) Error() string { return string(e) }

// xS3 is the stand-in's directory in a test node (test/harness/s3/setup.sh).
const xS3 = "/var/lib/sp/s3"

var (
	xCfg   = nodecfg.Default("sp.test")
	xPaths nodecfg.Paths
	xAg    = agent.New(xCfg, xPaths)
)

func expCmd(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	err := xDispatch(ctx, args)
	var u xUsage
	switch {
	case errors.As(err, &u):
		fmt.Fprintln(stderr, "usage: supapaced exp "+string(u))
		return 2
	case err != nil:
		fmt.Fprintln(stderr, "exp: "+pgsock.Sanitize(err.Error(), 2048))
		return 1
	}
	return 0
}

func xDispatch(ctx context.Context, a []string) error {
	if len(a) == 0 {
		return xUsage("node|set|up|stop|start|wipe|down|quota|sql|job|recover|rekey|cp|mpu|downall …")
	}
	if os.Geteuid() != 0 {
		return errors.New("runs as root in a bare test node")
	}
	need := func(n int, u string) error {
		if len(a)-1 != n {
			return xUsage(a[0] + " " + u)
		}
		return nil
	}
	switch a[0] {
	case "node":
		return xNode(ctx, a[1:])
	case "set":
		return xSet(ctx, a[1:])
	case "up":
		if err := need(5, "REF UID SLICE DISKMB REPOMB"); err != nil {
			return err
		}
		return xUp(ctx, a[1:])
	case "stop", "start", "wipe", "down", "rekey", "rmfetch":
		if err := need(1, "REF"); err != nil {
			return err
		}
		return xOne(ctx, a[0], a[1])
	case "quota":
		if err := need(3, "REF DISKMB REPOMB"); err != nil {
			return err
		}
		return xQuota(ctx, a[1:])
	case "sql":
		return xSQL(ctx, a[1:])
	case "job":
		return xJob(ctx, a[1:])
	case "recover":
		return xRecover(ctx, a[1:])
	case "cp":
		return xCP(ctx, a[1:])
	case "mpu":
		if err := need(3, "ROLE KEY N"); err != nil {
			return err
		}
		return xMPU(ctx, a[1:])
	case "nftcheck":
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return nft.Check(cctx, xPaths)
	case "rquota":
		if err := need(1, "MB"); err != nil {
			return err
		}
		mb, err := strconv.Atoi(a[1])
		if err != nil {
			return xUsage("rquota MB")
		}
		return xAg.SetReplicatorQuota(ctx, mb)
	case "pass":
		if err := need(2, "REF FILE"); err != nil {
			return err
		}
		return xPass(a[1], a[2])
	case "downall":
		return xDownAll(ctx)
	}
	return xUsage(a[0] + ": unknown subcommand")
}

// --- the lab's state ---------------------------------------------------------

type xProject struct {
	Ref                             string
	UID, Slice, DiskMB, RepoMB, Gen int
}

func xDir() (string, error) {
	d := os.Getenv("SUPAPACE_EXP_DIR")
	if d == "" || !filepath.IsAbs(d) {
		return "", errors.New("SUPAPACE_EXP_DIR must name an absolute directory")
	}
	return d, os.MkdirAll(d, 0o700)
}

// xSeed is the lab's random seed, made once per lab directory.
func xSeed() ([]byte, error) {
	d, err := xDir()
	if err != nil {
		return nil, err
	}
	f := filepath.Join(d, "seed")
	b, err := os.ReadFile(f)
	if errors.Is(err, os.ErrNotExist) {
		b = make([]byte, 32)
		if _, err := randRead(b); err != nil {
			return nil, err
		}
		b = []byte(hex.EncodeToString(b))
		err = os.WriteFile(f, b, 0o600)
	}
	return b, err
}

func randRead(b []byte) (int, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Read(b)
}

// xLab derives one lab value from the seed.
func xLab(parts ...string) (string, error) {
	seed, err := xSeed()
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, seed)
	m.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(m.Sum(nil)), nil
}

func xLoad(ref string) (xProject, error) {
	d, err := xDir()
	if err != nil {
		return xProject{}, err
	}
	var p xProject
	b, err := os.ReadFile(filepath.Join(d, ref+".json"))
	if err == nil {
		err = json.Unmarshal(b, &p)
	}
	if err != nil {
		return p, fmt.Errorf("project %s: %w", ref, err)
	}
	return p, nil
}

func xSave(p xProject) error {
	d, err := xDir()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(p)
	return os.WriteFile(filepath.Join(d, p.Ref+".json"), b, 0o600)
}

// xSpec is the agent's spec of a recorded project at its generation.
func xSpec(p xProject) (agent.Spec, error) {
	s := agent.Spec{Ref: p.Ref, Epoch: 1, Generation: int64(p.Gen), UID: p.UID, GID: p.UID, SubnetIndex: p.Slice,
		DiskQuotaMB: p.DiskMB, MemMB: 512, Pids: 512, Layout: 2, RepoQuotaMB: p.RepoMB, Stanza: p.Ref + "-1"}
	dek, err := xLab("dek", p.Ref)
	if err != nil {
		return s, err
	}
	s.Secrets.ScramSalts = map[string][]byte{}
	for _, r := range []string{"supabase_admin", "postgres", "authenticator"} {
		if s.Secrets.ScramSalts[r], err = pgsock.ScramSalt([]byte(dek), p.Ref, r); err != nil {
			return s, err
		}
	}
	pw := func(role string) string {
		v, _ := xLab("password", p.Ref, role, strconv.Itoa(p.Gen))
		return "lab" + strconv.Itoa(p.Gen) + "-" + v[:32]
	}
	s.Secrets.SupabaseAdminPassword, s.Secrets.PostgresPassword, s.Secrets.AuthenticatorPassword =
		pw("supabase_admin"), pw("postgres"), pw("authenticator")
	if s.Secrets.PgsodiumRootKey, err = xLab("pgsodium", p.Ref); err != nil {
		return s, err
	}
	pass, err := xLab("stanza", p.Ref)
	s.StanzaPass = "lab-" + pass[:48]
	return s, err
}

// --- the node -----------------------------------------------------------------

// xStandin is the stand-in's endpoint and its two addresses, if any.
func xStandin() (endpoint string, addrs []netip.AddrPort, err error) {
	e, err := os.ReadFile(xS3 + "/endpoint")
	if err != nil {
		return "", nil, err
	}
	endpoint = strings.TrimSpace(string(e))
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", nil, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return "", nil, err
	}
	b, err := os.ReadFile(xS3 + "/addrs")
	if err != nil {
		return "", nil, err
	}
	for _, f := range strings.Fields(string(b)) {
		ip, err := netip.ParseAddr(f)
		if err != nil {
			return "", nil, err
		}
		addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
	}
	return endpoint, addrs, nil
}

func xNode(ctx context.Context, a []string) error {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	off := fs.Bool("offsite", false, "")
	if fs.Parse(a) != nil || fs.NArg() != 0 {
		return xUsage("node [-offsite]")
	}
	for _, f := range []func(context.Context) error{xAg.EnsurePlatformNetworks, xAg.EnsureImageFiles} {
		if err := f(ctx); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(xPaths.NftFile()), 0o700); err != nil {
		return err
	}
	if _, err := nft.EnsureRules(ctx, xPaths, xCfg, true); err != nil {
		return err
	}
	if *off {
		_, addrs, err := xStandin()
		if err != nil {
			return fmt.Errorf("no object-store stand-in beside this node: %w", err)
		}
		if err := nft.InstallSet(ctx, xPaths, xCfg, addrs); err != nil {
			return err
		}
	}
	return xAg.EnsureBackupNetwork(ctx)
}

func xSet(ctx context.Context, a []string) error {
	var set []netip.AddrPort
	if len(a) == 0 {
		return xUsage("set ADDR:PORT…|none")
	}
	if !(len(a) == 1 && a[0] == "none") {
		for _, s := range a {
			ap, err := netip.ParseAddrPort(s)
			if err != nil {
				return xUsage("set: " + err.Error())
			}
			set = append(set, ap)
		}
	}
	if err := nft.InstallSet(ctx, xPaths, xCfg, set); err != nil {
		return err
	}
	return nft.Check(ctx, xPaths)
}

// --- projects -------------------------------------------------------------------

func xUp(ctx context.Context, a []string) error {
	n := make([]int, 4)
	for i, s := range a[1:] {
		v, err := strconv.Atoi(s)
		if err != nil {
			return xUsage("up REF UID SLICE DISKMB REPOMB")
		}
		n[i] = v
	}
	p := xProject{Ref: a[0], UID: n[0], Slice: n[1], DiskMB: n[2], RepoMB: n[3], Gen: 1}
	if err := xSave(p); err != nil {
		return err
	}
	s, err := xSpec(p)
	if err != nil {
		return err
	}
	for _, f := range []func(context.Context, agent.Spec) error{xAg.EnsureDir, xAg.EnsureRepoDir, xAg.SetQuota, xAg.EnsureNetwork} {
		if err := f(ctx, s); err != nil {
			return err
		}
	}
	s.FirstBoot = true
	if err := xAg.EnsureCluster(ctx, s); err != nil {
		return fmt.Errorf("first boot: %w", err)
	}
	s.FirstBoot = false
	if err := xAg.EnsureCluster(ctx, s); err != nil {
		return fmt.Errorf("first networked start: %w", err)
	}
	return nil
}

func xOne(ctx context.Context, verb, ref string) error {
	p, err := xLoad(ref)
	if err != nil {
		if verb == "down" && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	s, err := xSpec(p)
	if err != nil {
		return err
	}
	switch verb {
	case "stop":
		return xAg.StopCluster(ctx, ref)
	case "start":
		return xAg.EnsureCluster(ctx, s)
	case "wipe":
		return xAg.WipeData(ctx, s)
	case "rmfetch":
		return xAg.RemoveFetch(ctx, s)
	case "rekey":
		p.Gen++
		if s, err = xSpec(p); err != nil {
			return err
		}
		tl, err := xAg.Rekey(ctx, s)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "rekey timeline %d generation %d\n", tl, p.Gen)
		return xSave(p)
	}
	return xDown(ctx, p)
}

// xDown removes what the lab made of one project, by its names.
func xDown(ctx context.Context, p xProject) error {
	ref := p.Ref
	errs := []error{xAg.KillJobs(ctx, ref), xAg.StopCluster(ctx, ref)}
	for _, k := range []string{"wipe", "prevalidate", "purge", "spool", "purge-repo", "purge-fetch"} {
		exec.CommandContext(ctx, "docker", "rm", "-f", "-v", "task-"+ref+"-"+k).Run()
	}
	errs = append(errs, xAg.RemoveNetwork(ctx, ref))
	for _, d := range []string{xPaths.ProjectDir(ref), xPaths.RepoDir(ref)} {
		errs = append(errs, os.RemoveAll(d)) // the lab, as root; the daemon never does this
	}
	for _, root := range []string{xPaths.ProjectsDir(), xPaths.RepoRoot()} {
		errs = append(errs, nodefs.SetQuotaAt(root, p.UID, 0))
	}
	errs = append(errs, xAg.RemoveRender(ctx, ref), os.Remove(xPaths.IndexFile(ref)))
	if d, err := xDir(); err == nil {
		errs = append(errs, os.Remove(filepath.Join(d, ref+".json")))
	}
	return xJoin(errs)
}

// xJoin joins errors, leaving out a path that was already gone.
func xJoin(errs []error) error {
	var out []error
	for _, e := range errs {
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			out = append(out, e)
		}
	}
	return errors.Join(out...)
}

func xQuota(ctx context.Context, a []string) error {
	p, err := xLoad(a[0])
	if err != nil {
		return err
	}
	if p.DiskMB, err = strconv.Atoi(a[1]); err != nil {
		return xUsage("quota REF DISKMB REPOMB")
	}
	if p.RepoMB, err = strconv.Atoi(a[2]); err != nil {
		return xUsage("quota REF DISKMB REPOMB")
	}
	s, err := xSpec(p)
	if err != nil {
		return err
	}
	if err := xAg.SetQuota(ctx, s); err != nil {
		return err
	}
	return xSave(p)
}

// xState is the agent's record of the project's running cluster.
func xState(ref string) (agent.State, error) {
	var st agent.State
	b, err := os.ReadFile(filepath.Join(xPaths.RenderDir(ref), "state.json"))
	if err == nil {
		err = json.Unmarshal(b, &st)
	}
	return st, err
}

func xSQL(ctx context.Context, a []string) error {
	fs := flag.NewFlagSet("sql", flag.ContinueOnError)
	trust := fs.Bool("trust", false, "")
	bare := fs.Bool("bare", false, "")
	gen := fs.Int("gen", 0, "")
	var set []string
	fs.Func("set", "", func(s string) error {
		if k, _, ok := strings.Cut(s, "="); !ok || k == "" {
			return errors.New("-set takes NAME=VALUE")
		}
		set = append(set, s)
		return nil
	})
	if fs.Parse(a) != nil || fs.NArg() != 2 {
		return xUsage("sql [-trust | -bare [-set NAME=VALUE]…] [-gen N] REF SQL")
	}
	p, err := xLoad(fs.Arg(0))
	if err != nil {
		return err
	}
	if *bare {
		return xBare(ctx, p, set, fs.Arg(1))
	}
	if *gen > 0 {
		p.Gen = *gen
	}
	s, err := xSpec(p)
	if err != nil {
		return err
	}
	st, err := xState(p.Ref)
	if err != nil {
		return err
	}
	t := pgsock.Target{ProjectsDir: xPaths.ProjectsDir(), Ref: p.Ref, UID: p.UID, PostmasterPid: st.PMPid,
		PostmasterStart: st.PMStart, ListenerPid: st.ListenerPid, ListenerStart: st.ListenerStart, User: "supabase_admin",
		ScramSalt: s.Secrets.ScramSalts["supabase_admin"], Superuser: true, AllowTrust: *trust}
	if !*trust {
		t.Password = s.Secrets.SupabaseAdminPassword
	}
	c, err := pgsock.Dial(ctx, t)
	if err != nil {
		return err
	}
	defer c.Close(context.Background())
	return xQuery(ctx, c, fs.Arg(1))
}

// xBare is a control session: supabase_admin over the project's socket without
// a password and without the platform's startup list — what a session that
// is not the platform's gets from the restored settings. Trust only (the
// recovery start's own access files); 30 s to connect. -set adds startup
// parameters of its own.
func xBare(ctx context.Context, p xProject, set []string, sql string) error {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return err
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = filepath.Join(xPaths.ProjectDir(p.Ref), "sock"), 5432, "postgres", "supabase_admin", ""
	for _, kv := range set {
		k, v, _ := strings.Cut(kv, "=")
		cfg.RuntimeParams[k] = v
	}
	cfg.TLSConfig, cfg.Fallbacks, cfg.ConnectTimeout = nil, nil, 30*time.Second
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close(context.Background())
	return xQuery(ctx, c, sql)
}

func xQuery(ctx context.Context, c *pgx.Conn, sql string) error {
	sctx, cancel := pgsock.Stmt(ctx, pgsock.DefaultBudget)
	defer cancel()
	res, err := c.PgConn().Exec(sctx, sql).ReadAll()
	for _, r := range res {
		for _, row := range r.Rows {
			f := make([]string, len(row))
			for i, v := range row {
				f[i] = "NULL"
				if v != nil {
					f[i] = pgsock.Sanitize(string(v), 4096)
				}
			}
			fmt.Fprintln(stdout, strings.Join(f, "|"))
		}
		if err == nil {
			err = r.Err
		}
	}
	return pgsock.Clean(err)
}

// xPass writes the stanza passphrase of REF to FILE (0600, made new), for
// pgBackRest commands no job of the platform runs (verify, expire). It is never
// printed.
func xPass(ref, file string) error {
	p, err := xLoad(ref)
	if err != nil {
		return err
	}
	s, err := xSpec(p)
	if err != nil {
		return err
	}
	os.Remove(file)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(s.StanzaPass)
	return errors.Join(err, f.Close())
}

// --- jobs ---------------------------------------------------------------------

// xJob runs one job as the daemon's runner does (internal/backup jobspec.go):
// the input, the passphrase for the six kinds that take one, and for replicate
// and fetch the subject's credential, the endpoint and the loaded address set.
func xJob(ctx context.Context, a []string) error {
	if len(a) < 2 {
		return xUsage("job REF|cp KIND [OPTIONS]")
	}
	subj, kind := a[0], a[1]
	fs := flag.NewFlagSet("job", flag.ContinueOnError)
	tls := fs.String("tl", "1", "")
	set := fs.String("set", "", "")
	mode := fs.String("mode", "none", "")
	target := fs.Int("target", 0, "")
	role := fs.String("role", "", "")
	prefix := fs.String("prefix", "", "")
	addrs := fs.String("addrs", "", "")
	maxBytes := fs.Int64("maxbytes", 0, "")
	fs.StringVar(&xFrom, "from", "", "")
	if fs.Parse(a[2:]) != nil || fs.NArg() != 0 {
		return xUsage("job REF|cp KIND [-tl 1,2] [-set L] [-mode M] [-target N] [-role R] [-prefix P] [-addrs A,B] [-maxbytes N] [-from SEG]")
	}
	if xFrom != "" && walname.SegmentOf(xFrom) != xFrom {
		return xUsage("job: -from takes a segment name (24 hex digits)")
	}
	if kind == "probe" {
		return xProbe(ctx, subj, *prefix)
	}
	var in jobio.Input
	var spec agent.JobSpec
	var repoMB, diskMB int
	pass := ""
	if subj == nodecfg.ControlPlaneSubject {
		u := nodecfg.ControlPlaneUID
		in = jobio.Input{Job: 1, Kind: kind, Subject: subj, Stanza: "cp-1", UID: u}
		spec = agent.JobSpec{ID: 1, Subject: subj, Kind: kind, UID: u, GID: u}
		diskMB, repoMB = nodecfg.CPQuotas(xCfg, xPaths)
		v, err := xLab("stanza", "cp")
		if err != nil {
			return err
		}
		pass = "lab-" + v[:48]
	} else {
		p, err := xLoad(subj)
		if err != nil {
			return err
		}
		s, err := xSpec(p)
		if err != nil {
			return err
		}
		in = jobio.Input{Job: 1, Kind: kind, Subject: subj, Stanza: s.Stanza, UID: s.UID, Timelines: []uint32{}}
		for _, f := range strings.Split(*tls, ",") {
			if f == "" {
				continue
			}
			v, err := strconv.ParseUint(f, 10, 32)
			if err != nil {
				return xUsage("job: -tl takes timeline numbers")
			}
			in.Timelines = append(in.Timelines, uint32(v))
		}
		spec = agent.JobSpec{ID: 1, Subject: subj, Kind: kind, UID: s.UID, GID: s.GID}
		diskMB, repoMB, pass = p.DiskMB, p.RepoMB, s.StanzaPass
	}
	d, err := bklimit.Deadline(kind, diskMB, repoMB)
	if err != nil {
		return xUsage("job: " + err.Error())
	}
	spec.Deadline = d
	switch kind {
	case "push", "stanza-create", "backup", "check", "restore", "serve":
		spec.SecretEnv = map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": pass}
	}
	switch kind {
	case "push":
		in.MaxEntries = bklimit.PushMaxEntries
	case "backup":
		in.Type = "full"
	case "serve":
		in.MaxAnswers = bklimit.ServeMaxAnswers
	case "restore":
		in.Set, in.Mode, in.TargetTimeline = *set, *mode, *target
	case "replicate", "fetch":
		if err := xNetworked(ctx, &spec, &in, subj, kind, *role, *prefix, *addrs); err != nil {
			return err
		}
		if kind == "fetch" {
			in.MaxBytes = int64(repoMB) << 20
			if *maxBytes > 0 {
				in.MaxBytes = *maxBytes
			}
		}
	}
	b, err := jobio.MarshalInput(in)
	if err != nil {
		return err
	}
	spec.Input = b
	t0 := time.Now()
	r, err := xAg.RunJob(ctx, spec)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "exit %d after %.1f s%s\n", r.ExitCode, time.Since(t0).Seconds(), map[bool]string{true: " (timed out)"}[r.TimedOut])
	fmt.Fprintf(stdout, "result %s\n", r.Result)
	if s := xSummary(kind, r.Result); s != "" {
		fmt.Fprintln(stdout, "summary "+s)
	}
	if e := strings.TrimSpace(r.Stderr); e != "" {
		fmt.Fprintf(stderr, "stderr: %s\n", e)
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("job %s of %s exited %d", kind, subj, r.ExitCode)
	}
	return nil
}

// xProbe runs the operator check of one bucket (projects or cp): its write
// pair then its read-only pair, the other bucket named for the cross row.
func xProbe(ctx context.Context, side, prefix string) error {
	if side != "projects" && side != nodecfg.ControlPlaneSubject {
		return xUsage("job projects|cp probe [-prefix P]")
	}
	spec := agent.JobSpec{Subject: side, Kind: "probe", Deadline: 120 * time.Second}
	in := jobio.Input{Kind: "probe", Subject: side, Repl: &jobio.ReplInput{Mode: "probe"}}
	if err := xNetworked(ctx, &spec, &in, side, "probe", side+"-write", prefix, ""); err != nil {
		return err
	}
	ro, err := os.ReadFile(xS3 + "/" + side + "-read.keys")
	if err != nil {
		return err
	}
	spec.Cred = append(append(spec.Cred, '\n'), strings.TrimSuffix(string(ro), "\n")...)
	spec.Env["SUPAPACE_S3_OTHER_BUCKET"] = map[string]string{"projects": "sp-cp", "cp": "sp-projects"}[side]
	b, err := jobio.MarshalInput(in)
	if err != nil {
		return err
	}
	spec.Input = b
	r, err := xAg.RunJob(ctx, spec)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "exit %d\n", r.ExitCode)
	v, fail, err := jobio.ParseResult("probe", r.Result)
	if err != nil || fail != nil {
		return fmt.Errorf("probe: %v %v (%s)", err, fail, strings.TrimSpace(r.Stderr))
	}
	for _, row := range v.(jobio.ReplResult).ProbeRows {
		fmt.Fprintf(stdout, "row %s %v %s\n", row.Name, row.OK, row.Detail)
	}
	return nil
}

// xNetworked gives a replicate or fetch job what the runner's networked step
// gives it, from the stand-in's files. role defaults to the subject's write
// (replicate) or read-only (fetch) credential; addrs (a test's) replaces the
// handed address list, which is otherwise the loaded set.
func xNetworked(ctx context.Context, spec *agent.JobSpec, in *jobio.Input, subj, kind, role, prefix, addrs string) error {
	endpoint, all, err := xStandin()
	if err != nil {
		return fmt.Errorf("no object-store stand-in beside this node: %w", err)
	}
	bucket, side := "sp-projects", "projects"
	if subj == nodecfg.ControlPlaneSubject {
		bucket, side = "sp-cp", "cp"
	}
	if role == "" {
		role = side + map[string]string{"replicate": "-write", "fetch": "-read"}[kind]
	}
	keys, err := os.ReadFile(xS3 + "/" + role + ".keys")
	if err != nil {
		return err
	}
	spec.Cred = []byte(strings.TrimSuffix(string(keys), "\n"))
	ca, err := os.ReadFile(xS3 + "/ca.pem")
	if err != nil {
		return err
	}
	list := make([]string, len(all))
	for i, a := range all {
		list[i] = a.String()
	}
	if addrs != "" {
		list = strings.Split(addrs, ",")
	}
	spec.Env = map[string]string{"SUPAPACE_S3_ENDPOINT": endpoint, "SUPAPACE_S3_REGION": "us-east-1",
		"SUPAPACE_S3_BUCKET": bucket, "SUPAPACE_S3_PREFIX": prefix, "SUPAPACE_S3_PATH_STYLE": "1",
		"SUPAPACE_S3_ADDRS": strings.Join(list, ",")}
	spec.Files = map[string][]byte{"ca.pem": ca}
	if kind == "probe" {
		return nil
	}
	if kind == "replicate" {
		// An empty record: nothing is known uploaded, so every file is created
		// once or, already there, compared by HEAD.
		idx := xPaths.IndexFile(subj)
		if err := os.MkdirAll(filepath.Dir(idx), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(idx, nil, 0o444); err != nil {
			return err
		}
		in.Repl = &jobio.ReplInput{Mode: "copy", MaxFiles: bklimit.ReplMaxFiles, MaxEntries: bklimit.ReplMaxEntries,
			MaxBytes: bklimit.ReplMaxBytes, BudgetBytes: -1, BudgetObjects: -1, InfoSHA256: map[string]string{}}
		return nil
	}
	if subj == nodecfg.ControlPlaneSubject {
		in.ListCurrent = true
		return nil
	}
	plan, err := xPlan(ctx, endpoint, all, string(keys), string(ca), bucket, prefix, subj, in)
	if err != nil {
		return err
	}
	spec.Files["plan"] = plan
	return nil
}

// xPlan is a project's fetch plan made from the store's own listing (the
// daemon makes it from its record, which the lab does not have): every key of
// the project's stanza, an admitted timeline's only, at its oldest object
// version; the four info files at their newest, with their kind's bound.
// xFrom (fetch -from SEG): the plan leaves out archive files of a position
// below SEG's, as the daemon's plan does below the chosen set's start segment.
var xFrom string

func xPlan(ctx context.Context, endpoint string, addrs []netip.AddrPort, keys, ca, bucket, prefix, subj string, in *jobio.Input) ([]byte, error) {
	c, err := xClient(endpoint, addrs, keys, ca, bucket)
	if err != nil {
		return nil, err
	}
	base := subj + "/"
	if prefix != "" {
		base = prefix + "/" + base
	}
	type pick struct {
		row  jobio.PlanRow
		info bool
	}
	picked := map[string]pick{}
	var order []string
	km, vm := "", ""
	for {
		page, nk, nv, err := c.ListVersions(ctx, base, km, vm)
		if err != nil {
			return nil, err
		}
		for _, o := range page { // per key newest first
			if o.DeleteMarker {
				continue
			}
			rel := strings.TrimPrefix(o.Key, base)
			k, tli, _, ok := walname.RepoPath(in.Stanza, rel)
			if !ok || (tli != 0 && !walname.Admitted(tli, in.Timelines)) {
				continue
			}
			if b := path.Base(rel); xFrom != "" && (k == walname.Segment || k == walname.Label) && b[8:24] < xFrom[8:24] {
				continue
			}
			if _, seen := picked[rel]; !seen {
				order = append(order, rel)
			}
			if k == walname.Info {
				if _, seen := picked[rel]; !seen {
					picked[rel] = pick{jobio.PlanRow{Key: rel, VersionID: o.VersionID, Size: bklimit.SmallMax}, true}
				}
				continue
			}
			picked[rel] = pick{row: jobio.PlanRow{Key: rel, VersionID: o.VersionID, Size: o.Size}} // older replaces newer
		}
		if nk == "" && nv == "" {
			break
		}
		km, vm = nk, nv
	}
	rows := make([]jobio.PlanRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, picked[k].row)
	}
	var b strings.Builder
	if err := jobio.WritePlan(&b, rows); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func xClient(endpoint string, addrs []netip.AddrPort, keys, ca, bucket string) (*s3x.Client, error) {
	f := strings.Fields(keys)
	if len(f) != 2 {
		return nil, errors.New("a keys file holds two lines")
	}
	return s3x.New(s3x.Config{Endpoint: endpoint, Region: "us-east-1", Bucket: bucket, AccessKey: f[0], SecretKey: f[1],
		Addrs: addrs, CAPEM: ca, PathStyle: true, Timeout: 60 * time.Second})
}

// --- recovery -----------------------------------------------------------------

func xTarget(fs *flag.FlagSet, a []string) (pgconf.RecoveryTarget, int, error) {
	tm := fs.String("time", "", "")
	lsn := fs.String("lsn", "", "")
	tl := fs.String("timeline", "latest", "")
	wait := fs.Int("wait", 180, "")
	if err := fs.Parse(a); err != nil {
		return pgconf.RecoveryTarget{}, 0, err
	}
	t := pgconf.RecoveryTarget{LSN: *lsn, Timeline: *tl}
	if *tm != "" {
		var err error
		for _, l := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07"} {
			if t.Time, err = time.Parse(l, *tm); err == nil {
				break
			}
		}
		if err != nil {
			return t, 0, xUsage("recover: -time takes RFC 3339 or the server's text form")
		}
	}
	return t, *wait, nil
}

// xWait polls state once a second until promoted, exited or wait seconds.
func xWait(ctx context.Context, wait int, state func() (promoted, exited bool, err error)) error {
	t0 := time.Now()
	for {
		pr, ex, err := state()
		n := int(time.Since(t0).Seconds())
		switch {
		case err != nil:
			return err
		case pr:
			fmt.Fprintf(stdout, "promoted after %d s\n", n)
			return nil
		case ex:
			fmt.Fprintf(stdout, "exited after %d s\n", n)
			return errors.New("the recovery start exited without promoting")
		case n >= wait:
			fmt.Fprintf(stdout, "not promoted after %d s\n", n)
			return errors.New("not promoted")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func xRecover(ctx context.Context, a []string) error {
	if len(a) < 1 {
		return xUsage("recover REF [-time T | -lsn L] [-timeline TL] [-wait S]")
	}
	t, wait, err := xTarget(flag.NewFlagSet("recover", flag.ContinueOnError), a[1:])
	if err != nil {
		return xUsage("recover REF [-time T | -lsn L] [-timeline TL] [-wait S]")
	}
	p, err := xLoad(a[0])
	if err != nil {
		return err
	}
	s, err := xSpec(p)
	if err != nil {
		return err
	}
	if err := xAg.EnsureRecovery(ctx, s, t); err != nil {
		return err
	}
	return xWait(ctx, wait, func() (bool, bool, error) { return xAg.RecoveryState(ctx, s) })
}

// --- the control-plane database ---------------------------------------------------

func xCP(ctx context.Context, a []string) error {
	if len(a) < 1 {
		return xUsage("cp ensure|prepare|recover|state|finish|migrate|stop|sql SQL")
	}
	switch a[0] {
	case "ensure":
		return xAg.EnsureControlPlaneDB(ctx)
	case "prepare":
		return xAg.PrepareControlPlaneRestore(ctx)
	case "finish":
		return xAg.FinishControlPlaneRestore(ctx)
	case "stop":
		return xAg.StopControlPlaneRecovery(ctx)
	case "recover":
		t, wait, err := xTarget(flag.NewFlagSet("cp recover", flag.ContinueOnError), a[1:])
		if err != nil {
			return xUsage("cp recover [-time T | -lsn L] [-timeline TL] [-wait S]")
		}
		if err := xAg.EnsureControlPlaneRecovery(ctx, t); err != nil {
			return err
		}
		return xWait(ctx, wait, func() (bool, bool, error) {
			pr, ex, _, err := xAg.ControlPlaneRecoveryState(ctx)
			return pr, ex, err
		})
	case "state":
		pr, ex, id, err := xAg.ControlPlaneRecoveryState(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "promoted %v exited %v system %s\n", pr, ex, id)
		return nil
	case "migrate":
		st, err := store.Open(ctx, filepath.Join(xPaths.CPDir(), "sock"))
		if err != nil {
			return err
		}
		defer st.Close()
		return st.Migrate(ctx)
	case "sql":
		if len(a) != 2 {
			return xUsage("cp sql SQL")
		}
		cfg, err := pgx.ParseConfig("")
		if err != nil {
			return err
		}
		cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = filepath.Join(xPaths.CPDir(), "sock"), 5432, "supapaced", "supapaced", ""
		cfg.TLSConfig, cfg.Fallbacks, cfg.ConnectTimeout = nil, nil, 10*time.Second
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return err
		}
		defer c.Close(context.Background())
		return xQuery(ctx, c, a[1])
	}
	return xUsage("cp " + a[0] + ": unknown")
}

// --- the object store -------------------------------------------------------------

// xMPU opens n multipart uploads of one key (one 5 MiB part each, its own
// bytes), then completes all of them at once with the conditional create, and
// prints how many completions the store answered with a version and how many
// with 412; refused uploads are aborted.
func xMPU(ctx context.Context, a []string) error {
	n, err := strconv.Atoi(a[2])
	if err != nil || n < 1 || n > 32 {
		return xUsage("mpu ROLE KEY N (1..32)")
	}
	endpoint, addrs, err := xStandin()
	if err != nil {
		return err
	}
	keys, err := os.ReadFile(xS3 + "/" + a[0] + ".keys")
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(xS3 + "/ca.pem")
	if err != nil {
		return err
	}
	bucket := "sp-projects"
	if strings.HasPrefix(a[0], "cp-") {
		bucket = "sp-cp"
	}
	c, err := xClient(endpoint, addrs, string(keys), string(ca), bucket)
	if err != nil {
		return err
	}
	key := a[1]
	ids, tags := make([]string, n), make([]string, n)
	for i := range n {
		if ids[i], err = c.CreateMultipart(ctx, key, nil); err != nil {
			return err
		}
		body := make([]byte, 5<<20)
		for j := range body {
			body[j] = byte(i + j)
		}
		if tags[i], err = c.UploadPart(ctx, key, ids[i], 1, body); err != nil {
			return err
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	won, refused, other := 0, 0, 0
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := c.CompleteMultipart(ctx, key, ids[i], []string{tags[i]}, true)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, s3x.ErrExists):
				refused++
				if aerr := c.AbortMultipart(ctx, key, ids[i]); aerr != nil {
					other++
				}
			default:
				other++
				fmt.Fprintln(stderr, "complete: "+err.Error())
			}
		}()
	}
	close(start)
	wg.Wait()
	versions := 0
	km, vm := "", ""
	for {
		page, nk, nv, err := c.ListVersions(ctx, key, km, vm)
		if err != nil {
			return err
		}
		for _, o := range page {
			if o.Key == key && !o.DeleteMarker {
				versions++
			}
		}
		if nk == "" && nv == "" {
			break
		}
		km, vm = nk, nv
	}
	fmt.Fprintf(stdout, "completed %d refused %d other %d versions %d\n", won, refused, other, versions)
	return nil
}

// --- everything ---------------------------------------------------------------------

// xDownAll removes every project the directory records, the control-plane
// database's containers, trees and quotas, the replicator's quota, the
// networks and the ruleset the lab made; nothing by a shared name prefix.
func xDownAll(ctx context.Context) error {
	var errs []error
	if d, err := xDir(); err == nil {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if ref, ok := strings.CutSuffix(e.Name(), ".json"); ok {
				p, err := xLoad(ref)
				if err == nil {
					err = xDown(ctx, p)
				}
				errs = append(errs, err)
			}
		}
	}
	errs = append(errs, xAg.KillJobs(ctx, nodecfg.ControlPlaneSubject))
	for _, n := range []string{"sp-cp-db", "sp-cp-recovery", "task-cp-purge-repo", "task-cp-purge-fetch"} {
		exec.CommandContext(ctx, "docker", "rm", "-f", "-v", n).Run()
	}
	for _, d := range []string{xPaths.CPProjectDir(), xPaths.RepoDir(nodecfg.ControlPlaneSubject), xPaths.CPDir()} {
		errs = append(errs, os.RemoveAll(d))
	}
	for _, uid := range []int{nodecfg.ControlPlaneUID, nodecfg.ReplicatorUID} {
		for _, root := range []string{xPaths.ProjectsDir(), xPaths.RepoRoot()} {
			if _, err := os.Stat(root); err == nil {
				errs = append(errs, nodefs.SetQuotaAt(root, uid, 0))
			}
		}
	}
	errs = append(errs, os.Remove(xPaths.IndexFile(nodecfg.ControlPlaneSubject)))
	for _, n := range []string{nodecfg.BackupNetwork, "platform", "ingress"} {
		exec.CommandContext(ctx, "docker", "network", "rm", n).Run()
	}
	for _, t := range [][]string{{"inet", "supapace"}, {"bridge", "supapace"}} {
		exec.CommandContext(ctx, "nft", "delete", "table", t[0], t[1]).Run()
	}
	for _, f := range []string{xPaths.NftFile(), xPaths.NftSum(), xPaths.OffsiteAddrs(), xPaths.NftLock()} {
		errs = append(errs, os.Remove(f))
	}
	return xJoin(errs)
}

// xSummary is one line of the counts a script tests, from the parsed result:
// "fail CODE MESSAGE" for a failure document.
func xSummary(kind string, line []byte) string {
	v, fail, err := jobio.ParseResult(kind, line)
	switch {
	case err != nil:
		return "unparsed " + err.Error()
	case fail != nil:
		return "fail " + fail.Code + " " + fail.Message
	}
	push := func(p *jobio.PushResult) string {
		if p == nil {
			return "push none"
		}
		var q []string
		for _, e := range p.Quarantined {
			q = append(q, e.Name+":"+e.Reason)
		}
		return fmt.Sprintf("pushed %d remaining %d quarantined [%s] histories [%s]", p.Pushed, p.Remaining,
			strings.Join(q, " "), strings.Join(p.Histories, " "))
	}
	switch r := v.(type) {
	case jobio.PushResult:
		return push(&r)
	case jobio.CheckJobResult:
		return "ok; " + push(r.Push)
	case jobio.BackupResult:
		return fmt.Sprintf("label %s timeline %d start %s stop %s; %s", r.Label, r.Timeline, r.StartSegment, r.StopSegment, push(r.Push))
	case jobio.RestoreResult:
		return "mode " + r.Mode
	case jobio.ServeResult:
		return fmt.Sprintf("served %d none %d refused %d last_segment %s", r.Served, len(r.None), r.Refused, r.LastSegment)
	case jobio.SeedResult:
		return fmt.Sprintf("files %d bytes %d", r.Files, r.Bytes)
	case jobio.FetchResult:
		return fmt.Sprintf("files %d bytes %d newest_set %s newest_segment %s", r.Files, r.Bytes, r.NewestSet, r.NewestSegment)
	case jobio.ReplResult:
		var n []string
		for _, e := range r.Notices {
			n = append(n, fmt.Sprintf("%s:%d", e.Code, e.Count))
		}
		return fmt.Sprintf("uploaded %d adopted %d info %d walked %d held %d complete %v stopped %q notices [%s]",
			len(r.Uploaded), len(r.Adopted), len(r.Info), r.Walked, r.Held, r.Complete, r.Stopped, strings.Join(n, " "))
	}
	return fmt.Sprintf("%T", v)
}
