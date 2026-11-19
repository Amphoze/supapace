// Command bk is the Go half of the backup experiments' kit
// (test/harness/experiments/lib-backup.sh). It is test tooling: it lives
// outside cmd/, so `make build` never builds it and no image carries it; the
// kit's wrapper builds it into a scratch directory and copies it into a bare
// test node. It runs there as root and uses the platform's own packages as
// they are, so a lab project is laid out, rendered and logged in to as the
// agent does it:
//
//	bk render REF UID IDX DISK_MB REPO_MB IMGDIR
//	    the layout-2 project directory and both quotas (nodefs), the repository
//	    directory, and the rendered files (pgconf) in the render directory,
//	    with the image's files from IMGDIR; also `cmdline` (CommandLine, then
//	    Pins: the cluster's arguments after "postgres -D /etc/postgresql", one
//	    per line) and `pgoptions` (the jobs' PGOPTIONS value). Prints
//	    "slice PREFIX cluster ADDR".
//	bk bootstrap REF UID PID          first-boot bootstrap over the checked socket (trust)
//	bk sql REF UID PID GEN SQL        SQL as supabase_admin by SCRAM with generation GEN's password
//	bk scram REF UID PID GEN          the re-key after a restore, in one trust session: the
//	                                  verifiers of generation GEN, the timeline, the statistics reset
//	bk trust [-su] [-set N=V]… [-unset N]… SOCKDIR USER SQL
//	                                  SQL in a session opened with pgx directly over SOCKDIR,
//	                                  trust, with an explicit parameter list: the platform's
//	                                  list (-su: the superuser one) edited by -set and -unset
//	bk pins [-time T | -lsn L] -timeline TL
//	                                  the recovery start's extension pins, then its recovery
//	                                  pins (pgconf), one argument per line
//
// SQL runs by the simple protocol (several statements allowed); every row is
// printed as its fields joined by "|", NULL as "NULL". Exit 0 ok, 1 failed,
// 2 usage. Passwords are lab values derived from the ref and the generation:
// lab clusters only.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// memMB is the lab cluster's memory (the kit's --memory), for OverridesPinned.
const memMB = 512

type usageError string

func (e usageError) Error() string { return string(e) }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	err := dispatch(args, stdout, stderr)
	var u usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &u):
		fmt.Fprintf(stderr, "bk: usage: %v\n", err)
		return 2
	default:
		fmt.Fprintf(stderr, "bk: %v\n", pgsock.Clean(err))
		return 1
	}
}

func dispatch(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("bk render|bootstrap|sql|scram|trust|pins …")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd, a := args[0], args[1:]
	need := func(n int, form string) error {
		if len(a) != n {
			return usageError("bk " + cmd + " " + form)
		}
		return nil
	}
	switch cmd {
	case "render":
		if err := need(6, "REF UID IDX DISK_MB REPO_MB IMGDIR"); err != nil {
			return err
		}
		n, err := ints(a[1:5])
		if err != nil {
			return err
		}
		return render(stdout, a[0], n[0], n[1], n[2], n[3], a[5])
	case "bootstrap":
		if err := need(3, "REF UID PID"); err != nil {
			return err
		}
		c, err := dialTarget(ctx, a, 0, true)
		if err != nil {
			return err
		}
		defer c.Close(context.Background())
		if err := bootstrap.Run(ctx, c, secrets(a[0], 0)); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "bootstrap ok")
		return nil
	case "sql":
		if err := need(5, "REF UID PID GEN SQL"); err != nil {
			return err
		}
		gen, err := strconv.Atoi(a[3])
		if err != nil {
			return usageError("GEN: " + err.Error())
		}
		c, err := dialTarget(ctx, a, gen, false)
		if err != nil {
			return err
		}
		defer c.Close(context.Background())
		return query(ctx, c, a[4], stdout)
	case "scram":
		if err := need(4, "REF UID PID GEN"); err != nil {
			return err
		}
		gen, err := strconv.Atoi(a[3])
		if err != nil {
			return usageError("GEN: " + err.Error())
		}
		c, err := dialTarget(ctx, a, gen, true)
		if err != nil {
			return err
		}
		defer c.Close(context.Background())
		// The agent's re-key (Agent.Rekey): the verifier statements first,
		// then the timeline, the statistics reset last and best effort.
		if err := bootstrap.Rekey(ctx, c, secrets(a[0], gen)); err != nil {
			return err
		}
		tl, err := bootstrap.ReadTimeline(ctx, c)
		if err != nil {
			return err
		}
		reset, err := bootstrap.ResetStatementStats(ctx, c)
		if err != nil {
			fmt.Fprintf(stderr, "bk: statistics reset: %v\n", pgsock.Clean(err))
		}
		fmt.Fprintf(stdout, "rekey ok timeline %d reset %t\n", tl, reset)
		return nil
	case "trust":
		return trust(ctx, a, stdout, stderr)
	case "pins":
		return pins(a, stdout)
	}
	return usageError("unknown subcommand " + strconv.Quote(cmd))
}

func ints(ss []string) ([]int, error) {
	n := make([]int, len(ss))
	for i, s := range ss {
		v, err := strconv.Atoi(s)
		if err != nil {
			return nil, usageError(err.Error())
		}
		n[i] = v
	}
	return n, nil
}

// password is generation gen's lab password of a role: deterministic, so a
// script can log in again after a restore, and never a real value.
func password(ref, role string, gen int) string {
	h := sha256.Sum256(fmt.Appendf(nil, "supapace-lab|%s|%s|%d", ref, role, gen))
	return fmt.Sprintf("lab%d-%x", gen, h[:12])
}

func secrets(ref string, gen int) bootstrap.Secrets {
	dek := sha256.Sum256([]byte("supapace-lab-data-key"))
	s := bootstrap.Secrets{SupabaseAdminPassword: password(ref, "supabase_admin", gen),
		PostgresPassword: password(ref, "postgres", gen), AuthenticatorPassword: password(ref, "authenticator", gen),
		ScramSalts: map[string][]byte{}}
	for _, r := range []string{"supabase_admin", "postgres", "authenticator"} {
		salt, err := pgsock.ScramSalt(dek[:], ref, r)
		if err != nil {
			panic(err) // a fixed non-empty key: cannot fail
		}
		s.ScramSalts[r] = salt
	}
	return s
}

// dialTarget opens a pgsock session as supabase_admin: a = REF UID PID ….
func dialTarget(ctx context.Context, a []string, gen int, trust bool) (*pgx.Conn, error) {
	n, err := ints(a[1:3])
	if err != nil {
		return nil, err
	}
	start, err := pgsock.ProcStart(n[1])
	if err != nil {
		return nil, err
	}
	s := secrets(a[0], gen)
	t := pgsock.Target{ProjectsDir: nodecfg.Paths{}.ProjectsDir(), Ref: a[0], UID: n[0], PostmasterPid: n[1],
		PostmasterStart: start, User: "supabase_admin", ScramSalt: s.ScramSalts["supabase_admin"],
		Superuser: true, AllowTrust: trust}
	if !trust {
		t.Password = s.SupabaseAdminPassword
	}
	return pgsock.Dial(ctx, t)
}

func query(ctx context.Context, c *pgx.Conn, sql string, w io.Writer) error {
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
			fmt.Fprintln(w, strings.Join(f, "|"))
		}
		if err == nil {
			err = r.Err
		}
	}
	return err
}

// pgOptions is the jobs' PGOPTIONS: "-c name=value" for each parameter, by
// name, joined by single spaces; a space or a backslash in a value is
// preceded by a backslash (libpq splits the variable on unescaped white
// space); an empty value is "-c name=".
func pgOptions(m map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("-c " + k + "=")
		for _, r := range m[k] {
			if r == ' ' || r == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

func render(w io.Writer, ref string, uid, idx, diskMB, repoMB int, img string) error {
	p, cfg := nodecfg.Paths{}, nodecfg.Default("sp.test")
	if idx < 0 || idx >= cfg.Slices() {
		return usageError(fmt.Sprintf("IDX %d: the node has slices 0 to %d", idx, cfg.Slices()-1))
	}
	if err := nodefs.CreateProjectDirL2(p, ref, uid, uid, diskMB); err != nil {
		return err
	}
	if err := nodefs.EnsureRepoDir(p, ref, uid, uid, repoMB); err != nil {
		return err
	}
	out := p.RenderDir(ref)
	for _, d := range []string{"conf.d", "tools"} {
		if err := os.MkdirAll(filepath.Join(out, d), 0o755); err != nil {
			return err
		}
	}
	rd := func(n string) ([]byte, error) { return os.ReadFile(filepath.Join(img, n)) }
	files := map[string][]byte{"pg_ident.conf": pgconf.Ident()}
	gen := func(name, src string, f func([]byte) ([]byte, error)) error {
		b, err := rd(src)
		if err == nil {
			files[name], err = f(b)
		}
		return err
	}
	var names []string
	ents, err := os.ReadDir(filepath.Join(img, "conf.d"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		names = append(names, e.Name())
		if err := gen(filepath.Join("conf.d", e.Name()), filepath.Join("conf.d", e.Name()),
			func(b []byte) ([]byte, error) { return b, nil }); err != nil {
			return err
		}
	}
	if err := pgconf.SortsLast(names); err != nil {
		return err
	}
	cmdline := func(b []byte) ([]byte, error) {
		cl, err := pgconf.CommandLine(b)
		if err != nil {
			return nil, err
		}
		pins, err := pgconf.Pins(nil)
		if err != nil {
			return nil, err
		}
		return []byte(strings.Join(append(cl, pins...), "\n") + "\n"), nil
	}
	for _, g := range []struct {
		name, src string
		f         func([]byte) ([]byte, error)
	}{
		{"passwd", "passwd", func(b []byte) ([]byte, error) { return pgconf.Passwd(b, uid, uid) }},
		{"group", "group", func(b []byte) ([]byte, error) { return pgconf.Group(b, uid) }},
		{"supautils.conf", "supautils.conf", func(b []byte) ([]byte, error) { return pgconf.Supautils(b, false) }},
		{"cmdline", "postgresql.conf", cmdline},
	} {
		if err := gen(g.name, g.src, g.f); err != nil {
			return fmt.Errorf("%s: %w", g.name, err)
		}
	}
	if files["pg_hba.conf"], err = pgconf.HBA(cfg.Slice(idx)); err != nil {
		return err
	}
	if files[filepath.Join("conf.d", pgconf.OverrideFile)], err = pgconf.OverridesPinned(nil, memMB); err != nil {
		return err
	}
	files["pgoptions"] = []byte(pgOptions(pgsock.StartupParams(false)) + "\n")
	for n, b := range files {
		f := filepath.Join(out, n)
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.WriteFile(f, b, 0o444); err != nil {
			return err
		}
	}
	// The pgsodium root key: once, the project's own, 0400.
	key := filepath.Join(out, "pgsodium_root.key")
	if _, err := os.Lstat(key); errors.Is(err, os.ErrNotExist) {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return err
		}
		if err := os.WriteFile(key, []byte(hex.EncodeToString(k)), 0o400); err != nil {
			return err
		}
		if err := os.Chown(key, uid, uid); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	fmt.Fprintf(w, "slice %s cluster %s\n", cfg.Slice(idx), cfg.ClusterAddr(idx))
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// trustParams is the platform's startup list (superuser or not) with -set
// entries added or replaced and -unset entries removed.
func trustParams(su bool, set, unset []string) (map[string]string, error) {
	m := pgsock.StartupParams(su)
	for _, kv := range set {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, usageError("-set takes NAME=VALUE: " + strconv.Quote(kv))
		}
		m[k] = v
	}
	for _, k := range unset {
		delete(m, k)
	}
	return m, nil
}

func trust(ctx context.Context, a []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	su := fs.Bool("su", false, "")
	var set, unset multi
	fs.Var(&set, "set", "")
	fs.Var(&unset, "unset", "")
	if err := fs.Parse(a); err != nil || fs.NArg() != 3 {
		return usageError("bk trust [-su] [-set NAME=VALUE]… [-unset NAME]… SOCKDIR USER SQL")
	}
	params, err := trustParams(*su, set, unset)
	if err != nil {
		return err
	}
	cfg, err := pgx.ParseConfig("host=" + fs.Arg(0) + " port=5432 dbname=postgres sslmode=disable user=" + fs.Arg(1))
	if err != nil {
		return usageError(err.Error())
	}
	cfg.RuntimeParams = params
	cfg.ConnectTimeout = 5 * time.Second
	fmt.Fprintf(stderr, "bk: startup parameters: %s\n", strings.Join(slices.Sorted(maps.Keys(params)), " "))
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close(context.Background())
	return query(ctx, c, fs.Arg(2), stdout)
}

// parseTime reads a time with its zone: RFC 3339, or the server's own text
// form ("2006-01-02 15:04:05.999999+00"), so a time a script read from the
// cluster can be passed back as it came.
func parseTime(s string) (time.Time, error) {
	for _, l := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07", "2006-01-02 15:04:05.999999999-07:00"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, usageError("time " + strconv.Quote(s) + ": want RFC 3339 or 2006-01-02 15:04:05[.frac]+zz")
}

func pins(a []string, w io.Writer) error {
	fs := flag.NewFlagSet("pins", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	tm := fs.String("time", "", "")
	lsn := fs.String("lsn", "", "")
	tl := fs.String("timeline", "", "")
	if err := fs.Parse(a); err != nil || fs.NArg() != 0 {
		return usageError("bk pins [-time T | -lsn L] -timeline TL")
	}
	t := pgconf.RecoveryTarget{LSN: *lsn, Timeline: *tl}
	if *tm != "" {
		var err error
		if t.Time, err = parseTime(*tm); err != nil {
			return err
		}
	}
	rp, err := pgconf.RecoveryPins(t)
	if err != nil {
		return err
	}
	for _, s := range append(pgconf.RecoveryExtensionPins(), rp...) {
		fmt.Fprintln(w, s)
	}
	return nil
}
