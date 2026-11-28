package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/poolcfg"
	"github.com/jackc/pgx/v5"
)

// The platform database, sp-platform-db: the pooler's registry server on a
// node with a pooler label. It is derived state — not backed up; the
// registry is rebuilt by registering the projects again.
const (
	pdbRole       = "platform-db" // its role label
	rowPlatformDB = "platform-db" // its node-check row
)

var (
	// pdbProvision is the session over the socket that makes the registry
	// role and database (tests replace it).
	pdbProvision = provisionPlatformDB
	// pdbAnswerWait bounds the wait for the server to answer after an
	// ensure (a first start initialises its directory); the interval is
	// cpPoll.
	pdbAnswerWait = 3 * time.Minute
	// pdbShortWait bounds the attempt on a container found running.
	pdbShortWait = 10 * time.Second
	// errPDBNotUp: no session could be opened over the socket.
	errPDBNotUp = errors.New("agent: the platform database does not answer")
)

// poolAddrs is the node's pooler addresses: ok when the node has a pooler
// label and poolcfg.For accepts its configuration (else err says why).
func (a *Agent) poolAddrs() (ad poolcfg.Addrs, ok bool, err error) {
	if a.cfg.PoolerLabel == "" {
		return poolcfg.Addrs{}, false, nil
	}
	ad, err = poolcfg.For(a.cfg)
	return ad, err == nil, err
}

func (a *Agent) pdbDir() string { return filepath.Join(a.p.PlatformDir(), "pdb") }

// EnsurePlatformDB runs sp-platform-db on a node with a pooler label and
// makes, over its socket, the registry role (a SCRAM verifier of the node's
// meta.password, never the password) and its database. Without a label it
// does nothing; when poolcfg.For refuses the node's configuration it does
// nothing and returns the refusal. Idempotent.
func (a *Agent) EnsurePlatformDB(ctx context.Context) error {
	ad, ok, err := a.poolAddrs()
	if !ok {
		if err != nil {
			return fmt.Errorf("agent: platform database: %w", err)
		}
		return nil
	}
	pw, err := a.metaPassword()
	if err != nil {
		return err
	}
	rewrote, err := a.ensurePDBDirs(ad)
	if err != nil {
		return err
	}
	opts, cmd, conf, err := a.pdbConfig(ad)
	if err != nil {
		return err
	}
	confs, err := a.existing(ctx, poolcfg.PlatformDBName)
	if err != nil {
		return err
	}
	data, stamp := filepath.Join(a.pdbDir(), "data"), filepath.Join(a.pdbDir(), "initialised")
	hasDB, err := present(stamp)
	if err == nil && hasDB {
		hasDB, err = present(filepath.Join(data, "PG_VERSION"))
	}
	if err != nil {
		return err
	}
	if !hasDB {
		// A new node, an initialisation that did not complete (initdb writes
		// PG_VERSION first; the stamp is written last), or the data are gone:
		// derived state, made again from empty. The stamp goes first.
		if err := os.Remove(stamp); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if len(confs) == 1 {
			logRecreate(poolcfg.PlatformDBName, "its data directory holds no database", confs[0].Running)
			if err := removeControlPlaneDB(ctx, poolcfg.PlatformDBName, confs[0].Running); err != nil {
				return err
			}
			confs = nil
		}
		// A task left by an interrupted ensure must not write under the
		// emptying.
		if _, err := dockerRun(ctx, "rm", "-f", "-v", "--", pdbInitTask); err != nil {
			return err
		}
		if err := emptyDir(data); err != nil {
			return err
		}
		if err := a.initPDB(ctx); err != nil {
			return err
		}
		if err := writeFile(a.p, a.pdbDir(), filepath.Base(stamp), nil, 0o444, os.Geteuid(), os.Getegid()); err != nil {
			return err
		}
	}
	made, started := false, false
	if len(confs) == 1 {
		c := confs[0]
		addr, on := c.addr(platformNet)
		switch {
		case c.Labels[labelConfig] == conf && on && addr == ad.PlatformDB.String() && len(c.Networks) == 1 && !rewrote:
			if !c.Running {
				if _, err := dockerRun(ctx, "start", "--", poolcfg.PlatformDBName); err != nil {
					return err
				}
				started = true
			}
		default:
			why := "its configuration changed"
			switch {
			case rewrote:
				why = "its access files were changed on disk"
			case c.Labels[labelConfig] == conf:
				why = "its networks changed"
			}
			logRecreate(poolcfg.PlatformDBName, why, c.Running)
			if err := removeControlPlaneDB(ctx, poolcfg.PlatformDBName, c.Running); err != nil {
				return err
			}
			made = true
		}
	} else {
		made = true
	}
	if made {
		if _, err := dockerRun(ctx, slices.Concat(opts, []string{"--label", labelConfig + "=" + conf, "--"}, cmd)...); err != nil {
			return err
		}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	v, err := pgsock.ScramVerifier(pw, salt)
	if err != nil {
		return err
	}
	// A container this call made or started may still be starting; one found
	// running is asked briefly: a crash loop must not hold the caller's round.
	wait := pdbShortWait
	if made || started {
		wait = pdbAnswerWait
	}
	return a.provisionPDB(ctx, v, wait)
}

// provisionPDB runs pdbProvision until the server answers, while
// sp-platform-db runs, within wait.
func (a *Agent) provisionPDB(ctx context.Context, verifier string, wait time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	sock := filepath.Join(a.pdbDir(), "sock")
	for {
		c, err := dockerInspectContainer(ctx, poolcfg.PlatformDBName)
		switch {
		case err != nil:
			return err
		case c == nil || !c.Running:
			return fmt.Errorf("agent: %s stopped before it answered", poolcfg.PlatformDBName)
		}
		err = pdbProvision(ctx, sock, verifier)
		if !errors.Is(err, errPDBNotUp) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("agent: %s did not answer within %v: %w", poolcfg.PlatformDBName, wait, err)
		case <-time.After(cpPoll):
		}
	}
}

// metaPasswordRE is the form of meta.password as made here.
var metaPasswordRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// metaPassword returns the node's meta.password, making it once when absent:
// 32 random bytes in hex, root 0600 in the root 0700 pooler secrets
// directory, never replaced. A file that is not a regular root 0600 file of
// that form is refused.
func (a *Agent) metaPassword() (string, error) {
	dir := a.p.PoolerSecrets()
	if err := ensureDir(dir, 0o700, -1, -1); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "meta.password")
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		if err := makeSecret(dir, p); err != nil {
			return "", err
		}
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return "", fmt.Errorf("agent: %s: %w", p, err)
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || st == nil || int(st.Uid) != os.Geteuid() {
		return "", fmt.Errorf("agent: %s is not a regular file of mode 0600 owned by the daemon's user", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("agent: %s: %w", p, err)
	}
	if !metaPasswordRE.Match(b) {
		return "", fmt.Errorf("agent: %s is not 64 hexadecimal characters", p)
	}
	return string(b), nil
}

// linkSecret puts the made secret in place (tests replace it).
var linkSecret = os.Link

// makeSecret writes 32 random bytes in hex under a temporary name in dir
// (root 0600), syncs it and links it to p: p is never a partial file and
// never replaced (another maker's link wins; this one's is then dropped).
// The temporary name is removed either way.
func makeSecret(dir, p string) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".meta.password.*")
	if err != nil {
		return fmt.Errorf("agent: %s: %w", dir, err)
	}
	defer os.Remove(f.Name())
	_, err = f.Write([]byte(hex.EncodeToString(b)))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if err = linkSecret(f.Name(), p); errors.Is(err, fs.ErrExist) {
			err = nil
		}
	}
	if err == nil {
		err = syncPath(dir)
	}
	if err != nil {
		return fmt.Errorf("agent: %s: %w", p, err)
	}
	return nil
}

// ensurePDBDirs makes PlatformDir()/pdb (root 0700) with data and sock
// (PlatformDBUID, 0700) and etc (root 0755) holding the two access files
// (root 0444): peer for root as postgres over the socket; SCRAM for the
// registry role from the pooler's address, to its database alone. rewrote:
// an access file was on disk with other content (a server may have read it).
func (a *Agent) ensurePDBDirs(ad poolcfg.Addrs) (rewrote bool, err error) {
	if err := a.ensurePlatformDir(); err != nil {
		return false, err
	}
	pd := a.pdbDir()
	u := poolcfg.PlatformDBUID
	for _, d := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{
		{pd, 0o700, -1, -1},
		{filepath.Join(pd, "data"), 0o700, u, u},
		{filepath.Join(pd, "sock"), 0o700, u, u},
		{filepath.Join(pd, "etc"), 0o755, -1, -1},
	} {
		if err := ensureDir(d.path, d.mode, d.uid, d.gid); err != nil {
			return false, err
		}
	}
	etc := filepath.Join(pd, "etc")
	hba := "local all postgres peer map=agent\n" +
		"host " + poolcfg.RegistryDB + " " + poolcfg.RegistryRole + " " + ad.Pooler.String() + "/32 scram-sha-256\n"
	for _, f := range []struct{ name, content string }{{"pg_hba.conf", hba}, {"pg_ident.conf", "agent root postgres\n"}} {
		if old, err := os.ReadFile(filepath.Join(etc, f.name)); err == nil && string(old) != f.content {
			rewrote = true
		}
		if err := writeFile(a.p, etc, f.name, []byte(f.content), 0o444, os.Geteuid(), os.Getegid()); err != nil {
			return false, err
		}
	}
	return rewrote, nil
}

// pdbConfig is sp-platform-db's run options, command and configuration
// label (over them, the profile and the two access files as now on disk).
// The data directory is initialised beforehand (initPDB): the image's
// entrypoint then only starts the server, and with no password in its
// environment it refuses to initialise an empty directory by itself.
func (a *Agent) pdbConfig(ad poolcfg.Addrs) (opts, cmd []string, conf string, err error) {
	pd := a.pdbDir()
	u := strconv.Itoa(poolcfg.PlatformDBUID)
	opts = []string{"run", "-d", "--name", poolcfg.PlatformDBName, "--network", platformNet, "--ip", ad.PlatformDB.String(),
		"--user", u + ":" + u, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--tmpfs", "/tmp", "--memory", strconv.Itoa(poolcfg.PlatformDBMemMB) + "m", "--pids-limit", "128", "--ulimit", "core=0",
		"--restart", "unless-stopped", "--label", labelRole + "=" + pdbRole,
		"-v", filepath.Join(pd, "data") + ":/var/lib/postgresql/data", "-v", filepath.Join(pd, "sock") + ":/var/run/postgresql",
		"-v", filepath.Join(pd, "etc") + ":/etc/sp:ro"}
	cmd = []string{a.cfg.Images.ControlPlane, "postgres", "-c", "listen_addresses=" + ad.PlatformDB.String(),
		"-c", "max_connections=40", "-c", "password_encryption=scram-sha-256",
		"-c", "hba_file=/etc/sp/pg_hba.conf", "-c", "ident_file=/etc/sp/pg_ident.conf"}
	etc := filepath.Join(pd, "etc")
	extra, err := fileDigests(a.seccompFile(), filepath.Join(etc, "pg_hba.conf"), filepath.Join(etc, "pg_ident.conf"))
	if err != nil {
		return nil, nil, "", err
	}
	return opts, cmd, configHash(opts, cmd, extra...), nil
}

// CheckPlatformDB is the row platform-db (not blocking): sp-platform-db
// runs with this daemon's configuration at its platform address and is not
// caught by the restart rule (dashRestarting). No row on a node without a
// pooler label.
func (a *Agent) CheckPlatformDB(ctx context.Context) []nodecfg.CheckResult {
	ad, ok, err := a.poolAddrs()
	if !ok && err == nil {
		return nil
	}
	if ok {
		err = dashRestarting(ctx, poolcfg.PlatformDBName) // a crash loop reads as one, with its last line
	}
	if ok && err == nil {
		err = a.checkPlatformContainer(ctx, poolcfg.PlatformDBName, map[string]string{platformNet: ad.PlatformDB.String()},
			func() (string, error) {
				_, _, conf, err := a.pdbConfig(ad)
				return conf, err
			})
	}
	r := nodecfg.CheckResult{Name: rowPlatformDB, OK: err == nil}
	if err != nil {
		r.Detail = err.Error()
	}
	return []nodecfg.CheckResult{r}
}

// provisionPlatformDB opens one session over the socket in sock as postgres
// (peer authentication: root maps to it) and, idempotently: the registry
// role with its attributes, connection limit and verifier; its database,
// owned by it; CONNECT revoked from PUBLIC on that database and on postgres.
// A failed connection wraps errPDBNotUp.
func provisionPlatformDB(ctx context.Context, sock, verifier string) error {
	if !verifierRE.MatchString(verifier) {
		return errors.New("agent: malformed verifier")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return err
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = sock, 5432, "postgres", "postgres", ""
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("%w: %w", errPDBNotUp, pgsock.Clean(err))
	}
	defer conn.Close(context.WithoutCancel(ctx))
	role, db := pgx.Identifier{poolcfg.RegistryRole}.Sanitize(), pgx.Identifier{poolcfg.RegistryDB}.Sanitize()
	var hasRole, hasDB bool
	if err := conn.QueryRow(ctx, "select exists(select from pg_catalog.pg_roles where rolname = $1), "+
		"exists(select from pg_catalog.pg_database where datname = $2)", poolcfg.RegistryRole, poolcfg.RegistryDB).Scan(&hasRole, &hasDB); err != nil {
		return fmt.Errorf("agent: platform database: %w", pgsock.Clean(err))
	}
	var stmts []string
	if !hasRole {
		stmts = append(stmts, "create role "+role)
	}
	// The verifier matched verifierRE above: no quote can be in it.
	stmts = append(stmts, "alter role "+role+" login nosuperuser nocreatedb nocreaterole noreplication connection limit 30 password '"+verifier+"'")
	if hasDB {
		stmts = append(stmts, "alter database "+db+" owner to "+role)
	} else {
		stmts = append(stmts, "create database "+db+" owner "+role)
	}
	stmts = append(stmts, "revoke connect on database "+db+" from public", "revoke connect on database postgres from public")
	for i, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			return fmt.Errorf("agent: platform database: statement %d of %d: %w", i+1, len(stmts), pgsock.Clean(err))
		}
	}
	return nil
}

// verifierRE: a SCRAM-SHA-256 verifier with 4096 iterations and nothing else.
var verifierRE = regexp.MustCompile(`^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$`)

// The initialisation task: its kind, and the name runTaskImage gives it.
const (
	pdbInitKind = "initdb"
	pdbInitTask = "task-pdb-" + pdbInitKind
)

// pdbInitScript initialises the data directory with the image's initdb at
// the container's uid, which the image's account file does not hold: initdb
// looks its user up, so a one-line account file is given to it through the
// image's nss_wrapper, as the image's own entrypoint does. The superuser has
// no password; the access file initdb writes into the data directory rejects
// everything and is never read (the server is given the mounted one).
const pdbInitScript = `set -eu
printf 'postgres:x:%s:%s::/nonexistent:/bin/false\n' "$(id -u)" "$(id -g)" >/tmp/passwd
printf 'postgres:x:%s:\n' "$(id -g)" >/tmp/group
LD_PRELOAD=/usr/lib/libnss_wrapper.so NSS_WRAPPER_PASSWD=/tmp/passwd NSS_WRAPPER_GROUP=/tmp/group \
exec initdb -D /var/lib/postgresql/data -U postgres --data-checksums --auth=reject`

// initPDB runs pdbInitScript in a task container (no network, the data
// directory alone mounted) on the emptied data directory.
func (a *Agent) initPDB(ctx context.Context) error {
	s := Spec{Ref: "pdb", UID: poolcfg.PlatformDBUID, GID: poolcfg.PlatformDBUID}
	data := filepath.Join(a.pdbDir(), "data")
	code, out, err := a.runTaskImage(ctx, s, a.cfg.Images.ControlPlane, pdbInitKind,
		[]string{"--tmpfs", "/tmp", "-v", data + ":/var/lib/postgresql/data"}, "sh", "-c", pdbInitScript)
	if err != nil {
		return err
	}
	if code != 0 {
		return taskFailed("initdb", s, code, out)
	}
	if ok, err := present(filepath.Join(data, "PG_VERSION")); err != nil || !ok {
		return errors.Join(fmt.Errorf("agent: %s holds no database after initdb", data), err)
	}
	return nil
}
