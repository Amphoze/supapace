package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

func init() { commands["escrow"] = escrowCmd }

// supapacedVersion is the release the escrow document names, so that a
// custodian knows which build reads it. Set at link time for a release.
var supapacedVersion = "v0.2.0"

// workerArchive is the file name the worker image is archived under, beside
// the escrow set.
const workerArchive = "supapace-worker.tar"

var imageIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// errNoImage: the image is not in Docker's store, as opposed to an inspection
// that failed.
var errNoImage = errors.New("no such image")

// imageID returns the id of a local image, errNoImage when there is none;
// tests substitute their own.
var imageID = func(ctx context.Context, ref string) (string, error) {
	out, err := dockerx.Run(ctx, "image", "inspect", "--format", "{{json .Id}}", "--", ref)
	if err != nil {
		if strings.Contains(err.Error(), "No such image") {
			return "", fmt.Errorf("%w: %s", errNoImage, ref)
		}
		return "", err
	}
	var id string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &id); err != nil || !imageIDRE.MatchString(id) {
		return "", fmt.Errorf("docker image inspect %s: not an image id", ref)
	}
	return id, nil
}

// openCPStore opens the node's control-plane database through the daemon's
// socket directory; it works with the daemon running or stopped. While a
// restore is marked it refuses: what answers there then is a recovery start
// nothing has checked yet.
func openCPStore(ctx context.Context) (*store.Store, error) {
	if exists(paths.CPRestoring()) {
		return nil, errors.New("a control-plane restore is marked on this node: finish supapaced recover first")
	}
	return dialCPStore(ctx)
}

// dialCPStore opens whatever database answers on the daemon's socket, with
// no setting taken from the environment.
func dialCPStore(ctx context.Context) (*store.Store, error) {
	if err := pgsock.CheckEnv(); err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, filepath.Join(paths.CPDir(), "sock"))
	if err != nil {
		return nil, fmt.Errorf("the control-plane database does not answer on %s (is this node's sp-cp-db running?): %w", filepath.Join(paths.CPDir(), "sock"), err)
	}
	return st, nil
}

// escrowCmd is `supapaced escrow show [--part kek|rest]` and `supapaced
// escrow ack`. show prints the escrow document — the one place the node's
// key, the control plane's cipher passphrase and the read-only credential of
// its bucket leave the node — whole or as one of its two parts. ack records
// that the operator holds the "rest" part as the node now stands: it shows
// that part unless it is the acknowledged one, and writes its hash.
func escrowCmd(args []string) int {
	usage := func() int {
		fmt.Fprintln(stderr, "usage: supapaced escrow show [--part kek|rest] | supapaced escrow ack")
		return 2
	}
	if len(args) == 0 || args[0] != "show" && args[0] != "ack" {
		return usage()
	}
	fl := flag.NewFlagSet("escrow "+args[0], flag.ContinueOnError)
	fl.SetOutput(stderr)
	part := ""
	if args[0] == "show" {
		fl.StringVar(&part, "part", "", "print one part only: kek or rest")
	}
	if err := fl.Parse(args[1:]); err != nil {
		return 2
	}
	if fl.NArg() != 0 || part != "" && part != "kek" && part != "rest" {
		return usage()
	}
	name := "supapaced escrow " + args[0]
	if rootOnly && os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "%s: must run as root\n", name)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var err error
	if args[0] == "show" {
		err = escrowShow(ctx, part)
	} else {
		err = escrowAck(ctx)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", name, clean(err))
		return 1
	}
	return 0
}

// escrowState is what the escrow document reads from the control-plane store.
type escrowState interface {
	GetBackupState(ctx context.Context, subject string) (store.BackupState, error)
}

// nodeEscrow builds the escrow document from the node's current state: the
// key, the declared store, the control plane's stanza and passphrase, the
// two images and this build. It refuses until the store is declared and the
// control plane's stanza exists: before that there is nothing to recover
// from. `escrow show`, `escrow ack` and the node check's escrow row all
// build the document here, so that their hashes cannot disagree.
func nodeEscrow(ctx context.Context, p nodecfg.Paths, cfg nodecfg.Config, k secrets.KEK, st escrowState, at time.Time) (all, kek, rest []byte, err error) {
	d, state, err := offsite.Load(p, k)
	if err != nil {
		return nil, nil, nil, err
	}
	if state != offsite.StateDeclared {
		return nil, nil, nil, fmt.Errorf("the off-site store is not declared (it is %s): run supapaced offsite set first", state)
	}
	bs, err := st.GetBackupState(ctx, nodecfg.ControlPlaneSubject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil, err
	}
	if err != nil || !bs.StanzaCreated {
		return nil, nil, nil, errors.New("the control plane has no backup stanza yet: nothing could be recovered from this set; wait for the daemon's first backup of the control plane")
	}
	// The passphrase is made once by init; a missing file is never made here.
	if _, err := os.Lstat(p.CPStanzaSealed()); err != nil {
		return nil, nil, nil, fmt.Errorf("the control plane's passphrase: %w", err)
	}
	pass, err := offsite.EnsureControlPlanePass(p, k)
	if err != nil {
		return nil, nil, nil, err
	}
	id, err := imageID(ctx, cfg.Images.Worker)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("the worker image: %w", err)
	}
	return offsite.BuildEscrow(k, d,
		offsite.EscrowControlPlane{Stanza: nodecfg.ControlPlaneSubject + "-" + bs.Incarnation, Incarnation: bs.Incarnation,
			CipherPass: pass, Image: cfg.Images.ControlPlane, SchemaVersion: store.SchemaVersion()},
		offsite.EscrowWorkerImage{Reference: cfg.Images.Worker, ID: id, Archive: workerArchive}, supapacedVersion, at)
}

// currentEscrow gathers the node's state for nodeEscrow.
func currentEscrow(ctx context.Context) (all, kek, rest []byte, err error) {
	cfg, err := nodecfg.Load(paths.NodeJSON())
	if err != nil {
		return nil, nil, nil, err
	}
	k, err := loadKEK(paths.KEK())
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(k[:])
	st, err := openCPStore(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer st.Close()
	return nodeEscrow(ctx, paths, cfg, k, st, now())
}

func escrowShow(ctx context.Context, part string) error {
	all, kek, rest, err := currentEscrow(ctx)
	if err != nil {
		return err
	}
	doc := map[string][]byte{"": all, "kek": kek, "rest": rest}[part]
	_, err = stdout.Write(doc)
	clear(all)
	clear(kek)
	clear(rest)
	return err
}

// escrowAck acknowledges the "rest" part as the node now stands. The key has
// its own acknowledgement, at init, and is not shown here. A part that is
// already the acknowledged one is neither shown nor written again; any other
// — the first, or one whose location, credential, incarnation or image has
// changed — is shown first, and a display that provably went nowhere cannot
// be acknowledged.
func escrowAck(ctx context.Context) error {
	all, kek, rest, err := currentEscrow(ctx)
	if err != nil {
		return err
	}
	clear(all)
	clear(kek)
	defer clear(rest)
	hash, err := offsite.EscrowRestHash(rest)
	if err != nil {
		return err
	}
	path := paths.EscrowAcked()
	if have, err := readRegular(path); err == nil && string(have) == hash {
		fmt.Fprintln(stdout, "supapaced escrow ack: the escrow set is already acknowledged as it stands")
		return nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if toNullDevice(stdout) {
		return fmt.Errorf("the escrow set must be shown somewhere before it is acknowledged: standard output is %s", os.DevNull)
	}
	if _, err := stdout.Write(rest); err != nil {
		return fmt.Errorf("the escrow set could not be shown: %w", err)
	}
	if err := nodefs.WriteFile(paths, filepath.Dir(path), filepath.Base(path), []byte(hash), 0o600, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "supapaced escrow ack: wrote %s\n", path)
	return nil
}
