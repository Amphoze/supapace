package nft

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// The errors of Check and Load. ErrAbsent, ErrDrift and ErrBridgeNF say the
// installed state is wrong; ErrUnverified says it could not be examined. Any
// non-nil error means the node's containment is not verified.
var (
	// ErrAbsent: one of our tables is not installed.
	ErrAbsent = errors.New("nft: supapace table absent")
	// ErrDrift: the installed tables or the ruleset file differ from what Load installed.
	ErrDrift = errors.New("nft: supapace tables drifted")
	// ErrBridgeNF: a bridge-nf-call switch is on, so bridged frames would enter the routed chains.
	ErrBridgeNF = errors.New("nft: bridge-nf-call switch on")
	// ErrUnverified: nft could not be run or failed, so the tables could not be examined.
	ErrUnverified = errors.New("nft: tables not verified")
)

// ourTables are the only tables the ruleset touches, in listing order.
var ourTables = []string{"inet supapace", "bridge supapace"}

// Load installs the ruleset file in one nft transaction (replacing our two
// tables and nothing else), records the SHA-256 of the file and of the
// installed tables' listing in the sum file, and then switches bridge-nf off.
// A switch that cannot be written is reported after the tables are in place.
func Load(ctx context.Context, p nodecfg.Paths) error {
	file, err := os.ReadFile(p.NftFile())
	if err != nil {
		return fmt.Errorf("nft: load: %w", err)
	}
	// The bytes hashed are the bytes loaded: the file goes in on stdin.
	if _, err := nft(ctx, file, "-f", "-"); err != nil {
		return fmt.Errorf("nft: load: %w", err)
	}
	listing, err := listTables(ctx)
	if err != nil {
		return fmt.Errorf("nft: load: %w", err)
	}
	if err := writeFile(p.NftSum(), sums(file, listing)); err != nil {
		return err
	}
	return EnsureBridgeNF()
}

// Check returns ErrAbsent when a table is missing, ErrDrift when the file or
// the installed tables differ from what Load recorded, and ErrBridgeNF when a
// bridge-nf switch is on.
func Check(ctx context.Context, p nodecfg.Paths) error {
	listing, err := listTables(ctx)
	if err != nil {
		return err
	}
	file, err := os.ReadFile(p.NftFile())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDrift, err)
	}
	sum, err := os.ReadFile(p.NftSum())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDrift, err)
	}
	if !bytes.Equal(sum, sums(file, listing)) {
		return fmt.Errorf("%w: file or tables differ from the last load", ErrDrift)
	}
	return checkBridgeNF()
}

// sums is the content of the sum file: the SHA-256 of the ruleset file and of
// the stateless listing of our tables.
func sums(file, listing []byte) []byte {
	return fmt.Appendf(nil, "file %x\ntables %x\n", sha256.Sum256(file), sha256.Sum256(listing))
}

// listTables returns `nft -s list table` of both our tables, concatenated, or
// ErrAbsent when either is not installed.
func listTables(ctx context.Context) ([]byte, error) {
	out, err := nft(ctx, nil, "list", "tables")
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		have[strings.TrimSpace(strings.TrimPrefix(l, "table "))] = true
	}
	var listing []byte
	for _, t := range ourTables {
		if !have[t] {
			return nil, fmt.Errorf("%w: table %s", ErrAbsent, t)
		}
		f := strings.Fields(t)
		out, err := nft(ctx, nil, "-s", "list", "table", f[0], f[1])
		if err != nil {
			return nil, err
		}
		listing = append(listing, out...)
	}
	return listing, nil
}

// nft runs the nft binary with args (no shell) and stdin, returning stdout.
// Any failure, including a deadline, is ErrUnverified.
func nft(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nft", args...)
	cmd.WaitDelay = time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: nft %s: %w: %s", ErrUnverified, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// writeFile replaces path atomically with data, mode 0600.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("nft: %w", err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
		return fmt.Errorf("nft: writing %s: %w", path, err)
	}
	return nil
}
