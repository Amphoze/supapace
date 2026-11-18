package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Cluster phases recorded in state.json.
const (
	PhaseADone = "A-done" // first boot's phase A finished; the container is gone
	PhaseB     = "B"
)

// State is a project's applied state, kept root-only in
// <render>/state.json. ListenerPid/ListenerStart stay zero unless the
// listener is not the container's init.
type State struct {
	Epoch         int64  `json:"epoch"`
	Generation    int64  `json:"generation"`
	Phase         string `json:"phase"`
	PMPid         int    `json:"pm_pid"`
	PMStart       uint64 `json:"pm_start"`
	ListenerPid   int    `json:"listener_pid"`
	ListenerStart uint64 `json:"listener_start"`
}

const (
	stateFile    = "state.json"
	maxStateSize = 4096
)

// readState returns the project's applied state; ok is false when no
// state.json exists. Anything but exactly one State with a known phase in at
// most 4096 bytes (null, an unknown phase, trailing data, a larger file, a
// link, not a regular file) is an error.
func (a *Agent) readState(ref string) (st State, ok bool, err error) {
	if err := checkRef(ref); err != nil {
		return State{}, false, err
	}
	path := filepath.Join(a.p.RenderDir(ref), stateFile)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("agent: %s: %w", path, err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return State{}, false, fmt.Errorf("agent: %s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStateSize+1))
	if err != nil {
		return State{}, false, fmt.Errorf("agent: %s: %w", path, err)
	}
	if len(b) > maxStateSize {
		return State{}, false, fmt.Errorf("agent: %s is larger than %d bytes", path, maxStateSize)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p *State
	if err := dec.Decode(&p); err != nil {
		return State{}, false, fmt.Errorf("agent: %s: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return State{}, false, fmt.Errorf("agent: %s: trailing data", path)
	}
	if p == nil || (p.Phase != PhaseADone && p.Phase != PhaseB) {
		return State{}, false, fmt.Errorf("agent: %s: not a state", path)
	}
	return *p, true, nil
}

// writeState replaces state.json atomically (root, 0600). The render
// directory must exist.
func (a *Agent) writeState(ref string, st State) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	if st.Phase != PhaseADone && st.Phase != PhaseB {
		return fmt.Errorf("agent: unknown phase %q", st.Phase)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeFile(a.p, a.p.RenderDir(ref), stateFile, append(b, '\n'), 0o600, os.Geteuid(), os.Getegid())
}

// checkState compares the applied state with the desired one: another epoch
// is ErrEpochDivergence (reported, never resolved here); an older desired
// generation in the same epoch is ErrStaleGeneration.
func checkState(st State, have bool, s Spec) error {
	if !have {
		return nil
	}
	if st.Epoch != s.Epoch {
		return fmt.Errorf("%w: applied epoch %d, desired %d", ErrEpochDivergence, st.Epoch, s.Epoch)
	}
	if s.Generation < st.Generation {
		return fmt.Errorf("%w: applied %d, desired %d", ErrStaleGeneration, st.Generation, s.Generation)
	}
	return nil
}
