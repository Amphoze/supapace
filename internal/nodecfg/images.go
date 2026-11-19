package nodecfg

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// images.lock pins every upstream image: "tag" is the human name, "digest" the
// multi-platform index the platform pulls, "amd64"/"arm64" the per-platform
// manifests (recorded for audit; empty where a platform is not published).
// One entry per line, so scripts/cache-images.sh can read it without a JSON tool.
//
//go:embed images.lock
var imagesLock []byte

type lockEntry struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
	AMD64  string `json:"amd64"`
	ARM64  string `json:"arm64"`
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// lockedRef returns "<repository>@<index digest>" for one key of images.lock.
func lockedRef(key string) (string, error) {
	var lock map[string]lockEntry
	dec := json.NewDecoder(bytes.NewReader(imagesLock))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lock); err != nil {
		return "", fmt.Errorf("images.lock: %w", err)
	}
	e, ok := lock[key]
	if !ok {
		return "", fmt.Errorf("images.lock: no %q entry", key)
	}
	repo := e.Tag
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	if repo == "" || !digestRE.MatchString(e.Digest) {
		return "", fmt.Errorf("images.lock: %q: bad tag or digest", key)
	}
	return repo + "@" + e.Digest, nil
}

// LockedImages returns the images a node runs, each pinned by digest; the gateway
// and the worker are the locally built GatewayImage and WorkerImage.
func LockedImages() (Images, error) {
	var im Images
	for _, f := range []struct {
		key string
		dst *string
	}{{"postgres", &im.Postgres}, {"postgrest", &im.PostgREST}, {"control_plane", &im.ControlPlane}} {
		ref, err := lockedRef(f.key)
		if err != nil {
			return Images{}, err
		}
		*f.dst = ref
	}
	im.Gateway, im.Worker = GatewayImage, WorkerImage
	return im, nil
}

// NodeImage returns the pinned base image of the test harness node.
func NodeImage() (string, error) { return lockedRef("node") }
