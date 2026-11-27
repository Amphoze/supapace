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

var versionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)

// LockedPostgresVersion returns the version part of the lock's "postgres" tag
// (the text after its colon: dot-separated numbers). It goes through
// lockedRef, so the entry is checked as the image reference is.
func LockedPostgresVersion() (string, error) {
	if _, err := lockedRef("postgres"); err != nil {
		return "", err
	}
	var lock map[string]lockEntry
	if err := json.Unmarshal(imagesLock, &lock); err != nil {
		return "", fmt.Errorf("images.lock: %w", err)
	}
	tag := lock["postgres"].Tag
	v := tag[strings.LastIndex(tag, ":")+1:]
	if strings.LastIndex(tag, ":") < strings.LastIndex(tag, "/") || !versionRE.MatchString(v) {
		return "", fmt.Errorf("images.lock: %q: the tag has no version", "postgres")
	}
	return v, nil
}

// PgMetaImage returns the pinned postgres-meta image the dashboard runs,
// "<repository>@<index digest>". Only a node with a studio domain uses it.
func PgMetaImage() (string, error) { return lockedRef("pgmeta") }
