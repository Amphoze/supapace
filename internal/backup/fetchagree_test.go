package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/repl"
	"github.com/Amphoze/supapace/internal/s3x"
)

// memBucket is a versioned bucket in memory, oldest version first.
type memBucket struct {
	prefix string
	objs   map[string][]memVersion
}

type memVersion struct {
	vid  string
	body []byte
}

func (m *memBucket) Prefix() string { return m.prefix }
func (m *memBucket) Put(context.Context, string, []byte, map[string]string, bool) (string, error) {
	panic("a fetch writes nothing to the store")
}
func (m *memBucket) Head(context.Context, string, string) (s3x.Object, error) { panic("unused") }
func (m *memBucket) CreateMultipart(context.Context, string, map[string]string) (string, error) {
	panic("unused")
}
func (m *memBucket) UploadPart(context.Context, string, string, int, []byte) (string, error) {
	panic("unused")
}
func (m *memBucket) CompleteMultipart(context.Context, string, string, []string, bool) (string, error) {
	panic("unused")
}
func (m *memBucket) AbortMultipart(context.Context, string, string) error { panic("unused") }

func (m *memBucket) Get(_ context.Context, key, vid string, w io.Writer, max int64) (s3x.Object, error) {
	for _, v := range m.objs[key] {
		if v.vid == vid {
			if int64(len(v.body)) > max {
				return s3x.Object{Size: int64(len(v.body))}, fmt.Errorf("over %d", max)
			}
			_, err := w.Write(v.body)
			return s3x.Object{Key: key, VersionID: vid, Size: int64(len(v.body))}, err
		}
	}
	return s3x.Object{}, s3x.ErrNotFound
}

func (m *memBucket) ListVersions(_ context.Context, prefix, _, _ string) ([]s3x.Object, string, string, error) {
	var page []s3x.Object
	for k, vs := range m.objs {
		if strings.HasPrefix(k, prefix) {
			for i := len(vs) - 1; i >= 0; i-- { // newest first
				page = append(page, s3x.Object{Key: k, VersionID: vs[i].vid, Size: int64(len(vs[i].body))})
			}
		}
	}
	return page, "", "", nil
}

// The plan the runner builds from its record is a plan the fetch takes as it
// is: repository paths, recorded version ids or none, hashes or none, exact
// sizes and an info file's bound. Every planned file arrives byte for byte.
func TestFetchPlan_TheRunnersPlanFetchesEveryFileByteForByte(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	b := &memBucket{prefix: "p", objs: map[string][]memVersion{}}
	put := func(rel, vid string, body []byte) {
		k := "p/" + ref + "/" + rel
		b.objs[k] = append(b.objs[k], memVersion{vid, body})
	}
	sum := func(body []byte) []byte { s := sha256.Sum256(body); return s[:] }
	want := map[string][]byte{}
	// Copied rows: version and hash; a rebuilt row: version, no hash; a row
	// without a version id: the oldest version, a newer one planted on top.
	for i, mode := range []string{"copied", "rebuilt", "oldest"} {
		rel := segKey(st, 1, uint32(4+i))
		body := []byte("segment " + mode)
		put(rel, "v"+mode, body)
		want[rel] = body
		switch mode {
		case "copied":
			e.object(ref, rel, int64(len(body)), sum(body), "v"+mode, listed)
		case "rebuilt":
			e.object(ref, rel, int64(len(body)), nil, "v"+mode, listed)
		case "oldest":
			put(rel, "vplanted", []byte("planted newer version"))
			e.object(ref, rel, int64(len(body)), nil, "", listed)
		}
	}
	set := "backup/" + st + "/" + planSet + "/backup.manifest"
	man := []byte("manifest")
	put(set, "vman", man)
	e.object(ref, set, int64(len(man)), sum(man), "vman", listed)
	want[set] = man
	info := []byte("archive info")
	put("archive/"+st+"/archive.info", "vinfo", info)
	_, err := e.db.Exec(context.Background(), `insert into offsite_info_version (subject, name, version_id, sha256, uploaded_at)
		values ($1, 'archive.info', 'vinfo', $2, $3)`, ref, sum(info), listed)
	must(t, err)
	want["archive/"+st+"/archive.info"] = info

	// The plan as the runner writes it for the job, run through the program's
	// fetch, recorded as the runner records it.
	dest := t.TempDir()
	var plan []byte
	e.declare()
	e.ag.setScript("fetch", func(ctx context.Context, spec agent.JobSpec) (agent.JobResult, error) {
		plan = spec.Files["plan"]
		in, err := jobio.ParseInput(spec.Input)
		if err != nil {
			return agent.JobResult{}, err
		}
		res, err := repl.Fetch(ctx, in, bytes.NewReader(plan), dest, b)
		if err != nil {
			return agent.JobResult{ExitCode: 1, Result: line(jobio.Failure{Code: "store", Message: err.Error()})}, nil
		}
		return agent.JobResult{Result: line(res)}, nil
	})
	got := e.fetch(ref, fetchParamsJSON)
	if got.State != "done" {
		t.Fatalf("job %+v %s\nplan:\n%s", got, got.Result, plan)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(plan)), "\n") {
		if f := strings.Split(l, "\t"); strings.HasSuffix(f[0], ".info") && f[3] != fmt.Sprint(bklimit.SmallMax) {
			t.Errorf("info row %q: the size is not the bound", l)
		}
	}
	var doc struct{ Files int }
	must(t, json.Unmarshal(got.Result, &doc))
	if doc.Files != len(want) {
		t.Errorf("fetched %d files, want %d", doc.Files, len(want))
	}
	for rel, body := range want {
		got, err := os.ReadFile(filepath.Join(dest, rel))
		if err != nil || !bytes.Equal(got, body) {
			t.Errorf("%s: %q %v, want %q", rel, got, err, body)
		}
	}
}
