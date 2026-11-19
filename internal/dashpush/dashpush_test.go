package dashpush

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

const ref1, ref2 = "abcdefghij0123456789", "bcdefghij0123456789a"

// fakeSource answers with its table, or its error.
type fakeSource struct {
	mu  sync.Mutex
	tbl store.DashboardTable
	err error
}

func (f *fakeSource) DashboardTable(context.Context) (store.DashboardTable, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tbl, f.err
}

func (f *fakeSource) set(tbl store.DashboardTable) {
	f.mu.Lock()
	f.tbl = tbl
	f.mu.Unlock()
}

var pushN = sync.OnceValue(func() string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.N.Bytes())
})

func pushTable() store.DashboardTable {
	m := func(sub, role string) store.Member {
		return store.Member{Ref: ref1, Issuer: "https://issuer.test", Subject: sub, Role: role}
	}
	return store.DashboardTable{
		Issuer: &store.DashboardIssuer{Issuer: "https://issuer.test", ClientID: "supapace", AuthorizeURL: "https://issuer.test/authorize",
			SessionSeconds: 3600, JWKS: json.RawMessage(`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","n":"` + pushN() + `","e":"AQAB"}]}`)},
		Revoked: []store.Revocation{{Issuer: "https://issuer.test", Subject: "gone", NotBefore: time.Unix(1800000000, 300_000_000)}},
		Projects: []store.TableProject{
			{Ref: ref1, Name: "Shop", Members: []store.Member{m("user-1", "owner"), m("user-2", "read_only")}},
			{Ref: ref2, Name: "Empty"},
		},
	}
}

// pushEnv is a pusher for a temporary node with the studio domain set, and
// the path of its file.
func pushEnv(t *testing.T, src Source) (*Pusher, string) {
	t.Helper()
	paths := nodecfg.Paths{Root: t.TempDir()}
	path := dashcfg.PathsFor(paths).DashboardFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	p := New(src, nodecfg.Default("example.test"), paths)
	p.domain = "studio.test"
	return p, path
}

func pushOK(t *testing.T, p *Pusher) int64 {
	t.Helper()
	g, err := p.Push(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func pushRead(t *testing.T, path string) dashfile.File {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := dashfile.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func pushInode(t *testing.T, path string) (uint64, time.Time) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino, fi.ModTime()
}

func TestPush_FileParsesStrictly(t *testing.T) {
	p, path := pushEnv(t, &fakeSource{tbl: pushTable()})
	gen := pushOK(t, p)
	f := pushRead(t, path)
	want := dashfile.File{Generation: gen, Node: "local", StudioDomain: "studio.test", Studio: "http://10.212.0.3:3000",
		Issuer: &dashfile.Issuer{Iss: "https://issuer.test", ClientID: "supapace", AuthorizeURL: "https://issuer.test/authorize",
			SessionSeconds: 3600, Keys: []dashfile.IssuerKey{{Kid: "k1", Kty: "RSA", N: pushN(), E: "AQAB"}}},
		Revoked: []dashfile.Revocation{{Iss: "https://issuer.test", Sub: "gone", NotBefore: 1800000001}},
		Projects: map[string]dashfile.Project{
			ref1: {Name: "Shop", Members: []dashfile.Member{{Iss: "https://issuer.test", Sub: "user-1", Role: "owner"}, {Iss: "https://issuer.test", Sub: "user-2", Role: "read_only"}}},
			ref2: {Name: "Empty", Members: []dashfile.Member{}},
		}}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("file\n%+v\nwant\n%+v", f, want)
	}
	if now := time.Now().UnixMilli(); gen < now-60_000 || gen > now+1 {
		t.Fatalf("generation %d, now %d", gen, now)
	}
	// No issuer: null, and sign-in is closed.
	src := &fakeSource{tbl: store.DashboardTable{}}
	p, path = pushEnv(t, src)
	pushOK(t, p)
	if f := pushRead(t, path); f.Issuer != nil || len(f.Projects) != 0 || len(f.Revoked) != 0 {
		t.Fatalf("empty table: %+v", f)
	}
}

func TestPush_NotBeforeRoundsUp(t *testing.T) {
	tbl := pushTable()
	tbl.Revoked = []store.Revocation{
		{Issuer: "i", Subject: "a", NotBefore: time.Unix(1800000000, 300_000_000)},
		{Issuer: "i", Subject: "b", NotBefore: time.Unix(1800000000, 0)},
		{Issuer: "i", Subject: "c", NotBefore: time.Unix(1800000000, 1000)},
	}
	p, path := pushEnv(t, &fakeSource{tbl: tbl})
	pushOK(t, p)
	got := map[string]int64{}
	for _, r := range pushRead(t, path).Revoked {
		got[r.Sub] = r.NotBefore
	}
	if got["a"] != 1800000001 || got["b"] != 1800000000 || got["c"] != 1800000001 {
		t.Fatalf("not_before %v", got)
	}
}

func TestPush_ByRename_Mode0444(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	src := &fakeSource{tbl: pushTable()}
	p, path := pushEnv(t, src)
	pushOK(t, p)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != 0o444 {
		t.Fatalf("mode %v under umask 077, want -r--r--r--", fi.Mode())
	}
	if uid := fi.Sys().(*syscall.Stat_t).Uid; int(uid) != os.Getuid() {
		t.Fatalf("owner %d", uid)
	}
	// A reader that holds the old file keeps the old content whole: the new
	// one is a new inode put in place by rename.
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keep := path + ".held"
	if err := os.Link(path, keep); err != nil {
		t.Fatal(err)
	}
	ino, _ := pushInode(t, path)
	tbl := pushTable()
	tbl.Projects = tbl.Projects[:1]
	src.set(tbl)
	pushOK(t, p)
	if after, _ := os.ReadFile(keep); string(after) != string(before) {
		t.Fatal("the old file was written in place")
	}
	if ino2, _ := pushInode(t, path); ino2 == ino {
		t.Fatal("the file was not replaced")
	}
	if fi, _ := os.Stat(path); fi.Mode() != 0o444 {
		t.Fatalf("mode %v after a replacement", fi.Mode())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatalf("directory holds %v", entries)
	}
}

func TestPush_NoChange_NoWrite(t *testing.T) {
	src := &fakeSource{tbl: pushTable()}
	p, path := pushEnv(t, src)
	g1 := pushOK(t, p)
	ino, mt := pushInode(t, path)
	if g2 := pushOK(t, p); g2 != g1 {
		t.Fatalf("generation %d after a push without a change, was %d", g2, g1)
	}
	if ino2, mt2 := pushInode(t, path); ino2 != ino || !mt2.Equal(mt) {
		t.Fatal("a push without a change wrote the file")
	}
	tbl := pushTable()
	tbl.Projects[0].Members[1].Role = "developer"
	src.set(tbl)
	if g3 := pushOK(t, p); g3 <= g1 {
		t.Fatalf("generation %d after a change, was %d", g3, g1)
	}
	if f := pushRead(t, path); f.Projects[ref1].Members[1].Role != "developer" {
		t.Fatal("the change is not in the file")
	}
}

func TestPush_GenerationOnlyGrows(t *testing.T) {
	src := &fakeSource{tbl: pushTable()}
	p, path := pushEnv(t, src)
	// A file whose generation is ahead of the clock.
	ahead := time.Now().UnixMilli() + 1_000_000_000
	f := dashfile.File{Generation: ahead, Node: "local", StudioDomain: "studio.test", Studio: "http://10.212.0.3:3000"}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o444); err != nil {
		t.Fatal(err)
	}
	if g := pushOK(t, p); g != ahead+1 {
		t.Fatalf("generation %d, want %d", g, ahead+1)
	}
	last := ahead + 1
	for i := range 5 {
		tbl := pushTable()
		tbl.Projects[1].Name = fmt.Sprint("n", i)
		src.set(tbl)
		g := pushOK(t, p)
		if g <= last || pushRead(t, path).Generation != g {
			t.Fatalf("push %d: generation %d after %d", i, g, last)
		}
		last = g
	}
}

func TestPush_NoStudioDomain_WritesNothing(t *testing.T) {
	src := &fakeSource{tbl: pushTable()}
	p, path := pushEnv(t, src)
	p.domain = ""
	if g, err := p.Push(context.Background()); g != 0 || err != nil {
		t.Fatalf("Push = %d, %v", g, err)
	}
	if g, in, err := p.InForce(context.Background()); g != 0 || in || err != nil {
		t.Fatalf("InForce = %d, %v, %v", g, in, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a file was written: %v", err)
	}
}

// New takes the studio domain from the node file: a pusher built from a node
// file with one writes the file under that domain, one built from a node file
// without one writes nothing.
func TestNew_StudioDomainFromTheNodeFile(t *testing.T) {
	src := &fakeSource{tbl: pushTable()}
	for _, domain := range []string{"", "studio.test"} {
		paths := nodecfg.Paths{Root: t.TempDir()}
		path := dashcfg.PathsFor(paths).DashboardFile()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		c := nodecfg.Default("example.test")
		c.StudioDomain = domain
		g, err := New(src, c, paths).Push(context.Background())
		if err != nil {
			t.Fatalf("%q: %v", domain, err)
		}
		if domain == "" {
			if g != 0 {
				t.Errorf("no studio domain: generation %d", g)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("no studio domain: a file was written (%v)", err)
			}
			continue
		}
		if f := pushRead(t, path); g < 1 || f.Generation != g || f.StudioDomain != domain {
			t.Errorf("generation %d, file %d for %q", g, f.Generation, f.StudioDomain)
		}
	}
}

func TestInForce_ComparesWithoutWriting(t *testing.T) {
	src := &fakeSource{tbl: pushTable()}
	p, path := pushEnv(t, src)
	ctx := context.Background()
	if g, in, err := p.InForce(ctx); g != 0 || in || err != nil {
		t.Fatalf("no file: %d %v %v", g, in, err)
	}
	gen := pushOK(t, p)
	if g, in, err := p.InForce(ctx); g != gen || !in || err != nil {
		t.Fatalf("after a push: %d %v %v", g, in, err)
	}
	ino, mt := pushInode(t, path)
	tbl := pushTable()
	tbl.Revoked = nil
	src.set(tbl)
	if g, in, err := p.InForce(ctx); g != gen || in || err != nil {
		t.Fatalf("after a change: %d %v %v", g, in, err)
	}
	if ino2, mt2 := pushInode(t, path); ino2 != ino || !mt2.Equal(mt) {
		t.Fatal("InForce wrote the file")
	}
	gen2 := pushOK(t, p)
	if g, in, _ := p.InForce(ctx); g != gen2 || !in {
		t.Fatal("not in force after the push")
	}
}

// A push that cannot render — the source fails, or a row the file refuses —
// writes nothing and leaves the file in force as it was.
func TestPush_FailureKeepsTheFile(t *testing.T) {
	src := &fakeSource{tbl: pushTable()}
	p, path := pushEnv(t, src)
	gen := pushOK(t, p)
	src.err = errors.New("store down")
	if _, err := p.Push(context.Background()); err == nil || !strings.Contains(err.Error(), "store down") {
		t.Fatalf("Push with a failing source: %v", err)
	}
	src.err = nil
	tbl := pushTable()
	tbl.Projects[0].Members[0].Role = "admin"
	src.set(tbl)
	if _, err := p.Push(context.Background()); err == nil {
		t.Fatal("a table the file refuses was written")
	}
	tbl = pushTable()
	tbl.Issuer.JWKS = json.RawMessage(`[]`)
	src.set(tbl)
	if _, err := p.Push(context.Background()); err == nil {
		t.Fatal("a key set that does not read was written")
	}
	if f := pushRead(t, path); f.Generation != gen {
		t.Fatalf("generation %d, want %d", f.Generation, gen)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("directory holds %v", entries)
	}
}

// What is at the path is never trusted: a file that does not parse is
// replaced, and a FIFO, held open by a writer, neither blocks the push nor
// stays.
func TestPush_ReplacesWhatIsNotItsFile(t *testing.T) {
	p, path := pushEnv(t, &fakeSource{tbl: pushTable()})
	if err := os.WriteFile(path, []byte("{"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, in, err := p.InForce(context.Background()); in || err != nil {
		t.Fatalf("a broken file is in force: %v %v", in, err)
	}
	pushOK(t, p)
	pushRead(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// A writer holds it open, so a read would wait for data.
	w, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	done := make(chan error, 1)
	go func() { _, err := p.Push(context.Background()); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Minute):
		t.Fatal("a FIFO at the path held the push")
	}
	pushRead(t, path)
}

// The new caps: 16,384 member rows over 4,096 projects, 4,096 revocations,
// every string at its cap in the byte the encoder writes longest. The file
// marshals, is within MaxBytes and parses.
func TestPush_AtTheCapsStillParses(t *testing.T) {
	long := func(n int, suffix string) string { return strings.Repeat("<", n-len(suffix)) + suffix }
	var keys []string
	for i := range dashfile.MaxKeys {
		keys = append(keys, fmt.Sprintf(`{"kid":%q,"kty":"RSA","n":%q,"e":"AQAB"}`, long(dashfile.MaxKidBytes, fmt.Sprint(i)), pushN()))
	}
	tbl := store.DashboardTable{Issuer: &store.DashboardIssuer{Issuer: long(255, ""), ClientID: long(dashfile.MaxClientIDBytes, ""),
		AuthorizeURL: long(dashfile.MaxURLBytes, ""), EndSessionURL: long(dashfile.MaxURLBytes, ""), SessionSeconds: store.MaxSessionSeconds,
		JWKS: json.RawMessage(`{"keys":[` + strings.Join(keys, ",") + `]}`)}}
	for i := range dashfile.MaxRevocations {
		tbl.Revoked = append(tbl.Revoked, store.Revocation{Issuer: long(255, ""), Subject: long(255, fmt.Sprint(i)), NotBefore: time.Now()})
	}
	per := dashfile.MaxMemberRows / dashfile.MaxProjects
	for p := range dashfile.MaxProjects {
		r := fmt.Sprintf("r%019d", p)
		tp := store.TableProject{Ref: r, Name: long(dashfile.MaxNameBytes, "")}
		for i := range per {
			tp.Members = append(tp.Members, store.Member{Ref: r, Issuer: long(255, ""), Subject: long(255, fmt.Sprint(i)), Role: "read_only"})
		}
		tbl.Projects = append(tbl.Projects, tp)
	}
	p, path := pushEnv(t, &fakeSource{tbl: tbl})
	pushOK(t, p)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d bytes", fi.Size())
	if fi.Size() > dashfile.MaxBytes || fi.Size() < dashfile.MaxBytes*9/10 {
		t.Fatalf("%d bytes; MaxBytes %d", fi.Size(), dashfile.MaxBytes)
	}
	f := pushRead(t, path)
	rows := 0
	for _, p := range f.Projects {
		rows += len(p.Members)
	}
	if len(f.Projects) != dashfile.MaxProjects || rows != dashfile.MaxMemberRows || len(f.Revoked) != dashfile.MaxRevocations || len(f.Issuer.Keys) != dashfile.MaxKeys {
		t.Fatalf("%d projects, %d rows, %d revocations", len(f.Projects), rows, len(f.Revoked))
	}
}
