package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/pgconf"
)

// TestClusterArgs_Layout2_ProjectSettingReachesOnlyThePin: a project's own
// max_connections is rendered nowhere but in the pins, which end the command
// line in both start kinds: no configuration file the server reads and no
// later flag can set a pinned name again.
func TestClusterArgs_Layout2_ProjectSettingReachesOnlyThePin(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	s.GUC = map[string]string{"max_connections": "55"}
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	s.FirstBoot = false
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	pinned := pgconf.PinnedNames(2)[2:]
	for _, run := range clRuns(f, "pg-"+s.Ref) {
		cmd := positional(run)
		for _, name := range pinned {
			var at []int
			for i, arg := range cmd {
				if strings.HasPrefix(arg, name+"=") {
					at = append(at, i)
				}
			}
			if len(at) != 1 {
				t.Fatalf("%s set %d times on the command line: %q", name, len(at), cmd)
			}
			if i := at[0]; i < len(cmd)-12 || cmd[i-1] != "-c" {
				t.Fatalf("%s is not among the last flags: %q", name, cmd)
			}
		}
		if !slices.Contains(cmd, "max_connections=55") {
			t.Fatalf("the project's value is not pinned: %q", cmd)
		}
	}
	conf := string(clRead(t, filepath.Join(a.p.RenderDir(s.Ref), "conf.d", pgconf.OverrideFile)))
	for _, name := range pinned {
		if strings.Contains(conf, name) {
			t.Errorf("override file names %s", name)
		}
	}
}

// TestPurgeRepo_Layout2AbsentSubjectStillClearsTheRepositoryQuota: at
// layout 2 an absent subject directory launches nothing, yet the uid's
// repository quota is cleared through nodefs, which refuses a repository
// root that is absent or not a quota-enforcing mount (an unmounted
// repository filesystem must not pass for a purged repository). At
// layout 1 a node without a repository root is done with nothing called.
// Red until PurgeRepo makes that call.
func TestPurgeRepo_Layout2AbsentSubjectStillClearsTheRepositoryQuota(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	f.resetLog()
	if err := a.PurgeRepo(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if got := l2Own(f); !slices.Equal(got, []string{"repoSetQuota " + a.p.RepoRoot() + " 700005 0"}) {
		t.Errorf("layout 2, no subject directory: root's calls %q", got)
	}
	if len(l2Runs(f)) != 0 {
		t.Errorf("tasks launched: %q", l2Runs(f))
	}
	s.Layout = 1
	os.RemoveAll(a.p.RepoRoot())
	f.resetLog()
	if err := a.PurgeRepo(context.Background(), s); err != nil || len(l2Own(f)) != 0 || len(l2Runs(f)) != 0 {
		t.Fatalf("layout 1, no repository root: %v %q", err, f.calls())
	}
}
