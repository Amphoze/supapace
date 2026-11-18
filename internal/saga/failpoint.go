package saga

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// exit ends the process at a failpoint; tests replace it.
var exit = os.Exit

// hitFailpoint is the crash test hook, called at every step boundary of the
// worker with "<kind>:<step>" of the step about to run. When the failpoint
// file holds exactly that name it deletes the file, then exits with status
// 137 (a kill): one shot. It is inert when the file is absent, and on any
// node without the development marker that `init --dev` writes — a
// production node never has it, so there the file is never read or removed.
// Neither file is followed through a link.
func hitFailpoint(p nodecfg.Paths, name string) {
	if fi, err := os.Lstat(filepath.Join(filepath.Dir(p.NodeJSON()), "dev-mode")); err != nil || !fi.Mode().IsRegular() {
		return
	}
	f, err := os.OpenFile(p.Failpoint(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, 256))
	f.Close()
	if err != nil || strings.TrimSpace(string(b)) != name {
		return
	}
	if os.Remove(p.Failpoint()) != nil {
		return // exiting with the file in place would loop the supervisor
	}
	exit(137)
}
