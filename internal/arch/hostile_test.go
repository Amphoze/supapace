package arch

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPush_TargetIsFifoOrDirectoryFails(t *testing.T) {
	for _, plant := range []func(string) error{
		func(p string) error { return syscall.Mkfifo(p, 0o600) },
		func(p string) error { return os.Mkdir(p, 0o700) },
	} {
		spool := t.TempDir()
		target := filepath.Join(spool, seg)
		if err := plant(target); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- push(spool, source(t, []byte("wal")), seg) }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a non-regular target was accepted")
			}
		case <-time.After(10 * time.Second):
			// Unblock the open so the goroutine ends.
			if w, err := os.OpenFile(target, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			t.Fatal("push blocked on the planted target")
		}
		if got := entries(t, spool); len(got) != 1 {
			t.Fatalf("spool holds %v", got)
		}
	}
}

// A write that fails (a full quota surfaces at write or fsync) leaves nothing
// under the final name and no temporary file.
func TestPush_FailedWriteLeavesNothing(t *testing.T) {
	spool := t.TempDir()
	old := fsync
	fsync = func(*os.File) error { return syscall.EDQUOT }
	t.Cleanup(func() { fsync = old })
	if err := push(spool, source(t, []byte("wal")), seg); !errors.Is(err, syscall.EDQUOT) {
		t.Fatalf("got %v, want the quota error", err)
	}
	if got := entries(t, spool); len(got) != 0 {
		t.Fatalf("spool holds %v", got)
	}
}

// The file the server names is opened without blocking: a FIFO there is
// refused at once instead of stopping the archiver for good.
// Red until push opens its source with O_NONBLOCK and checks it is regular.
func TestPush_SourceIsFifoRefused(t *testing.T) {
	spool := t.TempDir()
	src := filepath.Join(t.TempDir(), "wal")
	if err := syscall.Mkfifo(src, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- push(spool, src, seg) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO source was archived")
		}
	case <-time.After(10 * time.Second):
		if w, err := os.OpenFile(src, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		<-done
		t.Fatal("push blocked on a FIFO source")
	}
	if got := entries(t, spool); len(got) != 0 {
		t.Fatalf("spool holds %v", got)
	}
}

// Every way get can fail other than the archive's own "not there" exits above
// 125, so the server stops instead of ending recovery.
func TestGet_ErrorsExitAbove125(t *testing.T) {
	shortTimeout(t)
	cases := map[string]func(t *testing.T, rs string){
		"no req directory": func(t *testing.T, rs string) { os.Remove(filepath.Join(rs, "req")) },
		"req is a file": func(t *testing.T, rs string) {
			os.Remove(filepath.Join(rs, "req"))
			writeFile(t, filepath.Join(rs, "req"), nil)
		},
		"no out directory": func(t *testing.T, rs string) { os.Remove(filepath.Join(rs, "out")) },
		"answer unreadable": func(t *testing.T, rs string) {
			writeFile(t, filepath.Join(rs, "out", seg), []byte("x"))
			os.Chmod(filepath.Join(rs, "out", seg), 0)
		},
		"answer is a socket": func(t *testing.T, rs string) {
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(rs, "out", seg), Net: "unix"})
			if err != nil {
				t.Skip(err)
			}
			t.Cleanup(func() { l.Close() })
		},
		"answer is a directory": func(t *testing.T, rs string) { os.Mkdir(filepath.Join(rs, "out", seg), 0o700) },
		"destination directory missing": func(t *testing.T, rs string) {
			writeFile(t, filepath.Join(rs, "out", seg), []byte("x"))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			if os.Geteuid() == 0 && name == "answer unreadable" {
				t.Skip("root reads anything")
			}
			rs := rspool(t)
			useRSpool(t, rs)
			setup(t, rs)
			dest := filepath.Join(t.TempDir(), "d")
			if name == "destination directory missing" {
				dest = filepath.Join(t.TempDir(), "gone", "d")
			}
			if code := Main([]string{"supapace-arch.test", "get", seg, dest}, os.Stderr); code <= 125 {
				t.Fatalf("exit %d: the server would read it as not in the archive", code)
			}
		})
	}
}

// A whole 16 MiB segment fits the bound, whatever the constant says.
func TestGet_ServesWholeSegment(t *testing.T) {
	rs := rspool(t)
	writeFile(t, filepath.Join(rs, "out", seg), make([]byte, 16<<20))
	dest := filepath.Join(t.TempDir(), "d")
	if err := get(rs, seg, dest, time.Minute); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dest); err != nil || fi.Size() != 16<<20 {
		t.Fatalf("served %v %v", fi, err)
	}
}
