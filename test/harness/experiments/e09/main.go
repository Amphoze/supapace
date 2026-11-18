// Command e09 connects to a Postgres cluster with pgx (SCRAM) through a socket
// reached as /proc/self/fd/N/.s.PGSQL.5432, where N is a directory descriptor
// opened with O_PATH|O_DIRECTORY|O_NOFOLLOW, and checks that the dial still
// works after the directory's path has been renamed while the absolute path
// no longer does. It also dials /proc/self/fd/M, where M is an O_PATH|O_NOFOLLOW
// descriptor of the socket itself (the inode that was checked), and shows that
// replacing the name by a link to another socket after the check redirects a
// name-based dial but not that one.
//
//	e09 ROOT REF USER PASSFILE
//
// ROOT/REF/sock holds the socket. The program opens ROOT, then REF and sock
// below it by descriptor, renames ROOT/REF to ROOT/REF.moved and back, swaps the
// socket name for a link to a decoy listener at ROOT/decoy.sock and back, and
// prints one line per step: "<step>: ok …" or "<step>: error …".
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
)

// Linux constants the syscall package does not export (amd64 and arm64).
const (
	oPath    = 0x200000 // O_PATH, include/uapi/asm-generic/fcntl.h
	sockName = ".s.PGSQL.5432"
	maxMsg   = 1 << 20 // bytes; far above any message before AuthenticationOk
)

const dirFlags = oPath | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: e09 ROOT REF USER PASSFILE")
		os.Exit(2)
	}
	root, ref, user := os.Args[1], os.Args[2], os.Args[3]
	pw, err := os.ReadFile(os.Args[4])
	if err != nil {
		fatal(err)
	}
	password := strings.TrimSpace(string(pw))

	rootFD, err := syscall.Open(root, dirFlags, 0)
	if err != nil {
		fatal(err)
	}
	refFD, err := syscall.Openat(rootFD, ref, dirFlags, 0)
	if err != nil {
		fatal(err)
	}
	sockFD, err := syscall.Openat(refFD, "sock", dirFlags, 0)
	if err != nil {
		fatal(err)
	}
	fl, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(sockFD), syscall.F_GETFL, 0)
	if e != 0 {
		fatal(e)
	}
	fmt.Printf("o_path: ok F_GETFL=%#x, O_PATH bit %#x set=%v\n", fl, oPath, fl&oPath != 0)

	// O_PATH|O_NOFOLLOW opens a link itself rather than its target, so the
	// fstat below sees what fstatat(AT_SYMLINK_NOFOLLOW) would.
	sfd, err := syscall.Openat(sockFD, sockName, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(sfd, &st); err != nil {
		fatal(err)
	}
	fmt.Printf("stat: ok socket=%v uid=%d\n", st.Mode&syscall.S_IFMT == syscall.S_IFSOCK, st.Uid)

	link := filepath.Join(root, ref+".link")
	_ = os.Remove(link)
	if err := os.Symlink(ref, link); err != nil {
		fatal(err)
	}
	if fd, err := syscall.Openat(rootFD, ref+".link", dirFlags, 0); err != nil {
		fmt.Printf("nofollow: ok a link in place of the directory is refused: %v\n", err)
	} else {
		syscall.Close(fd)
		fmt.Println("nofollow: error a link in place of the directory was opened")
	}
	os.Remove(link)

	viaFD := fmt.Sprintf("/proc/self/fd/%d/%s", sockFD, sockName)
	abs := filepath.Join(root, ref, "sock", sockName)
	fmt.Println("descriptor path:", viaFD)

	report("fd-dial", viaFD, user, password)
	report("abs-dial", abs, user, password)
	report("fd-dial-wrong-password", viaFD, user, password+"x")

	if err := os.Rename(filepath.Join(root, ref), filepath.Join(root, ref+".moved")); err != nil {
		fatal(err)
	}
	fmt.Println("renamed:", ref, "->", ref+".moved")
	report("fd-dial-after-rename", viaFD, user, password)
	report("abs-dial-after-rename", abs, user, password)
	if err := os.Rename(filepath.Join(root, ref+".moved"), filepath.Join(root, ref)); err != nil {
		fatal(err)
	}
	fmt.Println("renamed back")

	// Connect through the checked inode, then swap the name after the check.
	viaInode := fmt.Sprintf("/proc/self/fd/%d", sfd)
	fmt.Println("inode path:", viaInode)
	report("inode-dial", viaInode, user, password)
	decoyPath := filepath.Join(root, "decoy.sock")
	_ = os.Remove(decoyPath)
	decoy, err := net.Listen("unix", decoyPath)
	if err != nil {
		fatal(err)
	}
	hits := make(chan struct{}, 16)
	go func() {
		for {
			c, err := decoy.Accept()
			if err != nil {
				return
			}
			hits <- struct{}{}
			c.Close()
		}
	}()
	name := filepath.Join(root, ref, "sock", sockName)
	if err := os.Rename(name, name+".real"); err != nil {
		fatal(err)
	}
	if err := os.Symlink(decoyPath, name); err != nil {
		fatal(err)
	}
	fmt.Println("swapped:", sockName, "-> link to", decoyPath)
	report("inode-dial-after-swap", viaInode, user, password)
	report("name-dial-after-swap", viaFD, user, password)
	fmt.Printf("decoy: %d connection(s); this process is pid %d\n", len(hits), os.Getpid())
	if err := os.Remove(name); err != nil {
		fatal(err)
	}
	if err := os.Rename(name+".real", name); err != nil {
		fatal(err)
	}
	decoy.Close()
	fmt.Println("swapped back")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "e09:", err)
	os.Exit(1)
}

func report(step, path, user, password string) {
	codes, peer, who, err := connect(path, user, password)
	if err != nil {
		fmt.Printf("%s: error %v (auth messages %v, peer pid %d)\n", step, err, codes, peer)
		return
	}
	fmt.Printf("%s: ok %s (auth messages %v, peer pid %d)\n", step, who, codes, peer)
}

// connect logs in with pgx over the socket at path and returns the
// authentication request codes the server sent, the peer pid and
// "current_user system_user".
func connect(path, user, password string) (codes []uint32, peer int32, who string, err error) {
	cfg, err := pgx.ParseConfig("host=/nonexistent dbname=postgres sslmode=disable connect_timeout=5")
	if err != nil {
		return nil, 0, "", err
	}
	cfg.User, cfg.Password = user, password
	cfg.Fallbacks = nil
	cfg.RuntimeParams = map[string]string{"application_name": "e09"}
	tap := &authTap{}
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		raw, err := c.(*net.UnixConn).SyscallConn()
		if err != nil {
			c.Close()
			return nil, err
		}
		var uerr error
		if err := raw.Control(func(fd uintptr) {
			var u *syscall.Ucred
			if u, uerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); uerr == nil {
				peer = u.Pid
			}
		}); err != nil || uerr != nil {
			c.Close()
			return nil, fmt.Errorf("peer credentials: %v %v", err, uerr)
		}
		tap.Conn = c
		return tap, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return tap.codes, peer, "", err
	}
	defer conn.Close(context.Background())
	var cu, su string
	if err := conn.QueryRow(ctx, "select current_user::text, coalesce(system_user, '(null)')").Scan(&cu, &su); err != nil {
		return tap.codes, peer, "", err
	}
	return tap.codes, peer, "current_user=" + cu + " system_user=" + su, nil
}

// authTap records the code of every Authentication message ('R') the server
// sends until AuthenticationOk (code 0). A message length below 4, above
// maxMsg, or an Authentication message too short for its code fails the read.
type authTap struct {
	net.Conn
	buf   bytes.Buffer
	codes []uint32
	done  bool
}

func (t *authTap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if !t.done && n > 0 {
		t.buf.Write(p[:n])
		for !t.done && t.buf.Len() >= 5 {
			b := t.buf.Bytes()
			l := int(binary.BigEndian.Uint32(b[1:5]))
			if l < 4 || l > maxMsg || (b[0] == 'R' && l < 8) {
				return n, fmt.Errorf("auth tap: message %q with bad length %d", b[0], l)
			}
			if t.buf.Len() < 1+l {
				break
			}
			if b[0] == 'R' {
				c := binary.BigEndian.Uint32(b[5:9])
				t.codes = append(t.codes, c)
				t.done = c == 0
			}
			t.buf.Next(1 + l)
		}
	}
	return n, err
}
