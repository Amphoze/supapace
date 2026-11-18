package pgsock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// oPath is O_PATH from include/uapi/asm-generic/fcntl.h (amd64, arm64).
const oPath = 0x200000

const dirFlags = oPath | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// openSocket opens <projects>/<ref>/sock/.s.PGSQL.5432 by descriptor, refusing
// a link at any of the last three components, and returns an O_PATH
// descriptor of the socket inode after checking that it is a socket owned by
// uid. O_PATH|O_NOFOLLOW opens a link itself, so fstat sees what
// fstatat(AT_SYMLINK_NOFOLLOW) would.
func openSocket(projects, ref string, uid int) (int, error) {
	root, err := syscall.Open(projects, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: projects directory: %v", ErrNotSocket, err)
	}
	defer syscall.Close(root)
	refFD, err := syscall.Openat(root, ref, dirFlags, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: project directory: %v", ErrNotSocket, err)
	}
	defer syscall.Close(refFD)
	sockFD, err := syscall.Openat(refFD, "sock", dirFlags, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: socket directory: %v", ErrNotSocket, err)
	}
	defer syscall.Close(sockFD)
	fd, err := syscall.Openat(sockFD, ".s.PGSQL.5432", oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: socket: %v", ErrNotSocket, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("%w: socket: %v", ErrNotSocket, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK || int(st.Uid) != uid {
		syscall.Close(fd)
		return -1, fmt.Errorf("%w: not a socket owned by uid %d", ErrNotSocket, uid)
	}
	return fd, nil
}

// peerCred returns the pid and uid of the process that created the listening
// socket at the other end of c.
func peerCred(c *net.UnixConn) (pid int, uid int, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var u *syscall.Ucred
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		u, gerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if gerr != nil {
		return 0, 0, gerr
	}
	return int(u.Pid), int(u.Uid), nil
}

// ProcStart returns field 22 (starttime, in clock ticks since boot) of
// /proc/<pid>/stat.
func ProcStart(pid int) (uint64, error) {
	_, start, err := procStat(pid)
	return start, err
}

func procStat(pid int) (ppid int, start uint64, err error) {
	if pid <= 0 {
		return 0, 0, fmt.Errorf("pgsock: pid %d", pid)
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, fmt.Errorf("pgsock: stat of pid %d: %w", pid, errors.Unwrap(err))
	}
	return parseStat(b)
}

// parseStat reads the parent pid (field 4) and the start time (field 22).
// Fields are taken after the last ')', so a command name holding spaces,
// parentheses or newlines cannot shift them.
func parseStat(b []byte) (ppid int, start uint64, err error) {
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, 0, errors.New("pgsock: malformed stat")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, 0, errors.New("pgsock: malformed stat")
	}
	ppid, err = strconv.Atoi(f[1])
	if err != nil {
		return 0, 0, errors.New("pgsock: malformed stat")
	}
	start, err = strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0, 0, errors.New("pgsock: malformed stat")
	}
	return ppid, start, nil
}
