// Command e08 reads the peer credentials (SO_PEERCRED) a Unix stream socket
// reports to a client, and can stand in as a different listener on a path.
//
//	e08 peer PATH N     open N connections at once; for each print
//	                    "pid uid gid start" (start = field 22 of /proc/<pid>/stat)
//	e08 listen PATH     listen on PATH, print "listening pid=<pid>", accept forever
//	e08 handoff PATH    listen on PATH, pass the listener to a child process and
//	                    exit: the socket's creator is then gone while the listener lives
//
// It never writes to a connection. Exit codes: 0 ok, 1 error, 2 usage,
// 3 peer pid 0 or 1 as seen from this pid namespace (refused),
// 4 /proc/<pid>/stat of the peer unreadable (refused).
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

type refusal struct {
	code int
	msg  string
}

func (r refusal) Error() string { return r.msg }

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch {
	case os.Args[1] == "peer" && len(os.Args) == 4:
		n, aerr := strconv.Atoi(os.Args[3])
		if aerr != nil || n < 1 {
			usage()
		}
		err = peer(os.Args[2], n)
	case os.Args[1] == "listen" && len(os.Args) == 3:
		err = listen(os.Args[2])
	case os.Args[1] == "handoff" && len(os.Args) == 3:
		err = handoff(os.Args[2])
	case os.Args[1] == "serve-fd" && len(os.Args) == 2:
		err = serveFD()
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "e08:", err)
		var r refusal
		if errors.As(err, &r) {
			os.Exit(r.code)
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: e08 peer PATH N | e08 listen PATH | e08 handoff PATH")
	os.Exit(2)
}

// peer holds n connections open together, so each is served by its own forked
// backend while the credentials are read.
func peer(path string, n int) error {
	conns := make([]*net.UnixConn, 0, n)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < n; i++ {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return err
		}
		conns = append(conns, c)
		raw, err := c.SyscallConn()
		if err != nil {
			return err
		}
		var cred *syscall.Ucred
		var gerr error
		if err := raw.Control(func(fd uintptr) {
			cred, gerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		}); err != nil {
			return err
		}
		if gerr != nil {
			return gerr
		}
		if cred.Pid <= 1 {
			return refusal{3, fmt.Sprintf("refused: peer pid %d (0 or 1 as seen from this pid namespace)", cred.Pid)}
		}
		start, err := procStart(int(cred.Pid))
		if err != nil {
			return refusal{4, fmt.Sprintf("refused: /proc/%d/stat unreadable: %v", cred.Pid, err)}
		}
		fmt.Println(cred.Pid, cred.Uid, cred.Gid, start)
	}
	return nil
}

// procStart returns field 22 (starttime) of /proc/pid/stat, read after the
// last ')' so a command name with spaces or parentheses cannot shift it.
func procStart(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", errors.New("malformed")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return "", errors.New("malformed")
	}
	return f[19], nil
}

func listen(path string) error {
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	fmt.Printf("listening pid=%d\n", os.Getpid())
	return accept(l)
}

func accept(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		c.Close()
	}
}

func handoff(path string) error {
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	f, err := l.(*net.UnixListener).File()
	if err != nil {
		return err
	}
	cmd := exec.Command("/proc/self/exe", "serve-fd")
	cmd.ExtraFiles = []*os.File{f}
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Printf("creator pid=%d holder pid=%d\n", os.Getpid(), cmd.Process.Pid)
	// Exit without closing l: a Close would unlink the socket file.
	os.Exit(0)
	return nil
}

func serveFD() error {
	l, err := net.FileListener(os.NewFile(3, "listener"))
	if err != nil {
		return err
	}
	return accept(l)
}
