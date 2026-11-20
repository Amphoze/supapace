package main

// sp-dashstub delay --listen ADDR --to ADDR --rtt DURATION: a TCP relay for
// tests of a slow path. Each connection accepted is relayed to --to; each
// direction holds every chunk it reads for half the round trip from when it
// was read, then writes it. Each direction reads through 32 KiB buffers and
// holds at most delayQueue of them queued, one being written and one read:
// beyond that it stops reading, and the sender's window fills. A direction
// that ends is passed on as a half close; an error ends both.

import (
	"flag"
	"fmt"
	"io"
	"net"
	"time"
)

func init() { subcommands["delay"] = delay }

const (
	delayChunk = 32 << 10
	delayQueue = 16
)

type delayer struct {
	to   string
	half time.Duration
	now  func() time.Time
	// wait ends when due has come; the tests release it themselves.
	wait func(due time.Time) <-chan time.Time
}

func realWait(due time.Time) <-chan time.Time { return time.After(time.Until(due)) }

func parseDelay(args []string, stderr io.Writer) (*delayer, string, int) {
	fs := flag.NewFlagSet("delay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "", "listen address")
	to := fs.String("to", "", "the address each connection is relayed to")
	rtt := fs.Duration("rtt", 0, "the round trip added")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *listen == "" || *to == "" || *rtt <= 0 {
		fmt.Fprintln(stderr, "usage: sp-dashstub delay --listen ADDR --to ADDR --rtt DURATION")
		return nil, "", 2
	}
	return &delayer{to: *to, half: *rtt / 2, now: time.Now, wait: realWait}, *listen, 0
}

func delay(args []string, stdout, stderr io.Writer) int {
	d, listen, code := parseDelay(args, stderr)
	if code != 0 {
		return code
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(stderr, "delay:", err)
		return 1
	}
	fmt.Fprintln(stdout, "listening", ln.Addr())
	fmt.Fprintln(stderr, "delay:", d.serve(ln))
	return 1
}

func (d *delayer) serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go d.relay(c)
	}
}

func (d *delayer) relay(down net.Conn) {
	defer down.Close()
	up, err := net.DialTimeout("tcp", d.to, 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{})
	go func() { d.pipe(up, down); close(done) }()
	d.pipe(down, up)
	<-done
}

type chunk struct {
	b   []byte
	due time.Time
}

// pipe copies src to dst, each chunk half the round trip after it was read.
func (d *delayer) pipe(dst, src net.Conn) {
	q := make(chan chunk, delayQueue)
	stop := make(chan struct{})
	defer close(stop)
	var readErr error
	go func() {
		defer close(q)
		for {
			b := make([]byte, delayChunk)
			n, err := src.Read(b)
			if n > 0 {
				select {
				case q <- chunk{b[:n], d.now().Add(d.half)}:
				case <-stop:
					return
				}
			}
			if err != nil {
				readErr = err
				return
			}
		}
	}()
	for c := range q {
		<-d.wait(c.due)
		if _, err := dst.Write(c.b); err != nil {
			dst.Close()
			src.Close()
			return
		}
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok && readErr == io.EOF {
		cw.CloseWrite()
		return
	}
	dst.Close()
	src.Close()
}
