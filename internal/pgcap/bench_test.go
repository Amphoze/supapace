package pgcap

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// BenchmarkRelay_SmallRows measures a result of many small data rows through
// the relay on loopback, one connection, a class without a window: one
// iteration is one row.
func BenchmarkRelay_SmallRows(b *testing.B) {
	for _, size := range []int{30, 100, 1000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			cl, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer cl.Close()
			chunk := bytes.Repeat(dataRow(size), (64<<10)/size)
			go func() {
				s, err := cl.Accept()
				if err != nil {
					return
				}
				defer s.Close()
				var h [8]byte
				io.ReadFull(s, h[:])
				s.Write(login)
				for {
					if _, err := s.Write(chunk); err != nil {
						return
					}
				}
			}()
			front, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer front.Close()
			client, err := net.Dial("tcp4", front.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			acc, err := front.Accept()
			if err != nil {
				b.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- Relay(ctx, Conn{Class: noneClass(), Client: acc, First: startupPacket("user\x00u\x00\x00"),
					From: netip.MustParseAddr("127.0.0.1"), To: netip.MustParseAddrPort(cl.Addr().String()),
					Accepted: time.Now().Add(time.Hour)})
			}()
			if _, err := io.CopyN(io.Discard, client, int64(len(login))); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ResetTimer()
			if _, err := io.CopyN(io.Discard, client, int64(b.N)*int64(size)); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			cancel()
			<-done
		})
	}
}
