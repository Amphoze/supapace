//go:build !linux || !(amd64 || arm64)

package nsdial

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var errUnsupported = errors.New("nsdial: not supported on this platform")

// TargetOf is Linux-only (amd64, arm64).
func TargetOf(pid int) (Target, error) { return Target{}, errUnsupported }

// DialTCP is Linux-only (amd64, arm64).
func DialTCP(ctx context.Context, t Target, recheck func(context.Context) (Target, error), addr netip.AddrPort) (net.Conn, error) {
	return nil, errUnsupported
}
