package offsite

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// maxAddrs bounds the resolved set: the lowest addresses of a longer answer.
const maxAddrs = 16

// iface is one network interface of the node: whether the kernel lists it as
// a bridge, and its IPv4 networks.
type iface struct {
	Name   string
	Bridge bool
	Nets   []netip.Prefix
}

// The resolver and the interface list; tests substitute their own.
var (
	lookupIP   = net.DefaultResolver.LookupNetIP
	interfaces = kernelInterfaces
)

// kernelInterfaces reads the interface list; an interface is a bridge when
// sysfs has a bridge directory for it.
func kernelInterfaces() ([]iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]iface, 0, len(ifs))
	for _, i := range ifs {
		_, err := os.Lstat(filepath.Join("/sys/class/net", i.Name, "bridge"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		x := iface{Name: i.Name, Bridge: err == nil}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			ones, bits := n.Mask.Size()
			if ip = ip.Unmap(); !ok || !ip.Is4() || bits == 0 {
				continue
			}
			if bits == 128 {
				ones -= 96
			}
			x.Nets = append(x.Nets, netip.PrefixFrom(ip, ones).Masked())
		}
		out = append(out, x)
	}
	return out, nil
}

// Resolve looks up the endpoint's IPv4 addresses and returns them with the
// endpoint's port, sorted, at most 16. The whole answer is refused when any
// address fails CheckAddrs.
func Resolve(ctx context.Context, d Declaration, c nodecfg.Config) ([]netip.AddrPort, error) {
	host, port, err := hostPort(d.Endpoint)
	if err != nil {
		return nil, err
	}
	ips, err := lookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("offsite: resolve %s: %w", host, err)
	}
	var out []netip.AddrPort
	for _, ip := range ips {
		if a := netip.AddrPortFrom(ip.Unmap(), port); !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("offsite: %s has no IPv4 address", host)
	}
	slices.SortFunc(out, netip.AddrPort.Compare)
	if err := CheckAddrs(c, out); err != nil {
		return nil, err
	}
	return out[:min(len(out), maxAddrs)], nil
}

// CheckAddrs refuses the whole set when any address is not IPv4 with a port,
// is loopback, link-local, multicast, unspecified, in 0.0.0.0/8 or in
// 240.0.0.0/4 (broadcast included), lies in one of the node's
// address blocks (project block, platform, ingress and backup subnets, Docker
// pool), or lies inside the subnet of a bridge interface of the node now. An
// address on the subnet of an interface that is not a bridge is accepted.
func CheckAddrs(c nodecfg.Config, addrs []netip.AddrPort) error {
	if len(addrs) == 0 {
		return nil
	}
	type block struct {
		name string
		p    netip.Prefix
	}
	var blocks []block
	for _, b := range []struct{ name, s string }{
		{"the project block", c.ProjectBlock}, {"the platform subnet", c.PlatformSubnet}, {"the ingress subnet", c.IngressSubnet},
		{"the backup subnet", c.BackupSubnet}, {"the Docker address pool", c.DockerPool},
	} {
		p, err := netip.ParsePrefix(b.s)
		if err != nil {
			return fmt.Errorf("offsite: node configuration: %s %q is not a network", b.name, b.s)
		}
		blocks = append(blocks, block{b.name, p.Masked()})
	}
	ifs, err := interfaces()
	if err != nil {
		return fmt.Errorf("offsite: reading the node's interfaces: %w", err)
	}
	for _, i := range ifs {
		if i.Bridge {
			for _, n := range i.Nets {
				blocks = append(blocks, block{"the subnet of bridge " + i.Name, n})
			}
		}
	}
	for _, a := range addrs {
		ip := a.Addr()
		why := ""
		switch {
		case !a.IsValid() || a.Port() == 0 || !ip.Is4():
			why = "not an IPv4 address with a port"
		case ip.IsLoopback():
			why = "loopback"
		case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
			why = "link-local"
		case ip.IsMulticast():
			why = "multicast"
		case ip.IsUnspecified():
			why = "unspecified"
		case ip.As4()[0] == 0:
			why = "in 0.0.0.0/8"
		case ip.As4()[0] >= 240:
			why = "reserved or broadcast (240.0.0.0/4)"
		}
		for _, b := range blocks {
			if why == "" && b.p.Contains(ip) {
				why = "inside " + b.name + " " + b.p.String()
			}
		}
		if why != "" {
			return fmt.Errorf("offsite: endpoint address %v refused: %s", a, why)
		}
	}
	return nil
}
