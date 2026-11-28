package agent

import (
	"context"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// EnsureNetwork creates proj-<ref> with the platform's options. A network of
// that name that lacks any of them is never adopted, re-created or removed:
// ErrContainment.
func (a *Agent) EnsureNetwork(ctx context.Context, s Spec) error {
	if err := s.valid(a.cfg); err != nil {
		return err
	}
	name := networkName(s.Ref)
	n, err := dockerInspectNetwork(ctx, name)
	if err != nil {
		return err
	}
	if n != nil {
		if why := a.projectNetMismatch(n, s.SubnetIndex); why != "" {
			return refuse(nil, "%s exists: %s", name, why)
		}
		return refuseIPv6(ctx, name)
	}
	_, err = dockerRun(ctx, "network", "create", "--internal", "--ipv6=false", "--subnet", a.cfg.Slice(s.SubnetIndex).String(),
		"-o", optBridgeName+"="+nodecfg.BridgeName(s.SubnetIndex), "-o", optGatewayMode+"=isolated", "--", name)
	return err
}

// RemoveNetwork removes proj-<ref> whatever its options (delete, abort);
// nil when absent. Its members must be gone, but for the wire proxy: its
// slice leaves the proxy's table and the proxy the network first
// (DetachProxy), and a failure there leaves the network in place.
func (a *Agent) RemoveNetwork(ctx context.Context, ref string) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	if err := a.DetachProxy(ctx, ref); err != nil {
		return err
	}
	n, err := dockerInspectNetwork(ctx, networkName(ref))
	if err != nil || n == nil {
		return err
	}
	if _, err := dockerRun(ctx, "network", "rm", "--", networkName(ref)); err != nil {
		// Gone in between counts as removed.
		if n, ierr := dockerInspectNetwork(ctx, networkName(ref)); ierr == nil && n == nil {
			return nil
		}
		return err
	}
	return nil
}

// EnsureBackupNetwork creates `backup`, the network of the jobs that reach
// the object store: a bridge spb0 on the node's backup subnet with IPv6
// off and no other option. Leaving it is the node ruleset's (only the
// declared store addresses, nothing between members). A network of that
// name with anything else is never adopted, re-created or removed:
// ErrContainment.
func (a *Agent) EnsureBackupNetwork(ctx context.Context) error {
	n, err := dockerInspectNetwork(ctx, nodecfg.BackupNetwork)
	if err != nil {
		return err
	}
	if n == nil {
		_, err := dockerRun(ctx, "network", "create", "--driver", "bridge", "--subnet", a.cfg.BackupSubnet, "--ipv6=false",
			"-o", optBridgeName+"="+nodecfg.BackupBridge, "--", nodecfg.BackupNetwork)
		if err == nil {
			return nil
		}
		// Another launch may have made it meanwhile: then it is checked like any.
		if n, _ = dockerInspectNetwork(ctx, nodecfg.BackupNetwork); n == nil {
			return err
		}
	}
	switch {
	case n.Internal:
		return refuse(nil, "%s exists: internal", nodecfg.BackupNetwork)
	case n.BridgeName != nodecfg.BackupBridge:
		return refuse(nil, "%s exists: bridge %q, want %q", nodecfg.BackupNetwork, n.BridgeName, nodecfg.BackupBridge)
	case !samePrefix(n.Subnet, netPrefix(a.cfg.BackupSubnet)):
		return refuse(nil, "%s exists: subnet %q, want %s", nodecfg.BackupNetwork, n.Subnet, a.cfg.BackupSubnet)
	case len(n.Options) != 1 || n.Options[optBridgeName] != nodecfg.BackupBridge:
		return refuse(nil, "%s exists with other options", nodecfg.BackupNetwork)
	}
	return refuseIPv6(ctx, nodecfg.BackupNetwork)
}
