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
// nil when absent. Its members must be gone.
func (a *Agent) RemoveNetwork(ctx context.Context, ref string) error {
	if err := checkRef(ref); err != nil {
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
