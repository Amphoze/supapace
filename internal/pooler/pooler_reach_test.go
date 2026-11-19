//go:build reach && linux && (amd64 || arm64)

// TestReach_Step makes one admin call against a running pooler, from inside
// its network namespace, as the daemon will: a lab script runs this test
// binary as root on a bare test node once per step and reads the registry
// and the cluster's sessions itself between steps. Without POOLER_STEP it
// skips. Secrets come from files, never from the environment or arguments:
//
//	POOLER_STEP       health | put | terminate | delete | unban
//	POOLER_CONTAINER  the pooler's container name
//	POOLER_SECRET     file holding the API secret
//	POOLER_REF        the tenant's ref
//	POOLER_DBHOST     put: the cluster's address (port 5432)
//	POOLER_PASSWORD   put: file holding the manager's password
//	POOLER_POOL       put: the pool size
//	POOLER_ADDR       unban: one address; empty clears all of the tenant's
package pooler

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nsdial"
	"github.com/Amphoze/supapace/internal/poolcfg"
)

func targetOf(ctx context.Context, name string) (nsdial.Target, error) {
	c, err := dockerx.InspectContainer(ctx, name)
	if err != nil {
		return nsdial.Target{}, err
	}
	if c == nil || !c.Running || c.Pid == 0 {
		return nsdial.Target{}, fmt.Errorf("%s is not running", name)
	}
	return nsdial.TargetOf(c.Pid)
}

func readFile(t *testing.T, env string) []byte {
	t.Helper()
	b, err := os.ReadFile(os.Getenv(env))
	if err != nil || len(b) == 0 {
		t.Fatalf("%s: the file cannot be read or is empty", env)
	}
	return b
}

func TestReach_Step(t *testing.T) {
	step := os.Getenv("POOLER_STEP")
	if step == "" {
		t.Skip("POOLER_STEP not set")
	}
	name, ref := os.Getenv("POOLER_CONTAINER"), os.Getenv("POOLER_REF")
	recheck := func(ctx context.Context) (nsdial.Target, error) { return targetOf(ctx, name) }
	dial := func(ctx context.Context) (net.Conn, error) {
		tg, err := recheck(ctx)
		if err != nil {
			return nil, err
		}
		return nsdial.DialTCP(ctx, tg, recheck, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), poolcfg.AdminPort))
	}
	c := New(dial, readFile(t, "POOLER_SECRET"))
	ctx := context.Background()
	start := time.Now()
	var err error
	switch step {
	case "health":
		err = c.Health(ctx)
	case "put":
		pool, _ := strconv.Atoi(os.Getenv("POOLER_POOL"))
		host, perr := netip.ParseAddr(os.Getenv("POOLER_DBHOST"))
		if perr != nil {
			t.Fatal(perr)
		}
		err = c.PutTenant(ctx, ref, poolcfg.Tenant{DBHost: host, DBPort: 5432, PoolSize: pool,
			MaxClients: poolcfg.DefaultMaxClients, AllowList: poolcfg.OpenAllowList(),
			ManagerPassword: string(readFile(t, "POOLER_PASSWORD"))})
	case "terminate":
		err = c.Terminate(ctx, ref)
	case "delete":
		err = c.Delete(ctx, ref)
	case "unban":
		var addrs []netip.Addr
		if s := os.Getenv("POOLER_ADDR"); s != "" {
			addrs = []netip.Addr{netip.MustParseAddr(s)}
		}
		err = c.ClearBans(ctx, ref, addrs)
	default:
		t.Fatalf("step %q", step)
	}
	t.Logf("pooler_step %s %s: %v in %v", step, ref, err, time.Since(start).Round(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
}
