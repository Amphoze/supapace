package nodecfg

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// valid is a configuration Validate accepts.
func valid() Config {
	c := Default("sp.test")
	c.MemAllocMB, c.PidsAlloc = 1, 1
	return c
}

// The node file written before the pooler's members existed: a Config that
// sets none of them marshals to exactly the members it had, and one that sets
// each marshals it under its name.
func TestConfig_WithoutNewMembersMarshalsAsBefore(t *testing.T) {
	asBuilt := []string{"node_id", "domain", "project_block", "slice_prefix", "platform_subnet", "platform_ip_range",
		"gateway_ip", "ingress_subnet", "gateway_ingress_ip", "docker_pool", "docker_pool_size", "uid_base", "uid_count",
		"mem_alloc_mb", "pids_alloc", "retention", "uplinks", "images", "backup_subnet"}
	keys := func(c Config) []string {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	want := slices.Clone(asBuilt)
	slices.Sort(want)
	if got := keys(valid()); !slices.Equal(got, want) {
		t.Errorf("members of a default node file: %v\nwant %v", got, want)
	}
	c := valid()
	c.PoolerLabel, c.PublicAddrs, c.EgressSubnet = "db", []string{"192.0.2.10"}, "10.212.11.0/24"
	c.ProxyMaxConns, c.RestIdleStopS, c.OffsiteWindowS, c.RekeySettleS = 1, 2, 3, 4
	got := keys(c)
	for _, k := range []string{"pooler_label", "public_addrs", "egress_subnet", "proxy_max_conns", "rest_idle_stop_s", "offsite_window_s", "rekey_settle_s"} {
		if !slices.Contains(got, k) {
			t.Errorf("member %s not written: %v", k, got)
		}
	}
	// And a file with them loads back as it was.
	p := filepath.Join(t.TempDir(), "node.json")
	b, _ := json.Marshal(c)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := Load(p); err != nil || !reflect.DeepEqual(l, c) {
		t.Errorf("round trip: %+v, %v", l, err)
	}
}

func TestValidate_PoolerLabelAndEgressSubnet(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	if got := valid().Egress(); got != "10.212.10.0/24" {
		t.Errorf("Egress() of a default node = %q", got)
	}
	label := func(s string) Config { c := valid(); c.PoolerLabel = s; return c }
	for _, ok := range []string{"db", "pool-1", "a", strings.Repeat("a", 63), "abcdefghij012345678"} {
		if err := label(ok).Validate(); err != nil {
			t.Errorf("label %q refused: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{
		"dash first": "-db", "dash last": "db-", "a dot": "db.x", "capitals": "Db", "underscore": "d_b",
		"64 characters": strings.Repeat("a", 64), "a ref's shape": "abcdefghij0123456789", "space": "d b",
	} {
		if err := label(bad).Validate(); err == nil || !strings.Contains(err.Error(), "pooler_label") {
			t.Errorf("%s (%q): %v, want a pooler_label error", name, bad, err)
		}
	}
	// <ref>.<label>.<domain>: 253 characters pass, 254 do not.
	c := valid()
	c.Domain = strings.Repeat("d", 60) + "." + strings.Repeat("e", 60) + "." + strings.Repeat("f", 60) + ".test" // 188
	c.PoolerLabel = strings.Repeat("a", 253-20-1-1-len(c.Domain))
	if n := len("aaaaaaaaaaaaaaaaaaaa." + c.PoolerLabel + "." + c.Domain); n != 253 {
		t.Fatalf("fixture: %d", n)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("a 253-character pooler host refused: %v", err)
	}
	c.PoolerLabel += "a"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "253") {
		t.Errorf("a 254-character pooler host: %v", err)
	}

	egress := func(s string) Config { c := valid(); c.EgressSubnet = s; return c }
	if err := egress("10.212.11.0/24").Validate(); err != nil {
		t.Errorf("a free egress subnet refused: %v", err)
	}
	if got := egress("10.212.11.0/24").Egress(); got != "10.212.11.0/24" {
		t.Errorf("Egress() = %q", got)
	}
	for name, s := range map[string]string{
		"platform": "10.212.0.0/24", "ingress": "10.212.8.0/25", "backup": "10.212.9.0/24", "project block": "10.213.0.0/24",
		"docker pool": "10.214.4.0/24", "covers all": "10.212.0.0/14", "not masked": "10.212.11.1/24", "ipv6": "2001:db8::/64", "garbage": "spe0",
	} {
		if err := egress(s).Validate(); err == nil || !strings.Contains(err.Error(), "egress_subnet") {
			t.Errorf("%s (%q): %v, want an egress_subnet error", name, s, err)
		}
	}
	// The default is checked too: another network moved onto it is refused.
	d := valid()
	d.BackupSubnet = "10.212.10.0/24"
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "egress_subnet") {
		t.Errorf("backup subnet over the default egress subnet: %v", err)
	}
}

func TestValidate_PublicAddrsAndBounds(t *testing.T) {
	addrs := func(a ...string) Config { c := valid(); c.PublicAddrs = a; return c }
	if err := addrs("192.0.2.10", "198.51.100.7", "10.215.250.1").Validate(); err != nil {
		t.Errorf("control: %v", err)
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = "192.0.2." + strconv.Itoa(i+1)
	}
	if err := addrs(many[:32]...).Validate(); err != nil {
		t.Errorf("32 addresses refused: %v", err)
	}
	for name, a := range map[string][]string{
		"33 addresses": many, "inside the platform subnet": {"10.212.0.9"}, "inside the egress subnet": {"10.212.10.1"},
		"inside the project block": {"10.213.0.2"}, "multicast": {"224.0.0.251"}, "loopback": {"127.0.0.1"},
		"link-local": {"169.254.0.0"}, "unspecified": {"0.0.0.0"}, "broadcast": {"255.255.255.255"},
		"this network": {"0.1.2.3"}, "reserved block": {"240.0.0.1"},
		"ipv6": {"2001:db8::1"}, "mapped": {"::ffff:192.0.2.1"}, "not canonical": {"192.0.2.010"},
		"a prefix": {"192.0.2.0/24"}, "repeated": {"192.0.2.1", "192.0.2.1"}, "empty": {""},
	} {
		if err := addrs(a...).Validate(); err == nil || !strings.Contains(err.Error(), "public_addrs") {
			t.Errorf("%s: %v, want a public_addrs error", name, err)
		}
	}
	for name, edit := range map[string]func(*Config){
		"rest_idle_stop_s above a day": func(c *Config) { c.RestIdleStopS = 86401 },
		"rest_idle_stop_s negative":    func(c *Config) { c.RestIdleStopS = -1 },
		"proxy_max_conns negative":     func(c *Config) { c.ProxyMaxConns = -1 },
		"offsite_window_s negative":    func(c *Config) { c.OffsiteWindowS = -1 },
		"rekey_settle_s negative":      func(c *Config) { c.RekeySettleS = -1 },
	} {
		c := valid()
		edit(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), strings.Fields(name)[0]) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c := valid()
	c.RestIdleStopS, c.ProxyMaxConns, c.OffsiteWindowS, c.RekeySettleS = 86400, 1, 1, 1
	if err := c.Validate(); err != nil {
		t.Errorf("the bounds themselves refused: %v", err)
	}
}

func TestPaths_PoolerAndOperations(t *testing.T) {
	root := t.TempDir()
	p, prod := Paths{Root: root}, Paths{}
	for _, pr := range []struct{ got, prod, want string }{
		{p.PoolerSecrets(), prod.PoolerSecrets(), "/etc/supapace/pooler"},
		{p.PoolerTLS(), prod.PoolerTLS(), "/etc/supapace/tls-pooler"},
		{p.NftLimitFile(), prod.NftLimitFile(), "/etc/supapace/nftables-limit.nft"},
		{p.WakeDir(), prod.WakeDir(), "/var/lib/supapace/platform/wake"},
		{p.ScheduleCache(), prod.ScheduleCache(), "/var/lib/supapace/platform/schedule.json"},
	} {
		if pr.prod != pr.want || pr.got != root+pr.want {
			t.Errorf("path %q (rooted %q), want %q", pr.prod, pr.got, pr.want)
		}
	}
	if EgressBridge != "spe0" || EgressNetwork != "tenant-egress" {
		t.Error("an egress constant changed")
	}
}

func TestSupavisorImage_FromTheLock(t *testing.T) {
	ref, err := SupavisorImage()
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{}
	f, err := os.Open("../../test/harness/experiments/pins-pool.env")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for s := bufio.NewScanner(f); s.Scan(); {
		if k, v, ok := strings.Cut(s.Text(), "="); ok && !strings.HasPrefix(k, "#") {
			pins[k] = v
		}
	}
	repo := pins["SUPAVISOR_TAG"][:strings.LastIndex(pins["SUPAVISOR_TAG"], ":")]
	if ref != repo+"@"+pins["SUPAVISOR_INDEX"] {
		t.Errorf("SupavisorImage() = %q, want the index %s@%s", ref, repo, pins["SUPAVISOR_INDEX"])
	}
	var lock map[string]lockEntry
	if err := json.Unmarshal(imagesLock, &lock); err != nil {
		t.Fatal(err)
	}
	if e := lock["supavisor"]; e.Tag != pins["SUPAVISOR_TAG"] || e.AMD64 != pins["SUPAVISOR_AMD64"] || e.ARM64 != pins["SUPAVISOR_ARM64"] {
		t.Errorf("lock row %+v, want the three digests of pins-pool.env %v", e, pins)
	}

	saved := imagesLock
	defer func() { imagesLock = saved }()
	d := "sha256:" + strings.Repeat("a", 64)
	for name, body := range map[string]string{
		"no index digest":       `{"supavisor":{"tag":"x/y:1","amd64":"` + d + `","arm64":"` + d + `"}}`,
		"platform digests only": `{"supavisor":{"tag":"x/y:1","digest":"","amd64":"` + d + `"}}`,
		"no row":                `{"postgres":{"tag":"x/y:1","digest":"` + d + `"}}`,
	} {
		imagesLock = []byte(body)
		if r, err := SupavisorImage(); err == nil {
			t.Errorf("%s: %q accepted", name, r)
		}
	}
	imagesLock = []byte(`{"supavisor":{"tag":"x/y:1","digest":"` + d + `","amd64":"sha256:` + strings.Repeat("b", 64) + `"}}`)
	if r, err := SupavisorImage(); err != nil || r != "x/y@"+d {
		t.Errorf("control: %q, %v; want the index digest, never a platform one", r, err)
	}
}

func TestPostgresImages_LockRowsToVersions(t *testing.T) {
	m, err := PostgresImages()
	if err != nil {
		t.Fatal(err)
	}
	im, _ := LockedImages()
	v, _ := LockedPostgresVersion()
	if len(m) != 1 || m[im.Postgres] != v {
		t.Errorf("PostgresImages() = %v, want {%s: %s}", m, im.Postgres, v)
	}

	saved := imagesLock
	defer func() { imagesLock = saved }()
	d := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	row := func(key, tag, digest string) string {
		return `"` + key + `":{"tag":"` + tag + `","digest":"` + digest + `"}`
	}
	imagesLock = []byte("{" + row("postgres", "s/postgres:17.6.1", d("a")) + "," +
		row("postgres@17.4.1", "s/postgres:17.4.1", d("b")) + "," + row("postgrest", "p/q:1", d("c")) + "}")
	m, err = PostgresImages()
	want := map[string]string{"s/postgres@" + d("a"): "17.6.1", "s/postgres@" + d("b"): "17.4.1"}
	if err != nil || !reflect.DeepEqual(m, want) {
		t.Errorf("two rows: %v, %v; want %v", m, err, want)
	}
	for name, body := range map[string]string{
		"key and tag disagree": "{" + row("postgres", "s/postgres:17.6.1", d("a")) + "," + row("postgres@17.4.1", "s/postgres:17.4.2", d("b")) + "}",
		"a row without digest": "{" + row("postgres", "s/postgres:17.6.1", d("a")) + "," + row("postgres@17.4.1", "s/postgres:17.4.1", "") + "}",
		"one image twice":      "{" + row("postgres", "s/postgres:17.6.1", d("a")) + "," + row("postgres@17.4.1", "s/postgres:17.4.1", d("a")) + "}",
		"no postgres row":      "{" + row("postgres@17.4.1", "s/postgres:17.4.1", d("b")) + "}",
		"a version not dotted": "{" + row("postgres", "s/postgres:17.6.1", d("a")) + "," + row("postgres@latest", "s/postgres:latest", d("b")) + "}",
	} {
		imagesLock = []byte(body)
		if m, err := PostgresImages(); err == nil {
			t.Errorf("%s: accepted %v", name, m)
		}
	}
}

// Several refusals come in one fixed order, whatever the map order of Go.
func TestValidate_RefusalsInAFixedOrder(t *testing.T) {
	c := valid()
	c.ProxyMaxConns, c.OffsiteWindowS, c.RekeySettleS = -1, -1, -1
	want := c.Validate().Error()
	if i, j, k := strings.Index(want, "proxy_max_conns"), strings.Index(want, "offsite_window_s"), strings.Index(want, "rekey_settle_s"); !(0 <= i && i < j && j < k) {
		t.Fatalf("order: %q", want)
	}
	for range 50 {
		if got := c.Validate().Error(); got != want {
			t.Fatalf("%q, then %q", want, got)
		}
	}
}
