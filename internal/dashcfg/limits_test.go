package dashcfg

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestLimits_DefaultsPassCheck(t *testing.T) {
	if err := Limits.Check(); err != nil {
		t.Fatal(err)
	}
	// The figures as written in the bounds table.
	l := Limits
	for _, c := range []struct {
		name      string
		got, want int64
	}{
		{"row 1", int64(l.TransferMS), 30000}, {"row 1s", int64(l.StudioHandoverMS), 32000},
		{"row 2", int64(l.StudioHeaderMS), 70000}, {"row 3", int64(l.SocketCallMS), 1000},
		{"row 4", int64(l.SlotWaitMS), 10000}, {"row 5", int64(l.MetaCallMS), 57000},
		{"row 6", int64(l.ProxyWallMS), 55000}, {"row 7", int64(l.MetaQuerySecs), 45},
		{"row 8", int64(l.ProxyAuthMS), 10000}, {"row 9", int64(l.MetaConnSecs), 8},
		{"row 10", int64(l.ProxyDialMS), 3000},
		{"row a", int64(l.BodyBytes), 2 << 20}, {"row a parse", int64(l.ParseBodyBytes), 256 << 10},
		{"row b", int64(l.MetaBodyMB), 3}, {"row c", l.ProxyWindowBytes, 12 << 20},
		{"row d", int64(l.MetaResultMB), 6}, {"row e", l.StudioResultBytes, 8 << 20},
		{"gateway node", int64(l.GatewayDashNode), 256}, {"gateway project", int64(l.GatewayDashProject), 32},
		{"studio conns", int64(l.StudioConns), 256}, {"header", int64(l.HeaderBytes), 32 << 10},
		{"sign-in body", int64(l.SignInBodyBytes), 16 << 10},
		{"instance calls", int64(l.InstanceCalls), 4}, {"project calls", int64(l.ProjectCalls), 2},
		{"project waiting", int64(l.ProjectWaiting), 32}, {"parser slots", int64(l.ParserSlots), 1},
		{"resolve memory", int64(l.ResolveMemorySecs), 60}, {"resolve disk", int64(l.ResolveDiskDays), 7},
		{"snippet bytes", l.SnippetBytes, 64 << 20}, {"snippet entries", int64(l.SnippetEntries), 2000},
		{"audit file", l.AuditFileBytes, 8 << 20}, {"volume", int64(l.StudioVolumeMB), 4096},
		{"studio mem", int64(l.StudioMemMB), 896}, {"pgmeta mem", int64(l.PgMetaMemMB), 768},
		{"pgcap mem", int64(l.PgcapMemMB), 64},
		{"slice hold", int64(l.SliceHoldSecs), 691200},
		{"max conns", int64(l.Proxy.MaxConns), 80}, {"refusals", int64(l.Proxy.RefusalsMax), 32},
		{"preamble", int64(l.Proxy.PreambleMS), 2000}, {"conns/project", int64(l.Proxy.ConnsPerProject), 5},
		{"conns/peer", int64(l.Proxy.ConnsPerPeer), 16}, {"cancels/project", int64(l.Proxy.CancelsPerProject), 2},
		{"cancels/peer", int64(l.Proxy.CancelsPerPeer), 8}, {"cancel", int64(l.Proxy.CancelMS), 2000},
		{"rate", int64(l.Proxy.ConnsPerSecond), 30}, {"burst", int64(l.Proxy.ConnsBurst), 60},
		{"copy buf", int64(l.Proxy.CopyBufBytes), 64 << 10}, {"sock buf", int64(l.Proxy.SockBufBytes), 32 << 10},
		{"scram", int64(l.Proxy.ScramIter), 4096}, {"param status", int64(l.Proxy.ParamStatusMax), 64},
		{"row fields", int64(l.Proxy.RowFieldsMax), 1664},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestLimits_CheckRefusesEachBrokenNesting(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*LimitSet)
	}{
		{"row 9 + row 7 = row 6", func(l *LimitSet) { l.MetaQuerySecs = l.ProxyWallMS/1000 - l.MetaConnSecs }},
		{"row 6 = row 5", func(l *LimitSet) { l.ProxyWallMS = l.MetaCallMS }},
		{"row 3 + row 4 + row 5 = row 2", func(l *LimitSet) { l.StudioHeaderMS = l.SocketCallMS + l.SlotWaitMS + l.MetaCallMS }},
		{"row 10 = row 9", func(l *LimitSet) { l.ProxyDialMS = l.MetaConnSecs * 1000 }},
		{"row 9 = row 8", func(l *LimitSet) { l.ProxyAuthMS = l.MetaConnSecs * 1000 }},
		{"row a = row b", func(l *LimitSet) { l.BodyBytes = l.MetaBodyMB << 20 }},
		{"row a (parse) = row b", func(l *LimitSet) { l.ParseBodyBytes = l.MetaBodyMB << 20 }},
		{"row d = row c", func(l *LimitSet) { l.ProxyWindowBytes = int64(l.MetaResultMB) << 20 }},
		{"row e at 320 KiB/s = row 1", func(l *LimitSet) { l.TransferMS = int(l.StudioResultBytes * 1000 / (320 << 10)) }},
		{"the proxy's pool one below both instances' connections", func(l *LimitSet) { l.Proxy.RefusalsMax = 2*l.Proxy.ConnsPerPeer - 1 }},
		{"disk + memory cache + row 2 + row 6 = slice hold", func(l *LimitSet) {
			l.SliceHoldSecs = l.ResolveDiskDays*86400 + l.ResolveMemorySecs + (l.StudioHeaderMS+l.ProxyWallMS)/1000
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := Limits
			tc.mod(&l)
			if err := l.Check(); err == nil {
				t.Fatalf("Check accepted %+v", l)
			}
		})
	}
	// Control: every case above breaks exactly one inequality of the defaults,
	// which pass.
	if err := Limits.Check(); err != nil {
		t.Fatal(err)
	}
	// Row e: exactly at the line fails, one millisecond more passes.
	l := Limits
	l.StudioResultBytes, l.TransferMS = 320<<10*30, 30000
	if l.Check() == nil {
		t.Error("row e at exactly row 1 accepted")
	}
	l.TransferMS++
	l.StudioHandoverMS = l.TransferMS + 2000
	if err := l.Check(); err != nil {
		t.Errorf("row e inside row 1: %v", err)
	}
}

func TestLimits_StudioJSON(t *testing.T) {
	const want = `{"socket_call_ms":1000,"slot_wait_ms":10000,"meta_call_ms":57000,"handover_ms":32000,` +
		`"result_bytes":8388608,"instance_calls":4,"project_calls":2,"project_waiting":32,"parser_slots":1,` +
		`"resolve_memory_s":60,"resolve_disk_days":7,"snippet_bytes":67108864,"snippet_entries":2000,` +
		`"audit_file_bytes":8388608,"meta_body_bytes":3145728}`
	if got := Limits.StudioJSON(); got != want {
		t.Fatalf("StudioJSON =\n%s\nwant\n%s", got, want)
	}
	// The body bound Studio is given is the one postgres-meta is given: one figure, rendered twice.
	l := Limits
	l.MetaBodyMB = 4
	if got := l.StudioJSON(); !strings.HasSuffix(got, `,"meta_body_bytes":4194304}`) {
		t.Errorf("with postgres-meta's body limit at 4 MiB, StudioJSON ends %q", got[len(got)-40:])
	}
	if env := strings.Join(PgMetaEnv(l), " "); !strings.Contains(env, "PG_META_MAX_BODY_LIMIT_MB=4") {
		t.Errorf("PgMetaEnv with the limit at 4: %s", env)
	}
}

func envNames(env []string) []string {
	var n []string
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		n = append(n, name)
	}
	return n
}

func TestStudioEnv_IsTheFixedSetPlusWhatTheImageMayDeclare(t *testing.T) {
	a, _ := For(defaultCfg())
	env, err := StudioEnv(a, "local", Limits, map[string]string{
		"ENABLED_FEATURES_LOGS_ALL": "false", "PORT": "3000", "HOST": "0.0.0.0", "NITRO_PORT": "3000", "NITRO_HOST": "0.0.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ENABLED_FEATURES_LOGS_ALL=false",
		"HOST=0.0.0.0",
		"NITRO_HOST=0.0.0.0",
		"NITRO_PORT=3000",
		"NODE_ENV=production",
		"PORT=3000",
		"SUPAPACE_DASH_DATA=/var/lib/dash",
		"SUPAPACE_DASH_KEYS=/etc/dash",
		"SUPAPACE_DASH_SOCKET=/run/dash/dash.sock",
		"SUPAPACE_LIMITS=" + Limits.StudioJSON(),
		"SUPAPACE_NODE_ID=local",
		"SUPAPACE_PGCAP=10.212.0.6:20000:21023",
		"SUPAPACE_PGMETA=http://10.212.0.4:8080,http://10.212.0.5:8080",
	}
	if !slices.Equal(env, want) {
		t.Fatalf("StudioEnv =\n%s\nwant\n%s", strings.Join(env, "\n"), strings.Join(want, "\n"))
	}
	// The fixed names are each present once, and are exactly FixedEnvNames.
	fixed := FixedEnvNames()
	if len(fixed) != 8 {
		t.Fatalf("fixed names %v", fixed)
	}
	for _, n := range fixed {
		if c := slices.Index(envNames(env), n); c < 0 || slices.Index(envNames(env)[c+1:], n) >= 0 {
			t.Errorf("fixed name %s not present exactly once", n)
		}
	}
	// With no image environment, the fixed set alone.
	env, err = StudioEnv(a, "local", Limits, nil)
	if err != nil || !slices.Equal(envNames(env), fixed) {
		t.Fatalf("fixed only: %v %v", envNames(env), err)
	}
	if !slices.Equal(ListenerNames, []string{"PORT", "HOST", "NITRO_PORT", "NITRO_HOST", "NITRO_SSL_CERT", "NITRO_SSL_KEY"}) {
		t.Fatalf("ListenerNames = %v", ListenerNames)
	}
	refused := []map[string]string{
		{"HOSTNAME": "x"},
		{"NODE_OPTIONS": "--inspect"},
		{"SUPAPACE_NODE_ID": "other"},
		{"SUPAPACE_LIMITS": "{}"},
		{"NODE_ENV": "development"},
		{"ENABLED_FEATURES_LOGS_ALL": "true"},
		{"ENABLED_FEATURES_LOGS_ALL": ""},
		{"ENABLED_FEATURES_": "false"},
		{"ENABLED_FEATURES_logs": "false"},
		{"ENABLED_FEATURES_A-B": "false"},
		{"enabled_features_X": "false"},
		{"PORT": "3001"},
		{"NITRO_PORT": "80"},
		// listener names the image may not set: Studio never serves TLS, the gateway does
		{"NITRO_SSL_CERT": "/etc/cert.pem"},
		{"NITRO_SSL_KEY": "/etc/key.pem"},
		{"port": "3000"},
		{"": "x"},
	}
	for _, m := range refused {
		if _, err := StudioEnv(a, "local", Limits, m); err == nil {
			t.Errorf("image environment %v accepted", m)
		}
	}
	// A broken bounds table, a missing address or node id is refused too.
	bad := Limits
	bad.ProxyWallMS = bad.MetaCallMS
	if _, err := StudioEnv(a, "local", bad, nil); err == nil {
		t.Error("a set that fails Check rendered")
	}
	for i, zero := range []func(*Addrs){
		func(z *Addrs) { z.Pgcap = netip.Addr{} }, func(z *Addrs) { z.PgMeta0 = netip.Addr{} },
		func(z *Addrs) { z.PgMeta1 = netip.Addr{} }, func(z *Addrs) { z.MetaPortLo, z.MetaPortHi = 0, 0 },
	} {
		z := a
		zero(&z)
		if _, err := StudioEnv(z, "local", Limits, nil); err == nil {
			t.Errorf("zero member %d rendered", i)
		}
	}
	if _, err := StudioEnv(a, "", Limits, nil); err == nil {
		t.Error("an empty node id rendered")
	}
	// SUPAPACE_LIMITS is valid JSON.
	var m map[string]int64
	if err := json.Unmarshal([]byte(Limits.StudioJSON()), &m); err != nil || len(m) != 15 {
		t.Fatalf("StudioJSON: %v %d", err, len(m))
	}
}

func TestPgMetaEnv_AllOfIt(t *testing.T) {
	want := []string{
		"PG_CONN_TIMEOUT_SECS=8",
		"PG_META_DB_URL=postgresql://none:none@127.0.0.1:9/none",
		"PG_META_FORMAT_IN_WORKER=true",
		"PG_META_MAX_BODY_LIMIT_MB=3",
		"PG_META_MAX_RESULT_SIZE_MB=6",
		"PG_META_PORT=8080",
		"PG_QUERY_TIMEOUT_SECS=45",
	}
	if got := PgMetaEnv(Limits); !slices.Equal(got, want) {
		t.Fatalf("PgMetaEnv =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	l := Limits
	l.MetaResultMB, l.MetaConnSecs, l.MetaQuerySecs, l.MetaBodyMB = 5, 7, 44, 4
	got := PgMetaEnv(l)
	for _, w := range []string{"PG_META_MAX_RESULT_SIZE_MB=5", "PG_CONN_TIMEOUT_SECS=7", "PG_QUERY_TIMEOUT_SECS=44", "PG_META_MAX_BODY_LIMIT_MB=4"} {
		if !slices.Contains(got, w) {
			t.Errorf("%s not rendered from the set: %v", w, got)
		}
	}
}

func TestNoForwardArgs(t *testing.T) {
	want := []string{
		"--sysctl", "net.ipv4.ip_forward=0",
		"--sysctl", "net.ipv4.conf.all.rp_filter=1",
		"--sysctl", "net.ipv4.conf.all.arp_ignore=1",
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
	}
	got := NoForwardArgs()
	if !slices.Equal(got, want) {
		t.Fatalf("NoForwardArgs = %q", got)
	}
	got[1] = "x"
	if NoForwardArgs()[1] != want[1] {
		t.Fatal("NoForwardArgs shares its slice")
	}
}

// The slice hold outlasts every holder of a connection string: refused at the
// line, accepted one second above it; milliseconds count, not truncated.
func TestLimits_SliceHoldNesting(t *testing.T) {
	l := Limits
	line := l.ResolveDiskDays*86400 + l.ResolveMemorySecs + (l.StudioHeaderMS+l.ProxyWallMS)/1000
	if line != 604985 {
		t.Fatal(line)
	}
	l.SliceHoldSecs = line
	if l.Check() == nil {
		t.Error("slice hold at the line accepted")
	}
	l.SliceHoldSecs = line + 1
	if err := l.Check(); err != nil {
		t.Errorf("slice hold above the line: %v", err)
	}
	l.StudioHeaderMS += 600 // 1.1 s more in all, each part under a second
	l.ProxyWallMS += 500
	if l.Check() == nil {
		t.Error("the milliseconds of rows 2 and 6 were truncated away")
	}
	l = Limits // 30 days in milliseconds does not fit 32 bits
	l.ResolveDiskDays, l.SliceHoldSecs = 30, 31*86400
	if err := l.Check(); err != nil {
		t.Errorf("a month of days: %v", err)
	}
}
