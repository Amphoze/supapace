package dashcfg

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
)

// ListenerNames is the closed list of the names Studio's server can read for its
// listener. An image may declare these, but for tlsNames, with the features it
// switches off.
var ListenerNames = []string{"PORT", "HOST", "NITRO_PORT", "NITRO_HOST", "NITRO_SSL_CERT", "NITRO_SSL_KEY"}

// tlsNames switch Studio's listener to TLS; the gateway terminates TLS, so an
// image may not set them.
var tlsNames = []string{"NITRO_SSL_CERT", "NITRO_SSL_KEY"}

// portNames are the listener names whose value must be StudioPort.
var portNames = []string{"PORT", "NITRO_PORT"}

var featureRE = regexp.MustCompile(`^ENABLED_FEATURES_[A-Z0-9_]+$`)

// fixedEnv is Studio's fixed environment, the names in sorted order.
func fixedEnv(a Addrs, node string, l LimitSet) [][2]string {
	return [][2]string{
		{"NODE_ENV", "production"},
		{"SUPAPACE_DASH_DATA", "/var/lib/dash"},
		{"SUPAPACE_DASH_KEYS", "/etc/dash"},
		{"SUPAPACE_DASH_SOCKET", "/run/dash/dash.sock"},
		{"SUPAPACE_LIMITS", l.StudioJSON()},
		{"SUPAPACE_NODE_ID", node},
		{"SUPAPACE_PGCAP", fmt.Sprintf("%s:%d:%d", a.Pgcap, a.MetaPortLo, a.MetaPortHi)},
		{"SUPAPACE_PGMETA", fmt.Sprintf("http://%s:%d,http://%s:%d", a.PgMeta0, PgMetaPort, a.PgMeta1, PgMetaPort)},
	}
}

// FixedEnvNames are the names StudioEnv always sets, sorted.
func FixedEnvNames() []string {
	var n []string
	for _, kv := range fixedEnv(Addrs{}, "", LimitSet{}) {
		n = append(n, kv[0])
	}
	return n
}

// StudioEnv is Studio's whole environment, NAME=value, sorted: the fixed names
// and what the image declares it needs (its label supapace.studio.env). An
// image may name its listener (a port only as StudioPort, never the TLS pair)
// and switch features off; any other name is refused.
func StudioEnv(a Addrs, node string, l LimitSet, imageEnv map[string]string) ([]string, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	if node == "" || !a.Pgcap.IsValid() || !a.PgMeta0.IsValid() || !a.PgMeta1.IsValid() || a.MetaPortLo < 1 {
		return nil, errors.New("studio env: no node id or a dashboard address missing")
	}
	var env []string
	for _, kv := range fixedEnv(a, node, l) {
		env = append(env, kv[0]+"="+kv[1])
	}
	for name, v := range imageEnv {
		switch {
		case slices.Contains(tlsNames, name):
			return nil, fmt.Errorf("studio env: the image may not set %q: Studio does not serve TLS", name)
		case slices.Contains(portNames, name):
			if v != strconv.Itoa(StudioPort) {
				return nil, fmt.Errorf("studio env: the image sets %s=%q, not %d", name, v, StudioPort)
			}
		case slices.Contains(ListenerNames, name):
		case featureRE.MatchString(name):
			if v != "false" {
				return nil, fmt.Errorf("studio env: the image sets %s=%q; a feature may only be switched off", name, v)
			}
		default:
			return nil, fmt.Errorf("studio env: the image may not set %q", name)
		}
		env = append(env, name+"="+v)
	}
	slices.Sort(env)
	return env, nil
}

// PgMetaEnv is postgres-meta's environment without CRYPTO_KEY, which the agent
// adds from the key file. Sorted; the same for both instances.
func PgMetaEnv(l LimitSet) []string {
	return []string{
		"PG_CONN_TIMEOUT_SECS=" + strconv.Itoa(l.MetaConnSecs),
		"PG_META_DB_URL=postgresql://none:none@127.0.0.1:9/none", // a dead address: every request names its own
		"PG_META_FORMAT_IN_WORKER=true",
		"PG_META_MAX_BODY_LIMIT_MB=" + strconv.Itoa(l.MetaBodyMB),
		"PG_META_MAX_RESULT_SIZE_MB=" + strconv.Itoa(l.MetaResultMB),
		"PG_META_PORT=" + strconv.Itoa(PgMetaPort),
		"PG_QUERY_TIMEOUT_SECS=" + strconv.Itoa(l.MetaQuerySecs),
	}
}

// NoForwardArgs are the docker arguments that keep a container on two networks
// from forwarding between them.
func NoForwardArgs() []string {
	return []string{
		"--sysctl", "net.ipv4.ip_forward=0",
		"--sysctl", "net.ipv4.conf.all.rp_filter=1",
		"--sysctl", "net.ipv4.conf.all.arp_ignore=1",
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
	}
}
