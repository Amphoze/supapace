package dashcfg

import (
	"encoding/json"
	"errors"
)

// LimitSet is the dashboard's bounds table: every figure is written here once
// and rendered from here (the gateway reads it; the agent renders postgres-meta's
// settings, pgcap's class table and Studio's SUPAPACE_LIMITS from it).
type LimitSet struct {
	// the rows; a member's unit is in its name
	TransferMS, StudioHandoverMS, StudioHeaderMS, SocketCallMS, SlotWaitMS, MetaCallMS int // rows 1, 1s, 2, 3, 4, 5
	ProxyWallMS, MetaQuerySecs, ProxyAuthMS, MetaConnSecs, ProxyDialMS                 int // rows 6, 7, 8, 9, 10
	BodyBytes, ParseBodyBytes, MetaBodyMB                                              int // rows a (both), b
	ProxyWindowBytes                                                                   int64
	MetaResultMB                                                                       int
	StudioResultBytes                                                                  int64 // rows c, d, e
	// the caps
	GatewayDashNode, GatewayDashProject, StudioConns, HeaderBytes, SignInBodyBytes int // gateway
	InstanceCalls, ProjectCalls, ProjectWaiting, ParserSlots                       int // Studio
	ResolveMemorySecs, ResolveDiskDays                                             int
	SnippetBytes                                                                   int64
	SnippetEntries                                                                 int
	AuditFileBytes                                                                 int64
	StudioVolumeMB                                                                 int // stores
	StudioMemMB, PgMetaMemMB, PgcapMemMB                                           int // memory limits
	SliceHoldSecs                                                                  int // how long a purged project's slice is held; not a member of StudioJSON
	Proxy                                                                          ProxyLimits
}

// ProxyLimits is pgcap's class meta; each member is the class-table member of
// the same name in snake case. ScramIter is both the floor and the cap.
type ProxyLimits struct {
	MaxConns, RefusalsMax, PreambleMS, ConnsPerProject, ConnsPerPeer, CancelsPerProject, CancelsPerPeer, CancelMS int
	ConnsPerSecond, ConnsBurst, CopyBufBytes, SockBufBytes, ScramIter, ParamStatusMax, RowFieldsMax               int
}

const kib, mib = 1 << 10, 1 << 20

// Limits are the defaults; every figure is unmeasured until measured.
var Limits = LimitSet{
	TransferMS: 30000, StudioHandoverMS: 32000, StudioHeaderMS: 70000, SocketCallMS: 1000, SlotWaitMS: 10000, MetaCallMS: 57000,
	ProxyWallMS: 55000, MetaQuerySecs: 45, ProxyAuthMS: 10000, MetaConnSecs: 8, ProxyDialMS: 3000,
	BodyBytes: 2 * mib, ParseBodyBytes: 256 * kib, MetaBodyMB: 3,
	ProxyWindowBytes: 12 * mib, MetaResultMB: 6, StudioResultBytes: 8 * mib,

	GatewayDashNode: 256, GatewayDashProject: 32, StudioConns: 256, HeaderBytes: 32 * kib, SignInBodyBytes: 16 * kib,
	InstanceCalls: 4, ProjectCalls: 2, ProjectWaiting: 32, ParserSlots: 1,
	ResolveMemorySecs: 60, ResolveDiskDays: 7,
	SnippetBytes: 64 * mib, SnippetEntries: 2000, AuditFileBytes: 8 * mib, StudioVolumeMB: 4096,
	StudioMemMB: 896, PgMetaMemMB: 768, PgcapMemMB: 64,
	SliceHoldSecs: 8 * 86400,
	Proxy: ProxyLimits{
		MaxConns: 64, RefusalsMax: 16, PreambleMS: 2000, ConnsPerProject: 5, ConnsPerPeer: 16,
		CancelsPerProject: 2, CancelsPerPeer: 8, CancelMS: 2000,
		ConnsPerSecond: 20, ConnsBurst: 10, CopyBufBytes: 64 * kib, SockBufBytes: 32 * kib,
		ScramIter: 4096, ParamStatusMax: 64, RowFieldsMax: 1664,
	},
}

// Check holds the nesting of the bounds, whatever the figures: each clock fires
// inside the one that waits for it, and each byte cap inside the next.
func (l LimitSet) Check() error {
	var errs []error
	need := func(ok bool, rule string) {
		if !ok {
			errs = append(errs, errors.New("limits: "+rule))
		}
	}
	need(l.MetaConnSecs*1000+l.MetaQuerySecs*1000 < l.ProxyWallMS, "row 9 + row 7 < row 6")
	need(l.ProxyWallMS < l.MetaCallMS, "row 6 < row 5")
	need(l.SocketCallMS+l.SlotWaitMS+l.MetaCallMS < l.StudioHeaderMS, "row 3 + row 4 + row 5 < row 2")
	need(l.ProxyDialMS < l.MetaConnSecs*1000, "row 10 < row 9")
	need(l.MetaConnSecs*1000 < l.ProxyAuthMS, "row 9 < row 8")
	need(l.BodyBytes < l.MetaBodyMB*mib && l.ParseBodyBytes < l.MetaBodyMB*mib, "row a < row b")
	need(int64(l.MetaResultMB)*mib < l.ProxyWindowBytes, "row d < row c")
	// row e at 320 KiB/s within row 1: bytes / (320 KiB/s) < TransferMS / 1000 s.
	need(l.StudioResultBytes*1000 < int64(l.TransferMS)*320*kib, "row e ÷ 320 KiB/s < row 1")
	// A purged slice is held longer than any holder of its connection string: the
	// disk and memory caches, a request waiting on Studio, a proxied connection. In
	// milliseconds, so no part is truncated.
	need(int64(l.ResolveDiskDays*86400+l.ResolveMemorySecs)*1000+int64(l.StudioHeaderMS+l.ProxyWallMS) < int64(l.SliceHoldSecs)*1000,
		"resolve disk days + resolve memory + row 2 + row 6 < slice hold")
	return errors.Join(errs...)
}

// StudioJSON is the value of Studio's SUPAPACE_LIMITS: its members in a fixed
// order, no white space.
func (l LimitSet) StudioJSON() string {
	b, _ := json.Marshal(struct {
		SocketCallMS      int   `json:"socket_call_ms"`
		SlotWaitMS        int   `json:"slot_wait_ms"`
		MetaCallMS        int   `json:"meta_call_ms"`
		HandoverMS        int   `json:"handover_ms"`
		ResultBytes       int64 `json:"result_bytes"`
		InstanceCalls     int   `json:"instance_calls"`
		ProjectCalls      int   `json:"project_calls"`
		ProjectWaiting    int   `json:"project_waiting"`
		ParserSlots       int   `json:"parser_slots"`
		ResolveMemorySecs int   `json:"resolve_memory_s"`
		ResolveDiskDays   int   `json:"resolve_disk_days"`
		SnippetBytes      int64 `json:"snippet_bytes"`
		SnippetEntries    int   `json:"snippet_entries"`
		AuditFileBytes    int64 `json:"audit_file_bytes"`
	}{l.SocketCallMS, l.SlotWaitMS, l.MetaCallMS, l.StudioHandoverMS, l.StudioResultBytes, l.InstanceCalls,
		l.ProjectCalls, l.ProjectWaiting, l.ParserSlots, l.ResolveMemorySecs, l.ResolveDiskDays, l.SnippetBytes,
		l.SnippetEntries, l.AuditFileBytes})
	return string(b)
}
