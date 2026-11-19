package dashcfg

import (
	"path/filepath"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// Paths locates the dashboard's files under a node's Paths (and its Root).
type Paths struct{ p nodecfg.Paths }

func PathsFor(p nodecfg.Paths) Paths { return Paths{p} }

func (d Paths) etc(name string) string { return filepath.Join(filepath.Dir(d.p.NodeJSON()), name) }

func (d Paths) KeyDir() string           { return d.etc("dash") }
func (d Paths) StudioTLS() string        { return d.etc("tls-studio") }
func (d Paths) GatewayDash() string      { return filepath.Join(d.p.GatewayDir(), "dash") }
func (d Paths) GatewayStudioTLS() string { return filepath.Join(d.p.GatewayDir(), "tls-studio") }
func (d Paths) DashboardFile() string    { return filepath.Join(d.p.GatewayDir(), "dashboard.json") }
func (d Paths) DashDir() string          { return filepath.Join(d.p.PlatformDir(), "dash") }
func (d Paths) SocketDir() string        { return filepath.Join(d.DashDir(), "sock") }
func (d Paths) StudioKeys() string       { return filepath.Join(d.DashDir(), "keys") }
func (d Paths) ProxyConf() string        { return filepath.Join(d.DashDir(), "pgcap") }
func (d Paths) DataDir() string          { return filepath.Join(d.p.ProjectsDir(), "dash") }
