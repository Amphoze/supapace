package nodecfg

import (
	"path/filepath"
	"strings"
)

// Paths locates every file the platform keeps on a node. Root is "" in production
// and a temporary directory in tests; every path is Root joined with its fixed
// location.
type Paths struct{ Root string }

func (p Paths) at(parts ...string) string {
	return filepath.Join(append([]string{p.Root, "/"}, parts...)...)
}

const (
	etcDir = "etc/supapace"
	runDir = "run/supapace"
	varDir = "var/lib/supapace"
)

func (p Paths) NodeJSON() string  { return p.at(etcDir, "node.json") }
func (p Paths) KEK() string       { return p.at(etcDir, "kek") }
func (p Paths) NftFile() string   { return p.at(etcDir, "nftables.nft") }
func (p Paths) NftSum() string    { return p.at(etcDir, "nft.sha256") }
func (p Paths) TLSDir() string    { return p.at(etcDir, "tls") }
func (p Paths) CADir() string     { return p.at(etcDir, "ca") }
func (p Paths) AdminSock() string { return p.at(runDir, "admin.sock") }
func (p Paths) Failpoint() string { return p.at(runDir, "failpoint") }
func (p Paths) BootJSON() string  { return p.at(runDir, "boot.json") }
func (p Paths) DriftHold() string { return p.at(runDir, "drift-hold") }

func (p Paths) CPDir() string       { return p.at(varDir, "cp") }
func (p Paths) PlatformDir() string { return p.at(varDir, "platform") }

// ImageDir is platform/image/<first 12 hex digits of the digest>; digest may carry
// a "sha256:" prefix or be a whole "name@sha256:…" reference.
func (p Paths) ImageDir(digest string) string {
	if i := strings.LastIndex(digest, "sha256:"); i >= 0 {
		digest = digest[i+len("sha256:"):]
	}
	if len(digest) > 12 {
		digest = digest[:12]
	}
	return p.at(varDir, "platform", "image", digest)
}

func (p Paths) GatewayDir() string { return p.at(varDir, "platform", "gateway") }

// RenderDir is the root-owned directory of a project's rendered platform files.
func (p Paths) RenderDir(ref string) string { return p.at(varDir, "platform", "projects", ref) }

// ProjectsDir is the XFS mount holding the project-owned trees.
func (p Paths) ProjectsDir() string          { return p.at(varDir, "projects") }
func (p Paths) ProjectDir(ref string) string { return p.at(varDir, "projects", ref) }

// Backups. The repository filesystem holds one root-owned directory per
// subject; the control plane's data and spools sit on the projects filesystem.
func (p Paths) RepoRoot() string              { return p.at(varDir, "repo") }
func (p Paths) RepoDir(subject string) string { return p.at(varDir, "repo", subject) }
func (p Paths) CPProjectDir() string          { return p.at(varDir, "projects", ControlPlaneSubject) }
func (p Paths) CPRestoring() string           { return p.at(varDir, "cp", "restoring") }
func (p Paths) ToolsDir() string              { return p.at(varDir, "platform", "tools") }
func (p Paths) JobsDir() string               { return p.at(varDir, "platform", "jobs") }

// IndexFile is the replicator's index of subject's uploaded keys.
func (p Paths) IndexFile(subject string) string {
	return p.at(varDir, "platform", "replica", subject+".idx")
}

func (p Paths) OffsiteSealed() string  { return p.at(etcDir, "offsite.sealed") }
func (p Paths) OffsiteAddrs() string   { return p.at(etcDir, "offsite.addrs") }
func (p Paths) NftLock() string        { return p.at(etcDir, "nft.lock") }
func (p Paths) CPStanzaSealed() string { return p.at(etcDir, "cp-stanza.sealed") }
func (p Paths) EscrowAcked() string    { return p.at(etcDir, "escrow.acked") }
func (p Paths) OffsiteCheck() string   { return p.at(etcDir, "offsite.check") }
