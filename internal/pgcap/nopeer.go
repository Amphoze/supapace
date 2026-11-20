//go:build nopeer

package pgcap

// A build with the tag nopeer serves a socket whatever its two addresses: a
// test binary that shows what else keeps a stranger out. It is never put in an
// image.
func init() { peerCheck = false }
