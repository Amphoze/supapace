//go:build linux && amd64

package nsdial

// setns(2); the standard library's syscall package does not name it on amd64.
const sysSetns = 308
