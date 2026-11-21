//go:build linux

package agent

import "syscall"

// syncfs(2) on arm64.
const sysSyncfs = syscall.SYS_SYNCFS
