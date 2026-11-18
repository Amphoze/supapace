//go:build linux

package rmtree

import "syscall"

// fstatat(2) (newfstatat in the kernel's table) and renameat2(2) on arm64.
const (
	sysFstatat   = syscall.SYS_FSTATAT
	sysRenameat2 = syscall.SYS_RENAMEAT2
)
