//go:build linux

package rmtree

import "syscall"

// System call numbers the syscall package does not export on amd64
// (arch/x86/entry/syscalls/syscall_64.tbl).
const (
	sysFstatat   = syscall.SYS_NEWFSTATAT
	sysRenameat2 = 316
)
