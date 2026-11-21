//go:build linux

package agent

// syncfs(2), which the syscall package does not export on amd64
// (arch/x86/entry/syscalls/syscall_64.tbl).
const sysSyncfs = 306
