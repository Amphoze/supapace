package main

// System call numbers of the calls `sp-probe sys` makes, from the kernel's
// arch/x86/entry/syscalls/syscall_64.tbl (asm/unistd_64.h).
const (
	sysGetpid         = 39
	sysSyslog         = 103
	sysMount          = 165
	sysInitModule     = 175
	sysClockSettime   = 227
	sysKexecLoad      = 246
	sysAddKey         = 248
	sysRequestKey     = 249
	sysKeyctl         = 250
	sysPerfEventOpen  = 298
	sysOpenByHandleAt = 304
	sysBpf            = 321
	sysUserfaultfd    = 323
	sysIoUringSetup   = 425
)

// Referenced by sys.go, so a build for another architecture fails by this name.
const sysNumbersExistOnlyForLinuxAmd64AndArm64 = true
