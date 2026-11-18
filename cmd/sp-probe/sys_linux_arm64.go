package main

// System call numbers of the calls `sp-probe sys` makes, from the kernel's
// include/uapi/asm-generic/unistd.h, which arm64 uses.
const (
	sysMount          = 40
	sysKexecLoad      = 104
	sysInitModule     = 105
	sysClockSettime   = 112
	sysSyslog         = 116
	sysGetpid         = 172
	sysAddKey         = 217
	sysRequestKey     = 218
	sysKeyctl         = 219
	sysPerfEventOpen  = 241
	sysOpenByHandleAt = 265
	sysBpf            = 280
	sysUserfaultfd    = 282
	sysIoUringSetup   = 425
)

// Referenced by sys.go, so a build for another architecture fails by this name.
const sysNumbersExistOnlyForLinuxAmd64AndArm64 = true
