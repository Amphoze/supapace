//go:build linux && (amd64 || arm64)

// The O_PATH value and the ioctl encodings below are those of amd64 and
// arm64; other architectures encode them differently.

package nodefs

import (
	"syscall"
	"unsafe"
)

// Linux constants the standard syscall package does not export.
const (
	// oPath is O_PATH from include/uapi/asm-generic/fcntl.h (amd64, arm64).
	oPath = 0x200000
	// atFdcwd is AT_FDCWD from include/uapi/linux/fcntl.h.
	atFdcwd = -100
	// atRemoveDir is AT_REMOVEDIR from include/uapi/linux/fcntl.h.
	atRemoveDir = 0x200

	// fsIocFsGetXattr and fsIocFsSetXattr are FS_IOC_FSGETXATTR =
	// _IOR('X', 31, struct fsxattr) and FS_IOC_FSSETXATTR =
	// _IOW('X', 32, struct fsxattr) from include/uapi/linux/fs.h; the size
	// field (0x1c) is sizeof(struct fsxattr).
	fsIocFsGetXattr = 0x801c581f
	fsIocFsSetXattr = 0x401c5820
	// fsXflagProjInherit is FS_XFLAG_PROJINHERIT from include/uapi/linux/fs.h:
	// entries created in the directory inherit its project id.
	fsXflagProjInherit = 0x00000200

	// xfsSuperMagic is XFS_SUPER_MAGIC from include/uapi/linux/magic.h.
	xfsSuperMagic = 0x58465342
)

// fsxattr mirrors struct fsxattr from include/uapi/linux/fs.h (28 bytes).
type fsxattr struct {
	Xflags     uint32
	Extsize    uint32
	Nextents   uint32
	Projid     uint32
	Cowextsize uint32
	Pad        [8]byte
}

func ioctlFsxattr(fd int, req uintptr, x *fsxattr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(x))); e != 0 {
		return e
	}
	return nil
}

// unlinkatDir is unlinkat(dirfd, name, AT_REMOVEDIR): removes an empty
// directory entry of dirfd without following a link.
func unlinkatDir(dirfd int, name string) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	if _, _, e := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), atRemoveDir); e != 0 {
		return e
	}
	return nil
}
