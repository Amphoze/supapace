//go:build linux && arm64

package nsdial

import "syscall"

const sysSetns = syscall.SYS_SETNS
