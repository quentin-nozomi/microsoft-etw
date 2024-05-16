package winapi

import "syscall"

const (
	ERROR_SUCCESS                = syscall.Errno(0)
	ERROR_INSUFFICIENT_BUFFER    = syscall.Errno(122)
	ERROR_ALREADY_EXISTS         = syscall.Errno(183)
	ERROR_CTX_CLOSE_PENDING      = syscall.Errno(7007)
	ERROR_EVT_INVALID_EVENT_DATA = syscall.Errno(15005)
)

const (
	ERROR_CODE_SUCCESS = uintptr(0)
)
