package winapi

import (
	"syscall"
	"unsafe"
)

func Wcslen(uintf16 *uint16) (len uint64) {
	for it := uintptr(unsafe.Pointer(uintf16)); ; it += 2 {
		wc := (*uint16)(unsafe.Pointer(it))
		if *wc == 0 {
			return
		}
		len++
	}
}

func UTF16AtOffsetToString(pstruct uintptr, offset uintptr) string {
	out := make([]uint16, 0, 64)
	wideChar := (*uint16)(unsafe.Pointer(pstruct + offset))
	for i := uintptr(2); *wideChar != 0; i += 2 {
		out = append(out, *wideChar)
		wideChar = (*uint16)(unsafe.Pointer(pstruct + offset + i))
	}
	return syscall.UTF16ToString(out)
}
