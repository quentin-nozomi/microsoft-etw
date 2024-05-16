package winapi

import (
	"fmt"
	"syscall"
	"testing"
	"unsafe"
)

func TestUtils(t *testing.T) {
	s := "this is a utf16 string"
	sutf16, err := syscall.UTF16PtrFromString(s)
	fmt.Println(err)

	fmt.Println(UTF16PtrToString(sutf16) == s)
	fmt.Println(Wcslen(sutf16) == uint64(len(s)))

	// we have to double the length because we are in utf16
	butf16 := CopyData(uintptr(unsafe.Pointer(sutf16)), len(s)*2)

	fmt.Println(len(butf16) == len(s)*2)
	fmt.Println(UTF16BytesToString(butf16) == s)

	uuid, err := UUID()
	fmt.Println(err)
	t.Log(uuid)
}
