package winapi

import (
	"syscall"
)

var (
	tdh = syscall.NewLazyDLL("tdh.dll")

	// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty
	tdhFormatProperty = tdh.NewProc("TdhFormatProperty")
	
	// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation
	tdhGetEventInformation = tdh.NewProc("TdhGetEventInformation")

	// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventmapinformation
	tdhGetEventMapInformation = tdh.NewProc("TdhGetEventMapInformation")

	// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetproperty
	tdhGetProperty = tdh.NewProc("TdhGetProperty")

	// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetpropertysize
	tdhGetPropertySize = tdh.NewProc("TdhGetPropertySize")
)
