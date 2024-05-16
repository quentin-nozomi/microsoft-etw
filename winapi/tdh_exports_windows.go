package winapi

import (
	"syscall"
)

var (
	tdh = syscall.NewLazyDLL("tdh.dll")

	tdhFormatProperty         = tdh.NewProc("TdhFormatProperty")
	tdhGetEventInformation    = tdh.NewProc("TdhGetEventInformation")
	tdhGetEventMapInformation = tdh.NewProc("TdhGetEventMapInformation")
	tdhGetProperty            = tdh.NewProc("TdhGetProperty")
	tdhGetPropertySize        = tdh.NewProc("TdhGetPropertySize")
)
