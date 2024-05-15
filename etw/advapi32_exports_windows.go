package etw

import (
	"syscall"
)

var (
	advapi = syscall.NewLazyDLL("advapi32.dll")

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace
	closeTrace = advapi.NewProc("CloseTrace")

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	controlTraceW = advapi.NewProc("ControlTraceW")

	// https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsecuritydescriptortostringsecuritydescriptorw
	convertSecurityDescriptorToStringSecurityDescriptorW = advapi.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")

	// https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsidtosidw
	convertStringSidToSidW = advapi.NewProc("ConvertStringSidToSidW")

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
	enableTraceEx2 = advapi.NewProc("EnableTraceEx2")

	// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccesscontrol
	eventAccessControl = advapi.NewProc("EventAccessControl")

	// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccessquery
	eventAccessQuery = advapi.NewProc("EventAccessQuery")

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
	openTraceW = advapi.NewProc("OpenTraceW")

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
	processTrace = advapi.NewProc("ProcessTrace")

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
	startTraceW = advapi.NewProc("StartTraceW")
)