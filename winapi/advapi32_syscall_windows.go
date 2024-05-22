package winapi

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

func StartTrace(traceHandle *syscall.Handle, instanceName *uint16, properties *EventTraceProperties) error {
	errorCode, _, _ := startTraceW.Call(
		uintptr(unsafe.Pointer(traceHandle)),
		uintptr(unsafe.Pointer(instanceName)),
		uintptr(unsafe.Pointer(properties)))
	if errorCode == windows.NO_ERROR {
		return nil
	}
	return syscall.Errno(errorCode)
}

func EnableTraceEx2(traceHandle syscall.Handle,
	providerId *syscall.GUID,
	controlCode uint32,
	level uint8,
	matchAnyKeyword uint64,
	matchAllKeyword uint64,
	timeout uint32,
	enableParameters *EnableTraceParameters,
) error {
	errorCode, _, _ := enableTraceEx2.Call(
		uintptr(traceHandle),
		uintptr(unsafe.Pointer(providerId)),
		uintptr(controlCode),
		uintptr(level),
		uintptr(matchAnyKeyword),
		uintptr(matchAllKeyword),
		uintptr(timeout),
		uintptr(unsafe.Pointer(enableParameters)))
	if errorCode == windows.NO_ERROR {
		return nil
	}
	return syscall.Errno(errorCode)
}

// Blocking
func ProcessTrace(
	handleArray *syscall.Handle,
	handleCount uint32,
	startTime *syscall.Filetime,
	endTime *syscall.Filetime,
) error {
	errorCode, _, _ := processTrace.Call(
		uintptr(unsafe.Pointer(handleArray)),
		uintptr(handleCount),
		uintptr(unsafe.Pointer(startTime)),
		uintptr(unsafe.Pointer(endTime)))
	if errorCode == windows.NO_ERROR {
		return nil
	}
	return syscall.Errno(errorCode)
}

func OpenTrace(logfile *EventTraceLogfile) (syscall.Handle, error) {
	handle, _, err := openTraceW.Call(uintptr(unsafe.Pointer(logfile)))
	if err.(syscall.Errno) == windows.ERROR_SUCCESS {
		return syscall.Handle(handle), nil
	}
	return syscall.Handle(handle), err
}

func ControlTrace(traceHandle syscall.Handle, instanceName *uint16, properties *EventTraceProperties, controlCode uint32) error {
	errorCode, _, _ := controlTraceW.Call(
		uintptr(traceHandle),
		uintptr(unsafe.Pointer(instanceName)),
		uintptr(unsafe.Pointer(properties)),
		uintptr(controlCode))
	if errorCode == windows.NO_ERROR {
		return nil
	}
	return syscall.Errno(errorCode)
}

func CloseTrace(traceHandle syscall.Handle) error {
	errorCode, _, _ := closeTrace.Call(uintptr(traceHandle))
	if errorCode == windows.NO_ERROR {
		return nil
	}
	return syscall.Errno(errorCode)
}
