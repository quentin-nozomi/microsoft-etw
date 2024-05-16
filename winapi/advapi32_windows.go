package winapi

import (
	"syscall"
	"unsafe"
)

func StartTrace(
	traceHandle *syscall.Handle,
	instanceName *uint16,
	properties *EventTraceProperties,
) error {
	r1, _, _ := startTraceW.Call(
		uintptr(unsafe.Pointer(traceHandle)),
		uintptr(unsafe.Pointer(instanceName)),
		uintptr(unsafe.Pointer(properties)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func EnableTraceEx2(traceHandle syscall.Handle,
	providerId *GUID,
	controlCode uint32,
	level uint8,
	matchAnyKeyword uint64,
	matchAllKeyword uint64,
	timeout uint32,
	enableParameters *EnableTraceParameters,
) error {
	r1, _, _ := enableTraceEx2.Call(
		uintptr(traceHandle),
		uintptr(unsafe.Pointer(providerId)),
		uintptr(controlCode),
		uintptr(level),
		uintptr(matchAnyKeyword),
		uintptr(matchAllKeyword),
		uintptr(timeout),
		uintptr(unsafe.Pointer(enableParameters)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func ProcessTrace(handleArray *syscall.Handle,
	handleCount uint32,
	startTime *FileTime,
	endTime *FileTime) error {
	r1, _, _ := processTrace.Call(
		uintptr(unsafe.Pointer(handleArray)),
		uintptr(handleCount),
		uintptr(unsafe.Pointer(startTime)),
		uintptr(unsafe.Pointer(endTime)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func OpenTrace(logfile *EventTraceLogfile) (syscall.Handle, error) {
	r1, _, err := openTraceW.Call(
		uintptr(unsafe.Pointer(logfile)))
	// This call stores error in lastError so we can keep it like this
	if err.(syscall.Errno) == 0 {
		return syscall.Handle(r1), nil
	}
	return syscall.Handle(r1), err
}

func ControlTrace(traceHandle syscall.Handle,
	instanceName *uint16,
	properties *EventTraceProperties,
	controlCode uint32) error {
	r1, _, _ := controlTraceW.Call(
		uintptr(traceHandle),
		uintptr(unsafe.Pointer(instanceName)),
		uintptr(unsafe.Pointer(properties)),
		uintptr(controlCode))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func CloseTrace(traceHandle syscall.Handle) error {
	r1, _, _ := closeTrace.Call(
		uintptr(traceHandle))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func EventAccessQuery(
	guid *GUID,
	buffer *SecurityDescriptor,
	bufferSize *uint32) error {
	r1, _, _ := eventAccessQuery.Call(
		uintptr(unsafe.Pointer(guid)),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(unsafe.Pointer(bufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func ConvertSecurityDescriptorToStringSecurityDescriptorW(
	securityDescriptor *SecurityDescriptor,
	requestedStringSDRevision uint32,
	securityInformation SecurityInformation,
) (string, error) {
	var stringSecurityDescriptor uint16
	var stringSecurityDescriptorLen uint32

	pStringSecurityDescriptor := &stringSecurityDescriptor

	_, _, err := convertSecurityDescriptorToStringSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(securityDescriptor)),
		uintptr(requestedStringSDRevision),
		uintptr(securityInformation),
		uintptr(unsafe.Pointer(&pStringSecurityDescriptor)),
		uintptr(unsafe.Pointer(&stringSecurityDescriptorLen)))
	if err == ERROR_SUCCESS {
		s := UTF16PtrToString(pStringSecurityDescriptor)
		if _, err := syscall.LocalFree(syscall.Handle(unsafe.Pointer(pStringSecurityDescriptor))); err != nil {
			return "", err
		}
		return s, nil
	}
	return "", err
}
