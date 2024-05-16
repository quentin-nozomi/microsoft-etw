package winapi

import (
	"syscall"
	"unsafe"
)

func TdhGetEventInformation(pEvent *EventRecord,
	tdhContextCount uint32,
	pTdhContext *TdhContext,
	pBuffer *TraceEventInfo,
	pBufferSize *uint32) error {
	r1, _, _ := tdhGetEventInformation.Call(
		uintptr(unsafe.Pointer(pEvent)),
		uintptr(tdhContextCount),
		uintptr(unsafe.Pointer(pTdhContext)),
		uintptr(unsafe.Pointer(pBuffer)),
		uintptr(unsafe.Pointer(pBufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func TdhGetEventMapInformation(pEvent *EventRecord,
	pMapName *uint16,
	pBuffer *EventMapInfo,
	pBufferSize *uint32) error {
	r1, _, _ := tdhGetEventMapInformation.Call(
		uintptr(unsafe.Pointer(pEvent)),
		uintptr(unsafe.Pointer(pMapName)),
		uintptr(unsafe.Pointer(pBuffer)),
		uintptr(unsafe.Pointer(pBufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func TdhGetProperty(pEvent *EventRecord,
	tdhContextCount uint32,
	pTdhContext *TdhContext,
	propertyDataCount uint32,
	pPropertyData *PropertyDataDescriptor,
	bufferSize uint32,
	pBuffer *byte) error {
	r1, _, _ := tdhGetProperty.Call(
		uintptr(unsafe.Pointer(pEvent)),
		uintptr(tdhContextCount),
		uintptr(unsafe.Pointer(pTdhContext)),
		uintptr(propertyDataCount),
		uintptr(unsafe.Pointer(pPropertyData)),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(pBuffer)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func TdhGetPropertySize(pEvent *EventRecord,
	tdhContextCount uint32,
	pTdhContext *TdhContext,
	propertyDataCount uint32,
	pPropertyData *PropertyDataDescriptor,
	pPropertySize *uint32) error {
	r1, _, _ := tdhGetPropertySize.Call(
		uintptr(unsafe.Pointer(pEvent)),
		uintptr(tdhContextCount),
		uintptr(unsafe.Pointer(pTdhContext)),
		uintptr(propertyDataCount),
		uintptr(unsafe.Pointer(pPropertyData)),
		uintptr(unsafe.Pointer(pPropertySize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func TdhFormatProperty(
	eventInfo *TraceEventInfo,
	mapInfo *EventMapInfo,
	pointerSize uint32,
	propertyInType uint16,
	propertyOutType uint16,
	propertyLength uint16,
	userDataLength uint16,
	userData *byte,
	bufferSize *uint32,
	buffer *uint16,
	userDataConsumed *uint16) error {
	r1, _, _ := tdhFormatProperty.Call(
		uintptr(unsafe.Pointer(eventInfo)),
		uintptr(unsafe.Pointer(mapInfo)),
		uintptr(pointerSize),
		uintptr(propertyInType),
		uintptr(propertyOutType),
		uintptr(propertyLength),
		uintptr(userDataLength),
		uintptr(unsafe.Pointer(userData)),
		uintptr(unsafe.Pointer(bufferSize)),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(unsafe.Pointer(userDataConsumed)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}