package winapi

import (
	"syscall"
	"time"
	"unsafe"
)

const (
	WNODE_FLAG_ALL_DATA = 0x00000001
)

const (
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	EVENT_TRACE_REAL_TIME_MODE = 0x00000100

	EVENT_TRACE_CONTROL_STOP = 1
)

const (
	EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
)

const (
	PROCESS_TRACE_MODE_REAL_TIME    = 0x00000100
	PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
)

const (
	EVENT_HEADER_FLAG_32_BIT_HEADER = 0x0020
)

type WnodeHeader struct {
	BufferSize    uint32
	ProviderId    uint32
	Union1        uint64
	Union2        int64
	Guid          syscall.GUID
	ClientContext uint32
	Flags         uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
type EventTraceProperties struct {
	Wnode               WnodeHeader
	BufferSize          uint32 // in KB
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      syscall.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties#members
// https://learn.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings
func NewEventTracingSessionProperties(logSessionName string) *EventTraceProperties {
	// Go string UTF-8, will be converted to null terminated UTF-16 for Windows
	eventTracePropertiesBufferSize := ((len(logSessionName) + 1) * 2) + int(unsafe.Sizeof(EventTraceProperties{}))

	eventTraceProperties := EventTraceProperties{
		// https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header
		// https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header#members
		Wnode: WnodeHeader{
			BufferSize:    uint32(eventTracePropertiesBufferSize),
			Guid:          syscall.GUID{},
			ClientContext: 1,
			Flags:         WNODE_FLAG_ALL_DATA,
		},
		BufferSize:        64, // 64 KB
		LogFileMode:       EVENT_TRACE_REAL_TIME_MODE,
		LogFileNameOffset: 0,
		LoggerNameOffset:  uint32(unsafe.Sizeof(EventTraceProperties{})),
	}

	return &eventTraceProperties
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
type EnableTraceParameters struct {
	Version        uint32
	EnableProperty uint32
	ControlFlags   uint32
	SourceId       syscall.GUID

	EnableFilterDesc *EventFilterDescriptor
	FilterDescCount  uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_id
type EventFilterEventID struct {
	FilterIn uint8
	Reserved uint8
	Count    uint16

	Events [1]uint16
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
type EventFilterDescriptor struct {
	Ptr  uint64
	Size uint32
	Type uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
type EventTraceLogfile struct {
	LogFileName   *uint16
	LoggerName    *uint16
	CurrentTime   int64
	BuffersRead   uint32
	Union1        uint32 // (LogFileMode, ProcessTraceMode)
	CurrentEvent  EventTrace
	LogfileHeader TraceLogfileHeader

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_trace_buffer_callbackw
	BufferCallback uintptr
	BufferSize     uint32
	Filled         uint32
	EventsLost     uint32
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_callback
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_record_callback
	Callback      uintptr
	IsKernelTrace uint32
	Context       uintptr
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
type EventRecord struct {
	EventHeader       EventHeader
	BufferContext     BufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      *EventHeaderExtendedDataItem
	UserData          uintptr
	UserContext       uintptr
}

func (e *EventRecord) ExtendedDataItem(i uint16) *EventHeaderExtendedDataItem {
	if i < e.ExtendedDataCount {
		return (*EventHeaderExtendedDataItem)(
			unsafe.Pointer(uintptr(unsafe.Pointer(e.ExtendedData)) + (uintptr(i) * unsafe.Sizeof(EventHeaderExtendedDataItem{}))),
		)
	}
	panic("out of bound extended data item")
}

const traceEventInfoDefaultBufferSize = uint32(8192)

func buildTraceEventInfo(eventRecord *EventRecord, bufferSize uint32) (*TraceEventInfo, uint32, error) {
	var traceEventInfo *TraceEventInfo
	defaultBuffer := make([]byte, bufferSize)
	traceEventInfo = (*TraceEventInfo)(unsafe.Pointer(&defaultBuffer[0]))
	err := TdhGetEventInformation(eventRecord, 0, nil, traceEventInfo, &bufferSize) // returns proper bufferSize if insufficient
	return traceEventInfo, bufferSize, err
}

func (e *EventRecord) GetEventInformation() (*TraceEventInfo, error) {
	traceEventInfo, outBufferSize, err := buildTraceEventInfo(e, traceEventInfoDefaultBufferSize)

	if err == syscall.ERROR_INSUFFICIENT_BUFFER {
		traceEventInfo, outBufferSize, err = buildTraceEventInfo(e, outBufferSize)
	}

	return traceEventInfo, err
}

func (e *EventRecord) GetMapInfo(pMapName *uint16, decodingSource uint32) (pMapInfo *EventMapInfo, err error) {
	mapSize := uint32(64)
	buffer := make([]byte, mapSize)
	pMapInfo = (*EventMapInfo)(unsafe.Pointer(&buffer[0]))
	err = TdhGetEventMapInformation(e, pMapName, pMapInfo, &mapSize)

	if err == syscall.ERROR_INSUFFICIENT_BUFFER {
		buffer = make([]byte, mapSize)
		pMapInfo = (*EventMapInfo)(unsafe.Pointer(&buffer[0]))
		err = TdhGetEventMapInformation(e, pMapName, pMapInfo, &mapSize)
	}

	if err == syscall.ERROR_NOT_FOUND {
		err = nil
	}
	return
}

func (e *EventRecord) PointerSize() uint32 {
	if e.EventHeader.Flags&EVENT_HEADER_FLAG_32_BIT_HEADER == EVENT_HEADER_FLAG_32_BIT_HEADER {
		return 4
	}
	return 8
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
type EventHeaderExtendedDataItem struct {
	Reserved1      uint16
	ExtType        uint16
	InternalStruct uint16
	DataSize       uint16
	DataPtr        uintptr
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
type EventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      syscall.GUID
	EventDescriptor EventDescriptor
	Time            int64
	ActivityId      syscall.GUID
}

func ConvertInt64Timestamp(timestamp int64) time.Time {
	lower := uint32(timestamp)
	upper := uint32(timestamp >> 32)
	filetime := syscall.Filetime{
		LowDateTime:  lower,
		HighDateTime: upper,
	}
	return time.Unix(0, filetime.Nanoseconds()).UTC()
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor
type EventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type EventTrace struct {
	Header           EventTraceHeader
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       syscall.GUID
	MofData          uintptr
	MofLength        uint32
	UnionCtx         uint32
}

type BufferContext struct {
	Union    uint16
	LoggerId uint16
}

type EventTraceHeader struct {
	Size      uint16
	Union1    uint16
	Union2    uint32
	ThreadId  uint32
	ProcessId uint32
	TimeStamp int64
	Union3    [16]byte
	Union4    uint64
}

type TraceLogfileHeader struct {
	BufferSize         uint32
	VersionUnion       uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	Union1             [16]byte
	LoggerName         *uint16
	LogFileName        *uint16
	TimeZone           TimeZoneInformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

type TimeZoneInformation struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate SystemTime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate SystemTime
	DaylighBias  int32
}

type SystemTime struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

type SidIdentifierAuthority struct {
	Value [6]uint8
}

type SID struct {
	Revision            uint8
	SubAuthorityCount   uint8
	IdentifierAuthority SidIdentifierAuthority
	SubAuthority        [1]uint32
}

type ACL struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

type SecurityDescriptor struct {
	Revision                  byte
	Sbz1                      byte
	SecurityDescriptorControl uint32
	Owner                     *SID
	Group                     *SID
	Sacl                      *ACL
	Dacl                      *ACL
}
