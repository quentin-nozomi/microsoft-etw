//go:build windows

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
	EVENT_TRACE_FLAG_PROCESS    = 0x00000001
	EVENT_TRACE_FLAG_THREAD     = 0x00000002
	EVENT_TRACE_FLAG_IMAGE_LOAD = 0x00000004

	EVENT_TRACE_FLAG_DISK_IO = 0x00000100

	EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS = 0x00001000
	EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS = 0x00002000

	EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00010000

	EVENT_TRACE_FLAG_REGISTRY = 0x00020000
	EVENT_TRACE_FLAG_DBGPRINT = 0x00040000

	EVENT_TRACE_FLAG_PROCESS_COUNTERS = 0x00000008
	EVENT_TRACE_FLAG_DPC              = 0x00000020
	EVENT_TRACE_FLAG_INTERRUPT        = 0x00000040
	EVENT_TRACE_FLAG_SYSTEMCALL       = 0x00000080

	EVENT_TRACE_FLAG_DISK_IO_INIT = 0x00000400
	EVENT_TRACE_FLAG_ALPC         = 0x00100000
	EVENT_TRACE_FLAG_SPLIT_IO     = 0x00200000

	EVENT_TRACE_FLAG_DRIVER       = 0x00800000
	EVENT_TRACE_FLAG_PROFILE      = 0x01000000
	EVENT_TRACE_FLAG_FILE_IO      = 0x02000000
	EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000

	EVENT_TRACE_FLAG_VIRTUAL_ALLOC = 0x00004000

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

const (
	EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID = 0x0001
)

type WnodeHeader struct {
	BufferSize    uint32
	ProviderId    uint32
	Union1        uint64
	Union2        int64
	Guid          GUID
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
			Guid:          GUID{},
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

type EnableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceId         GUID
	EnableFilterDesc *EventFilterDescriptor
	FilterDescCount  uint32
}

const (
	EVENT_FILTER_TYPE_EVENT_ID = 0x80000200 // Event IDs.
)

type EventFilterEventID struct {
	FilterIn uint8
	Reserved uint8
	Count    uint16

	Events [1]uint16 // it is easier to implement in Go with a fixed array size
}

// built-in max only available in Go 1.21+
func getMax(a, b int) int {
	if a < b {
		return b
	}
	return a
}

func AllocEventFilterEventID(filter []uint16) (f *EventFilterEventID) {
	count := uint16(len(filter))
	size := getMax(4+len(filter)*2, int(unsafe.Sizeof(EventFilterEventID{})))
	buf := make([]byte, size)

	// buf[0] should always be valid
	f = (*EventFilterEventID)(unsafe.Pointer(&buf[0]))
	eid := unsafe.Pointer(&f.Events[0])
	for i := 0; i < len(filter); i++ {
		*((*uint16)(eid)) = filter[i]
		eid = unsafe.Add(eid, 2)
	}
	f.Count = count
	return
}

func (e *EventFilterEventID) Size() int {
	return 4 + int(e.Count)*2
}

type EventFilterDescriptor struct {
	Ptr  uint64
	Size uint32
	Type uint32
}

type FileTime struct {
	dwLowDateTime  uint32
	dwHighDateTime uint32
}

type EventTraceLogfile struct {
	LogFileName   *uint16
	LoggerName    *uint16
	CurrentTime   int64
	BuffersRead   uint32
	Union1        uint32
	CurrentEvent  EventTrace
	LogfileHeader TraceLogfileHeader

	BufferCallback uintptr //BufferCallback *EventTraceBufferCallback
	BufferSize     uint32
	Filled         uint32
	EventsLost     uint32
	Callback       uintptr
	IsKernelTrace  uint32
	Context        uintptr
}

func (e *EventTraceLogfile) SetProcessTraceMode(ptm uint32) {
	e.Union1 = ptm
}

type EventCallback func(*EventTrace)
type EventRecordCallback func(*EventRecord) uintptr
type EventTraceBufferCallback func(*EventTraceLogfile) uint32

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

func (e *EventRecord) RelatedActivityID() string {
	for i := uint16(0); i < e.ExtendedDataCount; i++ {
		item := e.ExtendedDataItem(i)
		if item.ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID {
			g := (*GUID)(unsafe.Pointer(item.DataPtr))
			return g.String()
		}
	}
	return nullGUIDStr
}

func (e *EventRecord) GetEventInformation() (tei *TraceEventInfo, err error) {
	bufferSize := uint32(0)
	if err = TdhGetEventInformation(e, 0, nil, nil, &bufferSize); err == syscall.ERROR_INSUFFICIENT_BUFFER {
		// don't know how this would behave
		buff := make([]byte, bufferSize)
		tei = (*TraceEventInfo)(unsafe.Pointer(&buff[0]))
		err = TdhGetEventInformation(e, 0, nil, tei, &bufferSize)
	}
	return
}

func (e *EventRecord) GetMapInfo(pMapName *uint16, decodingSource uint32) (pMapInfo *EventMapInfo, err error) {
	mapSize := uint32(64)
	buff := make([]byte, mapSize)
	pMapInfo = (*EventMapInfo)(unsafe.Pointer(&buff[0]))
	err = TdhGetEventMapInformation(e, pMapName, pMapInfo, &mapSize)

	if err == syscall.ERROR_INSUFFICIENT_BUFFER {
		buff := make([]byte, mapSize)
		pMapInfo = (*EventMapInfo)(unsafe.Pointer(&buff[0]))
		err = TdhGetEventMapInformation(e, pMapName, pMapInfo, &mapSize)
	}

	if err == nil {
		if DecodingSource(decodingSource) == DecodingSourceXMLFile {
			pMapInfo.RemoveTrailingSpace()
		}
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

type EventHeaderExtendedDataItem struct {
	Reserved1      uint16
	ExtType        uint16
	InternalStruct uint16
	DataSize       uint16
	DataPtr        uintptr
}

type EventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      GUID
	EventDescriptor EventDescriptor
	Time            int64
	ActivityId      GUID
}

func (e *EventHeader) UTCTimeStamp() time.Time {
	nano := int64(10000000)
	sec := int64(float64(e.TimeStamp)/float64(nano) - 11644473600.0)
	nsec := ((e.TimeStamp - 11644473600*nano) - sec*nano) * 100
	return time.Unix(sec, nsec).UTC()
}

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
	ParentGuid       GUID
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

const (
	SDDL_REVISION_1 = 1
)

type SecurityDescriptorControl uint32

type SecurityInformation uint32

const (
	DACL_SECURITY_INFORMATION = SecurityInformation(0x00000004)
)

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
	Revision byte
	Sbz1     byte
	Control  SecurityDescriptorControl
	Owner    *SID
	Group    *SID
	Sacl     *ACL
	Dacl     *ACL
}

type EventSecurityOperation uint32

const (
	EVENT_SECURITY_SET_DACL = EventSecurityOperation(0)
)
