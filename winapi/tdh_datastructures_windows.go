package winapi

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-tdh_context
type TdhContext struct {
	ParameterValue uint32
	ParameterType  TdhContextType
	ParameterSize  uint32
}

type TdhContextType int32

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-property_data_descriptor
type PropertyDataDescriptor struct {
	PropertyName uint64 // pointer
	ArrayIndex   uint32
	Reserved     uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-provider_field_infoarray
type ProviderFieldInfoArray struct {
	NumberOfElements uint32
	FieldType        EventFieldType
	FieldInfoArray   [1]ProviderFieldInfo
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-provider_field_info
type ProviderFieldInfo struct {
	NameOffset        uint32
	DescriptionOffset uint32
	Value             uint64
}

type EventFieldType int32

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-provider_enumeration_info
type ProviderEnumerationInfo struct {
	NumberOfProviders      uint32
	Reserved               uint32
	TraceProviderInfoArray [1]TraceProviderInfo
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_provider_info
type TraceProviderInfo struct {
	ProviderGuid       syscall.GUID
	SchemaSource       uint32
	ProviderNameOffset uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info
type TraceEventInfo struct {
	ProviderGUID                syscall.GUID
	EventGUID                   syscall.GUID
	EventDescriptor             EventDescriptor
	DecodingSource              DecodingSource
	ProviderNameOffset          uint32
	LevelNameOffset             uint32
	ChannelNameOffset           uint32
	KeywordsNameOffset          uint32
	TaskNameOffset              uint32
	OpcodeNameOffset            uint32
	EventMessageOffset          uint32
	ProviderMessageOffset       uint32
	BinaryXMLOffset             uint32
	BinaryXMLSize               uint32
	ActivityIDNameOffset        uint32
	RelatedActivityIDNameOffset uint32
	PropertyCount               uint32
	TopLevelPropertyCount       uint32
	Flags                       TemplateFlags
	EventPropertyInfoArray      [1]EventPropertyInfo
}

func (t *TraceEventInfo) stringAt(offset uintptr) string {
	if offset > 0 {
		return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(t)) + offset)))
	}
	return ""
}

func (t *TraceEventInfo) cleanStringAt(offset uintptr) string {
	if offset > 0 {
		return strings.Trim(t.stringAt(offset), " ")
	}
	return ""
}

func (t *TraceEventInfo) EventMessage() string {
	return t.cleanStringAt(uintptr(t.EventMessageOffset))
}

func (t *TraceEventInfo) ProviderName() string {
	return t.cleanStringAt(uintptr(t.ProviderNameOffset))
}

func (t *TraceEventInfo) TaskName() string {
	return t.cleanStringAt(uintptr(t.TaskNameOffset))
}

func (t *TraceEventInfo) LevelName() string {
	return t.cleanStringAt(uintptr(t.LevelNameOffset))
}

func (t *TraceEventInfo) OpcodeName() string {
	return t.cleanStringAt(uintptr(t.OpcodeNameOffset))
}

func (t *TraceEventInfo) KeywordName() string {
	return t.cleanStringAt(uintptr(t.KeywordsNameOffset))
}

func (t *TraceEventInfo) ChannelName() string {
	return t.cleanStringAt(uintptr(t.ChannelNameOffset))
}

func (t *TraceEventInfo) ActivityIDName() string {
	return t.stringAt(uintptr(t.ActivityIDNameOffset))
}

func (t *TraceEventInfo) RelatedActivityIDName() string {
	return t.stringAt(uintptr(t.RelatedActivityIDNameOffset))
}

func (t *TraceEventInfo) IsManagedObjectFormat() bool {
	return t.DecodingSource == DecodingSourceWbem
}

func (t *TraceEventInfo) IsXML() bool {
	return t.DecodingSource == DecodingSourceXMLFile
}

func (t *TraceEventInfo) EventID() uint16 {
	return t.EventDescriptor.Id
}

func (t *TraceEventInfo) GetEventPropertyInfoAt(index uint32) *EventPropertyInfo {
	if index < t.PropertyCount {
		offset := uintptr(index) * unsafe.Sizeof(EventPropertyInfo{})
		return (*EventPropertyInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(&t.EventPropertyInfoArray[0])) + offset))
	}
	panic(fmt.Errorf("index out of range"))
}

func (t *TraceEventInfo) PropertyNameOffset(index uint32) uintptr {
	return uintptr(unsafe.Pointer(t)) + uintptr(t.GetEventPropertyInfoAt(index).NameOffset)
}

type DecodingSource int32 // https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-decoding_source

const (
	DecodingSourceXMLFile = DecodingSource(0)
	DecodingSourceWbem    = DecodingSource(1)
	DecodingSourceWPP     = DecodingSource(2)
)

type TemplateFlags int32

const (
	TEMPLATE_EVENT_DATA = TemplateFlags(1)
	TEMPLATE_USER_DATA  = TemplateFlags(2)
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_map_info
type EventMapInfo struct {
	NameOffset    uint32
	Flag          MapFlags
	EntryCount    uint32
	Union         uint32
	MapEntryArray [1]EventMapEntry
}

func (e *EventMapInfo) GetEventMapEntryAt(i int) *EventMapEntry {
	if uint32(i) < e.EntryCount {
		return (*EventMapEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(&e.MapEntryArray[0])) + uintptr(i)*unsafe.Sizeof(EventMapEntry{})))
	}
	panic(fmt.Errorf("index out of range"))
}

type MapFlags int32

type MapValueType int32

type EventMapEntry struct {
	OutputOffset uint32
	Union        uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-property_flags
type PropertyFlags int32

const (
	PropertyStruct      = PropertyFlags(0x1)
	PropertyParamLength = PropertyFlags(0x2)
	PropertyParamCount  = PropertyFlags(0x4)
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_property_info
type EventPropertyInfo struct {
	Flags      PropertyFlags
	NameOffset uint32
	TypeUnion  struct {
		u1 uint16
		u2 uint16
		u3 uint32
	}
	CountUnion  uint16
	LengthUnion uint16
	ResTagUnion uint32
}

func (i *EventPropertyInfo) InType() uint16 {
	return i.TypeUnion.u1
}
func (i *EventPropertyInfo) StructStartIndex() uint16 {
	return i.TypeUnion.u1
}

func (i *EventPropertyInfo) OutType() uint16 {
	return i.TypeUnion.u2
}

func (i *EventPropertyInfo) NumOfStructMembers() uint16 {
	return i.TypeUnion.u2
}

func (i *EventPropertyInfo) MapNameOffset() uint32 {
	return i.TypeUnion.u3
}

func (i *EventPropertyInfo) CustomSchemaOffset() uint32 {
	return i.TypeUnion.u3
}

func (i *EventPropertyInfo) Count() uint16 {
	return i.CountUnion
}

func (i *EventPropertyInfo) CountPropertyIndex() uint16 {
	return i.CountUnion
}

func (i *EventPropertyInfo) LengthPropertyIndex() uint16 {
	return i.LengthUnion
}

func (i *EventPropertyInfo) Length() uint16 {
	return i.LengthUnion
}

type TdhInType uint32

// winmeta.xml
// https://github.com/microsoft/ETW2JSON/blob/6721e0438733b316d316d36c488166853a05f836/Deserializer/Tdh.cs
const (
	TdhInTypeNull = TdhInType(iota)
	TdhInTypeUnicodestring
	TdhInTypeAnsistring
	TdhInTypeInt8
	TdhInTypeUint8
	TdhInTypeInt16
	TdhInTypeUint16
	TdhInTypeInt32
	TdhInTypeUint32
	TdhInTypeInt64
	TdhInTypeUint64
	TdhInTypeFloat
	TdhInTypeDouble
	TdhInTypeBoolean
	TdhInTypeBinary
	TdhInTypeGUID
	TdhInTypePointer
	TdhInTypeFiletime
	TdhInTypeSystemtime
	TdhInTypeSid
	TdhInTypeHexint32
	TdhInTypeHexint64
)

const (
	TdhInTypeCountedstring = TdhInType(iota + 300)
	TdhInTypeCountedansistring
	TdhInTypeReversedcountedstring
	TdhInTypeReversedcountedansistring
	TdhInTypeNonnullterminatedstring
	TdhInTypeNonnullterminatedansistring
	TdhInTypeUnicodechar
	TdhInTypeAnsichar
	TdhInTypeSizet
	TdhInTypeHexdump
	TdhInTypeWbemsid
)

type TdhOutType uint32

const (
	TdhOutTypeNull = TdhOutType(iota)
	TdhOutTypeString
	TdhOutTypeDatetime
	TdhOutTypeByte
	TdhOutTypeUnsignedbyte
	TdhOutTypeShort
	TdhOutTypeUnsignedshort
	TdhOutTypeInt
	TdhOutTypeUnsignedint
	TdhOutTypeLong
	TdhOutTypeUnsignedlong
	TdhOutTypeFloat
	TdhOutTypeDouble
	TdhOutTypeBoolean
	TdhOutTypeGUID
	TdhOutTypeHexbinary
	TdhOutTypeHexint8
	TdhOutTypeHexint16
	TdhOutTypeHexint32
	TdhOutTypeHexint64
	TdhOutTypePid
	TdhOutTypeTid
	TdhOutTypePort
	TdhOutTypeIpv4
	TdhOutTypeIpv6
	TdhOutTypeSocketaddress
	TdhOutTypeCimdatetime
	TdhOutTypeEtwtime
	TdhOutTypeXML
	TdhOutTypeErrorcode
	TdhOutTypeWin32error
	TdhOutTypeNtstatus
	TdhOutTypeHresult
	TdhOutTypeCultureInsensitiveDatetime
	TdhOutTypeJSON
)

const (
	TdhOutTypeREDUCEDSTRING = TdhOutType(iota + 300)
	TdhOutTypeNOPRINT
)
