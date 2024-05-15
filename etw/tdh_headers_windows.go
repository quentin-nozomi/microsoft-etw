package etw

import (
	"fmt"
	"strings"
	"unsafe"
)

type TdhContext struct {
	ParameterValue uint32
	ParameterType  TdhContextType
	ParameterSize  uint32
}

type TdhContextType int32

type PropertyDataDescriptor struct {
	PropertyName uint64
	ArrayIndex   uint32
	Reserved     uint32
}

type ProviderFieldInfoArray struct {
	NumberOfElements uint32
	FieldType        EventFieldType // This field is initially an enum so I guess it has the size of an int
	FieldInfoArray   [1]ProviderFieldInfo
}

type ProviderFieldInfo struct {
	NameOffset        uint32
	DescriptionOffset uint32
	Value             uint64
}

type EventFieldType int32

type ProviderEnumerationInfo struct {
	NumberOfProviders      uint32
	Reserved               uint32
	TraceProviderInfoArray [1]TraceProviderInfo
}

type TraceProviderInfo struct {
	ProviderGuid       GUID
	SchemaSource       uint32
	ProviderNameOffset uint32
}

type TraceEventInfo struct {
	ProviderGUID                GUID
	EventGUID                   GUID
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

func (t *TraceEventInfo) pointer() uintptr {
	return uintptr(unsafe.Pointer(t))
}

func (t *TraceEventInfo) pointerOffset(offset uintptr) uintptr {
	return t.pointer() + offset
}

func (t *TraceEventInfo) stringAt(offset uintptr) string {
	if offset > 0 {
		return UTF16AtOffsetToString(t.pointer(), offset)
	}
	return ""
}

func (t *TraceEventInfo) cleanStringAt(offset uintptr) string {
	if offset > 0 {
		return strings.Trim(t.stringAt(offset), " ")
	}
	return ""
}

// Seems to be always empty
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

// Seems to be always empty
func (t *TraceEventInfo) ActivityIDName() string {
	return t.stringAt(uintptr(t.ActivityIDNameOffset))
}

// Seems to be always empty
func (t *TraceEventInfo) RelatedActivityIDName() string {
	return t.stringAt(uintptr(t.RelatedActivityIDNameOffset))
}

func (t *TraceEventInfo) IsMof() bool {
	return t.DecodingSource == DecodingSourceWbem
}

func (t *TraceEventInfo) IsXML() bool {
	return t.DecodingSource == DecodingSourceXMLFile
}

func (t *TraceEventInfo) EventID() uint16 {
	if t.IsXML() {
		return t.EventDescriptor.Id
	} else if t.IsMof() {
		if c, ok := MofClassMapping[t.EventGUID.Data1]; ok {
			return c.BaseId + uint16(t.EventDescriptor.Opcode)
		}
	}
	// not meaningful, cannot be used to identify event
	return 0
}

func (t *TraceEventInfo) GetEventPropertyInfoAt(i uint32) *EventPropertyInfo {
	if i < t.PropertyCount {
		pEpi := uintptr(unsafe.Pointer(&t.EventPropertyInfoArray[0]))
		pEpi += uintptr(i) * unsafe.Sizeof(EventPropertyInfo{})
		// this line triggers checkptr
		// I guess that is because TraceInfo is variable size C
		// struct we had to hack with to make it compatible with Go
		return ((*EventPropertyInfo)(unsafe.Pointer(pEpi)))
	}
	panic(fmt.Errorf("index out of range"))
}

func (t *TraceEventInfo) PropertyNameOffset(i uint32) uintptr {
	return t.pointer() + uintptr(t.GetEventPropertyInfoAt(i).NameOffset)
}

type DecodingSource int32

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

type EventMapInfo struct {
	NameOffset    uint32
	Flag          MapFlags
	EntryCount    uint32
	Union         uint32 // Not sure about size of union depends on size of enum MAP_VALUETYPE
	MapEntryArray [1]EventMapEntry
}

func (e *EventMapInfo) GetEventMapEntryAt(i int) *EventMapEntry {
	if uint32(i) < e.EntryCount {
		pEmi := uintptr(unsafe.Pointer(&e.MapEntryArray[0]))
		pEmi += uintptr(i) * unsafe.Sizeof(EventMapEntry{})
		return ((*EventMapEntry)(unsafe.Pointer(pEmi)))
	}
	panic(fmt.Errorf("Index out of range"))
}

func (e *EventMapInfo) RemoveTrailingSpace() {
	for i := uint32(0); i < e.EntryCount; i++ {
		me := e.GetEventMapEntryAt(int(i))
		pStr := uintptr(unsafe.Pointer(e)) + uintptr(me.OutputOffset)
		byteLen := (Wcslen(((*uint16)(unsafe.Pointer(pStr)))) - 1) * 2
		*((*uint16)(unsafe.Pointer(pStr + uintptr(byteLen)))) = 0
	}
}

type MapFlags int32

type MapValueType int32

type EventMapEntry struct {
	OutputOffset uint32
	Union        uint32
}

type PropertyFlags int32

const (
	PropertyStruct      = PropertyFlags(0x1)
	PropertyParamLength = PropertyFlags(0x2)
	PropertyParamCount  = PropertyFlags(0x4)
)

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
	return i.InType()
}

func (i *EventPropertyInfo) OutType() uint16 {
	return i.TypeUnion.u2
}

func (i *EventPropertyInfo) NumOfStructMembers() uint16 {
	return i.OutType()
}

func (i *EventPropertyInfo) MapNameOffset() uint32 {
	return i.CustomSchemaOffset()
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
