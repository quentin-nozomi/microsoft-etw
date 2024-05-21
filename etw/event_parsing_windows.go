package etw

import (
	"fmt"
	"math"
	"os"
	"syscall"
	"unsafe"

	"github.com/quentin-nozomi/microsoft-etw/winapi"
	"github.com/quentin-nozomi/microsoft-etw/winguid"
)

// https://learn.microsoft.com/en-us/windows/win32/etw/retrieving-event-data-using-tdh

const (
	StructurePropertyName = "Structures"
)

var (
	hostname, _ = os.Hostname()

	ErrPropertyParsing = fmt.Errorf("error parsing property")
	ErrUnknownProperty = fmt.Errorf("unknown property")
)

type Property struct {
	eventRecordParser *EventRecordParser
	eventPropertyInfo *winapi.EventPropertyInfo

	name   string
	value  string
	length uint32

	pValue         uintptr
	userDataLength uint16
}

func maxu32(a, b uint32) uint32 {
	if a < b {
		return b
	}
	return a
}

func (p *Property) Parseable() bool {
	return p.eventRecordParser != nil && p.eventPropertyInfo != nil && p.pValue > 0
}

func (p *Property) Value() (string, error) {
	var err error

	if p.value == "" && p.Parseable() {
		p.value, err = p.parse()
	}

	return p.value, err
}

func (p *Property) parse() (value string, err error) {
	var mapInfo *winapi.EventMapInfo
	var udc uint16
	var buff []uint16

	formattedDataSize := maxu32(16, p.length)

	// Get the name/value mapping if the property specifies a value map.
	if p.eventPropertyInfo.MapNameOffset() > 0 {
		pMapName := (*uint16)(unsafe.Pointer(p.eventRecordParser.TraceEventInfo.PointerOffset(uintptr(p.eventPropertyInfo.MapNameOffset()))))
		decSrc := p.eventRecordParser.TraceEventInfo.DecodingSource
		if mapInfo, err = p.eventRecordParser.EventRecord.GetMapInfo(pMapName, uint32(decSrc)); err != nil {
			err = fmt.Errorf("failed to get map info: %s", err)
			return
		}
	}

	for {
		buff = make([]uint16, formattedDataSize)

		err = winapi.TdhFormatProperty(
			p.eventRecordParser.TraceEventInfo,
			mapInfo,
			p.eventRecordParser.EventRecord.PointerSize(),
			p.eventPropertyInfo.InType(),
			p.eventPropertyInfo.OutType(),
			uint16(p.length),
			p.userDataLength,
			(*byte)(unsafe.Pointer(p.pValue)),
			&formattedDataSize,
			&buff[0],
			&udc)

		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			continue
		}

		if err == winapi.ERROR_EVT_INVALID_EVENT_DATA {
			if mapInfo == nil {
				break
			}
			mapInfo = nil
			continue
		}

		if err == nil {
			break
		}

		err = fmt.Errorf("failed to format property : %s", err)
		return
	}

	value = syscall.UTF16ToString(buff)

	return
}

type EventRecordParser struct {
	EventRecord    *winapi.EventRecord
	TraceEventInfo *winapi.TraceEventInfo

	Properties      map[string]*Property
	ArrayProperties map[string][]*Property
	Structures      []map[string]*Property

	userDataIterator uintptr
}

func newEventParser(eventRecord *winapi.EventRecord) (*EventRecordParser, error) {
	eventRecordParser := EventRecordParser{
		EventRecord: eventRecord,
	}

	var err error
	eventRecordParser.TraceEventInfo, err = eventRecord.GetEventInformation()
	if err != nil {
		return &eventRecordParser, err
	}

	eventRecordParser.Properties = make(map[string]*Property)
	eventRecordParser.ArrayProperties = make(map[string][]*Property)
	eventRecordParser.Structures = make([]map[string]*Property, 0)

	eventRecordParser.userDataIterator = eventRecordParser.EventRecord.UserData

	return &eventRecordParser, nil
}

func (e *EventRecordParser) setMetadata(event *Event) {
	event.System.Computer = hostname
	event.System.Execution.ProcessID = e.EventRecord.EventHeader.ProcessId
	event.System.Execution.ThreadID = e.EventRecord.EventHeader.ThreadId
	event.System.Correlation.ActivityID = winguid.ToString(&e.EventRecord.EventHeader.ActivityId)
	event.System.Correlation.RelatedActivityID = e.EventRecord.RelatedActivityID()
	event.System.EventID = e.TraceEventInfo.EventID()
	event.System.Channel = e.TraceEventInfo.ChannelName()
	event.System.Provider.Guid = winguid.ToString(&e.TraceEventInfo.ProviderGUID)
	event.System.Provider.Name = e.TraceEventInfo.ProviderName()
	event.System.Level.Value = e.TraceEventInfo.EventDescriptor.Level
	event.System.Level.Name = e.TraceEventInfo.LevelName()
	event.System.Opcode.Value = e.TraceEventInfo.EventDescriptor.Opcode
	event.System.Opcode.Name = e.TraceEventInfo.OpcodeName()
	event.System.Keywords.Value = e.TraceEventInfo.EventDescriptor.Keyword
	event.System.Keywords.Name = e.TraceEventInfo.KeywordName()
	event.System.Task.Value = uint8(e.TraceEventInfo.EventDescriptor.Task)
	event.System.Task.Name = e.TraceEventInfo.TaskName()

	event.System.TimestampUTC = e.EventRecord.EventHeader.ConvertTimestamp()

	if e.TraceEventInfo.IsMof() {
		var eventType string
		if t, ok := winapi.MofClassMapping[e.TraceEventInfo.EventGUID.Data1]; ok {
			eventType = fmt.Sprintf("%s/%s", t.Name, event.System.Opcode.Name)
		} else {
			eventType = fmt.Sprintf("UnknownClass/%s", event.System.Opcode.Name)
		}
		event.System.EventType = eventType
		event.System.EventGuid = winguid.ToString(&e.TraceEventInfo.EventGUID)
	}
}

func (e *EventRecordParser) endUserData() uintptr {
	return e.EventRecord.UserData + uintptr(e.EventRecord.UserDataLength)
}

func (e *EventRecordParser) userDataLength() uint16 {
	return uint16(e.endUserData() - e.userDataIterator)
}

func (e *EventRecordParser) getPropertyLength(i uint32) (uint32, error) {
	if epi := e.TraceEventInfo.GetEventPropertyInfoAt(i); epi.Flags&winapi.PropertyParamLength == winapi.PropertyParamLength {
		propSize := uint32(0)
		length := uint32(0)
		j := uint32(epi.LengthPropertyIndex())
		pdd := winapi.PropertyDataDescriptor{}
		pdd.PropertyName = uint64(e.TraceEventInfo.Pointer()) + uint64(e.TraceEventInfo.GetEventPropertyInfoAt(j).NameOffset)
		pdd.ArrayIndex = math.MaxUint32
		if err := winapi.TdhGetPropertySize(e.EventRecord, 0, nil, 1, &pdd, &propSize); err != nil {
			return 0, fmt.Errorf("failed to get property size: %s", err)
		} else {
			if err := winapi.TdhGetProperty(e.EventRecord, 0, nil, 1, &pdd, propSize, (*byte)(unsafe.Pointer(&length))); err != nil {
				return 0, fmt.Errorf("failed to get property: %s", err)
			}
			return length, nil
		}
	} else {
		if epi.Length() > 0 {
			return uint32(epi.Length()), nil
		} else {
			switch {
			// if there is an error returned here just try to add a switch case
			// with the proper in type
			case epi.InType() == uint16(winapi.TdhInTypeBinary) && epi.OutType() == uint16(winapi.TdhOutTypeIpv6):
				// sizeof(IN6_ADDR) == 16
				return uint32(16), nil
			case epi.InType() == uint16(winapi.TdhInTypeUnicodestring):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(winapi.TdhInTypeAnsistring):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(winapi.TdhInTypeSid):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(winapi.TdhInTypeWbemsid):
				return uint32(epi.Length()), nil
			case epi.Flags&winapi.PropertyStruct == winapi.PropertyStruct:
				return uint32(epi.Length()), nil
			default:
				return 0, fmt.Errorf("unexpected length of 0 for intype %d and outtype %d", epi.InType(), epi.OutType())
			}
		}
	}
}

func (e *EventRecordParser) getPropertySize(index uint32) (size uint32, err error) {
	dataDesc := winapi.PropertyDataDescriptor{}
	dataDesc.PropertyName = uint64(e.TraceEventInfo.PropertyNameOffset(index))
	dataDesc.ArrayIndex = math.MaxUint32
	err = winapi.TdhGetPropertySize(e.EventRecord, 0, nil, 1, &dataDesc, &size)
	return
}

func (e *EventRecordParser) getCount(eventPropertyInfo *winapi.EventPropertyInfo) (uint16, error) {
	var arraySize uint16
	var err error
	propertyDataDescriptor := winapi.PropertyDataDescriptor{}

	if (eventPropertyInfo.Flags & winapi.PropertyParamCount) == winapi.PropertyParamCount {
		nameOffset := uintptr(e.TraceEventInfo.GetEventPropertyInfoAt(uint32(eventPropertyInfo.CountUnion)).NameOffset)
		propertyDataDescriptor.PropertyName = uint64(e.TraceEventInfo.Pointer() + nameOffset)

		propertyDataDescriptor.ArrayIndex = math.MaxUint32 // https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-property_data_descriptor#members

		propertySize := uint32(0)
		err = winapi.TdhGetPropertySize(e.EventRecord, 0, nil, 1, &propertyDataDescriptor, &propertySize)
		if err != nil {
			return arraySize, err
		}
		count := uint32(0)
		err = winapi.TdhGetProperty(e.EventRecord, 0, nil, 1, &propertyDataDescriptor, propertySize, (*byte)(unsafe.Pointer(&count)))
		if err != nil {
			return arraySize, err
		}
		arraySize = uint16(count)
	} else {
		arraySize = eventPropertyInfo.CountUnion
	}

	return arraySize, err
}

func (e *EventRecordParser) prepareProperty(index uint32) (*Property, error) {
	var size uint32

	property := Property{}
	var err error

	property.eventPropertyInfo = e.TraceEventInfo.GetEventPropertyInfoAt(index)
	property.eventRecordParser = e
	property.name = winapi.UTF16AtOffsetToString(e.TraceEventInfo.Pointer(), uintptr(property.eventPropertyInfo.NameOffset))
	property.pValue = e.userDataIterator
	property.userDataLength = e.userDataLength()

	if property.length, err = e.getPropertyLength(index); err != nil {
		err = fmt.Errorf("failed to get property length: %s", err)
		return &property, err
	}

	size, err = e.getPropertySize(index)
	if err != nil {
		return &property, err
	}

	e.userDataIterator += uintptr(size)

	return &property, err
}

func (e *EventRecordParser) parseProperties() error {
	var count uint16
	var parseError error
	var property *Property

	for propertyIndex := uint32(0); propertyIndex < e.TraceEventInfo.TopLevelPropertyCount; propertyIndex++ {
		eventPropertyInfo := e.TraceEventInfo.GetEventPropertyInfoAt(propertyIndex)

		array := []*Property{}

		count, parseError = e.getCount(eventPropertyInfo)
		if parseError != nil {
			return parseError
		}

		var arrayName string
		for elementIndex := uint16(0); elementIndex < count; elementIndex++ {
			if eventPropertyInfo.Flags&winapi.PropertyStruct == winapi.PropertyStruct { // structure
				propStruct := make(map[string]*Property)
				lastMemberIndex := eventPropertyInfo.StructStartIndex() + eventPropertyInfo.NumOfStructMembers()

				for memberIndex := eventPropertyInfo.StructStartIndex(); memberIndex < lastMemberIndex; memberIndex++ {
					property, parseError = e.prepareProperty(uint32(memberIndex))
					if parseError != nil {
						return parseError
					} else {
						propStruct[property.name] = property
					}
				}
				e.Structures = append(e.Structures, propStruct)
			} else {
				property, parseError = e.prepareProperty(propertyIndex)
				if parseError != nil {
					return parseError
				}

				if eventPropertyInfo.Flags&winapi.PropertyParamCount == winapi.PropertyParamCount { // array
					arrayName = property.name
					array = append(array, property)
				} else {

					e.Properties[property.name] = property
				}
			}
		}

		if len(array) > 0 {
			e.ArrayProperties[arrayName] = array
		}
	}

	return parseError
}

func (e *EventRecordParser) buildEvent() (*Event, error) {
	event := Event{
		EventData:        make(map[string]string),
		EventDataArrays:  make(map[string][]string),
		EventDataStructs: make(map[string][]map[string]string),
		ExtendedData:     make([]string, 0),
	}

	err := e.setProperties(&event)
	if err != nil {
		return &event, err
	}

	e.setMetadata(&event)

	return &event, err
}

func (e *EventRecordParser) setProperties(out *Event) error {
	var lastErr error
	var err error

	if (e.TraceEventInfo.Flags & winapi.TEMPLATE_USER_DATA) == winapi.TEMPLATE_USER_DATA {
		out.UserDataTemplate = true
	}

	for _, p := range e.Properties {
		out.EventData[p.name], err = p.Value()
		if err != nil {
			lastErr = fmt.Errorf("%w %s: %s", ErrPropertyParsing, p.name, err)
		}
	}

	for pname, props := range e.ArrayProperties {
		values := make([]string, len(props))

		for _, p := range props {
			var v string
			v, err = p.Value()
			if err != nil {
				lastErr = fmt.Errorf("%w array %s: %s", ErrPropertyParsing, pname, err)
			}

			values = append(values, v)
		}

		out.EventDataArrays[pname] = values
	}

	if len(e.Structures) > 0 {
		structs := make([]map[string]string, len(e.Structures))
		for _, m := range e.Structures {
			s := make(map[string]string)
			for field, prop := range m {
				if s[field], err = prop.Value(); err != nil {
					lastErr = fmt.Errorf("%w %s.%s: %s", ErrPropertyParsing, StructurePropertyName, field, err)
				}
			}
		}

		out.EventDataStructs[StructurePropertyName] = structs
	}

	return lastErr
}

func (e *EventRecordParser) ProviderGUID() string {
	return winguid.ToString(&e.TraceEventInfo.ProviderGUID)
}

func (e *EventRecordParser) Provider() string {
	return e.TraceEventInfo.ProviderName()
}

func (e *EventRecordParser) Channel() string {
	return e.TraceEventInfo.ChannelName()
}

func (e *EventRecordParser) EventID() uint16 {
	return e.TraceEventInfo.EventID()
}

func (e *EventRecordParser) GetPropertyString(name string) (s string, err error) {
	if p, ok := e.Properties[name]; ok {
		return p.Value()
	}

	return "", fmt.Errorf("%w %s", ErrUnknownProperty, name)
}
