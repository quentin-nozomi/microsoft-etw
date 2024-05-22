package etw

import (
	"fmt"
	"math"
	"syscall"
	"unsafe"

	"golang.org/x/exp/constraints"
	"golang.org/x/sys/windows"

	"github.com/quentin-nozomi/microsoft-etw/winapi"
	"github.com/quentin-nozomi/microsoft-etw/winguid"
)

// https://learn.microsoft.com/en-us/windows/win32/etw/retrieving-event-data-using-tdh

type EventRecordParser struct {
	EventRecord    *winapi.EventRecord
	TraceEventInfo *winapi.TraceEventInfo

	Properties      map[string]*PropertyParser
	ArrayProperties map[string][]*PropertyParser
	Structures      []map[string]*PropertyParser

	userDataIterator uintptr
}

type PropertyParser struct {
	eventRecordParser *EventRecordParser
	eventPropertyInfo *winapi.EventPropertyInfo

	name string

	ptrValue uintptr
	value    string
	length   uint32

	userDataLength uint16
}

const (
	StructurePropertyName = "Structures"
)

var (
	ErrPropertyParsing = fmt.Errorf("error parsing property")
)

func newEventParser(eventRecord *winapi.EventRecord) (*EventRecordParser, error) {
	eventRecordParser := EventRecordParser{
		EventRecord: eventRecord,
	}

	var err error
	eventRecordParser.TraceEventInfo, err = eventRecord.GetEventInformation()
	if err != nil {
		return &eventRecordParser, err
	}

	eventRecordParser.Properties = make(map[string]*PropertyParser)
	eventRecordParser.ArrayProperties = make(map[string][]*PropertyParser)
	eventRecordParser.Structures = make([]map[string]*PropertyParser, 0)

	eventRecordParser.userDataIterator = eventRecordParser.EventRecord.UserData

	return &eventRecordParser, nil
}

func (e *EventRecordParser) loadMetadata(event *Event) {
	event.System.Execution.ProcessID = e.EventRecord.EventHeader.ProcessId
	event.System.Execution.ThreadID = e.EventRecord.EventHeader.ThreadId
	event.System.Correlation.ActivityID = winguid.ToString(&e.EventRecord.EventHeader.ActivityId)
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

	event.System.TimestampUTC = winapi.ConvertInt64Timestamp(e.EventRecord.EventHeader.TimeStamp)

	if e.TraceEventInfo.IsManagedObjectFormat() {
		var eventType string
		if managedObjectFormat, ok := winapi.ManagedObjectFormatMapping[e.TraceEventInfo.EventGUID.Data1]; ok {
			eventType = fmt.Sprintf("%s/%s", managedObjectFormat.Name, event.System.Opcode.Name)
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

func (e *EventRecordParser) getPropertySize(index uint32) (uint32, error) {
	propertyDataDescriptor := winapi.PropertyDataDescriptor{
		PropertyName: uint64(e.TraceEventInfo.PropertyNameOffset(index)),
		ArrayIndex:   math.MaxUint32,
	}
	var size uint32
	err := winapi.TdhGetPropertySize(e.EventRecord, 0, nil, 1, &propertyDataDescriptor, &size)
	return size, err
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty#parameters
// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_property_info#members
// Does not correspond to the actual size in memory, required by winapi.TdhFormatProperty
func (e *EventRecordParser) getPropertyLengthSpecification(eventPropertyInfo *winapi.EventPropertyInfo) (uint32, error) {
	if eventPropertyInfo.Flags&winapi.PropertyParamLength != winapi.PropertyParamLength {
		return uint32(eventPropertyInfo.Length()), nil
	} else {
		propertySize := uint32(0)
		length := uint32(0)
		lengthPropertyIndex := uint32(eventPropertyInfo.LengthPropertyIndex())
		propertyDataDescriptor := winapi.PropertyDataDescriptor{}
		propertyDataDescriptor.PropertyName = uint64(uintptr(unsafe.Pointer(e.TraceEventInfo))) + uint64(e.TraceEventInfo.GetEventPropertyInfoAt(lengthPropertyIndex).NameOffset)
		propertyDataDescriptor.ArrayIndex = math.MaxUint32
		if err := winapi.TdhGetPropertySize(e.EventRecord, 0, nil, 1, &propertyDataDescriptor, &propertySize); err != nil {
			return 0, fmt.Errorf("failed to get property length: %s", err)
		} else {
			getPropertyErr := winapi.TdhGetProperty(e.EventRecord, 0, nil, 1, &propertyDataDescriptor, propertySize, (*byte)(unsafe.Pointer(&length)))
			if getPropertyErr != nil {
				return 0, fmt.Errorf("failed to get property: %s", getPropertyErr)
			}
			return length, nil
		}
	}
}

func (e *EventRecordParser) getCount(eventPropertyInfo *winapi.EventPropertyInfo) (uint16, error) {
	var arraySize uint16
	var err error
	propertyDataDescriptor := winapi.PropertyDataDescriptor{}

	if (eventPropertyInfo.Flags & winapi.PropertyParamCount) == winapi.PropertyParamCount {
		nameOffset := uintptr(e.TraceEventInfo.GetEventPropertyInfoAt(uint32(eventPropertyInfo.CountUnion)).NameOffset)
		propertyDataDescriptor.PropertyName = uint64(uintptr(unsafe.Pointer(e.TraceEventInfo)) + nameOffset)
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

func (e *EventRecordParser) getPropertyObject(index uint32) (*PropertyParser, error) {
	property := PropertyParser{
		eventRecordParser: e,
		eventPropertyInfo: e.TraceEventInfo.GetEventPropertyInfoAt(index),
		ptrValue:          e.userDataIterator,
		userDataLength:    e.userDataLength(),
	}
	property.name = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(e.TraceEventInfo)) + uintptr(property.eventPropertyInfo.NameOffset))))

	size, err := e.getPropertySize(index)
	if err != nil {
		return &property, err
	}
	e.userDataIterator += uintptr(size) // advance iterator

	property.length, err = e.getPropertyLengthSpecification(property.eventPropertyInfo)
	if err != nil {
		return &property, err
	}

	return &property, err
}

func (e *EventRecordParser) getPropertiesObjects() error {
	var count uint16
	var parseError error
	var property *PropertyParser

	for propertyIndex := uint32(0); propertyIndex < e.TraceEventInfo.TopLevelPropertyCount; propertyIndex++ {
		eventPropertyInfo := e.TraceEventInfo.GetEventPropertyInfoAt(propertyIndex)

		array := []*PropertyParser{}

		count, parseError = e.getCount(eventPropertyInfo) // count is 1 if not an array
		if parseError != nil {
			return parseError
		}

		var arrayName string
		for elementIndex := uint16(0); elementIndex < count; elementIndex++ {
			if eventPropertyInfo.Flags&winapi.PropertyStruct == winapi.PropertyStruct {
				propStruct := make(map[string]*PropertyParser)
				lastMemberIndex := eventPropertyInfo.StructStartIndex() + eventPropertyInfo.NumOfStructMembers()
				for memberIndex := eventPropertyInfo.StructStartIndex(); memberIndex < lastMemberIndex; memberIndex++ {
					property, parseError = e.getPropertyObject(uint32(memberIndex))
					if parseError != nil {
						return parseError
					} else {
						propStruct[property.name] = property
					}
				}
				e.Structures = append(e.Structures, propStruct)
			} else {
				property, parseError = e.getPropertyObject(propertyIndex)
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
	parseErr := e.getPropertiesObjects()
	if parseErr != nil {
		return nil, parseErr
	}

	event := Event{
		EventData:        make(map[string]string),
		EventDataArrays:  make(map[string][]string),
		EventDataStructs: make(map[string][]map[string]string),
		ExtendedData:     make([]string, 0),
	}

	err := e.parseAllPropertiesObjects(&event)
	if err != nil {
		return &event, err
	}

	e.loadMetadata(&event)

	return &event, err
}

func (e *EventRecordParser) parseAllPropertiesObjects(event *Event) error {
	var lastErr error
	var err error

	if (e.TraceEventInfo.Flags & winapi.TEMPLATE_USER_DATA) == winapi.TEMPLATE_USER_DATA {
		event.UserDataTemplate = true
	}

	for _, property := range e.Properties {
		event.EventData[property.name], err = property.getValue()
		if err != nil {
			lastErr = fmt.Errorf("%w %s: %s", ErrPropertyParsing, property.name, err)
		}
	}

	for name, arrayProperty := range e.ArrayProperties {
		values := make([]string, len(arrayProperty))

		for _, p := range arrayProperty {
			var v string
			v, err = p.getValue()
			if err != nil {
				lastErr = fmt.Errorf("%w array %s: %s", ErrPropertyParsing, name, err)
			}

			values = append(values, v)
		}

		event.EventDataArrays[name] = values
	}

	if len(e.Structures) > 0 {
		structs := make([]map[string]string, len(e.Structures))
		for _, structureProperty := range e.Structures {
			structure := make(map[string]string)
			for field, property := range structureProperty {
				structure[field], err = property.getValue()
				if err != nil {
					lastErr = fmt.Errorf("%w %s.%s: %s", ErrPropertyParsing, StructurePropertyName, field, err)
				}
			}
		}

		event.EventDataStructs[StructurePropertyName] = structs
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

// built-in max function only in Go 1.21+
func getMax[T constraints.Ordered](a, b T) T {
	if a < b {
		return b
	}
	return a
}

func (p *PropertyParser) available() bool {
	return p.eventRecordParser != nil && p.eventPropertyInfo != nil && p.ptrValue > 0
}

func (p *PropertyParser) getValue() (string, error) {
	var err error

	if p.value == "" && p.available() {
		p.value, err = p.parse()
	}

	return p.value, err
}

const minPropertyBufferSize = uint32(512) // in bytes

func (p *PropertyParser) parse() (string, error) {
	value := ""
	var err error

	var buffer []uint16
	bufferSize := minPropertyBufferSize
	var mapInfo *winapi.EventMapInfo
	var userDataConsumed uint16 // unused

	if p.eventPropertyInfo.MapNameOffset() > 0 {
		pMapName := (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p.eventRecordParser.TraceEventInfo)) + uintptr(p.eventPropertyInfo.MapNameOffset())))
		decSrc := p.eventRecordParser.TraceEventInfo.DecodingSource
		if mapInfo, err = p.eventRecordParser.EventRecord.GetMapInfo(pMapName, uint32(decSrc)); err != nil {
			err = fmt.Errorf("failed to get map info: %s", err)
			return value, err
		}
	}

	for {
		buffer = make([]uint16, bufferSize)
		err = winapi.TdhFormatProperty(
			p.eventRecordParser.TraceEventInfo,
			mapInfo,
			p.eventRecordParser.EventRecord.PointerSize(),
			p.eventPropertyInfo.InType(),
			p.eventPropertyInfo.OutType(),
			uint16(p.length),
			p.userDataLength,
			p.ptrValue,
			&bufferSize,
			&buffer[0],
			&userDataConsumed,
		)

		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			continue // retry with updated buffer size
		}

		if err == windows.ERROR_EVT_INVALID_EVENT_DATA {
			if mapInfo == nil {
				break
			}
			mapInfo = nil
			continue
		}

		if err == nil {
			break
		}

		err = fmt.Errorf("failed to format property: %s", err)
		return value, err
	}

	value = syscall.UTF16ToString(buffer)

	return value, err
}
