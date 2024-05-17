package etw

import (
	"github.com/quentin-nozomi/microsoft-etw/winapi"
)

func EventIDFiltering(filter []uint16) []winapi.EventFilterDescriptor {
	var eventFilterDescriptor []winapi.EventFilterDescriptor
	eventFilterDescriptor = append(eventFilterDescriptor, winapi.NewEventIDFilterDescriptor(filter))
	return eventFilterDescriptor
}
