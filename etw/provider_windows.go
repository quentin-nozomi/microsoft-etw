package etw

import (
	"unsafe"

	"github.com/0xrawsec/golang-etw/winapi"
)

type Provider struct {
	GUID            string
	Name            string
	EnableLevel     uint8
	MatchAnyKeyword uint64
	MatchAllKeyword uint64
	Filter          []uint16
}

func (p *Provider) eventIDFilterDescriptor() (d winapi.EventFilterDescriptor) {
	efeid := winapi.AllocEventFilterEventID(p.Filter)
	efeid.FilterIn = 0x1

	d = winapi.EventFilterDescriptor{
		Ptr:  uint64(uintptr(unsafe.Pointer(efeid))),
		Size: uint32(efeid.Size()),
		Type: winapi.EVENT_FILTER_TYPE_EVENT_ID,
	}

	return
}

func (p *Provider) BuildFilterDesc() []winapi.EventFilterDescriptor {
	var eventFilterDescriptor []winapi.EventFilterDescriptor
	eventFilterDescriptor = append(eventFilterDescriptor, p.eventIDFilterDescriptor())
	return eventFilterDescriptor
}
