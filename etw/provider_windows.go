package etw

import (
	"unsafe"
)

type Provider struct {
	GUID            string
	Name            string
	EnableLevel     uint8
	MatchAnyKeyword uint64
	MatchAllKeyword uint64
	Filter          []uint16
}

func (p *Provider) eventIDFilterDescriptor() (d EventFilterDescriptor) {

	efeid := AllocEventFilterEventID(p.Filter)
	efeid.FilterIn = 0x1

	d = EventFilterDescriptor{
		Ptr:  uint64(uintptr(unsafe.Pointer(efeid))),
		Size: uint32(efeid.Size()),
		Type: EVENT_FILTER_TYPE_EVENT_ID,
	}

	return
}

func (p *Provider) BuildFilterDesc() (fd []EventFilterDescriptor) {

	fd = append(fd, p.eventIDFilterDescriptor())

	return
}
