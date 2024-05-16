package etw

import (
	"syscall"

	"github.com/0xrawsec/golang-etw/winapi"
)

type Session interface {
	TraceName() string
	Providers() []Provider
}

type EventTracingSession struct {
	traceName     string
	properties    *winapi.EventTraceProperties
	sessionHandle syscall.Handle

	providers []Provider
}

func NewEventTracingSession(name string) *EventTracingSession {
	eventTracingSession := &EventTracingSession{
		properties: winapi.NewEventTracingSessionProperties(name),
		traceName:  name,
		providers:  make([]Provider, 0),
	}

	return eventTracingSession
}

func (e *EventTracingSession) IsStarted() bool {
	return e.sessionHandle != 0
}

func (e *EventTracingSession) Start() error {
	u16TraceName, err := syscall.UTF16PtrFromString(e.traceName)
	if err != nil {
		return err
	}

	err = winapi.StartTrace(&e.sessionHandle, u16TraceName, e.properties)
	if err != nil {
		if err == winapi.ERROR_ALREADY_EXISTS {
			prop := *e.properties // copy
			_ = winapi.ControlTrace(0, u16TraceName, &prop, winapi.EVENT_TRACE_CONTROL_STOP)
			return winapi.StartTrace(&e.sessionHandle, u16TraceName, e.properties)
		}
		return nil
	}

	return nil
}

func (e *EventTracingSession) EnableProvider(prov Provider) error {
	var err error

	if !e.IsStarted() {
		if err = e.Start(); err != nil {
			return err
		}
	}

	guid, guidErr := winapi.ParseGUID(prov.GUID)
	if guidErr != nil {
		return guidErr
	}

	params := winapi.EnableTraceParameters{
		Version: 2,
	}

	if len(prov.Filter) > 0 {
		eventFilterDescriptors := prov.BuildFilterDesc()
		if len(eventFilterDescriptors) > 0 {
			params.EnableFilterDesc = &eventFilterDescriptors[0]
			params.FilterDescCount = uint32(len(eventFilterDescriptors))
		}
	}

	timeout := uint32(0)
	enableTraceErr := winapi.EnableTraceEx2(
		e.sessionHandle,
		guid,
		winapi.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		prov.EnableLevel,
		prov.MatchAnyKeyword,
		prov.MatchAllKeyword,
		timeout,
		&params,
	)
	if enableTraceErr != nil {
		return enableTraceErr
	}

	e.providers = append(e.providers, prov)

	return nil
}

func (e *EventTracingSession) TraceName() string {
	return e.traceName
}

func (e *EventTracingSession) Providers() []Provider {
	return e.providers
}

func (e *EventTracingSession) Stop() error {
	return winapi.ControlTrace(e.sessionHandle, nil, e.properties, winapi.EVENT_TRACE_CONTROL_STOP)
}
