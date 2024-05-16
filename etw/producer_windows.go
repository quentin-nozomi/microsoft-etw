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

// IsStarted returns true if the session is already started
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

// EnableProvider enables the session to receive events from a given provider
func (e *EventTracingSession) EnableProvider(prov Provider) (err error) {
	var guid *winapi.GUID

	if !e.IsStarted() {
		if err = e.Start(); err != nil {
			return
		}
	}

	if guid, err = winapi.ParseGUID(prov.GUID); err != nil {
		return
	}

	params := winapi.EnableTraceParameters{
		Version: 2,
		// Does not seem to bring valuable information
		// EnableProperty: EVENT_ENABLE_PROPERTY_PROCESS_START_KEY,
	}

	if len(prov.Filter) > 0 {
		fds := prov.BuildFilterDesc()
		if len(fds) > 0 {
			params.EnableFilterDesc = &fds[0]
			params.FilterDescCount = uint32(len(fds))
		}
	}

	if err = winapi.EnableTraceEx2(
		e.sessionHandle,
		guid,
		winapi.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		prov.EnableLevel,
		prov.MatchAnyKeyword,
		prov.MatchAllKeyword,
		0,
		&params,
	); err != nil {
		return
	}

	e.providers = append(e.providers, prov)

	return
}

// TraceName implements Session interface
func (e *EventTracingSession) TraceName() string {
	return e.traceName
}

// Providers implements Session interface
func (e *EventTracingSession) Providers() []Provider {
	return e.providers
}

// Stop stops the session
func (e *EventTracingSession) Stop() error {
	return winapi.ControlTrace(e.sessionHandle, nil, e.properties, winapi.EVENT_TRACE_CONTROL_STOP)
}
