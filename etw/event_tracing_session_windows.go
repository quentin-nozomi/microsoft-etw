package etw

import (
	"syscall"

	"github.com/0xrawsec/golang-etw/winapi"
)

type EventTracingSession struct {
	traceName  string
	properties *winapi.EventTraceProperties
	handle     syscall.Handle
}

func NewEventTracingSession(name string) *EventTracingSession {
	eventTracingSession := &EventTracingSession{
		properties: winapi.NewEventTracingSessionProperties(name),
		traceName:  name,
	}

	return eventTracingSession
}

func (e *EventTracingSession) IsStarted() bool {
	return e.handle != 0
}

func (e *EventTracingSession) StartTrace() error {
	u16TraceName, err := syscall.UTF16PtrFromString(e.traceName)
	if err != nil {
		return err
	}

	err = winapi.StartTrace(&e.handle, u16TraceName, e.properties)
	if err != nil {
		if err == winapi.ERROR_ALREADY_EXISTS {
			prop := *e.properties // copy
			_ = winapi.ControlTrace(0, u16TraceName, &prop, winapi.EVENT_TRACE_CONTROL_STOP)
			return winapi.StartTrace(&e.handle, u16TraceName, e.properties)
		}
		return nil
	}

	return nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#parameters
const (
	maxVerbosity           = uint8(255)
	defaultMatchAnyKeyword = uint64(0)
	defaultMatchAllKeyword = uint64(0)
)

func (e *EventTracingSession) EnableTrace(providerGUID *syscall.GUID, filter []uint16) error {
	var err error

	if !e.IsStarted() {
		if err = e.StartTrace(); err != nil {
			return err
		}
	}

	enableTraceParameters := winapi.EnableTraceParameters{Version: 2}

	if len(filter) > 0 {
		eventFilterDescriptors := EventIDFiltering(filter)
		if len(eventFilterDescriptors) > 0 {
			enableTraceParameters.EnableFilterDesc = &eventFilterDescriptors[0]
			enableTraceParameters.FilterDescCount = uint32(len(eventFilterDescriptors))
		}
	}

	timeout := uint32(0)
	enableTraceErr := winapi.EnableTraceEx2(
		e.handle,
		providerGUID,
		winapi.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		maxVerbosity,
		defaultMatchAnyKeyword,
		defaultMatchAllKeyword,
		timeout,
		&enableTraceParameters,
	)
	if enableTraceErr != nil {
		return enableTraceErr
	}

	return nil
}

func (e *EventTracingSession) Stop() error {
	return winapi.ControlTrace(e.handle, nil, e.properties, winapi.EVENT_TRACE_CONTROL_STOP)
}
