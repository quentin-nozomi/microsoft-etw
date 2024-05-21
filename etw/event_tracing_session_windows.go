package etw

import (
	"fmt"
	"github.com/quentin-nozomi/microsoft-etw/winapi"
	"syscall"
)

type EventTracingSession struct {
	traceName    string
	U16TraceName []uint16
	properties   *winapi.EventTraceProperties
	handle       syscall.Handle
}

func NewEventTracingSession(name string) (*EventTracingSession, error) {
	u16TraceName, err := syscall.UTF16FromString(name)
	if err != nil {
		return nil, err
	}

	eventTracingSession := &EventTracingSession{
		properties:   winapi.NewEventTracingSessionProperties(name),
		traceName:    name,
		U16TraceName: u16TraceName,
	}

	return eventTracingSession, nil
}

func (e *EventTracingSession) IsStarted() bool {
	return e.handle != 0
}

func (e *EventTracingSession) StartTrace() error {
	err := winapi.StartTrace(&e.handle, &e.U16TraceName[0], e.properties)

	if err == winapi.ERROR_ALREADY_EXISTS {
		originalProperties := *e.properties // copy
		controlTraceErr := winapi.ControlTrace(0, &e.U16TraceName[0], &originalProperties, winapi.EVENT_TRACE_CONTROL_STOP)
		if controlTraceErr != nil {
			fmt.Println(controlTraceErr.Error()) // TODO log
		}
		return winapi.StartTrace(&e.handle, &e.U16TraceName[0], e.properties)
	}

	return err
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#parameters
// https://learn.microsoft.com/en-us/windows/win32/wes/defining-keywords-used-to-classify-types-of-events
const (
	maxVerbosity           = uint8(255)
	defaultMatchAnyKeyword = uint64(0)
	defaultMatchAllKeyword = uint64(0)
)

func (e *EventTracingSession) EnableTrace(providerGUID *syscall.GUID) error {
	var err error

	if !e.IsStarted() {
		if err = e.StartTrace(); err != nil {
			return err
		}
	}

	enableTraceParameters := winapi.EnableTraceParameters{Version: 2}

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
