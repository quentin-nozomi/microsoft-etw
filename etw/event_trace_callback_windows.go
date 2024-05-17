package etw

import (
	"context"
	"fmt"
	"sync"
	"syscall"

	"github.com/quentin-nozomi/microsoft-etw/winapi"
	"github.com/quentin-nozomi/microsoft-etw/winguid"
)

// https://learn.microsoft.com/en-us/windows/win32/etw/lost-event
var realTimeSessionLostEventGuid = winguid.MustParse("{6A399AE0-4BC6-4DE9-870B-3657F8947E7E}")

type EventSender struct {
	Dropped uint64
}

func (e *EventSender) Forward(channel chan<- *Event, event *Event) {
	select {
	case channel <- event: // sent
	default:
		e.Dropped++
	}
	return
}

type EventCallback struct {
	ctx       context.Context
	waitGroup sync.WaitGroup

	Events      chan *Event
	traceHandle syscall.Handle
	LostEvents  uint64

	Sender EventSender

	lastError error
	closed    bool
}

func NewEventCallback(ctx context.Context) *EventCallback {
	return &EventCallback{
		ctx:    ctx,
		Events: make(chan *Event, 4096),
		Sender: EventSender{},
	}
}

func (e *EventCallback) eventBufferCallback(*winapi.EventTraceLogfile) uintptr {
	if e.ctx.Err() != nil {
		return 0 // stop processing
	}
	return 1 // continue
}

func (e *EventCallback) eventRecordCallback(er *winapi.EventRecord) uintptr {
	if winguid.Equals(&er.EventHeader.ProviderId, realTimeSessionLostEventGuid) {
		e.LostEvents++
	}

	eventParser, err := newEventParser(er)
	if err != nil {
		return 0
	}

	eventParser.initialize()
	parseErr := eventParser.prepareProperties()
	if err != nil {
		e.lastError = parseErr
		return 0
	}

	var event *Event
	if event, err = eventParser.buildEvent(); err != nil {
		e.lastError = err
	}

	e.Sender.Forward(e.Events, event)

	return 0
}

func (e *EventCallback) newEventTraceLogFile(eventTracingSessionName []uint16) *winapi.EventTraceLogfile {
	return &winapi.EventTraceLogfile{
		LoggerName:     &eventTracingSessionName[0],
		Union1:         winapi.PROCESS_TRACE_MODE_EVENT_RECORD | winapi.PROCESS_TRACE_MODE_REAL_TIME,
		BufferCallback: syscall.NewCallbackCDecl(e.eventBufferCallback),
		Callback:       syscall.NewCallbackCDecl(e.eventRecordCallback),
	}
}

func (e *EventCallback) OpenTrace(eventTracingSessionName []uint16) (syscall.Handle, error) {
	var traceHandle syscall.Handle
	var err error

	eventTraceLogFile := e.newEventTraceLogFile(eventTracingSessionName) // set callbacks
	if err != nil {
		return 0, err
	}

	traceHandle, err = winapi.OpenTrace(eventTraceLogFile)
	if err != nil {
		return 0, err
	}

	return traceHandle, nil
}

func (e *EventCallback) Start(eventTracingSessionName []uint16) error {
	traceHandle, err := e.OpenTrace(eventTracingSessionName)
	if err != nil {
		return fmt.Errorf("failed to open trace %s: %w", syscall.UTF16ToString(eventTracingSessionName), err)
	}
	e.traceHandle = traceHandle

	e.waitGroup.Add(1)
	go func(traceHandle *syscall.Handle) {
		defer e.waitGroup.Done()
		processTraceErr := winapi.ProcessTrace(
			traceHandle, 1, // 1 handle to a realtime session
			nil, // no start time
			nil, // no end time
		)
		if processTraceErr != nil {
			e.lastError = processTraceErr
		}
	}(&traceHandle)

	return nil
}

func (e *EventCallback) Err() error {
	return e.lastError
}

func (e *EventCallback) Stop() error {
	return e.close()
}

func (e *EventCallback) close() error {
	if e.closed {
		return nil
	}

	var err error

	closeTraceErr := winapi.CloseTrace(e.traceHandle)

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace#return-value
	if err != nil && err != winapi.ERROR_CTX_CLOSE_PENDING {
		err = closeTraceErr
	}

	e.waitGroup.Wait()
	close(e.Events)

	e.closed = true

	return err
}
