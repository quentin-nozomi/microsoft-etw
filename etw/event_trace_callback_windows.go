package etw

import (
	"context"
	"fmt"
	"sync"
	"syscall"

	"github.com/0xrawsec/golang-etw/winapi"
	"github.com/0xrawsec/golang-etw/winguid"
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

type Consumer struct {
	ctx       context.Context
	waitGroup sync.WaitGroup

	Events      chan *Event
	traceHandle syscall.Handle
	LostEvents  uint64

	Sender EventSender

	lastError error
	closed    bool
}

func NewEventCallback(ctx context.Context) (c *Consumer) {
	c = &Consumer{
		ctx:    ctx,
		Events: make(chan *Event, 4096),
		Sender: EventSender{},
	}

	return c
}

func (c *Consumer) bufferCallback(*winapi.EventTraceLogfile) uintptr {
	if c.ctx.Err() != nil {
		return 0 // stop processing
	}
	return 1 // continue
}

func (c *Consumer) eventRecordCallback(er *winapi.EventRecord) uintptr {
	var event *Event

	if winguid.Equals(&er.EventHeader.ProviderId, realTimeSessionLostEventGuid) {
		c.LostEvents++
	}

	eventParser, err := newEventParser(er)
	if err != nil {
		return 0
	}

	if eventParser.Flags.Skip {
		return 0
	}

	eventParser.initialize()

	if err := eventParser.prepareProperties(); err != nil {
		c.lastError = err
		return 0
	}

	if eventParser.Flags.Skip {
		return 0
	}

	if event, err = eventParser.buildEvent(); err != nil {
		c.lastError = err
	}

	c.Sender.Forward(c.Events, event)

	return 0
}

func (c *Consumer) newEventTraceLogFile(eventTracingSessionName []uint16) winapi.EventTraceLogfile {
	eventTraceLogfile := winapi.EventTraceLogfile{
		LoggerName:     &eventTracingSessionName[0],
		Union1:         winapi.PROCESS_TRACE_MODE_EVENT_RECORD | winapi.PROCESS_TRACE_MODE_REAL_TIME,
		BufferCallback: syscall.NewCallbackCDecl(c.bufferCallback),
		Callback:       syscall.NewCallbackCDecl(c.eventRecordCallback),
	}

	return eventTraceLogfile
}

func (c *Consumer) OpenTrace(eventTracingSessionName []uint16) (syscall.Handle, error) {
	var traceHandle syscall.Handle
	var err error

	eventTraceLogFile := c.newEventTraceLogFile(eventTracingSessionName) // set callbacks
	if err != nil {
		return 0, err
	}

	traceHandle, err = winapi.OpenTrace(&eventTraceLogFile)
	if err != nil {
		return 0, err
	}

	return traceHandle, nil
}

func (c *Consumer) Start(eventTracingSessionName []uint16) error {
	traceHandle, err := c.OpenTrace(eventTracingSessionName)
	if err != nil {
		return fmt.Errorf("failed to open trace %s: %w", syscall.UTF16ToString(eventTracingSessionName), err)
	}
	c.traceHandle = traceHandle

	c.waitGroup.Add(1)
	go func(traceHandle *syscall.Handle) {
		defer c.waitGroup.Done()
		processTraceErr := winapi.ProcessTrace(
			traceHandle, 1, // 1 handle to a realtime session
			nil, // no start time
			nil, // no end time
		)
		if processTraceErr != nil {
			c.lastError = processTraceErr
		}
	}(&traceHandle)

	return nil
}

func (c *Consumer) Err() error {
	return c.lastError
}

func (c *Consumer) Stop() error {
	return c.close()
}

func (c *Consumer) close() error {
	if c.closed {
		return nil
	}

	var err error

	closeTraceErr := winapi.CloseTrace(c.traceHandle)

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace#return-value
	if err != nil && err != winapi.ERROR_CTX_CLOSE_PENDING {
		err = closeTraceErr
	}

	c.waitGroup.Wait()
	close(c.Events)

	c.closed = true

	return err
}
