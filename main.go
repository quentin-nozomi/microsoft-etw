package main

import (
	"context"
	"fmt"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/golang-etw/winguid"
)

const (
	arcTraceSessionName = "ArcTraceSession"
)

const (
	sysmonGUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
)

// Requires elevated privileges
func main() {
	eventTracingSession, _ := etw.NewEventTracingSession(arcTraceSessionName)

	defer eventTracingSession.Stop()

	providerGUID, guidErr := winguid.Parse(sysmonGUID)
	if guidErr != nil {
		panic(guidErr)
	}

	var eventFilter []uint16 = nil

	sessionErr := eventTracingSession.EnableTrace(providerGUID, eventFilter)
	if sessionErr != nil {
		panic(sessionErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	consumer := etw.NewEventCallback(ctx)

	// receive events
	go func() {
		for e := range consumer.Events {
			fmt.Println(e)
		}
	}()

	startErr := consumer.Start(eventTracingSession.U16TraceName)
	defer consumer.Stop()

	if startErr != nil {
		panic(startErr)
	}

	time.Sleep(20 * time.Second)

	cancel()
	if consumer.Err() != nil {
		panic(consumer.Err())
	}
}
