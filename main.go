package main

import (
	"context"
	"fmt"
	"time"

	"github.com/quentin-nozomi/microsoft-etw/etw"
	"github.com/quentin-nozomi/microsoft-etw/winguid"
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

	sessionErr := eventTracingSession.EnableTrace(providerGUID)
	if sessionErr != nil {
		panic(sessionErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	eventCallback := etw.NewEventCallback(ctx)

	go func() { // receive events
		for e := range eventCallback.Events {
			fmt.Println(e)
		}
	}()

	startErr := eventCallback.ReceiveEvents(eventTracingSession.U16TraceName)
	defer eventCallback.Stop()

	if startErr != nil {
		panic(startErr)
	}

	time.Sleep(20 * time.Second)

	cancel()
	if eventCallback.Err() != nil {
		panic(eventCallback.Err())
	}
}
