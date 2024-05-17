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
	eventTracingSession := etw.NewEventTracingSession(arcTraceSessionName)

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

	consumer := etw.NewRealTimeConsumer(context.Background())
	consumer.FromTraceNames(arcTraceSessionName)
	defer consumer.Stop()

	// receive events
	go func() {
		for e := range consumer.Events {
			fmt.Println(e)
		}
	}()

	consumerErr := consumer.Start()
	if consumerErr != nil {
		panic(consumerErr)
	}

	time.Sleep(20 * time.Second)

	if consumer.Err() != nil {
		panic(consumer.Err())
	}
}
