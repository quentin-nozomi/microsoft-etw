package main

import (
	"context"
	"fmt"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/golang-etw/winguid"
)

const (
	sysmonGUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
)

// Requires elevated privileges
func main() {
	eventTracingSession := etw.NewEventTracingSession("NozomiArcETW")

	defer eventTracingSession.Stop()

	providerGUID, guidErr := winguid.Parse(sysmonGUID)
	if guidErr != nil {
		panic(guidErr)
	}

	var eventFilter []uint16 = nil

	if err := eventTracingSession.EnableTrace(providerGUID, eventFilter); err != nil {
		panic(err)
	}

	c := etw.NewRealTimeConsumer(context.Background())

	defer c.Stop()

	go func() {
		for e := range c.Events {
			fmt.Println(e)
		}
	}()

	if err := c.Start(); err != nil {
		panic(err)
	}

	time.Sleep(20 * time.Second)

	if c.Err() != nil {
		panic(c.Err())
	}
}
