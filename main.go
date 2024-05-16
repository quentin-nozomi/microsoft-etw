package main

import (
	"context"
	"fmt"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

// Requires elevated privileges
func main() {
	eventTracingSession := etw.NewEventTracingSession("ArcTraceSession")

	defer eventTracingSession.Stop()
	
	provider := etw.Provider{
		GUID:            "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
		Name:            "Microsoft-Windows-Sysmon",
		EnableLevel:     255,
		MatchAnyKeyword: 0,
		MatchAllKeyword: 0,
		Filter:          nil,
	}
	if err := eventTracingSession.EnableProvider(provider); err != nil {
		panic(err)
	}

	c := etw.NewRealTimeConsumer(context.Background())

	defer c.Stop()

	c.FromSessions(eventTracingSession)

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
