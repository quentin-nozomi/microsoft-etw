package etw

import (
	"fmt"
	"testing"
)

const (
	kernelFileProvider = "Microsoft-Windows-Kernel-File:0xff"
)

func TestAutologger(t *testing.T) {
	guid, err := UUID()
	fmt.Println(err)

	a := AutoLogger{
		Name:        "AutologgerTest",
		Guid:        guid,
		LogFileMode: 0x8001c0,
		BufferSize:  64,
		ClockType:   2,
	}

	defer a.Delete()

	a.Create()
	provider, err := ParseProvider(kernelFileProvider)

	a.EnableProvider(provider)
	a.Exists()
}
