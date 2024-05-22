package etw

import (
	"time"
)

type Event struct {
	EventData        map[string]string
	EventDataArrays  map[string][]string
	EventDataStructs map[string][]map[string]string

	UserDataTemplate bool

	System struct {
		Channel     string
		EventID     uint16
		EventType   string
		EventGuid   string
		Correlation struct {
			ActivityID string
		}
		Execution struct {
			ProcessID uint32
			ThreadID  uint32
		}
		Keywords struct {
			Value uint64
			Name  string
		}
		Level struct {
			Value uint8
			Name  string
		}
		Opcode struct {
			Value uint8
			Name  string
		}
		Task struct {
			Value uint8
			Name  string
		}
		Provider struct {
			Guid string
			Name string
		}
		TimestampUTC time.Time
	}
	ExtendedData []string
}
