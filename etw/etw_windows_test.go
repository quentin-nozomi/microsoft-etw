package etw

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// providers
	SysmonProvider           = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
	KernelMemoryProviderName = "{D1D93EF7-E1F2-4F45-9943-03D245FE6C00}"
	KernelFileProviderName   = "Microsoft-Windows-Kernel-File"
	// sessions
	EventlogSecurity = "Eventlog-Security"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randBetween(min, max int) (i int) {
	for ; i < min; i = rand.Int() % max {
	}
	return
}

func TestIsKnownProvider(t *testing.T) {
	IsKnownProvider("Microsoft-Windows-Kernel-File")
	IsKnownProvider("Microsoft-Windows-Unknown-Provider")
}

func TestProducerConsumer(t *testing.T) {
	var prov Provider

	eventCount := 0

	// Producer part
	prod := NewRealTimeSession("GolangTest")
	var err error
	prov, err = ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	fmt.Println(err)
	prod.EnableProvider(prov)
	prod.Start()
	prod.IsStarted()

	defer prod.Stop()

	// Consumer part
	c := NewRealTimeConsumer(context.Background()).FromSessions(prod).FromTraceNames(EventlogSecurity)

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { c.Stop() }()
	// starting consumer
	c.Start()

	start := time.Now()
	// consuming events in Golang
	go func() {
		for e := range c.Events {
			eventCount++

			if e.System.Provider.Name == KernelFileProviderName {
				check := e.System.EventID == 12 ||
					e.System.EventID == 13 ||
					e.System.EventID == 14 ||
					e.System.EventID == 15 ||
					e.System.EventID == 16
				fmt.Println(check)
			}

			_, err := json.Marshal(&e)
			fmt.Println(err)
		}
	}()

	time.Sleep(5 * time.Second)

	c.Stop()
	delta := time.Now().Sub(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	c.Err()
}

func TestKernelSession(t *testing.T) {
	eventCount := 0

	traceFlags := []uint32{
		// Trace process creation / termination
		//EVENT_TRACE_FLAG_PROCESS,
		// Trace image loading
		EVENT_TRACE_FLAG_IMAGE_LOAD,
		// Trace file operations
		//EVENT_TRACE_FLAG_FILE_IO_INIT,
		//EVENT_TRACE_FLAG_ALPC,
		EVENT_TRACE_FLAG_REGISTRY,
	}

	// producer part
	kp := NewKernelRealTimeSession(traceFlags...)

	kp.Start()
	kp.IsStarted()

	// consumer part
	c := NewRealTimeConsumer(context.Background()).FromSessions(kp)

	c.Stop()

	c.Start()

	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range c.Events {
			eventCount++

			_, err := json.Marshal(&e)
			fmt.Println(err)
		}
	}()

	time.Sleep(5 * time.Second)

	c.Stop()
	kp.Stop()
	wg.Wait()

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))
}

func TestEventMapInfo(t *testing.T) {
	eventCount := 0

	prod := NewRealTimeSession("GolangTest")

	mapInfoChannels := []string{
		"Microsoft-Windows-ProcessStateManager",
		"Microsoft-Windows-DNS-Client",
		"Microsoft-Windows-Win32k",
		"Microsoft-Windows-RPC",
		"Microsoft-Windows-Kernel-IoTrace"}

	for _, c := range mapInfoChannels {
		t.Log(c)
		prov, err := ParseProvider(c)
		fmt.Println(err)
		prod.EnableProvider(prov)
	}

	prod.Start()
	prod.IsStarted()

	defer prod.Stop()

	// consumer part
	fakeError := fmt.Errorf("fake")

	c := NewRealTimeConsumer(context.Background()).FromSessions(prod)
	// reducing size of channel so that we are obliged to skip events
	c.Events = make(chan *Event)
	c.PreparedCallback = func(erh *EventRecordHelper) error {

		erh.TraceInfo.EventMessage()
		erh.TraceInfo.ActivityIDName()
		erh.TraceInfo.RelatedActivityIDName()

		erh.Skip()

		for _, p := range erh.Properties {
			// calling those two method just to test they don't cause memory corruption
			p.evtPropInfo.Count()
			p.evtPropInfo.CountPropertyIndex()
			if p.evtPropInfo.MapNameOffset() > 0 {
				erh.Flags.Skip = false
			}
		}

		// don't skip events with related activity ID
		erh.Flags.Skip = erh.EventRec.RelatedActivityID() == nullGUIDStr

		return fakeError
	}

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { c.Stop() }()

	c.Start()

	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range c.Events {
			eventCount++

			_, err := json.Marshal(&e)
			fmt.Println(err)
			if e.System.Correlation.ActivityID != nullGUIDStr && e.System.Correlation.RelatedActivityID != nullGUIDStr {
				t.Logf("Provider=%s ActivityID=%s RelatedActivityID=%s", e.System.Provider.Name, e.System.Correlation.ActivityID, e.System.Correlation.RelatedActivityID)
			}
			//t.Log(string(b))
		}
	}()

	time.Sleep(10 * time.Second)

	c.Stop()
	wg.Wait()

	// we got many events so some must have been skipped
	t.Logf("skipped %d events", c.Skipped)
	fmt.Println(c.Skipped == 0)

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	c.Err()
}

func TestLostEvents(t *testing.T) {
	// Producer part
	prod := NewRealTimeSession("GolangTest")
	// small buffer size on purpose to trigger event loss
	prod.properties.BufferSize = 1

	prov, err := ParseProvider("Microsoft-Windows-Kernel-Memory" + ":0xff")
	fmt.Println(err)
	// enabling provider
	fmt.Println(prod.EnableProvider(prov))
	defer prod.Stop()

	// Consumer part
	c := NewRealTimeConsumer(context.Background()).FromSessions(prod).FromTraceNames(EventlogSecurity)
	// we have to declare a func otherwise c.Stop does not seem to be called
	defer func() { fmt.Println(c.Stop()) }()

	// starting consumer
	fmt.Println(c.Start())
	cnt := uint64(0)
	go func() {
		for range c.Events {
			cnt++
		}
	}()
	time.Sleep(20 * time.Second)
	fmt.Println(c.Stop())
	time.Sleep(5 * time.Second)
	t.Logf("Events received: %d", cnt)
	t.Logf("Events lost: %d", c.LostEvents)
	fmt.Println(c.LostEvents > 0)
}

func jsonStr(i interface{}) string {
	var b []byte
	var err error
	if b, err = json.Marshal(i); err != nil {
		panic(err)
	}
	return string(b)
}

func TestConsumerCallbacks(t *testing.T) {
	var prov Provider
	var err error

	eventCount := 0

	// Producer part
	prod := NewRealTimeSession("GolangTest")

	prov, err = ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	fmt.Println(err)
	// enabling provider
	fmt.Println(prod.EnableProvider(prov))
	// starting producer
	fmt.Println(prod.Start())
	// checking producer is running
	fmt.Println(prod.IsStarted())
	kernelFileProviderChannel := prov.Name + "/Analytic"
	kernelProviderGUID := MustParseGUIDFromString(prov.GUID)

	defer prod.Stop()

	// Consumer part
	c := NewRealTimeConsumer(context.Background()).FromSessions(prod).FromTraceNames(EventlogSecurity)

	c.EventRecordHelperCallback = func(erh *EventRecordHelper) (err error) {

		switch erh.EventID() {
		case 12, 14, 15, 16:
			break
		default:
			erh.Skip()
		}

		return
	}

	type file struct {
		name  string
		flags struct {
			read  bool
			write bool
		}
	}

	fileObjectMapping := make(map[string]*file)
	c.PreparedCallback = func(h *EventRecordHelper) error {
		fmt.Println(h.Provider() == prov.Name)
		fmt.Println(h.ProviderGUID() == prov.GUID)
		fmt.Println(h.EventRec.EventHeader.ProviderId.Equals(kernelProviderGUID))
		fmt.Println(h.TraceInfo.ProviderGUID.Equals(kernelProviderGUID))
		fmt.Println(h.Channel() == kernelFileProviderChannel)

		switch h.EventID() {
		case 12:
			fmt.Println(h.ParseProperties("FileName", "FileObject", "CreateOptions"))

			if fo, err := h.GetPropertyString("FileObject"); err == nil {
				if fn, err := h.GetPropertyString("FileName"); err == nil {
					fileObjectMapping[fo] = &file{name: fn}
				}
			}

			coUint, err := h.GetPropertyUint("CreateOptions")
			fmt.Println(err)
			coInt, err := h.GetPropertyInt("CreateOptions")
			fmt.Println(err)
			fmt.Println(coUint != 0 && coUint == uint64(coInt))

			unk, err := h.GetPropertyString("UnknownProperty")
			fmt.Println(unk == "")
			fmt.Println(err)

			// we skip file create events
			h.Skip()

		case 14:
			fmt.Println(h.ParseProperties("FileObject"))

			if object, err := h.GetPropertyString("FileObject"); err == nil {
				delete(fileObjectMapping, object)
			}

			// skip file close events
			h.Skip()

		case 15, 16:
			var f *file
			var object string
			var ok bool

			fmt.Println(h.ParseProperty("FileObject"))

			if object, err = h.GetPropertyString("FileObject"); err != nil {
				h.Skip()
				break
			}

			foUint, _ := h.GetPropertyUint("FileObject")
			fmt.Println(fmt.Sprintf("0x%X", foUint) == object)

			if f, ok = fileObjectMapping[object]; !ok {
				// we skip events we cannot enrich
				h.Skip()
				break
			}

			if (h.EventID() == 15 && f.flags.read) ||
				(h.EventID() == 16 && f.flags.write) {
				h.Skip()
				break
			}

			h.SetProperty("FileName", f.name)
			f.flags.read = h.EventID() == 15
			f.flags.write = h.EventID() == 16

			// event volume will so low that this call should have no effect
			h.Skippable()

		default:
			h.Skip()
		}

		return nil
	}

	// we have to declare a func otherwise c.Stop does not seem to be called
	defer func() { fmt.Println(c.Stop()) }()

	// starting consumer
	fmt.Println(c.Start())

	//testfile := `\Windows\Temp\test.txt`
	testfile := filepath.Join(t.TempDir()[2:], "test.txt")
	t.Logf("testfile: %s", testfile)

	start := time.Now()
	var etwread int
	var etwwrite int

	pid := os.Getpid()
	// consuming events in Golang
	go func() {
		for e := range c.Events {
			eventCount++

			_, err := json.Marshal(&e)
			fmt.Println(err)
			switch e.System.EventID {
			case 15, 16:
				var fn string
				var ok bool

				if fn, ok = e.GetPropertyString("FileName"); !ok {
					break
				}

				if !strings.Contains(fn, testfile) {
					break
				}

				if e.System.Execution.ProcessID != uint32(pid) {
					break
				}

				if e.System.EventID == 15 {
					etwread++
				} else {
					etwwrite++
				}
			}
		}
	}()

	// creating test files
	nReadWrite := 0
	tf := fmt.Sprintf("C:%s", testfile)
	for ; nReadWrite < randBetween(800, 1000); nReadWrite++ {
		tmp := fmt.Sprintf("%s.%d", tf, nReadWrite)
		fmt.Println(os.WriteFile(tmp, []byte("testdata"), 7777))
		_, err = os.ReadFile(tmp)
		fmt.Println(err)
		time.Sleep(time.Millisecond)
	}

	d := time.Duration(0)
	sleep := time.Second
	for d < 10*time.Second {
		if etwread == nReadWrite && etwwrite == nReadWrite {
			break
		}
		time.Sleep(sleep)
		d += sleep
	}

	// wait a couple of seconds more to see if we get more events
	time.Sleep(10 * time.Second)

	// stopping consumer
	fmt.Println(c.Stop())

	fmt.Println(eventCount != 0, "did not receive any event")
	fmt.Println(c.Skipped == 0)
	// verifying that we caught all events
	t.Logf("read=%d etwread=%d", nReadWrite, etwread)
	fmt.Println(nReadWrite == etwread)
	t.Logf("write=%d etwwrite=%d", nReadWrite, etwwrite)
	fmt.Println(nReadWrite == etwwrite)

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	// checking any consumer error
	fmt.Println(c.Err())
}

func TestConvertSid(t *testing.T) {
	t.Parallel()

	var sid *SID
	var err error
	systemSID := "S-1-5-18"

	sid, err = ConvertStringSidToSidW(systemSID)
	fmt.Println(err)
	fmt.Println(sid)
}

func TestSessionSlice(t *testing.T) {
	intSlice := make([]int, 0)
	sessions := make([]Session, 0)
	for i := 0; i < 10; i++ {
		sessions = append(sessions, NewRealTimeSession(fmt.Sprintf("test-%d", i)))
		intSlice = append(intSlice, i)
	}

	fmt.Println(len(SessionSlice(sessions)) == len(sessions))

	SessionSlice(sessions[0]) // should panic
	SessionSlice(intSlice)    // should panic
}
