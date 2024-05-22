package winapi

type MofClass struct {
	Name string
}

// Windows SDK // https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/km/wmiguid.h
// https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-classes
// https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
var (
	MofClassMapping = map[uint32]MofClass{
		1171836109: {Name: "ALPC"},
		2026983191: {Name: "ApplicationVerifier"},
		328690953:  {Name: "DbgPrint"},
		1030727892: {Name: "DiskIo"},
		3185075665: {Name: "DiskPerf"},
		3580666929: {Name: "DriverVerifier"},
		2976882526: {Name: "EventLog"},
		25508453:   {Name: "EventTraceConfig"},
		2429279289: {Name: "FileIo"},
		2369794079: {Name: "GenericMessage"},
		3901786812: {Name: "GlobalLogger"},
		1030727890: {Name: "HardFault"},
		749821213:  {Name: "ImageLoad"},
		2560801239: {Name: "MsSystemInformation"},
		1030727891: {Name: "PageFault"},
		3458056116: {Name: "PerfInfo"},
		1030727888: {Name: "Process"},
		2924704302: {Name: "Registry"},
		3627534994: {Name: "SplitIo"},
		2586315456: {Name: "TcpIp"},
		2713458880: {Name: "ThermalZone"},
		1030727889: {Name: "Thread"},
		964792796:  {Name: "TraceError"},
		3208270021: {Name: "UdpIp"},
		1147177553: {Name: "WmiEventLogger"},
		0x68fdd900: {Name: "EventTraceEvent"},
	}
)
