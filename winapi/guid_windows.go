package winapi

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
// https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid#members
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func MustParseGUID(sguid string) *GUID {
	guid, err := ParseGUID(sguid)
	if err != nil {
		panic(err)
	}
	return guid
}

var (
	guidRegex = regexp.MustCompile(`^\{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}}?$`)
)

func ParseGUID(guid string) (*GUID, error) {
	outGuid := GUID{}
	var err error

	guid = strings.ToUpper(guid)
	if !guidRegex.MatchString(guid) {
		return nil, fmt.Errorf("bad GUID format")
	}

	digitsGroups := strings.Split(strings.Trim(guid, "{}"), "-")

	var dataGroup uint64
	if dataGroup, err = strconv.ParseUint(digitsGroups[0], 16, 32); err != nil {
		return nil, err
	}
	outGuid.Data1 = uint32(dataGroup)

	if dataGroup, err = strconv.ParseUint(digitsGroups[1], 16, 16); err != nil {
		return nil, err
	}
	outGuid.Data2 = uint16(dataGroup)

	if dataGroup, err = strconv.ParseUint(digitsGroups[2], 16, 16); err != nil {
		return nil, err
	}
	outGuid.Data3 = uint16(dataGroup)

	if dataGroup, err = strconv.ParseUint(digitsGroups[3], 16, 16); err != nil {
		return nil, err
	}
	outGuid.Data4[0] = uint8(dataGroup >> 8)
	outGuid.Data4[1] = uint8(dataGroup & 0xff)

	if dataGroup, err = strconv.ParseUint(digitsGroups[4], 16, 64); err != nil {
		return nil, err
	}
	outGuid.Data4[2] = uint8(dataGroup >> 40)
	outGuid.Data4[3] = uint8((dataGroup >> 32) & 0xff)
	outGuid.Data4[4] = uint8((dataGroup >> 24) & 0xff)
	outGuid.Data4[5] = uint8((dataGroup >> 16) & 0xff)
	outGuid.Data4[6] = uint8((dataGroup >> 8) & 0xff)
	outGuid.Data4[7] = uint8(dataGroup & 0xff)

	return &outGuid, nil
}

const (
	nullGUIDStr = "{00000000-0000-0000-0000-000000000000}"
)

var (
	nullGUID = GUID{}
)

func (g *GUID) IsZero() bool {
	return g.Equals(&nullGUID)
}

func (g *GUID) String() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1,
		g.Data2,
		g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
	)
}

func (g *GUID) Equals(other *GUID) bool {
	return g.Data1 == other.Data1 &&
		g.Data2 == other.Data2 &&
		g.Data3 == other.Data3 &&
		g.Data4[0] == other.Data4[0] &&
		g.Data4[1] == other.Data4[1] &&
		g.Data4[2] == other.Data4[2] &&
		g.Data4[3] == other.Data4[3] &&
		g.Data4[4] == other.Data4[4] &&
		g.Data4[5] == other.Data4[5] &&
		g.Data4[6] == other.Data4[6] &&
		g.Data4[7] == other.Data4[7]
}
