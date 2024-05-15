package etw

import (
	"unsafe"
)

func GetAccessString(guid string) (s string, err error) {
	g := MustParseGUIDFromString(guid)
	bSize := uint32(0)
	// retrieves size
	_ = EventAccessQuery(g, nil, &bSize)
	buffer := make([]byte, bSize)
	sd := (*SecurityDescriptor)(unsafe.Pointer(&buffer[0]))
	// we get the security descriptor
	_ = EventAccessQuery(g, sd, &bSize)

	if s, err = ConvertSecurityDescriptorToStringSecurityDescriptorW(
		sd,
		SDDL_REVISION_1,
		DACL_SECURITY_INFORMATION); err != nil {
		return
	}

	return
}
