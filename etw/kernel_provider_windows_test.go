package etw

import (
	"fmt"
	"testing"
)

func hasFlag(flags, flag uint32) bool {
	return flags&flag == flag
}

func TestKernelProviders(t *testing.T) {
	for _, p := range KernelProviders {
		fmt.Println(IsKernelProvider(p.Name))
		fmt.Println(IsKernelProvider(p.GUID))

		fmt.Println(GetKernelProviderFlags(p.Name) == p.Flags)
		// some providers have the same GUID so we have to check flags contains p.Flags
		fmt.Println(GetKernelProviderFlags(p.GUID)&p.Flags == p.Flags)
	}

	combinedFlags := GetKernelProviderFlags("ALPC", "ImageLoad")
	fmt.Println(combinedFlags != EVENT_TRACE_FLAG_ALPC)
	fmt.Println(hasFlag(combinedFlags, EVENT_TRACE_FLAG_ALPC))
	fmt.Println(combinedFlags != EVENT_TRACE_FLAG_IMAGE_LOAD)
	fmt.Println(hasFlag(combinedFlags, EVENT_TRACE_FLAG_IMAGE_LOAD))
}
