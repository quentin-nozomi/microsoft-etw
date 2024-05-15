package etw

import (
	"fmt"
	"testing"
)

func TestAccessString(t *testing.T) {
	for _, p := range EnumerateProviders() {
		_, err := GetAccessString(p.GUID)
		fmt.Println(err)
	}
}
