//go:build windows

package dialer

import (
	"fmt"
	"syscall"
)

func applyTrafficClass(c syscall.RawConn, network string, trafficClass int) error {
	return fmt.Errorf("IPQoS is not supported on windows")
}
