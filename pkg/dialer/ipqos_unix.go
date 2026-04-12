//go:build unix

package dialer

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func applyTrafficClass(c syscall.RawConn, network string, trafficClass int) error {
	var applyErr error
	if err := c.Control(func(fd uintptr) {
		switch {
		case strings.HasSuffix(network, "4"):
			applyErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, trafficClass)
		case strings.HasSuffix(network, "6"):
			applyErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, trafficClass)
		default:
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, trafficClass); err == nil {
				return
			} else if !ignorableTrafficClassError(err) {
				applyErr = err
				return
			}
			applyErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, trafficClass)
		}
	}); err != nil {
		return err
	}
	if applyErr != nil {
		return fmt.Errorf("apply IPQoS: %w", applyErr)
	}
	return nil
}

func ignorableTrafficClassError(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EAFNOSUPPORT)
}
