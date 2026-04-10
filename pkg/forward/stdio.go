package forward

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// RunStdioForward connects stdin/stdout to a direct-tcpip channel.
// Returns the process exit code.
func RunStdioForward(sshClient *ssh.Client, target string) int {
	ch, reqs, err := sshClient.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		RHost string
		RPort uint32
		LHost string
		LPort uint32
	}{
		RHost: HostFromTarget(target),
		RPort: PortFromTarget(target),
		LHost: "127.0.0.1",
		LPort: 0,
	}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: stdio forwarding to %s failed: %v\n", target, err)
		return 255
	}
	go ssh.DiscardRequests(reqs)

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(ch, os.Stdin)
		ch.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(os.Stdout, ch)
		done <- struct{}{}
	}()

	<-done
	return 0
}

// HostFromTarget extracts the host from a host:port string.
func HostFromTarget(target string) string {
	h, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return h
}

// PortFromTarget extracts the port from a host:port string, defaulting to 22.
func PortFromTarget(target string) uint32 {
	_, p, err := net.SplitHostPort(target)
	if err != nil {
		return 22
	}
	port, err := strconv.ParseUint(p, 10, 32)
	if err != nil {
		return 22
	}
	return uint32(port)
}
