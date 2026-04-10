package forward

import (
	"context"
	"net"
	"strings"

	"github.com/things-go/go-socks5"
	"golang.org/x/crypto/ssh"
)

// newSOCKS5Server creates a SOCKS5 server that dials through the SSH client.
func newSOCKS5Server(sshClient *ssh.Client) *socks5.Server {
	return socks5.NewServer(
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sshClient.Dial(network, addr)
		}),
	)
}

// parseDynamicSpec parses a dynamic forward spec: [bind_addr:]port
func parseDynamicSpec(spec string, defaultBind string) (bind, port string) {
	bind = defaultBind
	port = spec
	if idx := strings.LastIndex(spec, ":"); idx >= 0 {
		bind = spec[:idx]
		port = spec[idx+1:]
	}
	return bind, port
}
