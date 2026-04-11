package sshserver

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

// DefaultTcpForwarder provides a straightforward TCP forwarding
// implementation suitable for drop-in use. It proxies direct-tcpip
// channels by dialing the requested destination, and services
// tcpip-forward global requests by listening on the requested address
// and opening forwarded-tcpip channels for each accepted connection.
//
// PermitOpen and PermitListen policies are enforced where applicable.
// The forwarder does NOT perform GSS-API or SOCKS specific handling —
// those concerns belong in higher-level code.
type DefaultTcpForwarder struct {
	mu       sync.Mutex
	forwards map[string]net.Listener
}

// HandleDirectTcpIP accepts a direct-tcpip channel, dials the requested
// host:port, and shuttles data both ways. PermitOpen is enforced before
// the dial; disallowed destinations are rejected with Prohibited.
func (f *DefaultTcpForwarder) HandleDirectTcpIP(nc ssh.NewChannel, meta ssh.ConnMetadata, opts *Options) error {
	var req struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &req); err != nil {
		return nc.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
	}

	dest := net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))
	if !permitOpenAllows(dest, opts.PermitOpen) {
		return nc.Reject(ssh.Prohibited, "destination not permitted")
	}

	target, err := net.Dial("tcp", dest)
	if err != nil {
		return nc.Reject(ssh.ConnectionFailed, err.Error())
	}

	ch, reqs, err := nc.Accept()
	if err != nil {
		target.Close()
		return err
	}
	go ssh.DiscardRequests(reqs)

	go pipeClose(target, ch)
	go pipeClose(ch, target)
	return nil
}

// StartRemoteForward begins listening on bindAddr:bindPort and forwards
// each accepted connection over a forwarded-tcpip channel on conn.
func (f *DefaultTcpForwarder) StartRemoteForward(bindAddr string, bindPort uint32, conn *ssh.ServerConn, opts *Options) (uint32, error) {
	if !permitListenAllows(bindAddr, bindPort, opts.PermitListen) {
		return 0, fmt.Errorf("listen not permitted")
	}

	laddr := net.JoinHostPort(bindAddr, strconv.Itoa(int(bindPort)))
	listener, err := net.Listen("tcp", laddr)
	if err != nil {
		return 0, err
	}
	actualPort := uint32(listener.Addr().(*net.TCPAddr).Port)

	key := forwardKey(bindAddr, actualPort)
	f.mu.Lock()
	if f.forwards == nil {
		f.forwards = make(map[string]net.Listener)
	}
	f.forwards[key] = listener
	f.mu.Unlock()

	go f.acceptLoop(listener, bindAddr, actualPort, conn)
	return actualPort, nil
}

// StopRemoteForward cancels a previously-started remote forward.
func (f *DefaultTcpForwarder) StopRemoteForward(bindAddr string, bindPort uint32, conn *ssh.ServerConn) error {
	key := forwardKey(bindAddr, bindPort)
	f.mu.Lock()
	listener, ok := f.forwards[key]
	if ok {
		delete(f.forwards, key)
	}
	f.mu.Unlock()
	if !ok {
		return fmt.Errorf("no such forward: %s", key)
	}
	return listener.Close()
}

// acceptLoop runs until the listener is closed, forwarding each accepted
// connection as a forwarded-tcpip channel on conn.
func (f *DefaultTcpForwarder) acceptLoop(listener net.Listener, bindAddr string, bindPort uint32, conn *ssh.ServerConn) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go f.dispatchForwarded(raw, bindAddr, bindPort, conn)
	}
}

// dispatchForwarded opens a forwarded-tcpip channel for the newly accepted
// connection and proxies bytes between the two.
func (f *DefaultTcpForwarder) dispatchForwarded(raw net.Conn, bindAddr string, bindPort uint32, conn *ssh.ServerConn) {
	origin := raw.RemoteAddr().(*net.TCPAddr)
	payload := ssh.Marshal(&struct {
		BindAddr   string
		BindPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		BindAddr:   bindAddr,
		BindPort:   bindPort,
		OriginAddr: origin.IP.String(),
		OriginPort: uint32(origin.Port),
	})

	ch, reqs, err := conn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		raw.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go pipeClose(raw, ch)
	go pipeClose(ch, raw)
}

// permitOpenAllows returns true if dest matches the PermitOpen policy.
// An empty or unset policy allows all destinations.
func permitOpenAllows(dest string, permits []string) bool {
	if len(permits) == 0 {
		return true
	}
	for _, p := range permits {
		switch p {
		case "any":
			return true
		case "none":
			return false
		}
		if p == dest {
			return true
		}
	}
	return false
}

// permitListenAllows returns true if bindAddr:bindPort matches PermitListen.
func permitListenAllows(bindAddr string, bindPort uint32, permits []string) bool {
	if len(permits) == 0 {
		return true
	}
	key := net.JoinHostPort(bindAddr, strconv.Itoa(int(bindPort)))
	for _, p := range permits {
		switch p {
		case "any":
			return true
		case "none":
			return false
		}
		if p == key || p == strconv.Itoa(int(bindPort)) {
			return true
		}
	}
	return false
}

// forwardKey canonicalizes the (bindAddr, bindPort) pair for map lookup.
func forwardKey(bindAddr string, bindPort uint32) string {
	return net.JoinHostPort(bindAddr, strconv.Itoa(int(bindPort)))
}

// pipeClose copies src into dst and closes dst (if it is a ReadCloser or
// WriteCloser) when the copy finishes. Errors from io.Copy are ignored
// because both sides of a pipe commonly report "use of closed connection"
// during orderly shutdown.
func pipeClose(dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)
	if wc, ok := dst.(io.Closer); ok {
		_ = wc.Close()
	}
	if rc, ok := src.(io.Closer); ok {
		_ = rc.Close()
	}
}
