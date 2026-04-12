package forward

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/jamesits/sshconf/pkg/sshclient"
	"golang.org/x/crypto/ssh"
)

// Handler implements sshclient.ForwardHandler.
type Handler struct {
	Logger sshclient.Logger
}

// NewHandler creates a Handler with the given logger.
func NewHandler(logger sshclient.Logger) *Handler {
	return &Handler{Logger: logger}
}

// SetupForwarding sets up local, remote, and dynamic port forwarding.
func (h *Handler) SetupForwarding(sshClient *ssh.Client, opts *sshclient.Options) error {
	bindHost := "127.0.0.1"
	if opts.GatewayPorts != nil && *opts.GatewayPorts {
		bindHost = ""
	}

	var firstErr error
	setErr := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	for _, fwd := range opts.LocalForward {
		if err := h.setupLocalForward(sshClient, fwd, bindHost); err != nil {
			h.logf("Warning: Could not set up local forwarding %s:%s -> %s:%s: %v",
				fwd.BindAddress, fwd.BindPort, fwd.Host, fwd.HostPort, err)
			setErr(err)
		}
	}

	for _, fwd := range opts.RemoteForward {
		if err := h.setupRemoteForward(sshClient, opts, fwd, bindHost); err != nil {
			h.logf("Warning: Could not set up remote forwarding %s:%s -> %s:%s: %v",
				fwd.BindAddress, fwd.BindPort, fwd.Host, fwd.HostPort, err)
			setErr(err)
		}
	}

	for _, spec := range opts.DynamicForward {
		if err := h.setupDynamicForward(sshClient, spec, bindHost); err != nil {
			h.logf("Warning: Could not set up dynamic forwarding %s: %v", spec, err)
			setErr(err)
		}
	}

	return firstErr
}

func (h *Handler) setupLocalForward(sshClient *ssh.Client, fwd sshclient.Forward, defaultBind string) error {
	bind := defaultBind
	if fwd.BindAddress != "" {
		bind = fwd.BindAddress
	}
	listenAddr := net.JoinHostPort(bind, fwd.BindPort)
	targetAddr := net.JoinHostPort(fwd.Host, fwd.HostPort)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	h.logf("Local forwarding: %s -> %s", listenAddr, targetAddr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				remote, err := sshClient.Dial("tcp", targetAddr)
				if err != nil {
					h.logf("Failed to dial remote %s: %v", targetAddr, err)
					return
				}
				defer remote.Close()
				BiCopy(conn, remote)
			}(conn)
		}
	}()

	return nil
}

func (h *Handler) setupRemoteForward(sshClient *ssh.Client, opts *sshclient.Options, fwd sshclient.Forward, defaultBind string) error {
	bind := defaultBind
	if fwd.BindAddress != "" {
		bind = fwd.BindAddress
	}
	listenAddr := net.JoinHostPort(bind, fwd.BindPort)
	targetAddr := net.JoinHostPort(fwd.Host, fwd.HostPort)

	listener, err := sshClient.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("remote listen on %s: %w", listenAddr, err)
	}

	h.logf("Remote forwarding: %s -> %s", listenAddr, targetAddr)
	dialer := opts.DialerConfig.GetDialer()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				local, err := dialer.DialContext(context.Background(), "tcp", targetAddr)
				if err != nil {
					h.logf("Failed to dial local %s: %v", targetAddr, err)
					return
				}
				defer local.Close()
				BiCopy(conn, local)
			}(conn)
		}
	}()

	return nil
}

func (h *Handler) setupDynamicForward(sshClient *ssh.Client, spec string, defaultBind string) error {
	bind, port := parseDynamicSpec(spec, defaultBind)
	listenAddr := net.JoinHostPort(bind, port)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	h.logf("Dynamic forwarding (SOCKS5): %s", listenAddr)

	srv := newSOCKS5Server(sshClient)
	go srv.Serve(listener)

	return nil
}

func (h *Handler) logf(format string, args ...any) {
	if h.Logger != nil {
		h.Logger.Log("INFO", fmt.Sprintf(format, args...))
	}
}

// BiCopy copies data bidirectionally between two read-write-closers.
func BiCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}
