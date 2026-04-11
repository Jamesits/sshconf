package sshclient

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh"
)

// SSHClientConfig converts the resolved Options into an ssh.ClientConfig
// ready for use with ssh.Dial or ssh.NewClientConn.
//
// The handlers parameter provides optional implementations for config
// options that cannot be automatically applied (proxy, forwarding,
// authentication prompts, host key confirmation, etc.). A zero-value
// Handlers preserves existing behavior.
func (opts *Options) SSHClientConfig(handlers Handlers) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{}

	// User
	if opts.User != nil {
		cfg.User = *opts.User
	}

	// Timeout
	if opts.ConnectTimeout != nil && *opts.ConnectTimeout > 0 {
		cfg.Timeout = time.Duration(*opts.ConnectTimeout) * time.Second
	}

	// Client version string
	if opts.VersionAddendum != nil && *opts.VersionAddendum != "none" {
		cfg.ClientVersion = "SSH-2.0-" + version.Version + " " + *opts.VersionAddendum
	} else {
		cfg.ClientVersion = "SSH-2.0-" + version.Version
	}

	// Crypto configuration
	if opts.Ciphers != nil {
		cfg.Config.Ciphers = ResolveCiphers(*opts.Ciphers)
	}
	if opts.KexAlgorithms != nil {
		cfg.Config.KeyExchanges = ResolveKexAlgorithms(*opts.KexAlgorithms)
	}
	if opts.MACs != nil {
		cfg.Config.MACs = ResolveMACs(*opts.MACs)
	}
	if opts.HostKeyAlgorithms != nil {
		cfg.HostKeyAlgorithms = ResolveHostKeyAlgorithms(*opts.HostKeyAlgorithms)
	}

	// RekeyLimit
	if opts.RekeyLimit != nil {
		bytes, _ := parseRekeyLimit(*opts.RekeyLimit)
		if bytes > 0 {
			cfg.Config.RekeyThreshold = bytes
		}
	}

	// Authentication methods
	authMethods, err := buildAuthMethods(opts, handlers)
	if err != nil {
		return nil, err
	}
	cfg.Auth = authMethods

	// Host key callback
	hostKeyCallback, err := buildHostKeyCallback(opts, handlers)
	if err != nil {
		return nil, err
	}
	cfg.HostKeyCallback = hostKeyCallback

	// Banner callback
	if handlers.UI != nil {
		cfg.BannerCallback = handlers.UI.BannerCallback
	} else if opts.BatchMode != nil && !*opts.BatchMode {
		// In non-batch mode, silently accept banners (caller can override)
		cfg.BannerCallback = func(message string) error { return nil }
	}

	return cfg, nil
}

// Dial establishes a network connection to the SSH server using the
// resolved configuration. It consults handlers in the following order:
//
//  1. Multiplexer.CheckExisting — returns an existing multiplexed connection
//  2. Dialer.Dial — custom connection logic (proxy, bind address, etc.)
//  3. Default net.DialTimeout — plain TCP connection
//
// If a Multiplexer returns an existing client, Dial returns nil (the caller
// should use the client returned by CheckExisting instead).
func (opts *Options) Dial(handlers Handlers) (net.Conn, error) {
	host := "localhost"
	if opts.Hostname != nil {
		host = *opts.Hostname
	}
	port := 22
	if opts.Port != nil {
		port = *opts.Port
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	timeout := 0 * time.Second
	if opts.ConnectTimeout != nil && *opts.ConnectTimeout > 0 {
		timeout = time.Duration(*opts.ConnectTimeout) * time.Second
	}

	// Use custom dialer if provided
	if handlers.Dialer != nil {
		return handlers.Dialer.Dial("tcp", addr, opts)
	}

	// Default: plain TCP connection
	if timeout > 0 {
		return net.DialTimeout("tcp", addr, timeout)
	}
	return net.Dial("tcp", addr)
}

// ConfigureSession applies session-related options to an SSH session
// by invoking the appropriate handlers.
//
// It calls handlers in the following order:
//  1. SessionConfigurator.ConfigureSession — TTY, env, command, timeouts
//  2. AgentForwarder.ForwardAgent — if ForwardAgent is enabled
//  3. X11Forwarder.ForwardX11 — if ForwardX11 is enabled
//  4. TerminalHandler.SetupTerminal — escape char, keystroke timing, etc.
func (opts *Options) ConfigureSession(client *ssh.Client, session *ssh.Session, handlers Handlers) error {
	if handlers.Session != nil {
		if err := handlers.Session.ConfigureSession(session, opts); err != nil {
			return fmt.Errorf("configuring session: %w", err)
		}
	}

	if handlers.AgentForwarding != nil && opts.ForwardAgent != nil && *opts.ForwardAgent != "no" {
		if err := handlers.AgentForwarding.ForwardAgent(client, session, opts); err != nil {
			return fmt.Errorf("setting up agent forwarding: %w", err)
		}
	}

	if handlers.X11Forwarding != nil && opts.ForwardX11 != nil && *opts.ForwardX11 {
		if err := handlers.X11Forwarding.ForwardX11(client, session, opts); err != nil {
			return fmt.Errorf("setting up X11 forwarding: %w", err)
		}
	}

	if handlers.Terminal != nil {
		if err := handlers.Terminal.SetupTerminal(opts); err != nil {
			return fmt.Errorf("setting up terminal: %w", err)
		}
	}

	return nil
}

// PostConnect performs post-connection setup by invoking the appropriate
// handlers. Call this after successfully establishing an SSH connection.
//
// It calls handlers in the following order:
//  1. Multiplexer.Register — register connection for multiplexing
//  2. ForwardHandler.SetupForwarding — local/remote/dynamic port forwarding
//  3. TunnelHandler.SetupTunnel — TUN/TAP tunnel forwarding
//  4. CommandExecutor.Execute — run LocalCommand if PermitLocalCommand is yes
func (opts *Options) PostConnect(client *ssh.Client, handlers Handlers) error {
	if handlers.Multiplexer != nil {
		if opts.ControlMaster != nil && *opts.ControlMaster != "no" {
			if err := handlers.Multiplexer.Register(client, opts); err != nil {
				return fmt.Errorf("registering multiplexed connection: %w", err)
			}
		}
	}

	if handlers.Forwarding != nil {
		if err := handlers.Forwarding.SetupForwarding(client, opts); err != nil {
			exitOnFail := opts.ExitOnForwardFailure != nil && *opts.ExitOnForwardFailure
			if exitOnFail {
				return fmt.Errorf("setting up forwarding: %w", err)
			}
			if handlers.Logger != nil {
				handlers.Logger.Log("ERROR", fmt.Sprintf("forwarding setup failed: %v", err))
			}
		}
	}

	if handlers.Tunnel != nil && opts.Tunnel != nil && *opts.Tunnel != "no" {
		if err := handlers.Tunnel.SetupTunnel(client, opts); err != nil {
			return fmt.Errorf("setting up tunnel: %w", err)
		}
	}

	if handlers.CommandExecutor != nil {
		if opts.PermitLocalCommand != nil && *opts.PermitLocalCommand && opts.LocalCommand != nil && *opts.LocalCommand != "" {
			if err := handlers.CommandExecutor.Execute(*opts.LocalCommand); err != nil {
				if handlers.Logger != nil {
					handlers.Logger.Log("ERROR", fmt.Sprintf("LocalCommand failed: %v", err))
				}
			}
		}
	}

	return nil
}
