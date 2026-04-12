package sshclient

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/jamesits/sshconf/pkg/dialer"
)

func (opts *Options) buildDialerConfig() DialConfig {
	cfg := dialer.DialConfig{}
	if opts.AddressFamily != nil {
		cfg.AddressFamily = *opts.AddressFamily
	}
	if opts.BindAddress != nil {
		cfg.BindAddress = *opts.BindAddress
	}
	if opts.BindInterface != nil {
		cfg.BindInterface = *opts.BindInterface
	}
	if opts.ConnectTimeout != nil && *opts.ConnectTimeout > 0 {
		cfg.ConnectTimeout = time.Duration(*opts.ConnectTimeout) * time.Second
	}
	if opts.IPQoS != nil {
		cfg.IPQoS = *opts.IPQoS
	}
	if opts.ProxyCommand != nil {
		cfg.ProxyCommand = *opts.ProxyCommand
	}
	if opts.ProxyJump != nil {
		cfg.ProxyJump = *opts.ProxyJump
	}
	if opts.ProxyUseFdpass != nil {
		cfg.ProxyUseFdpass = *opts.ProxyUseFdpass
	}
	return cfg
}

// RefreshDialerConfig rebuilds DialerConfig from the parsed SSH options.
// Callers that change dialer-related fields after Resolve should call this
// to resync the derived dialer state.
func (opts *Options) RefreshDialerConfig() {
	wrapper := opts.DialerConfig.Wrapper
	opts.DialerConfig = opts.buildDialerConfig()
	opts.DialerConfig.Wrapper = wrapper
}

// GetDialerConfig returns the stored dialer configuration. Resolve populates
// this field, and callers may adjust it before starting any action.
func (opts *Options) GetDialerConfig() DialConfig {
	return opts.DialerConfig
}

// GetDialer returns the outbound SSH dialer derived from the stored dialer
// configuration.
func (opts *Options) GetDialer() Dialer {
	return opts.DialerConfig.GetDialer()
}

// Dial remains as a convenience wrapper around GetDialer for callers that
// want the resolved target connection directly.
func (opts *Options) Dial() (net.Conn, error) {
	host := "localhost"
	if opts.Hostname != nil {
		host = *opts.Hostname
	}
	port := 22
	if opts.Port != nil {
		port = *opts.Port
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	return opts.DialerConfig.GetDialer().DialContext(context.Background(), "tcp", addr)
}
