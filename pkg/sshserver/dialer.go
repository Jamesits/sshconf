package sshserver

import (
	"github.com/jamesits/sshconf/pkg/dialer"
)

func (opts *Options) buildDialerConfig() dialer.DialConfig {
	cfg := dialer.DialConfig{}
	if opts.AddressFamily != nil {
		cfg.AddressFamily = *opts.AddressFamily
	}
	if opts.BindInterface != nil {
		cfg.BindInterface = *opts.BindInterface
	}
	if opts.IPQoS != nil {
		cfg.IPQoS = *opts.IPQoS
	}
	return cfg
}

// RefreshDialerConfig rebuilds DialerConfig from the parsed server options.
func (opts *Options) RefreshDialerConfig() {
	wrapper := opts.DialerConfig.Wrapper
	opts.DialerConfig = opts.buildDialerConfig()
	opts.DialerConfig.Wrapper = wrapper
}

// GetDialerConfig returns the stored dialer configuration. Resolve populates
// this field, and callers may adjust it before starting any action.
func (opts *Options) GetDialerConfig() dialer.DialConfig {
	return opts.DialerConfig
}

// GetDialer returns the server-side outbound dialer derived from the
// resolved configuration.
func (opts *Options) GetDialer() dialer.Dialer {
	return opts.DialerConfig.GetDialer()
}
