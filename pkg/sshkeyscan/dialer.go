package sshkeyscan

import (
	"time"

	"github.com/jamesits/sshconf/pkg/dialer"
)

func (cfg *Config) buildDialerConfig() dialer.DialConfig {
	return dialer.DialConfig{
		AddressFamily:  cfg.AddressFamily,
		ConnectTimeout: time.Duration(cfg.Timeout) * time.Second,
	}
}

// RefreshDialerConfig rebuilds DialerConfig from the parsed scanner args.
func (cfg *Config) RefreshDialerConfig() {
	wrapper := cfg.DialerConfig.Wrapper
	cfg.DialerConfig = cfg.buildDialerConfig()
	cfg.DialerConfig.Wrapper = wrapper
}

// GetDialerConfig returns the stored dialer configuration. Parse populates
// this field, and callers may adjust it before starting any scan.
func (cfg *Config) GetDialerConfig() dialer.DialConfig {
	return cfg.DialerConfig
}

// GetDialer returns the scanner dialer derived from the parsed config.
func (cfg *Config) GetDialer() dialer.Dialer {
	return cfg.DialerConfig.GetDialer()
}
