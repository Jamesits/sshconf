package sshkeyscan

import (
	"strconv"
	"strings"

	"github.com/jamesits/sshconf/pkg/dialer"
)

// Config holds parsed ssh-keyscan command-line arguments.
type Config struct {
	AddressFamily string   // "any", "inet", "inet6"
	Hosts         []string // positional host arguments
	HostFile      string   // -f
	Port          int      // -p
	Timeout       int      // -T (seconds)
	KeyTypes      []string // -t
	HashHosts     bool     // -H
	Verbose       bool     // -v
	Version       bool     // -V

	// DialerConfig is populated during Parse and can be adjusted by callers
	// before starting scans.
	DialerConfig dialer.DialConfig
}

// Parse populates cfg from command-line arguments.
// Fields set before calling Parse are preserved unless overridden.
// Default values: Port=22, Timeout=5.
func (cfg *Config) Parse(args ...string) error {
	if cfg.AddressFamily == "" {
		cfg.AddressFamily = "any"
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f":
			i++
			if i < len(args) {
				cfg.HostFile = args[i]
			}
		case "-p":
			i++
			if i < len(args) {
				cfg.Port, _ = strconv.Atoi(args[i])
			}
		case "-T":
			i++
			if i < len(args) {
				cfg.Timeout, _ = strconv.Atoi(args[i])
			}
		case "-t":
			i++
			if i < len(args) {
				cfg.KeyTypes = ParseKeyTypes(args[i])
			}
		case "-H":
			cfg.HashHosts = true
		case "-v":
			cfg.Verbose = true
		case "-4":
			cfg.AddressFamily = "inet"
		case "-6":
			cfg.AddressFamily = "inet6"
		case "-V":
			cfg.Version = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				cfg.Hosts = append(cfg.Hosts, args[i])
			}
		}
	}
	cfg.RefreshDialerConfig()
	return nil
}

// ParseKeyTypes translates user-friendly type names to SSH algorithm names.
func ParseKeyTypes(spec string) []string {
	var result []string
	for _, t := range strings.Split(spec, ",") {
		t = strings.TrimSpace(t)
		switch strings.ToLower(t) {
		case "rsa":
			result = append(result, "ssh-rsa")
		case "ecdsa":
			result = append(result, "ecdsa-sha2-nistp256")
		case "ed25519":
			result = append(result, "ssh-ed25519")
		default:
			result = append(result, t)
		}
	}
	return result
}
