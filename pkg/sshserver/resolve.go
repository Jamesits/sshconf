package sshserver

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/jamesits/sshconf/pkg/sshconfig"
)

// Lookup specifies the inputs for SSH daemon configuration resolution.
// At boot time many fields are zero; per-connection re-resolution fills in
// the RemoteAddr / LocalAddr / User fields to allow Match blocks to fire.
type Lookup struct {
	// ConfigFile is the path to sshd_config.
	// Empty means /etc/ssh/sshd_config.
	ConfigFile string

	// CommandLineDirectives are pre-parsed directives from CLI flags,
	// highest priority. Applied before CommandLineOptions.
	CommandLineDirectives []sshconfig.Directive

	// CommandLineOptions are raw -o "Key=Value" strings from the -o flag.
	CommandLineOptions []string

	// --- Per-connection Match context ---

	// User is the authenticating user (empty during boot).
	User string
	// Groups are the user's groups.
	Groups []string
	// Host is the DNS-resolved client hostname (empty if UseDNS=no).
	Host string
	// RemoteAddr is the client address in "ip:port" or bare IP form.
	RemoteAddr string
	// LocalAddr is the server address the client connected to.
	LocalAddr string
	// LocalPort is the server port.
	LocalPort int
	// RDomain is the routing domain.
	RDomain string
	// InvalidUser indicates an unknown account.
	InvalidUser bool

	// Version is the server version string (for Match version).
	Version string

	// ExecFunc evaluates "Match exec" commands. If nil, exec conditions
	// always evaluate to false.
	ExecFunc func(cmd string) bool
}

// Resolve applies the sshd configuration resolution algorithm:
//  1. Command-line directives (-f/-o flags)
//  2. Config file
//  3. Defaults
//
// For each matching block, first-value-wins for scalar options.
// Multi-value options (HostKey, ListenAddress, etc.) are accumulated.
func (l *Lookup) Resolve() (*Options, error) {
	opts := &Options{}

	// 1. Build command-line entries from pre-parsed directives and -o overrides
	var cliEntries []sshconfig.Entry
	for _, dir := range l.CommandLineDirectives {
		cliEntries = append(cliEntries, sshconfig.Entry{
			Directive: dir,
		})
	}
	for i, optStr := range l.CommandLineOptions {
		keyword, value, err := sshconfig.ParseOverride(optStr)
		if err != nil {
			return nil, fmt.Errorf("-o option %d: %w", i+1, err)
		}
		cliEntries = append(cliEntries, sshconfig.Entry{
			Directive: sshconfig.Directive{
				Keyword: keyword,
				Value:   value,
				Source: sshconfig.SourceInfo{
					File: "command-line",
					Line: i + 1,
				},
			},
		})
	}

	// 2. Parse config file
	configFile := l.ConfigFile
	if configFile == "" {
		configFile = "/etc/ssh/sshd_config"
	}
	var fileEntries []sshconfig.Entry
	if _, err := os.Stat(configFile); err == nil {
		fileEntries, err = sshconfig.ParseFile(configFile, sshconfig.ParseOptions{
			BaseDir: filepath.Dir(configFile),
			IsUser:  false,
		})
		if err != nil {
			return nil, fmt.Errorf("parsing config %s: %w", configFile, err)
		}
	}

	// Concatenate all entries in priority order: CLI first, then file.
	var allEntries []sshconfig.Entry
	allEntries = append(allEntries, cliEntries...)
	allEntries = append(allEntries, fileEntries...)

	// Build the match context.
	matchCtx := l.buildMatchContext()

	// Apply matching entries.
	for _, entry := range allEntries {
		if !sshconfig.EvaluateConditions(entry.Conditions, matchCtx) {
			continue
		}
		if err := opts.ApplyDirective(entry.Directive); err != nil {
			return nil, err
		}
	}

	// Apply defaults.
	applyDefaults(opts)

	// Expand tokens in path-valued options.
	expandPathTokens(opts, l)

	return opts, nil
}

// buildMatchContext constructs a MatchContext suitable for evaluating
// both ssh_config-style conditions (rarely used on the server) and
// sshd_config conditions.
func (l *Lookup) buildMatchContext() *sshconfig.MatchContext {
	version := l.Version
	if version == "" {
		version = "sshconf"
	}

	var localUser string
	if u, err := user.Current(); err == nil {
		localUser = u.Username
	}

	remoteIPStr, remotePort := splitAddr(l.RemoteAddr)
	localIPStr, lp := splitAddr(l.LocalAddr)
	remoteIP := net.ParseIP(remoteIPStr)
	localIP := net.ParseIP(localIPStr)

	localPortStr := strconv.Itoa(l.LocalPort)
	if l.LocalPort == 0 && lp != "" {
		localPortStr = lp
	}

	return &sshconfig.MatchContext{
		User:         l.User,
		Groups:       l.Groups,
		Host:         l.Host,
		OriginalHost: l.Host,
		LocalUser:    localUser,
		Port:         strconv.Itoa(portOrDefault(remotePort, 22)),
		Version:      version,
		RemoteAddr:   remoteIPStr,
		RemoteAddrIP: remoteIP,
		LocalAddr:    localIPStr,
		LocalAddrIP:  localIP,
		LocalPort:    localPortStr,
		RDomain:      l.RDomain,
		InvalidUser:  l.InvalidUser,
		ExecFunc:     l.ExecFunc,
	}
}

// splitAddr splits "ip:port" while tolerating bracketed IPv6 and bare IPs.
func splitAddr(s string) (ip, port string) {
	if s == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return s, ""
}

func portOrDefault(s string, d int) int {
	if s == "" {
		return d
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return d
}

// expandPathTokens expands tilde and %-tokens in path-valued options.
// sshd_config tokens use different semantics than ssh_config and are
// generally applied at use time (e.g. AuthorizedKeysFile per-user).
// Here we only expand boot-time paths (HostKey, HostCertificate, ...).
func expandPathTokens(opts *Options, l *Lookup) {
	homeDir := ""
	if h, err := os.UserHomeDir(); err == nil {
		homeDir = h
	}

	expand := func(s string) string {
		return sshconfig.ExpandTilde(s, homeDir)
	}

	for i := range opts.HostKey {
		opts.HostKey[i] = expand(opts.HostKey[i])
	}
	for i := range opts.HostCertificate {
		opts.HostCertificate[i] = expand(opts.HostCertificate[i])
	}
	if opts.HostKeyAgent != nil {
		*opts.HostKeyAgent = expand(*opts.HostKeyAgent)
	}
	if opts.PidFile != nil {
		*opts.PidFile = expand(*opts.PidFile)
	}
	if opts.Banner != nil {
		*opts.Banner = expand(*opts.Banner)
	}
	if opts.TrustedUserCAKeys != nil {
		*opts.TrustedUserCAKeys = expand(*opts.TrustedUserCAKeys)
	}
	if opts.RevokedKeys != nil {
		*opts.RevokedKeys = expand(*opts.RevokedKeys)
	}
	if opts.ModuliFile != nil {
		*opts.ModuliFile = expand(*opts.ModuliFile)
	}
}
