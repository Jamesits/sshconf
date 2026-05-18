package sshclient

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/jamesits/sshconf/pkg/sshconfig"
	versionpkg "github.com/jamesits/sshconf/pkg/version"
)

// Lookup specifies the inputs for SSH client configuration resolution.
type Lookup struct {
	// Host is the target hostname (may be overridden by Hostname directive).
	Host string
	// User is the target username (from command line; may be overridden by User directive).
	User string
	// Port is the target port from command line. 0 means not specified.
	Port int

	// OriginalHost is the hostname exactly as given on the command line.
	// If empty, defaults to Host.
	OriginalHost string
	// LocalUser is the local username. If empty, detected from OS.
	LocalUser string
	// Command is the remote command (for Match command criteria).
	Command string
	// Tag is the initial tag (from -P flag).
	Tag string
	// SessionType is one of "shell", "exec", "subsystem", "none".
	// If empty, defaults to "default".
	SessionType string
	// Version is the client version string for Match version.
	// If empty, defaults to a reasonable value.
	Version string

	// CommandLineDirectives are pre-parsed directives from CLI flags, highest priority.
	// These are applied before CommandLineOptions.
	CommandLineDirectives []sshconfig.Directive

	// CommandLineOptions are raw -o "Key=Value" strings, highest priority.
	CommandLineOptions []string

	// UserConfigFile is the path to the user config file.
	// Empty means ~/.ssh/config.
	UserConfigFile string
	// SystemConfigFile is the path to the system config file.
	// Empty means /etc/ssh/ssh_config.
	SystemConfigFile string

	// ExecFunc evaluates "Match exec" commands. If nil, exec conditions
	// always evaluate to false.
	ExecFunc func(cmd string) bool

	// Handlers provide optional implementations for config options that
	// cannot be automatically applied. During resolution, the
	// HostCanonicalizer and CommandExecutor handlers are consulted if set.
	Handlers Handlers
}

// Resolve applies the SSH configuration resolution algorithm:
//  1. Command-line -o overrides (highest priority)
//  2. User config file (~/.ssh/config)
//  3. System config file (/etc/ssh/ssh_config)
//  4. Defaults (lowest priority)
//
// For each matching block, first-value-wins for scalar options.
// Multi-value options (IdentityFile, etc.) are accumulated.
func (l *Lookup) Resolve() (*Options, error) {
	opts := &Options{}

	// Populate context defaults
	localUser := l.LocalUser
	if localUser == "" {
		if u, err := user.Current(); err == nil {
			localUser = u.Username
		}
	}
	homeDir := ""
	if h, err := os.UserHomeDir(); err == nil {
		homeDir = h
	}

	originalHost := l.OriginalHost
	if originalHost == "" {
		originalHost = l.Host
	}

	version := l.Version
	if version == "" {
		version = versionpkg.Version
	}

	// 1. Build command-line entries from pre-parsed directives and -o overrides
	var cliEntries []sshconfig.Entry
	for _, dir := range l.CommandLineDirectives {
		cliEntries = append(cliEntries, sshconfig.Entry{
			Conditions: nil, // unconditional
			Directive:  dir,
		})
	}
	overrides, err := ParseOverrides(l.CommandLineOptions)
	if err != nil {
		return nil, fmt.Errorf("parsing overrides: %w", err)
	}

	// 2. Parse user config
	userConfigFile := l.UserConfigFile
	if userConfigFile == "" {
		userConfigFile = filepath.Join(homeDir, ".ssh", "config")
	}
	var userEntries []sshconfig.Entry
	if _, err := os.Stat(userConfigFile); err == nil {
		userEntries, err = sshconfig.ParseFile(userConfigFile, sshconfig.ParseOptions{
			BaseDir: filepath.Dir(userConfigFile),
			IsUser:  true,
			HomeDir: homeDir,
		})
		if err != nil {
			return nil, fmt.Errorf("parsing user config %s: %w", userConfigFile, err)
		}
	}

	// 3. Parse system config
	systemConfigFile := l.SystemConfigFile
	if systemConfigFile == "" {
		systemConfigFile = "/etc/ssh/ssh_config"
	}
	var systemEntries []sshconfig.Entry
	if _, err := os.Stat(systemConfigFile); err == nil {
		systemEntries, err = sshconfig.ParseFile(systemConfigFile, sshconfig.ParseOptions{
			BaseDir: filepath.Dir(systemConfigFile),
			IsUser:  false,
			HomeDir: homeDir,
		})
		if err != nil {
			return nil, fmt.Errorf("parsing system config %s: %w", systemConfigFile, err)
		}
	}

	// Concatenate all entries in priority order
	var allEntries []sshconfig.Entry
	allEntries = append(allEntries, cliEntries...)
	allEntries = append(allEntries, overrides...)
	allEntries = append(allEntries, userEntries...)
	allEntries = append(allEntries, systemEntries...)

	// Get local addresses for Match localnetwork
	localAddresses := getLocalAddresses()

	// Build the initial match context
	port := l.Port
	if port == 0 {
		port = 22
	}
	matchCtx := &sshconfig.MatchContext{
		User:           l.User,
		Host:           l.Host,
		OriginalHost:   originalHost,
		LocalUser:      localUser,
		Port:           strconv.Itoa(port),
		Command:        l.Command,
		Tag:            l.Tag,
		Version:        version,
		SessionType:    l.SessionType,
		ExecFunc:       l.execFunc(),
		LocalAddresses: localAddresses,
	}

	// Apply matching entries
	for _, entry := range allEntries {
		if !sshconfig.EvaluateConditions(entry.Conditions, matchCtx) {
			continue
		}
		if err := opts.ApplyDirective(entry.Directive); err != nil {
			return nil, err
		}
		// Update match context as values are resolved so that later "Match
		// user"/"Match tagged" criteria see the resolved value, mirroring
		// OpenSSH's first-match-wins behavior for options->user etc.
		//
		// We intentionally do NOT mirror opts.Hostname into matchCtx.Host:
		// the host argument used for Host/Match-host pattern matching is the
		// command-line alias (or, on the canonical pass, the canonicalized
		// name) - never the value substituted by a HostName directive.
		// Updating it mid-loop would cause every directive that follows
		// HostName in the same block to fail its enclosing Host pattern
		// check and be silently dropped.
		if opts.User != nil && matchCtx.User == "" {
			matchCtx.User = *opts.User
		}
		if opts.Tag != nil {
			matchCtx.Tag = *opts.Tag
		}
	}

	// Set Hostname to the command-line host if not set by config
	if opts.Hostname == nil {
		opts.Hostname = strPtr(l.Host)
	}

	// Set User from command line or local user if not set by config
	if opts.User == nil {
		if l.User != "" {
			opts.User = strPtr(l.User)
		} else {
			opts.User = strPtr(localUser)
		}
	}

	// Handle canonicalization (re-parse with canonical flag)
	if opts.CanonicalizeHostname != nil && (*opts.CanonicalizeHostname == "yes" || *opts.CanonicalizeHostname == "always") {
		var canonHost string
		if l.Handlers.HostCanonicalizer != nil {
			if h, err := l.Handlers.HostCanonicalizer.Canonicalize(*opts.Hostname, opts); err == nil {
				canonHost = h
			}
		} else {
			canonHost = canonicalizeHost(*opts.Hostname, opts.CanonicalDomains, opts.CanonicalizeMaxDots)
		}
		if canonHost != "" {
			opts.Hostname = strPtr(canonHost)
			// Re-apply with canonical context
			canonOpts := &Options{}
			matchCtx.Host = canonHost
			matchCtx.IsCanonical = true
			for _, entry := range allEntries {
				if !sshconfig.EvaluateConditions(entry.Conditions, matchCtx) {
					continue
				}
				if err := canonOpts.ApplyDirective(entry.Directive); err != nil {
					return nil, err
				}
			}
			// Merge canonical results (only set unset fields)
			mergeOptions(opts, canonOpts)
		}
	}

	// Handle "Match final" pass
	finalOpts := &Options{}
	matchCtx.IsFinal = true
	for _, entry := range allEntries {
		if !sshconfig.EvaluateConditions(entry.Conditions, matchCtx) {
			continue
		}
		if err := finalOpts.ApplyDirective(entry.Directive); err != nil {
			return nil, err
		}
	}
	mergeOptions(opts, finalOpts)

	// Apply command-line port if specified (overrides config)
	if l.Port != 0 {
		opts.Port = intPtr(l.Port)
	}

	// 4. Apply defaults as the final step
	applyDefaults(opts)

	// Handle ClearAllForwardings
	if opts.ClearAllForwardings != nil && *opts.ClearAllForwardings {
		opts.LocalForward = nil
		opts.RemoteForward = nil
		opts.DynamicForward = nil
	}

	// Check RefuseConnection
	if opts.RefuseConnection != nil {
		return nil, fmt.Errorf("connection refused: %s", *opts.RefuseConnection)
	}

	// Expand tokens and tilde in paths
	tokenCtx := &sshconfig.TokenContext{
		RemoteHost:   *opts.Hostname,
		RemotePort:   strconv.Itoa(*opts.Port),
		RemoteUser:   *opts.User,
		LocalUser:    localUser,
		HomeDir:      homeDir,
		OriginalHost: originalHost,
	}
	if hn, err := os.Hostname(); err == nil {
		tokenCtx.LocalHost = hn
		tokenCtx.LocalHostFQDN = hn
	}
	if uid := os.Getuid(); uid >= 0 {
		tokenCtx.LocalUserID = strconv.Itoa(uid)
	}
	if opts.ProxyJump != nil {
		tokenCtx.ProxyJump = *opts.ProxyJump
	}
	if opts.HostKeyAlias != nil {
		tokenCtx.HostKeyAlias = *opts.HostKeyAlias
	} else {
		tokenCtx.HostKeyAlias = originalHost
	}

	expandPathTokens(opts, tokenCtx, homeDir)
	opts.RefreshDialerConfig()

	return opts, nil
}

// expandPathTokens expands tokens and tilde in path-valued options.
func expandPathTokens(opts *Options, ctx *sshconfig.TokenContext, homeDir string) {
	expandStrPtr := func(p *string) {
		if p != nil && *p != "" && *p != "none" {
			*p = sshconfig.ExpandTokens(*p, ctx)
			*p = sshconfig.ExpandTilde(*p, homeDir)
		}
	}

	expandStrSlice := func(s []string) {
		for i := range s {
			s[i] = sshconfig.ExpandTokens(s[i], ctx)
			s[i] = sshconfig.ExpandTilde(s[i], homeDir)
		}
	}

	expandStrPtr(opts.ControlPath)
	expandStrPtr(opts.IdentityAgent)
	expandStrPtr(opts.KnownHostsCommand)
	expandStrPtr(opts.LocalCommand)
	expandStrPtr(opts.RemoteCommand)
	expandStrPtr(opts.RevokedHostKeys)
	expandStrSlice(opts.IdentityFile)
	expandStrSlice(opts.CertificateFile)

	// Expand space-separated path lists
	if opts.UserKnownHostsFile != nil {
		*opts.UserKnownHostsFile = sshconfig.ExpandTokens(*opts.UserKnownHostsFile, ctx)
		*opts.UserKnownHostsFile = expandPathList(*opts.UserKnownHostsFile, homeDir)
	}
	if opts.GlobalKnownHostsFile != nil {
		*opts.GlobalKnownHostsFile = sshconfig.ExpandTokens(*opts.GlobalKnownHostsFile, ctx)
		*opts.GlobalKnownHostsFile = expandPathList(*opts.GlobalKnownHostsFile, homeDir)
	}

	// Expand tokens in ProxyCommand and ProxyJump (limited token set)
	if opts.ProxyCommand != nil && *opts.ProxyCommand != "none" {
		*opts.ProxyCommand = sshconfig.ExpandTokens(*opts.ProxyCommand, ctx)
	}
	if opts.ProxyJump != nil && *opts.ProxyJump != "none" {
		*opts.ProxyJump = sshconfig.ExpandTokens(*opts.ProxyJump, ctx)
	}

	// Hostname accepts only %% and %h
	if opts.Hostname != nil {
		*opts.Hostname = sshconfig.ExpandTokens(*opts.Hostname, ctx)
	}
}

// expandPathList expands tilde in each space-separated path.
func expandPathList(paths string, homeDir string) string {
	fields := sshconfig.SplitFields(paths)
	for i := range fields {
		fields[i] = sshconfig.ExpandTilde(fields[i], homeDir)
	}
	result := ""
	for i, f := range fields {
		if i > 0 {
			result += " "
		}
		result += f
	}
	return result
}

// mergeOptions copies values from src into dst where dst fields are nil.
func mergeOptions(dst, src *Options) {
	// Scalar fields: only set if nil in dst
	if dst.AddressFamily == nil {
		dst.AddressFamily = src.AddressFamily
	}
	if dst.BatchMode == nil {
		dst.BatchMode = src.BatchMode
	}
	if dst.BindAddress == nil {
		dst.BindAddress = src.BindAddress
	}
	if dst.BindInterface == nil {
		dst.BindInterface = src.BindInterface
	}
	if dst.ConnectTimeout == nil {
		dst.ConnectTimeout = src.ConnectTimeout
	}
	if dst.ConnectionAttempts == nil {
		dst.ConnectionAttempts = src.ConnectionAttempts
	}
	if dst.TCPKeepAlive == nil {
		dst.TCPKeepAlive = src.TCPKeepAlive
	}
	if dst.ServerAliveInterval == nil {
		dst.ServerAliveInterval = src.ServerAliveInterval
	}
	if dst.ServerAliveCountMax == nil {
		dst.ServerAliveCountMax = src.ServerAliveCountMax
	}
	if dst.Compression == nil {
		dst.Compression = src.Compression
	}
	if dst.Hostname == nil {
		dst.Hostname = src.Hostname
	}
	if dst.Port == nil {
		dst.Port = src.Port
	}
	if dst.CanonicalizeFallbackLocal == nil {
		dst.CanonicalizeFallbackLocal = src.CanonicalizeFallbackLocal
	}
	if dst.CanonicalizeHostname == nil {
		dst.CanonicalizeHostname = src.CanonicalizeHostname
	}
	if dst.CanonicalizeMaxDots == nil {
		dst.CanonicalizeMaxDots = src.CanonicalizeMaxDots
	}
	if dst.User == nil {
		dst.User = src.User
	}
	if dst.IdentitiesOnly == nil {
		dst.IdentitiesOnly = src.IdentitiesOnly
	}
	if dst.IdentityAgent == nil {
		dst.IdentityAgent = src.IdentityAgent
	}
	if dst.PasswordAuthentication == nil {
		dst.PasswordAuthentication = src.PasswordAuthentication
	}
	if dst.KbdInteractiveAuthentication == nil {
		dst.KbdInteractiveAuthentication = src.KbdInteractiveAuthentication
	}
	if dst.KbdInteractiveDevices == nil {
		dst.KbdInteractiveDevices = src.KbdInteractiveDevices
	}
	if dst.PubkeyAuthentication == nil {
		dst.PubkeyAuthentication = src.PubkeyAuthentication
	}
	if dst.PubkeyAcceptedAlgorithms == nil {
		dst.PubkeyAcceptedAlgorithms = src.PubkeyAcceptedAlgorithms
	}
	if dst.PreferredAuthentications == nil {
		dst.PreferredAuthentications = src.PreferredAuthentications
	}
	if dst.NumberOfPasswordPrompts == nil {
		dst.NumberOfPasswordPrompts = src.NumberOfPasswordPrompts
	}
	if dst.HostbasedAuthentication == nil {
		dst.HostbasedAuthentication = src.HostbasedAuthentication
	}
	if dst.HostbasedAcceptedAlgorithms == nil {
		dst.HostbasedAcceptedAlgorithms = src.HostbasedAcceptedAlgorithms
	}
	if dst.EnableSSHKeysign == nil {
		dst.EnableSSHKeysign = src.EnableSSHKeysign
	}
	if dst.GSSAPIAuthentication == nil {
		dst.GSSAPIAuthentication = src.GSSAPIAuthentication
	}
	if dst.GSSAPIDelegateCredentials == nil {
		dst.GSSAPIDelegateCredentials = src.GSSAPIDelegateCredentials
	}
	if dst.AddKeysToAgent == nil {
		dst.AddKeysToAgent = src.AddKeysToAgent
	}
	if dst.Ciphers == nil {
		dst.Ciphers = src.Ciphers
	}
	if dst.KexAlgorithms == nil {
		dst.KexAlgorithms = src.KexAlgorithms
	}
	if dst.MACs == nil {
		dst.MACs = src.MACs
	}
	if dst.CASignatureAlgorithms == nil {
		dst.CASignatureAlgorithms = src.CASignatureAlgorithms
	}
	if dst.HostKeyAlgorithms == nil {
		dst.HostKeyAlgorithms = src.HostKeyAlgorithms
	}
	if dst.RekeyLimit == nil {
		dst.RekeyLimit = src.RekeyLimit
	}
	if dst.RequiredRSASize == nil {
		dst.RequiredRSASize = src.RequiredRSASize
	}
	if dst.FingerprintHash == nil {
		dst.FingerprintHash = src.FingerprintHash
	}
	if dst.WarnWeakCrypto == nil {
		dst.WarnWeakCrypto = src.WarnWeakCrypto
	}
	if dst.CheckHostIP == nil {
		dst.CheckHostIP = src.CheckHostIP
	}
	if dst.GlobalKnownHostsFile == nil {
		dst.GlobalKnownHostsFile = src.GlobalKnownHostsFile
	}
	if dst.UserKnownHostsFile == nil {
		dst.UserKnownHostsFile = src.UserKnownHostsFile
	}
	if dst.HashKnownHosts == nil {
		dst.HashKnownHosts = src.HashKnownHosts
	}
	if dst.StrictHostKeyChecking == nil {
		dst.StrictHostKeyChecking = src.StrictHostKeyChecking
	}
	if dst.HostKeyAlias == nil {
		dst.HostKeyAlias = src.HostKeyAlias
	}
	if dst.KnownHostsCommand == nil {
		dst.KnownHostsCommand = src.KnownHostsCommand
	}
	if dst.RevokedHostKeys == nil {
		dst.RevokedHostKeys = src.RevokedHostKeys
	}
	if dst.UpdateHostKeys == nil {
		dst.UpdateHostKeys = src.UpdateHostKeys
	}
	if dst.VerifyHostKeyDNS == nil {
		dst.VerifyHostKeyDNS = src.VerifyHostKeyDNS
	}
	if dst.NoHostAuthenticationForLocalhost == nil {
		dst.NoHostAuthenticationForLocalhost = src.NoHostAuthenticationForLocalhost
	}
	if dst.ProxyCommand == nil {
		dst.ProxyCommand = src.ProxyCommand
	}
	if dst.ProxyJump == nil {
		dst.ProxyJump = src.ProxyJump
	}
	if dst.ProxyUseFdpass == nil {
		dst.ProxyUseFdpass = src.ProxyUseFdpass
	}
	if dst.ClearAllForwardings == nil {
		dst.ClearAllForwardings = src.ClearAllForwardings
	}
	if dst.ExitOnForwardFailure == nil {
		dst.ExitOnForwardFailure = src.ExitOnForwardFailure
	}
	if dst.GatewayPorts == nil {
		dst.GatewayPorts = src.GatewayPorts
	}
	if dst.StreamLocalBindMask == nil {
		dst.StreamLocalBindMask = src.StreamLocalBindMask
	}
	if dst.StreamLocalBindUnlink == nil {
		dst.StreamLocalBindUnlink = src.StreamLocalBindUnlink
	}
	if dst.ForwardAgent == nil {
		dst.ForwardAgent = src.ForwardAgent
	}
	if dst.ForwardX11 == nil {
		dst.ForwardX11 = src.ForwardX11
	}
	if dst.ForwardX11Timeout == nil {
		dst.ForwardX11Timeout = src.ForwardX11Timeout
	}
	if dst.ForwardX11Trusted == nil {
		dst.ForwardX11Trusted = src.ForwardX11Trusted
	}
	if dst.XAuthLocation == nil {
		dst.XAuthLocation = src.XAuthLocation
	}
	if dst.Tunnel == nil {
		dst.Tunnel = src.Tunnel
	}
	if dst.TunnelDevice == nil {
		dst.TunnelDevice = src.TunnelDevice
	}
	if dst.RequestTTY == nil {
		dst.RequestTTY = src.RequestTTY
	}
	if dst.SessionType == nil {
		dst.SessionType = src.SessionType
	}
	if dst.RemoteCommand == nil {
		dst.RemoteCommand = src.RemoteCommand
	}
	if dst.EscapeChar == nil {
		dst.EscapeChar = src.EscapeChar
	}
	if dst.IPQoS == nil {
		dst.IPQoS = src.IPQoS
	}
	if dst.LogLevel == nil {
		dst.LogLevel = src.LogLevel
	}
	if dst.Tag == nil {
		dst.Tag = src.Tag
	}
	if dst.ControlMaster == nil {
		dst.ControlMaster = src.ControlMaster
	}
	if dst.ControlPath == nil {
		dst.ControlPath = src.ControlPath
	}
	if dst.ControlPersist == nil {
		dst.ControlPersist = src.ControlPersist
	}
	if dst.PermitLocalCommand == nil {
		dst.PermitLocalCommand = src.PermitLocalCommand
	}
	if dst.LocalCommand == nil {
		dst.LocalCommand = src.LocalCommand
	}
	if dst.VisualHostKey == nil {
		dst.VisualHostKey = src.VisualHostKey
	}
	if dst.ForkAfterAuthentication == nil {
		dst.ForkAfterAuthentication = src.ForkAfterAuthentication
	}
	if dst.StdinNull == nil {
		dst.StdinNull = src.StdinNull
	}
	if dst.EnableEscapeCommandline == nil {
		dst.EnableEscapeCommandline = src.EnableEscapeCommandline
	}
	if dst.ObscureKeystrokeTiming == nil {
		dst.ObscureKeystrokeTiming = src.ObscureKeystrokeTiming
	}
	if dst.VersionAddendum == nil {
		dst.VersionAddendum = src.VersionAddendum
	}
	if dst.PKCS11Provider == nil {
		dst.PKCS11Provider = src.PKCS11Provider
	}
	if dst.SecurityKeyProvider == nil {
		dst.SecurityKeyProvider = src.SecurityKeyProvider
	}
	if dst.IgnoreUnknown == nil {
		dst.IgnoreUnknown = src.IgnoreUnknown
	}
	if dst.RefuseConnection == nil {
		dst.RefuseConnection = src.RefuseConnection
	}
	if dst.SyslogFacility == nil {
		dst.SyslogFacility = src.SyslogFacility
	}

	// Multi-value fields: accumulate from src
	dst.IdentityFile = append(dst.IdentityFile, src.IdentityFile...)
	dst.CertificateFile = append(dst.CertificateFile, src.CertificateFile...)
	dst.LocalForward = append(dst.LocalForward, src.LocalForward...)
	dst.RemoteForward = append(dst.RemoteForward, src.RemoteForward...)
	dst.DynamicForward = append(dst.DynamicForward, src.DynamicForward...)
	dst.SendEnv = append(dst.SendEnv, src.SendEnv...)
	dst.SetEnv = append(dst.SetEnv, src.SetEnv...)
	dst.LogVerbose = append(dst.LogVerbose, src.LogVerbose...)
	dst.ChannelTimeout = append(dst.ChannelTimeout, src.ChannelTimeout...)

	if dst.CanonicalDomains == nil {
		dst.CanonicalDomains = src.CanonicalDomains
	}
	if dst.CanonicalizePermittedCNAMEs == nil {
		dst.CanonicalizePermittedCNAMEs = src.CanonicalizePermittedCNAMEs
	}
	if dst.PermitRemoteOpen == nil {
		dst.PermitRemoteOpen = src.PermitRemoteOpen
	}
}

// canonicalizeHost attempts to canonicalize a hostname using the given domain suffixes.
func canonicalizeHost(host string, domains []string, maxDots *int) string {
	if len(domains) == 0 {
		return ""
	}

	// Count dots in host
	dots := 0
	for _, c := range host {
		if c == '.' {
			dots++
		}
	}

	max := 1
	if maxDots != nil {
		max = *maxDots
	}
	if dots > max {
		return "" // too many dots, don't canonicalize
	}

	// Try each domain suffix
	for _, domain := range domains {
		candidate := host + "." + domain
		addrs, err := net.LookupHost(candidate)
		if err == nil && len(addrs) > 0 {
			return candidate
		}
	}

	return ""
}

// getLocalAddresses returns the IP addresses of all local network interfaces.
// execFunc returns the Match exec evaluator. It prefers the caller-provided
// ExecFunc, falling back to the CommandExecutor handler if available.
func (l *Lookup) execFunc() func(string) bool {
	if l.ExecFunc != nil {
		return l.ExecFunc
	}
	if l.Handlers.CommandExecutor != nil {
		return func(cmd string) bool {
			err := l.Handlers.CommandExecutor.Execute(cmd)
			return err == nil
		}
	}
	return nil
}

func getLocalAddresses() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			ips = append(ips, ipNet.IP)
		}
	}
	return ips
}
