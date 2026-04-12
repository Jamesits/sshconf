package sshserver

import "github.com/jamesits/sshconf/pkg/dialer"

// Options holds all resolved SSH daemon configuration options.
// Pointer fields distinguish "not set" (nil) from the zero value.
// After Resolve(), all fields populated here will either hold a user-provided
// value, a default, or remain nil if no default applies.
type Options struct {
	// --- Listening ---
	AddressFamily  *string  // "any", "inet", "inet6"
	ListenAddress  []string // multi-value, accumulated (raw strings)
	Ports          []int    // multi-value, accumulated (accumulated; 'Port' directive)
	BindInterface  *string  // (not standard sshd_config; reserved for symmetry)
	RDomain        *string  // %D substitution target
	LoginGraceTime *int     // seconds; 0 = none

	// --- Host Keys ---
	HostKey           []string // multi-value; paths to private host keys
	HostKeyAgent      *string  // agent socket path or "SSH_AUTH_SOCK"
	HostCertificate   []string // multi-value; paths to host cert files
	TrustedUserCAKeys *string  // path to CA file
	RevokedKeys       *string  // path to revoked keys file

	// --- Crypto ---
	Ciphers                     *string // raw, may have +/-/^ prefix
	KexAlgorithms               *string // raw, may have +/-/^ prefix
	MACs                        *string // raw, may have +/-/^ prefix
	HostKeyAlgorithms           *string // raw, may have +/-/^ prefix
	CASignatureAlgorithms       *string // raw, may have +/-/^ prefix
	PubkeyAcceptedAlgorithms    *string // raw
	HostbasedAcceptedAlgorithms *string // raw
	RekeyLimit                  *string // "bytes [time]"
	RequiredRSASize             *int    // bits
	FingerprintHash             *string // "md5", "sha256"

	// --- Authentication ---
	AuthenticationMethods           *string // whitespace-separated lists
	PermitRootLogin                 *string // "yes", "prohibit-password", "forced-commands-only", "no"
	PasswordAuthentication          *bool
	PermitEmptyPasswords            *bool
	KbdInteractiveAuthentication    *bool
	PubkeyAuthentication            *bool
	PubkeyAuthOptions               *string // "none", "touch-required", "verify-required", ...
	HostbasedAuthentication         *bool
	HostbasedUsesNameFromPacketOnly *bool
	IgnoreRhosts                    *string // "yes", "no", "shosts-only"
	IgnoreUserKnownHosts            *bool
	GSSAPIAuthentication            *bool
	GSSAPICleanupCredentials        *bool
	GSSAPIStrictAcceptorCheck       *bool
	KerberosAuthentication          *bool
	KerberosGetAFSToken             *bool
	KerberosOrLocalPasswd           *bool
	KerberosTicketCleanup           *bool
	UsePAM                          *bool
	PAMServiceName                  *string
	MaxAuthTries                    *int
	LoginMaxRetries                 *int
	StrictModes                     *bool
	ExposeAuthInfo                  *bool
	PermitUserEnvironment           *string // "yes", "no", or pattern list
	PermitUserRC                    *bool

	// --- Access Control ---
	AllowUsers       []string // multi-value; user patterns
	DenyUsers        []string
	AllowGroups      []string
	DenyGroups       []string
	RefuseConnection *string // unconditional termination reason

	// --- Authorized Keys ---
	AuthorizedKeysFile              []string // default: ".ssh/authorized_keys .ssh/authorized_keys2"
	AuthorizedKeysCommand           *string
	AuthorizedKeysCommandUser       *string
	AuthorizedPrincipalsFile        *string
	AuthorizedPrincipalsCommand     *string
	AuthorizedPrincipalsCommandUser *string

	// --- Session / Forwarding ---
	AllowAgentForwarding       *bool
	AllowTcpForwarding         *string // "yes", "no", "local", "remote", "all"
	AllowStreamLocalForwarding *string // "yes", "no", "local", "remote", "all"
	DisableForwarding          *bool
	GatewayPorts               *string // "yes", "no", "clientspecified"
	PermitOpen                 []string
	PermitListen               []string
	PermitTTY                  *bool
	PermitTunnel               *string // "yes", "no", "point-to-point", "ethernet"
	X11Forwarding              *bool
	X11DisplayOffset           *int
	X11UseLocalhost            *bool
	XAuthLocation              *string
	StreamLocalBindMask        *string // octal
	StreamLocalBindUnlink      *bool
	ChrootDirectory            *string
	ForceCommand               *string
	Banner                     *string // path to file
	PrintLastLog               *bool
	PrintMotd                  *bool

	// --- Session Env ---
	AcceptEnv []string // multi-value
	SetEnv    []string // multi-value

	// --- Connection Lifetime ---
	TCPKeepAlive               *bool
	ClientAliveInterval        *int
	ClientAliveCountMax        *int
	UnusedConnectionTimeout    *string // "none" or time spec
	MaxSessions                *int
	MaxStartups                *string // "start:rate:full"
	PerSourceMaxStartups       *string
	PerSourceNetBlockSize      *string
	PerSourcePenalties         *string
	PerSourcePenaltyExemptList *string
	IPQoS                      *string
	ChannelTimeout             []string // multi-value; "type=interval"

	// --- Logging ---
	LogLevel       *string
	LogVerbose     []string
	SyslogFacility *string

	// --- Protocol ---
	Compression     *string // "yes", "delayed", "no"
	VersionAddendum *string
	ModuliFile      *string
	UseDNS          *bool

	// --- Subsystems ---
	// Subsystem maps a subsystem name (e.g. "sftp") to its definition.
	// An internal subsystem registered via a handler does not need to
	// appear here.
	Subsystems map[string]Subsystem

	// --- Daemon ---
	PidFile             *string
	SecurityKeyProvider *string
	SshdAuthPath        *string
	SshdSessionPath     *string

	// --- Misc ---
	IgnoreUnknown *string // pattern list

	// ignoredKeywords tracks keywords matched by IgnoreUnknown
	ignoredKeywords map[string]bool

	// DialerConfig is populated during Resolve and can be adjusted by callers
	// before any server-initiated outbound connection is started.
	DialerConfig dialer.DialConfig
}

// Subsystem represents a subsystem definition from sshd_config.
// External subsystems have a non-empty Command that is executed when
// the subsystem is requested. Internal subsystems are registered in
// code via Options.RegisterInternalSubsystem and carry a Handler
// rather than a command.
type Subsystem struct {
	// Name is the subsystem name as negotiated by the client (e.g. "sftp").
	Name string

	// Command is the external command to run for this subsystem.
	// Empty for internal subsystems.
	Command string

	// Internal indicates an in-process subsystem. When true, Handler is
	// invoked by the server's session handler on a subsystem request.
	Internal bool

	// Handler is invoked for internal subsystems. It must consume the
	// channel I/O itself; the caller closes the channel after return.
	// Nil for external subsystems.
	Handler SubsystemHandler
}

// RegisterInternalSubsystem records an in-process subsystem handler.
// It is safe to call this on an Options value before or after Resolve.
// An internal subsystem overrides any external definition with the same name.
func (opts *Options) RegisterInternalSubsystem(name string, handler SubsystemHandler) {
	if opts.Subsystems == nil {
		opts.Subsystems = make(map[string]Subsystem)
	}
	opts.Subsystems[name] = Subsystem{
		Name:     name,
		Internal: true,
		Handler:  handler,
	}
}

// LookupSubsystem returns the subsystem definition for the given name,
// preferring internal subsystems over external ones.
func (opts *Options) LookupSubsystem(name string) (Subsystem, bool) {
	s, ok := opts.Subsystems[name]
	return s, ok
}

// intPtr and strPtr return pointers to values — used by the resolver when
// applying command-line overrides and defaults.
func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }
func boolPtr(v bool) *bool    { return &v }
