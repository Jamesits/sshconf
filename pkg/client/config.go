// Package client provides OpenSSH client configuration parsing and resolution.
// It reads ssh_config(5) files, applies Host/Match blocks, command-line
// overrides (-o), and defaults to produce a resolved configuration that
// can be converted to golang.org/x/crypto/ssh.ClientConfig.
package client

// Options holds all resolved SSH client configuration options.
// Pointer fields distinguish "not set" (nil) from the zero value.
// After Resolve(), all fields will be populated (defaults applied).
type Options struct {
	// --- Connection ---
	AddressFamily       *string // "any", "inet", "inet6"
	BatchMode           *bool
	BindAddress         *string
	BindInterface       *string
	ConnectTimeout      *int // seconds; 0 = system default
	ConnectionAttempts  *int
	TCPKeepAlive        *bool
	ServerAliveInterval *int // seconds
	ServerAliveCountMax *int
	Compression         *bool

	// --- Host Resolution ---
	Hostname                    *string
	Port                        *int
	CanonicalDomains            []string
	CanonicalizeFallbackLocal   *bool
	CanonicalizeHostname        *string // "yes", "no", "always", "none"
	CanonicalizeMaxDots         *int
	CanonicalizePermittedCNAMEs []string // "source:target" rules

	// --- Authentication ---
	User                         *string
	IdentityFile                 []string // multi-value, accumulated
	IdentitiesOnly               *bool
	IdentityAgent                *string
	CertificateFile              []string // multi-value, accumulated
	PasswordAuthentication       *bool
	KbdInteractiveAuthentication *bool
	KbdInteractiveDevices        *string
	PubkeyAuthentication         *string // "yes", "no", "unbound", "host-bound"
	PubkeyAcceptedAlgorithms     *string // raw, may have +/-/^ prefix
	PreferredAuthentications     *string // comma-separated method list
	NumberOfPasswordPrompts      *int
	HostbasedAuthentication      *bool
	HostbasedAcceptedAlgorithms  *string // raw, may have +/-/^ prefix
	EnableSSHKeysign             *bool
	GSSAPIAuthentication         *bool
	GSSAPIDelegateCredentials    *bool
	AddKeysToAgent               *string // "yes", "no", "ask", "confirm", or time interval

	// --- Crypto ---
	Ciphers               *string // raw, may have +/-/^ prefix
	KexAlgorithms         *string // raw, may have +/-/^ prefix
	MACs                  *string // raw, may have +/-/^ prefix
	CASignatureAlgorithms *string // raw, may have +/-/^ prefix
	HostKeyAlgorithms     *string // raw, may have +/-/^ prefix
	RekeyLimit            *string // "bytes [time]"
	RequiredRSASize       *int    // bits
	FingerprintHash       *string // "md5", "sha256"
	WarnWeakCrypto        *string // "yes", "no", "no-pq-kex"

	// --- Host Key Verification ---
	CheckHostIP                      *bool
	GlobalKnownHostsFile             *string // whitespace-separated paths
	UserKnownHostsFile               *string // whitespace-separated paths
	HashKnownHosts                   *bool
	StrictHostKeyChecking            *string // "yes", "no", "ask", "accept-new", "off"
	HostKeyAlias                     *string
	KnownHostsCommand                *string
	RevokedHostKeys                  *string // path
	UpdateHostKeys                   *string // "yes", "no", "ask"
	VerifyHostKeyDNS                 *string // "yes", "no", "ask"
	NoHostAuthenticationForLocalhost *bool

	// --- Proxy ---
	ProxyCommand   *string
	ProxyJump      *string
	ProxyUseFdpass *bool

	// --- Forwarding ---
	LocalForward          []Forward // multi-value, accumulated
	RemoteForward         []Forward // multi-value, accumulated
	DynamicForward        []string  // multi-value, accumulated
	ClearAllForwardings   *bool
	ExitOnForwardFailure  *bool
	GatewayPorts          *bool
	PermitRemoteOpen      []string // multi-value
	StreamLocalBindMask   *string  // octal
	StreamLocalBindUnlink *bool

	// --- Agent Forwarding ---
	ForwardAgent *string // "yes", "no", path, or "$ENVVAR"

	// --- X11 ---
	ForwardX11        *bool
	ForwardX11Timeout *int // seconds
	ForwardX11Trusted *bool
	XAuthLocation     *string

	// --- Tunnel ---
	Tunnel       *string // "yes", "no", "point-to-point", "ethernet"
	TunnelDevice *string // "local[:remote]"

	// --- Session ---
	RequestTTY     *string // "yes", "no", "force", "auto"
	SessionType    *string // "none", "subsystem", "default"
	RemoteCommand  *string
	SendEnv        []string // multi-value, accumulated; '-' prefix clears
	SetEnv         []string // multi-value, accumulated; "NAME=VALUE"
	EscapeChar     *string  // single char, "^X", or "none"
	IPQoS          *string  // one or two DSCP values
	LogLevel       *string
	LogVerbose     []string
	Tag            *string
	ChannelTimeout []string // multi-value; "type=interval"

	// --- Connection Sharing ---
	ControlMaster  *string // "yes", "no", "ask", "auto", "autoask"
	ControlPath    *string
	ControlPersist *string // "yes", "no", time in seconds

	// --- Misc ---
	PermitLocalCommand      *bool
	LocalCommand            *string
	VisualHostKey           *bool
	ForkAfterAuthentication *bool
	StdinNull               *bool
	EnableEscapeCommandline *bool
	ObscureKeystrokeTiming  *string // "yes", "no", "interval:NNN"
	VersionAddendum         *string
	PKCS11Provider          *string
	SecurityKeyProvider     *string
	IgnoreUnknown           *string // pattern list
	RefuseConnection        *string // message
	SyslogFacility          *string

	// ignoredKeywords tracks keywords matched by IgnoreUnknown
	ignoredKeywords map[string]bool
}

// Forward represents a port forwarding specification.
type Forward struct {
	// BindAddress is the optional bind address (empty = loopback).
	BindAddress string
	// BindPort is the local/remote port, or a Unix socket path.
	BindPort string
	// Host is the destination host (for LocalForward/RemoteForward).
	Host string
	// HostPort is the destination port, or a Unix socket path.
	HostPort string
}

// intPtr returns a pointer to an int value.
func intPtr(v int) *int { return &v }

// strPtr returns a pointer to a string value.
func strPtr(v string) *string { return &v }
