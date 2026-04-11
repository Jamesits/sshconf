package client

import (
	"net"

	"golang.org/x/crypto/ssh"
)

// Handlers holds optional interface implementations for SSH config options
// that are parsed and stored but cannot be automatically applied to
// [ssh.ClientConfig]. Each handler covers a functional group of options.
// A nil handler means the corresponding options are ignored (the caller
// reads them from [Options] directly if needed).
//
// Zero-value Handlers (all nil) preserves the existing behavior exactly.
type Handlers struct {
	// --- User interaction ---

	// UI provides caller-implemented methods for authentication
	// prompts and host key confirmation. A nil UI disables all
	// interactive prompts.
	UI UI

	// GSSAPIClient provides a GSSAPI client for Kerberos auth.
	// If nil, GSSAPI auth is unavailable even if configured.
	GSSAPIClient ssh.GSSAPIClient

	// HostKeyCallback overrides the built-in host key verification.
	// If nil, host key verification is built from config (known_hosts, etc.).
	HostKeyCallback ssh.HostKeyCallback

	// --- Pre-connection ---

	// Dialer establishes the TCP connection to the SSH server.
	// When set, it is called instead of the default net.DialTimeout.
	Dialer Dialer

	// KeyProvider supplies additional SSH signing keys from external
	// sources such as PKCS#11 tokens or FIDO/U2F security keys.
	KeyProvider KeyProvider

	// HostKeySource provides additional trusted host keys beyond those
	// found in known_hosts files (e.g., via KnownHostsCommand).
	HostKeySource HostKeySource

	// HostbasedAuth provides a client-side hostbased authentication method.
	HostbasedAuth HostbasedAuthProvider

	// Multiplexer manages SSH connection multiplexing (ControlMaster).
	Multiplexer Multiplexer

	// HostCanonicalizer performs custom hostname canonicalization.
	HostCanonicalizer HostCanonicalizer

	// --- Post-connection ---

	// Forwarding sets up port forwarding (local, remote, dynamic).
	Forwarding ForwardHandler

	// AgentForwarding enables SSH agent forwarding on a session.
	AgentForwarding AgentForwarder

	// X11Forwarding enables X11 display forwarding on a session.
	X11Forwarding X11Forwarder

	// Tunnel sets up TUN/TAP tunnel forwarding.
	Tunnel TunnelHandler

	// Session configures an SSH session (TTY, env, command, timeouts).
	Session SessionConfigurator

	// --- Process/UI ---

	// CommandExecutor runs local commands (LocalCommand, Match exec).
	CommandExecutor CommandExecutor

	// Terminal handles terminal-related features (escape chars, keystroke
	// timing, visual host key, process backgrounding, stdin nullification).
	Terminal TerminalHandler

	// Logger receives diagnostic log messages.
	Logger Logger
}

// Dialer establishes network connections for SSH, replacing the default
// net.DialTimeout. Implementations should consult the following options
// from [Options]:
//
//   - ProxyCommand: external command whose stdio becomes the connection
//   - ProxyJump: chain of SSH jump hosts
//   - ProxyUseFdpass: whether ProxyCommand passes an fd instead of using stdio
//   - BindAddress: local address to bind the outgoing connection to
//   - BindInterface: local interface to bind to
//   - IPQoS: DSCP values for the connection
type Dialer interface {
	Dial(network, addr string, opts *Options) (net.Conn, error)
}

// KeyProvider loads additional SSH signing keys from external sources.
// The returned signers are added to the public key authentication method
// alongside keys from IdentityFile and the SSH agent.
//
// Relevant options in [Options]:
//   - PKCS11Provider: path to PKCS#11 shared library
//   - SecurityKeyProvider: path to FIDO/U2F authenticator library
type KeyProvider interface {
	Signers(opts *Options) ([]ssh.Signer, error)
}

// HostKeySource provides additional trusted host keys beyond those found
// in UserKnownHostsFile and GlobalKnownHostsFile. The returned keys are
// accepted as trusted for the given hostname.
//
// Relevant options in [Options]:
//   - KnownHostsCommand: command to execute for host key lookup
type HostKeySource interface {
	HostKeys(hostname string, opts *Options) ([]ssh.PublicKey, error)
}

// HostbasedAuthProvider creates an [ssh.AuthMethod] for client-side
// hostbased authentication. The x/crypto/ssh library does not include a
// built-in implementation, so this must be provided externally.
//
// Relevant options in [Options]:
//   - HostbasedAuthentication: whether hostbased auth is enabled
//   - HostbasedAcceptedAlgorithms: allowed signature algorithms
//   - EnableSSHKeysign: whether to use the ssh-keysign helper
type HostbasedAuthProvider interface {
	AuthMethod(opts *Options) ssh.AuthMethod
}

// Multiplexer manages SSH connection multiplexing, allowing multiple
// sessions to share a single network connection.
//
// Relevant options in [Options]:
//   - ControlMaster: whether to act as a multiplexing master
//   - ControlPath: path to the Unix domain socket for multiplexing
//   - ControlPersist: whether the master persists after the last client disconnects
type Multiplexer interface {
	// CheckExisting checks for an existing multiplexed connection.
	// Returns a connected client if one exists, nil otherwise.
	CheckExisting(opts *Options) (*ssh.Client, error)

	// Register registers a new connection for multiplexing so future
	// sessions can reuse it.
	Register(client *ssh.Client, opts *Options) error
}

// HostCanonicalizer performs hostname canonicalization using custom logic.
// When provided, it replaces the built-in DNS-based canonicalization.
//
// Relevant options in [Options]:
//   - CanonicalizeHostname: whether canonicalization is enabled
//   - CanonicalDomains: domain suffixes to search
//   - CanonicalizeMaxDots: max dots before skipping canonicalization
//   - CanonicalizePermittedCNAMEs: CNAME following rules
//   - CanonicalizeFallbackLocal: whether to fall back to unqualified name
type HostCanonicalizer interface {
	Canonicalize(host string, opts *Options) (string, error)
}

// ForwardHandler sets up port forwarding on an established SSH connection.
//
// Relevant options in [Options]:
//   - LocalForward: local-to-remote port forwarding rules
//   - RemoteForward: remote-to-local port forwarding rules
//   - DynamicForward: SOCKS proxy forwarding ports
//   - GatewayPorts: whether to bind forwarding ports on all interfaces
//   - PermitRemoteOpen: allowed destinations for remote forwarding
//   - StreamLocalBindMask: umask for Unix domain socket forwarding
//   - StreamLocalBindUnlink: whether to unlink existing sockets
//   - ExitOnForwardFailure: whether to abort if forwarding setup fails
//   - ClearAllForwardings: whether all forwarding was cleared
type ForwardHandler interface {
	SetupForwarding(client *ssh.Client, opts *Options) error
}

// AgentForwarder enables SSH agent forwarding on a session, allowing
// the remote host to use the local SSH agent for authentication.
//
// Relevant options in [Options]:
//   - ForwardAgent: "yes", "no", a socket path, or "$ENV_VAR"
type AgentForwarder interface {
	ForwardAgent(client *ssh.Client, session *ssh.Session, opts *Options) error
}

// X11Forwarder enables X11 display forwarding on a session, allowing
// remote graphical applications to display on the local X server.
//
// Relevant options in [Options]:
//   - ForwardX11: whether X11 forwarding is enabled
//   - ForwardX11Trusted: whether to use trusted X11 forwarding
//   - ForwardX11Timeout: timeout for untrusted X11 forwarding
//   - XAuthLocation: path to the xauth binary
type X11Forwarder interface {
	ForwardX11(client *ssh.Client, session *ssh.Session, opts *Options) error
}

// TunnelHandler sets up TUN/TAP layer 2/3 tunnel forwarding between
// the client and server.
//
// Relevant options in [Options]:
//   - Tunnel: "yes" (point-to-point), "point-to-point", "ethernet", or "no"
//   - TunnelDevice: "local_tun[:remote_tun]" device specification
type TunnelHandler interface {
	SetupTunnel(client *ssh.Client, opts *Options) error
}

// SessionConfigurator configures an SSH session based on resolved options.
// It is called after the session is created but before the command is started.
//
// Relevant options in [Options]:
//   - RequestTTY: whether to request a pseudo-terminal
//   - SessionType: "shell", "exec", "subsystem", or "none"
//   - RemoteCommand: command to execute on the remote host
//   - SendEnv: environment variable patterns to forward
//   - SetEnv: explicit environment variables to set
//   - ChannelTimeout: idle timeout per channel type
type SessionConfigurator interface {
	ConfigureSession(session *ssh.Session, opts *Options) error
}

// CommandExecutor executes local commands. It is used for:
//   - LocalCommand (executed after successful connection when PermitLocalCommand is yes)
//   - Match exec conditions during config resolution
//
// Relevant options in [Options]:
//   - LocalCommand: command to execute after connection
//   - PermitLocalCommand: whether local command execution is allowed
type CommandExecutor interface {
	// Execute runs a command and returns any error. Used for LocalCommand.
	Execute(command string) error

	// ExecuteWithOutput runs a command and returns its stdout. Used for
	// KnownHostsCommand and Match exec evaluation.
	ExecuteWithOutput(command string) ([]byte, error)
}

// TerminalHandler manages terminal and process lifecycle features that
// require direct interaction with the controlling terminal or process.
//
// Relevant options in [Options]:
//   - EscapeChar: the escape character for interactive sessions
//   - EnableEscapeCommandline: whether ~C escape command line is enabled
//   - ObscureKeystrokeTiming: keystroke timing obfuscation settings
//   - VisualHostKey: whether to display ASCII art host key fingerprints
//   - ForkAfterAuthentication: whether to fork to background
//   - StdinNull: whether to redirect stdin from /dev/null
type TerminalHandler interface {
	SetupTerminal(opts *Options) error
}

// Logger receives diagnostic messages from the SSH client library.
// The level parameter corresponds to the LogLevel option values:
// "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1",
// "DEBUG2", "DEBUG3".
//
// Relevant options in [Options]:
//   - LogLevel: minimum log level
//   - LogVerbose: per-file/function log overrides
//   - SyslogFacility: syslog facility code
type Logger interface {
	Log(level, msg string)
}

// UI provides caller-implemented methods for SSH operations that require
// user interaction. Implementations handle password/passphrase prompts,
// keyboard-interactive challenges, banner display, and host key confirmation.
// A nil UI disables all interactive code paths.
type UI interface {
	// PasswordCallback prompts for a password. Required for password auth.
	PasswordCallback() (string, error)

	// PassphraseCallback prompts for a private key passphrase.
	// The argument is the key file path.
	PassphraseCallback(keyFile string) ([]byte, error)

	// InteractiveCallback handles keyboard-interactive challenges.
	InteractiveCallback(name, instruction string, questions []string, echos []bool) ([]string, error)

	// BannerCallback handles SSH server banner messages.
	BannerCallback(message string) error

	// HostKeyConfirm is called when StrictHostKeyChecking is "ask" and
	// a new or changed host key is encountered. Return true to accept.
	HostKeyConfirm(hostname string, remote net.Addr, key ssh.PublicKey) bool
}
