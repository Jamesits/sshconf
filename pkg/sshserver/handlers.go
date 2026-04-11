package sshserver

import (
	"io"
	"net"

	"golang.org/x/crypto/ssh"
)

// Handlers holds optional interface implementations for SSH daemon features
// that cannot be derived solely from the config file. Each handler covers
// a functional group of options. A nil handler means the corresponding
// feature is unavailable (or uses a built-in fallback where applicable).
//
// Zero-value Handlers (all nil) yields a minimal server that still performs
// protocol handshake, auth via embedded callbacks, and session dispatch —
// but cannot authenticate users, run commands, or forward anything.
type Handlers struct {
	// --- Authentication providers ---

	// PasswordAuth validates a password. If nil, password authentication
	// is unavailable regardless of PasswordAuthentication in the config.
	PasswordAuth PasswordAuthenticator

	// PublicKeyAuth validates a client public key against the target
	// user's authorized keys, certificate principals, etc.
	PublicKeyAuth PublicKeyAuthenticator

	// KeyboardInteractiveAuth drives a keyboard-interactive exchange.
	KeyboardInteractiveAuth KeyboardInteractiveAuthenticator

	// HostbasedAuth validates hostbased authentication.
	HostbasedAuth HostbasedAuthenticator

	// GSSAPIServer provides the server-side GSSAPI implementation.
	GSSAPIServer ssh.GSSAPIServer

	// --- Access control ---

	// AccessController enforces AllowUsers/DenyUsers/AllowGroups/DenyGroups
	// and related policies. It is invoked before authentication succeeds.
	AccessController AccessController

	// --- Host keys ---

	// HostKeyProvider returns the signers used as host keys. When non-nil
	// it overrides the file-based HostKey resolution. This is useful for
	// agent-backed host keys (HostKeyAgent) or for callers that manage
	// host keys themselves.
	HostKeyProvider HostKeyProvider

	// --- Session dispatch ---

	// SessionHandler handles accepted "session" channels. It must service
	// channel requests ("pty-req", "shell", "exec", "subsystem", ...) and
	// read/write channel data. A nil SessionHandler causes session channels
	// to be rejected.
	SessionHandler SessionHandler

	// --- Forwarding ---

	// TcpForwarder handles "direct-tcpip" channel requests (local→remote
	// forwarding initiated by the client) and global "tcpip-forward"
	// requests (remote→local forwarding). A nil TcpForwarder rejects all
	// TCP forwarding regardless of AllowTcpForwarding.
	TcpForwarder TcpForwarder

	// StreamLocalForwarder handles Unix-domain socket forwarding
	// (direct-streamlocal and streamlocal-forward).
	StreamLocalForwarder StreamLocalForwarder

	// AgentForwarder handles "auth-agent-req@openssh.com" requests.
	AgentForwarder AgentForwarder

	// X11Forwarder handles "x11-req" requests.
	X11Forwarder X11Forwarder

	// TunnelForwarder handles "tun@openssh.com" requests.
	TunnelForwarder TunnelForwarder

	// --- Process helpers ---

	// CommandExecutor runs local commands such as AuthorizedKeysCommand
	// or AuthorizedPrincipalsCommand.
	CommandExecutor CommandExecutor

	// Logger receives diagnostic log messages.
	Logger Logger
}

// PasswordAuthenticator validates a password for a given user.
// Return a non-nil Permissions on success; return an error to deny.
//
// Relevant options:
//   - PasswordAuthentication, PermitEmptyPasswords, PermitRootLogin,
//     UsePAM, PAMServiceName
type PasswordAuthenticator interface {
	AuthenticatePassword(meta ssh.ConnMetadata, password []byte, opts *Options) (*ssh.Permissions, error)
}

// PublicKeyAuthenticator validates a client-offered public key.
// Return a non-nil Permissions on success; return an error to deny.
//
// Relevant options:
//   - PubkeyAuthentication, AuthorizedKeysFile, AuthorizedKeysCommand,
//     AuthorizedKeysCommandUser, AuthorizedPrincipalsFile,
//     AuthorizedPrincipalsCommand, TrustedUserCAKeys, RevokedKeys,
//     PubkeyAcceptedAlgorithms, RequiredRSASize, PubkeyAuthOptions
type PublicKeyAuthenticator interface {
	AuthenticatePublicKey(meta ssh.ConnMetadata, key ssh.PublicKey, opts *Options) (*ssh.Permissions, error)
}

// KeyboardInteractiveAuthenticator drives a keyboard-interactive exchange.
//
// Relevant options:
//   - KbdInteractiveAuthentication, UsePAM, PAMServiceName
type KeyboardInteractiveAuthenticator interface {
	AuthenticateKeyboardInteractive(meta ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge, opts *Options) (*ssh.Permissions, error)
}

// HostbasedAuthenticator validates hostbased authentication.
//
// Relevant options:
//   - HostbasedAuthentication, HostbasedAcceptedAlgorithms,
//     HostbasedUsesNameFromPacketOnly, IgnoreRhosts, IgnoreUserKnownHosts
type HostbasedAuthenticator interface {
	AuthenticateHostbased(meta ssh.ConnMetadata, key ssh.PublicKey, clientHost, clientUser string, opts *Options) (*ssh.Permissions, error)
}

// AccessController enforces coarse-grained access policies before
// authentication is considered successful.
//
// Relevant options:
//   - AllowUsers, DenyUsers, AllowGroups, DenyGroups, RefuseConnection,
//     MaxSessions
type AccessController interface {
	// CheckAccess is called after authentication but before the connection
	// is accepted. It may return an error to deny access.
	CheckAccess(meta ssh.ConnMetadata, perms *ssh.Permissions, opts *Options) error
}

// HostKeyProvider returns the signers to use as host keys. When non-nil,
// it overrides the file-based HostKey directive resolution.
//
// Relevant options:
//   - HostKey, HostKeyAgent, HostCertificate
type HostKeyProvider interface {
	HostKeys(opts *Options) ([]ssh.Signer, error)
}

// SessionHandler handles accepted "session" channels. The handler is given
// the newly-accepted channel and its request stream and is responsible for
// servicing pty-req, shell/exec/subsystem, env, signal, window-change, and
// break requests.
//
// Relevant options:
//   - PermitTTY, ForceCommand, ChrootDirectory, AcceptEnv, SetEnv,
//     PermitUserEnvironment, PermitUserRC, PrintLastLog, PrintMotd,
//     Banner, ChannelTimeout, UnusedConnectionTimeout, Subsystem
type SessionHandler interface {
	HandleSession(ctx SessionContext) error
}

// SessionContext is the per-session interface exposed to a SessionHandler.
// It bundles the channel, request stream, connection metadata, and the
// resolved options — a handler can read requests, write responses, launch
// commands, and dispatch subsystems without depending on the server's
// internal goroutine plumbing.
type SessionContext interface {
	// Channel returns the session data channel.
	Channel() ssh.Channel

	// Requests returns the channel request stream. The handler is
	// responsible for calling Reply on requests that set WantReply.
	Requests() <-chan *ssh.Request

	// ConnMetadata returns the underlying connection metadata.
	ConnMetadata() ssh.ConnMetadata

	// Permissions returns the permissions returned by the successful
	// authentication callback, or nil for pre-auth contexts.
	Permissions() *ssh.Permissions

	// Options returns the resolved config options. Options are matched
	// per-connection at accept time.
	Options() *Options

	// Handlers returns the global handler set (so the session handler can
	// dispatch to TcpForwarder, X11Forwarder, etc. for sub-requests).
	Handlers() Handlers

	// LookupSubsystem returns a subsystem definition by name. It consults
	// internal subsystems first, then sshd_config entries.
	LookupSubsystem(name string) (Subsystem, bool)
}

// SubsystemHandler services a single in-process subsystem invocation.
// The handler owns the channel I/O for its duration; the server closes
// the channel after the handler returns.
type SubsystemHandler interface {
	HandleSubsystem(ctx SubsystemContext) error
}

// SubsystemHandlerFunc is an adapter to allow using ordinary functions
// as SubsystemHandlers.
type SubsystemHandlerFunc func(ctx SubsystemContext) error

// HandleSubsystem calls f(ctx).
func (f SubsystemHandlerFunc) HandleSubsystem(ctx SubsystemContext) error { return f(ctx) }

// SubsystemContext provides everything a subsystem needs to service a
// single request.
type SubsystemContext interface {
	// Name returns the requested subsystem name (e.g. "sftp").
	Name() string

	// Stdin returns the channel read side.
	Stdin() io.Reader

	// Stdout returns the channel write side (normal data).
	Stdout() io.Writer

	// Stderr returns the channel stderr side (extended data).
	Stderr() io.Writer

	// Channel returns the underlying channel for handlers that need
	// low-level access (e.g. sending requests).
	Channel() ssh.Channel

	// ConnMetadata returns the underlying connection metadata.
	ConnMetadata() ssh.ConnMetadata

	// Options returns the resolved options for this connection.
	Options() *Options
}

// TcpForwarder handles TCP forwarding requests.
//
// Direct-tcpip (client→server "local forwarding"): the client opens a
// direct-tcpip channel and the server should dial the target and relay.
//
// Remote forwarding (server→client "remote forwarding"): the client sends a
// global "tcpip-forward" request. The server should begin listening on the
// requested address:port and open forwarded-tcpip channels for each
// accepted connection.
//
// Relevant options:
//   - AllowTcpForwarding, DisableForwarding, GatewayPorts,
//     PermitOpen, PermitListen
type TcpForwarder interface {
	// HandleDirectTcpIP services a direct-tcpip channel request.
	HandleDirectTcpIP(nc ssh.NewChannel, meta ssh.ConnMetadata, opts *Options) error

	// StartRemoteForward begins listening on the given address in response
	// to a tcpip-forward global request. If bindPort is 0, the server must
	// choose a port and return it in boundPort.
	StartRemoteForward(bindAddr string, bindPort uint32, conn *ssh.ServerConn, opts *Options) (boundPort uint32, err error)

	// StopRemoteForward cancels a previously started remote forward.
	StopRemoteForward(bindAddr string, bindPort uint32, conn *ssh.ServerConn) error
}

// StreamLocalForwarder handles Unix-domain socket forwarding.
//
// Relevant options:
//   - AllowStreamLocalForwarding, DisableForwarding, PermitOpen,
//     PermitListen, StreamLocalBindMask, StreamLocalBindUnlink
type StreamLocalForwarder interface {
	HandleDirectStreamLocal(nc ssh.NewChannel, meta ssh.ConnMetadata, opts *Options) error
	StartRemoteStreamLocalForward(path string, conn *ssh.ServerConn, opts *Options) error
	StopRemoteStreamLocalForward(path string, conn *ssh.ServerConn) error
}

// AgentForwarder handles ssh-agent forwarding.
//
// Relevant options:
//   - AllowAgentForwarding, DisableForwarding
type AgentForwarder interface {
	HandleAgentRequest(ctx SessionContext) error
}

// X11Forwarder handles X11 display forwarding.
//
// Relevant options:
//   - X11Forwarding, X11DisplayOffset, X11UseLocalhost, XAuthLocation,
//     DisableForwarding
type X11Forwarder interface {
	HandleX11Request(ctx SessionContext, req X11Request) error
}

// X11Request carries the parsed payload of an x11-req channel request.
type X11Request struct {
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

// TunnelForwarder handles TUN/TAP forwarding (tun@openssh.com).
//
// Relevant options:
//   - PermitTunnel
type TunnelForwarder interface {
	HandleTunnelRequest(nc ssh.NewChannel, meta ssh.ConnMetadata, opts *Options) error
}

// CommandExecutor executes local commands for features such as
// AuthorizedKeysCommand, AuthorizedPrincipalsCommand, and ForceCommand.
type CommandExecutor interface {
	// Execute runs cmd as the given user (empty user = current process user).
	// It returns stdout; caller is responsible for parsing it.
	ExecuteAs(user, cmd string, args []string) ([]byte, error)
}

// Logger receives diagnostic messages from the SSH daemon.
//
// Relevant options:
//   - LogLevel, LogVerbose, SyslogFacility
type Logger interface {
	Log(level, msg string)
}

// Ensure net.Addr is referenced so imports are not elided when we later
// add net-using helpers — keeps the import list stable.
var _ net.Addr = (*net.TCPAddr)(nil)
