// Package sshconfig provides a reusable parser for OpenSSH configuration file format.
// It handles the common syntax shared between ssh_config(5) and sshd_config(5):
// keyword-argument pairs, Host/Match blocks, Include directives, pattern matching,
// token expansion, and algorithm list operations (+/-/^).
package sshconfig

import (
	"net"
)

// SourceInfo records where a directive was found for diagnostics.
type SourceInfo struct {
	File string
	Line int
}

// Directive represents a single parsed keyword-value pair from a config file.
type Directive struct {
	Keyword string
	Value   string
	Source  SourceInfo
}

// Entry is the primary output of the parser: a directive with its associated
// conditions (from the enclosing Host/Match block). If Conditions is nil,
// the directive appeared before any Host/Match block and applies unconditionally.
type Entry struct {
	Conditions []Condition
	Directive  Directive
}

// MatchContext provides all values needed for evaluating Host/Match conditions.
// The caller populates this before resolving configuration.
type MatchContext struct {
	// User is the target remote username (after User directive resolution).
	User string
	// Host is the target hostname (after Hostname directive resolution).
	Host string
	// OriginalHost is the hostname as given on the command line.
	OriginalHost string
	// LocalUser is the name of the local user running the client.
	LocalUser string
	// Port is the target port (as string, e.g. "22").
	Port string
	// Command is the remote command requested (empty for interactive sessions).
	Command string
	// Tag is the tag set by a prior Tag directive or -P flag.
	Tag string
	// Version is the client version string for Match version.
	Version string
	// SessionType is one of "shell", "exec", "subsystem", or "none".
	SessionType string

	// ExecFunc is called to evaluate "Match exec" conditions.
	// It receives the command string (after token expansion) and returns
	// true if the command exits with status 0.
	ExecFunc func(cmd string) bool

	// LocalAddresses are the IP addresses of local network interfaces,
	// used for "Match localnetwork" conditions.
	LocalAddresses []net.IP

	// IsCanonical is true when re-parsing after hostname canonicalization.
	IsCanonical bool
	// IsFinal is true during the final configuration pass.
	IsFinal bool
}

// Condition represents a matching condition from a Host or Match block.
type Condition interface {
	Match(ctx *MatchContext) bool
}

// HostCondition matches the target hostname against a list of patterns.
// Patterns may be negated with '!' prefix.
type HostCondition struct {
	Patterns []HostPattern
}

// HostPattern is a single pattern in a Host directive.
type HostPattern struct {
	Pattern string
	Negated bool
}

// MatchAllCondition matches unconditionally (Match all).
type MatchAllCondition struct{}

// MatchCanonicalCondition matches only during canonical re-parse.
type MatchCanonicalCondition struct{}

// MatchFinalCondition matches only during the final pass.
type MatchFinalCondition struct{}

// MatchExecCondition matches when the given command exits with status 0.
type MatchExecCondition struct {
	Command string // raw command string (tokens not yet expanded)
}

// MatchLocalNetworkCondition matches when any local address falls within
// one of the specified CIDR networks.
type MatchLocalNetworkCondition struct {
	Networks []string // CIDR notation strings
}

// MatchFieldCondition matches a specific context field against a pattern list.
type MatchFieldCondition struct {
	Field    MatchField
	Patterns string // comma-separated pattern list
	Negated  bool   // '!' prefix on the criteria keyword
}

// MatchField identifies which MatchContext field to compare.
type MatchField int

const (
	MatchFieldHost MatchField = iota
	MatchFieldOriginalHost
	MatchFieldUser
	MatchFieldLocalUser
	MatchFieldTagged
	MatchFieldCommand
	MatchFieldVersion
	MatchFieldSessionType
)

// ParseOptions configures the behavior of the parser.
type ParseOptions struct {
	// BaseDir is the directory used to resolve relative Include paths.
	// For user configs this is typically ~/.ssh, for system configs /etc/ssh.
	BaseDir string

	// IsUser indicates whether this is a user config (true) or system config (false).
	// This affects Include path resolution: relative paths are resolved against
	// ~/.ssh for user configs and /etc/ssh for system configs.
	IsUser bool

	// MaxIncludeDepth limits Include recursion depth. 0 means use default (16).
	MaxIncludeDepth int

	// HomeDir is the user's home directory for tilde expansion.
	// If empty, os.UserHomeDir() is used.
	HomeDir string

	// TokenContext provides values for token expansion in Include paths.
	// May be nil if no token expansion is needed.
	TokenContext *TokenContext
}

// TokenContext provides values for expanding %-tokens in config values.
type TokenContext struct {
	// %h - remote hostname
	RemoteHost string
	// %p - remote port
	RemotePort string
	// %r - remote username
	RemoteUser string
	// %u - local username
	LocalUser string
	// %d - local user's home directory
	HomeDir string
	// %l - local hostname including domain
	LocalHostFQDN string
	// %L - local hostname (short)
	LocalHost string
	// %n - original remote hostname as given on command line
	OriginalHost string
	// %i - local user ID (UID as string)
	LocalUserID string
	// %j - contents of ProxyJump option
	ProxyJump string
	// %k - host key alias, or original hostname if unset
	HostKeyAlias string
	// %C - hash of %l%h%p%r%j
	ConnHash string
	// %f - fingerprint of server's host key
	ServerKeyFingerprint string
	// %H - known_hosts hostname or address being searched
	KnownHostsHost string
	// %I - reason for KnownHostsCommand execution
	KnownHostsReason string
	// %K - base64 encoded host key
	HostKeyBase64 string
	// %t - type of server host key
	HostKeyType string
	// %T - local tun/tap interface or "NONE"
	TunnelInterface string
}
