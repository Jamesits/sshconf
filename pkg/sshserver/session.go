package sshserver

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// sessionCtx is the default SessionContext implementation passed to
// SessionHandler.HandleSession. It is a thin view over the accepted
// channel and does not take ownership of it.
type sessionCtx struct {
	channel     ssh.Channel
	requests    <-chan *ssh.Request
	meta        ssh.ConnMetadata
	permissions *ssh.Permissions
	opts        *Options
	handlers    Handlers
}

func (s *sessionCtx) Channel() ssh.Channel           { return s.channel }
func (s *sessionCtx) Requests() <-chan *ssh.Request  { return s.requests }
func (s *sessionCtx) ConnMetadata() ssh.ConnMetadata { return s.meta }
func (s *sessionCtx) Permissions() *ssh.Permissions  { return s.permissions }
func (s *sessionCtx) Options() *Options              { return s.opts }
func (s *sessionCtx) Handlers() Handlers             { return s.handlers }

func (s *sessionCtx) LookupSubsystem(name string) (Subsystem, bool) {
	return s.opts.LookupSubsystem(name)
}

// subsystemCtx implements SubsystemContext and is supplied by SessionHandler
// implementations that want to delegate to a registered internal subsystem.
type subsystemCtx struct {
	name    string
	channel ssh.Channel
	meta    ssh.ConnMetadata
	opts    *Options
}

// NewSubsystemContext wraps a session channel for delivery to an internal
// subsystem handler. SessionHandler implementations that do their own
// subsystem dispatch can call this to construct the context they pass to
// Subsystem.Handler.
func NewSubsystemContext(name string, channel ssh.Channel, meta ssh.ConnMetadata, opts *Options) SubsystemContext {
	return &subsystemCtx{
		name:    name,
		channel: channel,
		meta:    meta,
		opts:    opts,
	}
}

func (s *subsystemCtx) Name() string                   { return s.name }
func (s *subsystemCtx) Stdin() io.Reader               { return s.channel }
func (s *subsystemCtx) Stdout() io.Writer              { return s.channel }
func (s *subsystemCtx) Stderr() io.Writer              { return s.channel.Stderr() }
func (s *subsystemCtx) Channel() ssh.Channel           { return s.channel }
func (s *subsystemCtx) ConnMetadata() ssh.ConnMetadata { return s.meta }
func (s *subsystemCtx) Options() *Options              { return s.opts }

// parseTcpForwardPayload decodes the SSH_MSG_GLOBAL_REQUEST payload for
// tcpip-forward / cancel-tcpip-forward (RFC 4254 section 7.1).
//
//	string  address to bind
//	uint32  port number to bind
func parseTcpForwardPayload(payload []byte) (string, uint32, error) {
	var req struct {
		BindAddr string
		BindPort uint32
	}
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return "", 0, fmt.Errorf("invalid tcpip-forward payload: %w", err)
	}
	return req.BindAddr, req.BindPort, nil
}

// parseStreamLocalPayload decodes the global request payload used by
// OpenSSH's streamlocal-forward@openssh.com (a single "path" string).
func parseStreamLocalPayload(payload []byte) (string, error) {
	var req struct {
		Path string
	}
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return "", fmt.Errorf("invalid streamlocal-forward payload: %w", err)
	}
	return req.Path, nil
}

// encodeUint32 encodes a single uint32 in big-endian wire order for use
// as the reply payload of a tcpip-forward success response.
func encodeUint32(n uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], n)
	return buf[:]
}
