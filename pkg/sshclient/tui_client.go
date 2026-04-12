// Package sshclient provides OpenSSH client configuration parsing and
// resolution, plus terminal user-interaction callbacks for SSH clients.
package sshclient

import (
	"github.com/jamesits/sshconf/pkg/stdio"
)

// TUI provides terminal-based user interaction for SSH client operations.
// Its methods are directly compatible with the corresponding fields of
// [UI], so callers can assign them without wrapping closures.
type TUI struct {
	stdio.TerminalStreams

	// Host and User identify the remote account and are used to render
	// the password prompt. Set these before PasswordCallback is invoked.
	Host string
	User string
}

// NewTUI returns a TUI wired to the supplied streams.
func NewTUI(streams stdio.TerminalStreams) *TUI {
	return &TUI{
		TerminalStreams: streams,
	}
}
