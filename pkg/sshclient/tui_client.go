// Package sshclient provides OpenSSH client configuration parsing and
// resolution, plus terminal user-interaction callbacks for SSH clients.
package sshclient

import (
	"io"
	"os"
)

// TUI provides terminal-based user interaction for SSH client operations.
// Its methods are directly compatible with the corresponding fields of
// [UI], so callers can assign them without wrapping closures.
type TUI struct {
	Stdin  *os.File  // terminal input (password reads need an fd)
	Stdout io.Writer // data output (e.g. query results, config dump)
	Stderr io.Writer // prompts and messages

	// Host and User identify the remote account and are used to render
	// the password prompt. Set these before PasswordCallback is invoked.
	Host string
	User string
}

// New returns a TUI wired to the standard file descriptors.
func New() *TUI {
	return &TUI{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}
