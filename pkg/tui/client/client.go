// Package client provides reusable terminal user-interaction callbacks for SSH
// clients. All I/O goes through the configurable Stdin/Stdout/Stderr fields
// so callers can redirect prompts, data output, and input as needed.
package client

import (
	"io"
	"os"
)

// TUI provides terminal-based user interaction for SSH client operations.
// Its methods are directly compatible with the corresponding fields of
// [github.com/jamesits/sshconf/pkg/client.UI], so callers can assign them
// without wrapping closures.
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
