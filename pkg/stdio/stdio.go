package stdio

import (
	"io"
)

// TerminalInput is a reader backed by a terminal file descriptor.
// Password prompts and other terminal interactions need both behaviors.
type TerminalInput interface {
	io.Reader
	Fd() uintptr
}

// Streams carries process stdio explicitly across package boundaries.
// Command entrypoints populate it and pass it into package code that
// needs terminal input or user-visible output.
type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// TerminalStreams extends Streams with a terminal-backed stdin for
// operations that need a file descriptor, such as password prompts.
type TerminalStreams struct {
	Streams
	Terminal TerminalInput
}

// New constructs a generic Streams bundle.
func New(stdin io.Reader, stdout, stderr io.Writer) Streams {
	return Streams{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
}

// NewTerminal constructs a terminal-capable stream bundle.
func NewTerminal(stdin TerminalInput, stdout, stderr io.Writer) TerminalStreams {
	return TerminalStreams{
		Streams:  New(stdin, stdout, stderr),
		Terminal: stdin,
	}
}
