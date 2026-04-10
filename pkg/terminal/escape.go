package terminal

import (
	"fmt"
	"io"
	"os"
)

// EscapeReader wraps an io.Reader and processes SSH escape characters.
type EscapeReader struct {
	r          io.Reader
	escapeChar byte
	atStart    bool // at start of line
	buf        [1]byte
	closeFn    func() // called on ~.
}

// NewEscapeReader creates an EscapeReader. escapeChar is the escape character
// string (e.g. "~", "^X", "none"). closeFn is called when the disconnect
// escape sequence is entered.
func NewEscapeReader(r io.Reader, escapeChar string, closeFn func()) *EscapeReader {
	esc := byte('~')
	if len(escapeChar) > 0 {
		if escapeChar == "none" {
			esc = 0
		} else if len(escapeChar) == 2 && escapeChar[0] == '^' {
			esc = escapeChar[1] & 0x1f // ^X notation
		} else {
			esc = escapeChar[0]
		}
	}
	return &EscapeReader{
		r:          r,
		escapeChar: esc,
		atStart:    true,
		closeFn:    closeFn,
	}
}

// Read implements io.Reader, processing escape sequences.
func (e *EscapeReader) Read(p []byte) (int, error) {
	if e.escapeChar == 0 {
		return e.r.Read(p)
	}

	n, err := e.r.Read(e.buf[:])
	if n == 0 {
		return 0, err
	}

	b := e.buf[0]

	if b == '\r' || b == '\n' {
		e.atStart = true
		p[0] = b
		return 1, err
	}

	if e.atStart && b == e.escapeChar {
		e.atStart = false
		// Read next byte
		n2, err2 := e.r.Read(e.buf[:])
		if n2 == 0 {
			p[0] = b
			return 1, err2
		}

		next := e.buf[0]
		switch next {
		case '.':
			// Disconnect
			if e.closeFn != nil {
				e.closeFn()
			}
			return 0, io.EOF
		case '?':
			// Print help to stderr
			fmt.Fprintf(os.Stderr, "\r\nSupported escape sequences:\r\n"+
				" %c.  - disconnect\r\n"+
				" %c?  - this message\r\n"+
				" %c%c  - send the escape character\r\n",
				e.escapeChar, e.escapeChar, e.escapeChar, e.escapeChar)
			// Don't forward anything
			return 0, err2
		case e.escapeChar:
			// Send literal escape char
			p[0] = e.escapeChar
			return 1, err2
		default:
			// Not a recognized escape; forward both characters
			if len(p) >= 2 {
				p[0] = e.escapeChar
				p[1] = next
				return 2, err2
			}
			// Buffer too small; just forward escape char, next byte is lost
			p[0] = e.escapeChar
			return 1, err2
		}
	}

	e.atStart = false
	p[0] = b
	return 1, err
}
