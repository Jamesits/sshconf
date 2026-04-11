package session

import (
	"fmt"
	"os"
	"strings"

	"github.com/jamesits/sshconf/pkg/sshclient"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Handler implements sshclient.SessionConfigurator.
type Handler struct {
	PTYRequested bool // set after PTY is successfully requested
	HasCommand   bool // whether a remote command was specified
}

// NewHandler creates a Handler.
func NewHandler(hasCommand bool) *Handler {
	return &Handler{HasCommand: hasCommand}
}

// ConfigureSession sets up environment variables and PTY allocation.
func (h *Handler) ConfigureSession(session *ssh.Session, opts *sshclient.Options) error {
	// Environment variables
	for _, env := range opts.SetEnv {
		if k, v, ok := strings.Cut(env, "="); ok {
			session.Setenv(k, v)
		}
	}

	// SendEnv: forward matching local env vars
	if len(opts.SendEnv) > 0 {
		for _, envVar := range os.Environ() {
			if k, v, ok := strings.Cut(envVar, "="); ok {
				for _, pattern := range opts.SendEnv {
					if MatchEnvPattern(pattern, k) {
						session.Setenv(k, v)
						break
					}
				}
			}
		}
	}

	// PTY allocation
	requestTTY := "auto"
	if opts.RequestTTY != nil {
		requestTTY = *opts.RequestTTY
	}

	wantPTY := false
	switch requestTTY {
	case "yes", "force":
		wantPTY = true
	case "auto":
		wantPTY = term.IsTerminal(int(os.Stdin.Fd())) && !h.HasCommand
	case "no":
		wantPTY = false
	}

	if wantPTY {
		termType := os.Getenv("TERM")
		if termType == "" {
			termType = "xterm-256color"
		}

		w, h2, err := term.GetSize(int(os.Stdin.Fd()))
		if err != nil {
			w, h2 = 80, 24
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		if err := session.RequestPty(termType, h2, w, modes); err != nil {
			if requestTTY == "force" {
				return fmt.Errorf("requesting PTY: %w", err)
			}
			// For "yes" and "auto", continue without PTY
		} else {
			h.PTYRequested = true
		}
	}

	return nil
}
