package terminal

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/jamesits/sshconf/pkg/client"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// State manages terminal raw mode and cleanup.
type State struct {
	mu       sync.Mutex
	oldState *term.State
	Session  *ssh.Session
}

// NewState creates a new terminal State.
func NewState() *State {
	return &State{}
}

// MakeRaw puts the terminal into raw mode.
func (t *State) MakeRaw() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	t.oldState = state
	return nil
}

// Restore restores the terminal to its previous state.
func (t *State) Restore() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.oldState != nil {
		term.Restore(int(os.Stdin.Fd()), t.oldState)
		t.oldState = nil
	}
}

// Handler implements client.TerminalHandler.
type Handler struct {
	State *State
}

// NewHandler creates a Handler wrapping the given State.
func NewHandler(state *State) *Handler {
	return &Handler{State: state}
}

// SetupTerminal enters raw mode if a PTY was allocated.
func (h *Handler) SetupTerminal(opts *client.Options) error {
	if h.State == nil {
		return nil
	}

	// Only enter raw mode if the session handler requested a PTY
	// (checked externally before calling)
	if h.State.oldState == nil && h.State.Session != nil {
		if err := h.State.MakeRaw(); err != nil {
			return fmt.Errorf("setting raw mode: %w", err)
		}
	}

	return nil
}

// SetupSIGWINCH starts a goroutine to handle window resize signals.
func SetupSIGWINCH(session *ssh.Session) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)

	go func() {
		for range sigCh {
			w, h, err := term.GetSize(int(os.Stdin.Fd()))
			if err == nil {
				session.WindowChange(h, w)
			}
		}
	}()
}
