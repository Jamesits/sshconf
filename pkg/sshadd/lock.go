package sshadd

import (
	"fmt"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// Lock locks the agent with a passphrase read from the terminal.
func Lock(client agent.ExtendedAgent, streams stdio.TerminalStreams) int {
	fmt.Fprintf(streams.Stderr, "Enter lock password: ")
	pw, err := term.ReadPassword(int(streams.Terminal.Fd()))
	fmt.Fprintf(streams.Stderr, "\n")
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-add: %v\n", err)
		return 1
	}
	fmt.Fprintf(streams.Stderr, "Again: ")
	pw2, err := term.ReadPassword(int(streams.Terminal.Fd()))
	fmt.Fprintf(streams.Stderr, "\n")
	if err != nil || string(pw) != string(pw2) {
		fmt.Fprintf(streams.Stderr, "Passwords do not match.\n")
		return 1
	}

	if err := client.Lock(pw); err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-add: could not lock agent: %v\n", err)
		return 1
	}
	fmt.Fprintln(streams.Stderr, "Agent locked.")
	return 0
}

// Unlock unlocks the agent with a passphrase read from the terminal.
func Unlock(client agent.ExtendedAgent, streams stdio.TerminalStreams) int {
	fmt.Fprintf(streams.Stderr, "Enter lock password: ")
	pw, err := term.ReadPassword(int(streams.Terminal.Fd()))
	fmt.Fprintf(streams.Stderr, "\n")
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-add: %v\n", err)
		return 1
	}

	if err := client.Unlock(pw); err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-add: could not unlock agent: %v\n", err)
		return 1
	}
	fmt.Fprintln(streams.Stderr, "Agent unlocked.")
	return 0
}
