package sshadd

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// Lock locks the agent with a passphrase read from the terminal.
func Lock(client agent.ExtendedAgent) int {
	fmt.Fprintf(os.Stderr, "Enter lock password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Again: ")
	pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil || string(pw) != string(pw2) {
		fmt.Fprintf(os.Stderr, "Passwords do not match.\n")
		return 1
	}

	if err := client.Lock(pw); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: could not lock agent: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "Agent locked.")
	return 0
}

// Unlock unlocks the agent with a passphrase read from the terminal.
func Unlock(client agent.ExtendedAgent) int {
	fmt.Fprintf(os.Stderr, "Enter lock password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: %v\n", err)
		return 1
	}

	if err := client.Unlock(pw); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: could not unlock agent: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "Agent unlocked.")
	return 0
}
