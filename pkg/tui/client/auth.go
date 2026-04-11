package client

import (
	"bufio"
	"fmt"
	"strings"

	"golang.org/x/term"
)

// readPassword reads a password from the terminal with echo disabled.
func (t *TUI) readPassword() (string, error) {
	pw, err := term.ReadPassword(int(t.Stdin.Fd()))
	fmt.Fprintf(t.Stderr, "\n")
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

// PasswordCallback prompts for a password. Its signature matches
// [github.com/jamesits/sshconf/pkg/client.UI.PasswordCallback], so it can
// be assigned directly. The prompt uses t.Host and t.User; set those
// before the callback fires.
func (t *TUI) PasswordCallback() (string, error) {
	fmt.Fprintf(t.Stderr, "%s@%s's password: ", t.User, t.Host)
	return t.readPassword()
}

// PassphraseCallback prompts for a private key passphrase.
func (t *TUI) PassphraseCallback(keyFile string) ([]byte, error) {
	fmt.Fprintf(t.Stderr, "Enter passphrase for key '%s': ", keyFile)
	pw, err := t.readPassword()
	if err != nil {
		return nil, err
	}
	return []byte(pw), nil
}

// InteractiveCallback handles keyboard-interactive authentication challenges.
func (t *TUI) InteractiveCallback(name, instruction string, questions []string, echos []bool) ([]string, error) {
	if name != "" {
		fmt.Fprintf(t.Stderr, "%s\n", name)
	}
	if instruction != "" {
		fmt.Fprintf(t.Stderr, "%s\n", instruction)
	}

	answers := make([]string, len(questions))
	reader := bufio.NewReader(t.Stdin)

	for i, q := range questions {
		fmt.Fprintf(t.Stderr, "%s", q)
		if echos[i] {
			line, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			answers[i] = strings.TrimRight(line, "\r\n")
		} else {
			pw, err := t.readPassword()
			if err != nil {
				return nil, err
			}
			answers[i] = pw
		}
	}

	return answers, nil
}
