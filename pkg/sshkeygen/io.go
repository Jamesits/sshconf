package sshkeygen

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/term"
)

func readLine(streams stdio.TerminalStreams) (string, error) {
	line, err := bufio.NewReader(streams.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readPassword(streams stdio.TerminalStreams, prompt string) ([]byte, error) {
	fmt.Fprint(streams.Stderr, prompt)
	pw, err := term.ReadPassword(int(streams.Terminal.Fd()))
	fmt.Fprint(streams.Stderr, "\n")
	if err != nil {
		return nil, err
	}
	return pw, nil
}
