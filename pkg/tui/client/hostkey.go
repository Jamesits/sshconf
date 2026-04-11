package client

import (
	"bufio"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// HostKeyConfirm prompts the user to accept an unknown or changed host key.
func (t *TUI) HostKeyConfirm(hostname string, remote net.Addr, key ssh.PublicKey) bool {
	fingerprint := ssh.FingerprintSHA256(key)
	fmt.Fprintf(t.Stderr, "The authenticity of host '%s (%s)' can't be established.\n",
		hostname, remote.String())
	fmt.Fprintf(t.Stderr, "%s key fingerprint is %s.\n",
		key.Type(), fingerprint)
	fmt.Fprintf(t.Stderr, "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")

	reader := bufio.NewReader(t.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.TrimSpace(answer)

	switch strings.ToLower(answer) {
	case "yes":
		return true
	case "no":
		return false
	default:
		return answer == fingerprint
	}
}
