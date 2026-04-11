package sshkeyscan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ScanHostKey connects to host:port and retrieves the host key of the
// specified type. Returns the key in known_hosts format "type base64-key".
func ScanHostKey(host string, port int, keyType string, timeout time.Duration) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		HostKeyAlgorithms: []string{keyType},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil
		},
		Timeout: timeout,
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	sshConn, _, _, err := ssh.NewClientConn(conn, addr, config)
	if sshConn != nil {
		sshConn.Close()
	}

	if hostKey != nil {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey))), nil
	}

	if err != nil {
		return "", fmt.Errorf("handshake: %w", err)
	}
	return "", fmt.Errorf("no host key received")
}
