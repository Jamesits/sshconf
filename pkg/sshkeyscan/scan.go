package sshkeyscan

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jamesits/sshconf/pkg/dialer"
	"golang.org/x/crypto/ssh"
)

// ScanHostKey connects to host:port and retrieves the host key of the
// specified type. Returns the key in known_hosts format "type base64-key".
func ScanHostKey(host string, port int, keyType string, timeout time.Duration) (string, error) {
	cfg := &Config{
		AddressFamily: "any",
		Port:          port,
		Timeout:       int(timeout / time.Second),
	}
	cfg.RefreshDialerConfig()
	return cfg.scanHostKey(host, keyType, cfg.DialerConfig.GetDialer(), timeout)
}

// ScanHostKey retrieves a host key using the scanner's stored dialer config.
func (cfg *Config) ScanHostKey(host string, keyType string) (string, error) {
	timeout := time.Duration(cfg.Timeout) * time.Second
	return cfg.scanHostKey(host, keyType, cfg.DialerConfig.GetDialer(), timeout)
}

func (cfg *Config) scanHostKey(host string, keyType string, dialer dialer.Dialer, timeout time.Duration) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(cfg.Port))

	var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		HostKeyAlgorithms: []string{keyType},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil
		},
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
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
