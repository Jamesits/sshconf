package sshkeygen

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/crypto/ssh"
)

// ChangeComment changes the comment on a key file.
func ChangeComment(cfg *Config, streams stdio.TerminalStreams) int {
	keyFile := cfg.KeyFile
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	var privKey any
	privKey, err = ssh.ParseRawPrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			pw, err := readPassword(streams, "Enter passphrase: ")
			if err != nil {
				fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
				return 1
			}
			privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pw)
			if err != nil {
				fmt.Fprintf(streams.Stderr, "ssh-keygen: incorrect passphrase\n")
				return 1
			}
		} else {
			fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, cfg.Comment)
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err == nil {
		pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
		pubLine += " " + cfg.Comment + "\n"
		_ = os.WriteFile(keyFile+".pub", []byte(pubLine), 0644)
	}

	fmt.Fprintf(streams.Stderr, "Comment '%s' applied\n", cfg.Comment)
	return 0
}
