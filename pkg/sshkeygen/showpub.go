package sshkeygen

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/crypto/ssh"
)

// ShowPublicKey extracts and prints the public key from a private key file.
func ShowPublicKey(cfg *Config, streams stdio.TerminalStreams) int {
	keyFile := cfg.KeyFile
	if keyFile == "" {
		home, _ := os.UserHomeDir()
		keyFile = filepath.Join(home, ".ssh", "id_ed25519")
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	var signer ssh.Signer
	signer, err = ssh.ParsePrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			pw, err := readPassword(streams, "Enter passphrase: ")
			if err != nil {
				fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
				return 1
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, pw)
			if err != nil {
				fmt.Fprintf(streams.Stderr, "ssh-keygen: incorrect passphrase\n")
				return 1
			}
		} else {
			fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
	}

	fmt.Fprint(streams.Stdout, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return 0
}
