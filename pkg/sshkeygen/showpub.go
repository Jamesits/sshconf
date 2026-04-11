package sshkeygen

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ShowPublicKey extracts and prints the public key from a private key file.
func ShowPublicKey(cfg *Config) int {
	keyFile := cfg.KeyFile
	if keyFile == "" {
		home, _ := os.UserHomeDir()
		keyFile = filepath.Join(home, ".ssh", "id_ed25519")
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	var signer ssh.Signer
	signer, err = ssh.ParsePrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			fmt.Fprintf(os.Stderr, "Enter passphrase: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
				return 1
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, pw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keygen: incorrect passphrase\n")
				return 1
			}
		} else {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
	}

	fmt.Print(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return 0
}
