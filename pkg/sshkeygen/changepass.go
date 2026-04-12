package sshkeygen

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/crypto/ssh"
)

// ChangePassphrase changes the passphrase on an existing private key.
func ChangePassphrase(cfg *Config, streams stdio.TerminalStreams) int {
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

	var privKey any
	oldPass := cfg.OldPass

	privKey, err = ssh.ParseRawPrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			if oldPass == "" {
				pw, err := readPassword(streams, "Enter old passphrase: ")
				if err != nil {
					fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
					return 1
				}
				oldPass = string(pw)
			}
			privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(oldPass))
			if err != nil {
				fmt.Fprintf(streams.Stderr, "ssh-keygen: incorrect passphrase\n")
				return 1
			}
		} else {
			fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
	}

	newPass := cfg.NewPass
	if newPass == "" {
		pw, err := readPassword(streams, "Enter new passphrase (empty for no passphrase): ")
		if err != nil {
			fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
		if len(pw) > 0 {
			pw2, err := readPassword(streams, "Enter same passphrase again: ")
			if err != nil || string(pw) != string(pw2) {
				fmt.Fprintf(streams.Stderr, "Passphrases do not match.\n")
				return 1
			}
		}
		newPass = string(pw)
	}

	var pemBlock *pem.Block
	if newPass != "" {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, "", []byte(newPass))
	} else {
		pemBlock, err = ssh.MarshalPrivateKey(privKey, "")
	}
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	fmt.Fprintf(streams.Stderr, "Your identification has been saved with the new passphrase.\n")
	return 0
}
