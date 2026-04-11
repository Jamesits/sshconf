package sshkeygen

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ChangePassphrase changes the passphrase on an existing private key.
func ChangePassphrase(cfg *Config) int {
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

	var privKey any
	oldPass := cfg.OldPass

	privKey, err = ssh.ParseRawPrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			if oldPass == "" {
				fmt.Fprintf(os.Stderr, "Enter old passphrase: ")
				pw, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintf(os.Stderr, "\n")
				if err != nil {
					fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
					return 1
				}
				oldPass = string(pw)
			}
			privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(oldPass))
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keygen: incorrect passphrase\n")
				return 1
			}
		} else {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
	}

	newPass := cfg.NewPass
	if newPass == "" {
		fmt.Fprintf(os.Stderr, "Enter new passphrase (empty for no passphrase): ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintf(os.Stderr, "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
		if len(pw) > 0 {
			fmt.Fprintf(os.Stderr, "Enter same passphrase again: ")
			pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil || string(pw) != string(pw2) {
				fmt.Fprintf(os.Stderr, "Passphrases do not match.\n")
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
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "Your identification has been saved with the new passphrase.\n")
	return 0
}
