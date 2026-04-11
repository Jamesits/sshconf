package sshkeygen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Fingerprint prints the fingerprint of a key file and returns an exit code.
func Fingerprint(cfg *Config) int {
	keyFile := cfg.KeyFile
	if keyFile == "" {
		home, _ := os.UserHomeDir()
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			candidate := filepath.Join(home, ".ssh", name+".pub")
			if _, err := os.Stat(candidate); err == nil {
				keyFile = candidate
				break
			}
		}
		if keyFile == "" {
			fmt.Fprintf(os.Stderr, "ssh-keygen: No key file specified and no default key found\n")
			return 1
		}
	}

	if !strings.HasSuffix(keyFile, ".pub") {
		if _, err := os.Stat(keyFile + ".pub"); err == nil {
			keyFile = keyFile + ".pub"
		}
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %s is not a key file\n", keyFile)
			return 1
		}
		pubKey = signer.PublicKey()
	}

	fp := FingerprintString(pubKey, cfg.HashAlgo)
	size := KeySize(pubKey)
	fmt.Printf("%d %s %s (%s)\n", size, fp, comment, KeyTypeName(pubKey))

	return 0
}
