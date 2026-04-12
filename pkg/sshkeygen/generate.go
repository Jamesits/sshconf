package sshkeygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/crypto/ssh"
)

// Generate generates a new SSH key pair.
func Generate(cfg *Config, streams stdio.TerminalStreams) int {
	keyFile := cfg.KeyFile
	if keyFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
		switch strings.ToLower(cfg.KeyType) {
		case "rsa":
			keyFile = filepath.Join(home, ".ssh", "id_rsa")
		case "ecdsa":
			keyFile = filepath.Join(home, ".ssh", "id_ecdsa")
		case "ed25519":
			keyFile = filepath.Join(home, ".ssh", "id_ed25519")
		default:
			keyFile = filepath.Join(home, ".ssh", "id_"+cfg.KeyType)
		}
	}

	if _, err := os.Stat(keyFile); err == nil {
		fmt.Fprintf(streams.Stderr, "%s already exists.\n", keyFile)
		fmt.Fprintf(streams.Stderr, "Overwrite (y/n)? ")
		answer, err := readLine(streams)
		if err != nil {
			fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
		if !strings.HasPrefix(strings.ToLower(answer), "y") {
			return 1
		}
	}

	dir := filepath.Dir(keyFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	var privKey any
	var err error

	switch strings.ToLower(cfg.KeyType) {
	case "rsa":
		bits := cfg.Bits
		if bits == 0 {
			bits = 3072
		}
		if bits < 1024 {
			fmt.Fprintf(streams.Stderr, "ssh-keygen: Invalid RSA key length: minimum is 1024 bits\n")
			return 1
		}
		privKey, err = rsa.GenerateKey(rand.Reader, bits)
	case "ecdsa":
		bits := cfg.Bits
		if bits == 0 {
			bits = 256
		}
		var curve elliptic.Curve
		switch bits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			fmt.Fprintf(streams.Stderr, "ssh-keygen: Invalid ECDSA key length: valid lengths are 256, 384, or 521 bits\n")
			return 1
		}
		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		fmt.Fprintf(streams.Stderr, "ssh-keygen: unknown key type %s\n", cfg.KeyType)
		return 1
	}

	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: key generation failed: %v\n", err)
		return 1
	}

	passphrase := []byte(cfg.NewPass)
	if cfg.NewPass == "" && !cfg.Quiet {
		pw, err := readPassword(streams, "Enter passphrase (empty for no passphrase): ")
		if err == nil && len(pw) > 0 {
			pw2, err := readPassword(streams, "Enter same passphrase again: ")
			if err != nil || string(pw) != string(pw2) {
				fmt.Fprintf(streams.Stderr, "Passphrases do not match.\n")
				return 1
			}
			passphrase = pw
		}
	}

	var pemBlock *pem.Block
	if len(passphrase) > 0 {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, cfg.Comment, passphrase)
	} else {
		pemBlock, err = ssh.MarshalPrivateKey(privKey, cfg.Comment)
	}
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}
	pubKey := signer.PublicKey()
	pubLine := string(ssh.MarshalAuthorizedKey(pubKey))
	pubLine = strings.TrimSpace(pubLine)
	if cfg.Comment != "" {
		pubLine += " " + cfg.Comment
	}
	pubLine += "\n"

	pubFile := keyFile + ".pub"
	if err := os.WriteFile(pubFile, []byte(pubLine), 0644); err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	if !cfg.Quiet {
		fmt.Fprintf(streams.Stderr, "Your identification has been saved in %s\n", keyFile)
		fmt.Fprintf(streams.Stderr, "Your public key has been saved in %s\n", pubFile)
		fmt.Fprintf(streams.Stderr, "The key fingerprint is:\n")
		fmt.Fprintf(streams.Stderr, "%s", FingerprintString(pubKey, cfg.HashAlgo))
		if cfg.Comment != "" {
			fmt.Fprintf(streams.Stderr, " %s", cfg.Comment)
		}
		fmt.Fprintf(streams.Stderr, "\n")
	}

	return 0
}
