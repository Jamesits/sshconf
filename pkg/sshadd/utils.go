package sshadd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// ConnectAgent dials the SSH agent socket specified by SSH_AUTH_SOCK.
func ConnectAgent() (net.Conn, error) {
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}
	return net.Dial("unix", socketPath)
}

// DefaultKeyFiles returns the paths of standard SSH private key files
// that exist in the user's ~/.ssh directory.
func DefaultKeyFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var files []string
	for _, name := range []string{"id_rsa", "id_ecdsa", "id_ed25519"} {
		path := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(path); err == nil {
			files = append(files, path)
		}
	}
	return files
}

// KeySize returns the key size in bits for the given public key.
func KeySize(key ssh.PublicKey) int {
	cryptoKey := key.(ssh.CryptoPublicKey).CryptoPublicKey()
	switch k := cryptoKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// KeyTypeName returns a human-readable name for the SSH key type.
func KeyTypeName(format string) string {
	switch format {
	case "ssh-rsa":
		return "RSA"
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return "ECDSA"
	case "ssh-ed25519":
		return "ED25519"
	default:
		return format
	}
}

func addKey(client agent.ExtendedAgent, path string, confirm bool, lifetime uint32, streams stdio.TerminalStreams) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var privKey any

	privKey, err = ssh.ParseRawPrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); !ok {
			return err
		}

		for attempt := 0; attempt < 3; attempt++ {
			fmt.Fprintf(streams.Stderr, "Enter passphrase for %s: ", path)
			pw, err := term.ReadPassword(int(streams.Terminal.Fd()))
			fmt.Fprintf(streams.Stderr, "\n")
			if err != nil {
				return err
			}
			privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pw)
			if err == nil {
				break
			}
			if attempt < 2 {
				fmt.Fprintf(streams.Stderr, "Bad passphrase, try again.\n")
			}
		}
		if privKey == nil {
			return fmt.Errorf("bad passphrase")
		}
	}

	addedKey := agent.AddedKey{
		PrivateKey:       privKey,
		Comment:          path,
		ConfirmBeforeUse: confirm,
		LifetimeSecs:     lifetime,
	}

	return client.Add(addedKey)
}
