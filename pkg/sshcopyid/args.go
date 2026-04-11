package sshcopyid

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config holds parsed ssh-copy-id command-line arguments.
type Config struct {
	IdentityFile string   // -i
	Port         string   // -p
	ConfigFile   string   // -F
	Options      []string // -o (repeatable)
	DryRun       bool     // -n
	ForceInstall bool     // -f
	Destination  string   // user@host positional argument
	Version      bool     // -V
}

// Parse populates cfg from command-line arguments.
// Fields set before calling Parse are preserved unless overridden.
func (cfg *Config) Parse(args ...string) error {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			i++
			if i < len(args) {
				cfg.IdentityFile = args[i]
			}
		case "-p":
			i++
			if i < len(args) {
				cfg.Port = args[i]
			}
		case "-F":
			i++
			if i < len(args) {
				cfg.ConfigFile = args[i]
			}
		case "-o":
			i++
			if i < len(args) {
				cfg.Options = append(cfg.Options, args[i])
			}
		case "-n":
			cfg.DryRun = true
		case "-f":
			cfg.ForceInstall = true
		case "-V":
			cfg.Version = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				cfg.Destination = args[i]
			}
		}
	}
	return nil
}

// buildDirectives constructs sshconfig.Directive values from the parsed
// command-line options.
func (cfg *Config) buildDirectives() ([]sshconfig.Directive, error) {
	var dirs []sshconfig.Directive
	if cfg.Port != "" {
		dirs = append(dirs, sshconfig.Directive{Keyword: "Port", Value: cfg.Port})
	}
	for _, opt := range cfg.Options {
		parts := strings.SplitN(opt, "=", 2)
		if len(parts) != 2 {
			parts = strings.SplitN(opt, " ", 2)
		}
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid -o option: %s", opt)
		}
		dirs = append(dirs, sshconfig.Directive{Keyword: strings.TrimSpace(parts[0]), Value: strings.TrimSpace(parts[1])})
	}
	return dirs, nil
}

// LoadPublicKey reads the public key to install.
// Tries (in order): the specified -i file, agent keys, default key files.
func LoadPublicKey(identityFile string) ([]byte, string, error) {
	if identityFile != "" {
		pubFile := identityFile
		if !strings.HasSuffix(pubFile, ".pub") {
			pubFile = identityFile + ".pub"
		}
		data, err := os.ReadFile(pubFile)
		if err != nil {
			return nil, "", fmt.Errorf("cannot read public key %s: %w", pubFile, err)
		}
		return data, pubFile, nil
	}

	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath != "" {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			defer conn.Close()
			agentClient := agent.NewClient(conn)
			keys, err := agentClient.List()
			if err == nil && len(keys) > 0 {
				key := keys[0]
				line := ssh.MarshalAuthorizedKey(key)
				return line, key.Comment, nil
			}
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	for _, name := range []string{"id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"} {
		path := filepath.Join(home, ".ssh", name)
		data, err := os.ReadFile(path)
		if err == nil {
			return data, path, nil
		}
	}

	return nil, "", fmt.Errorf("no public key found; specify one with -i")
}
