package sshagent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh/agent"
)

// Run dispatches to the appropriate action based on cfg and returns a
// process exit code.
func Run(cfg *Config) int {
	if cfg.Version {
		fmt.Printf("ssh-agent (sshconf) %s\n", version.Version)
		return 0
	}

	if cfg.Kill {
		return Kill()
	}

	socketPath := cfg.BindAddr
	if socketPath == "" {
		dir, err := os.MkdirTemp("", "ssh-agent-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-agent: %v\n", err)
			return 1
		}
		socketPath = filepath.Join(dir, "agent."+strconv.Itoa(os.Getpid()))
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: cannot listen on %s: %v\n", socketPath, err)
		return 1
	}
	defer listener.Close()

	os.Chmod(socketPath, 0600)

	keyring := agent.NewKeyring()

	if len(cfg.Command) > 0 {
		return runWithChild(socketPath, listener, keyring, cfg.Command)
	}

	if cfg.Foreground {
		return StartForeground(socketPath, listener, keyring, cfg.Shell)
	}

	return runDaemon(socketPath, listener, keyring, cfg.Shell)
}
