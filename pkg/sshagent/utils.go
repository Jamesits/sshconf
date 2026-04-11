package sshagent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh/agent"
)

// PrintEnv prints the SSH_AGENT_SOCK and SSH_AGENT_PID variables in the
// format appropriate for the given shell type ("bourne" or "csh").
func PrintEnv(socketPath string, pid int, shell string) {
	switch shell {
	case "csh":
		fmt.Printf("setenv SSH_AUTH_SOCK %s;\n", socketPath)
		fmt.Printf("setenv SSH_AGENT_PID %d;\n", pid)
	default:
		fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", socketPath)
		fmt.Printf("SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n", pid)
	}
	fmt.Printf("echo Agent pid %d;\n", pid)
}

func serveAgent(listener net.Listener, keyring agent.Agent) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go agent.ServeAgent(keyring, conn)
	}
}

func cleanupSocket(socketPath string) {
	os.Remove(socketPath)
	dir := filepath.Dir(socketPath)
	if strings.HasPrefix(filepath.Base(dir), "ssh-agent-") {
		os.Remove(dir)
	}
}
