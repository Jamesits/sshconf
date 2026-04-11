package sshagent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh/agent"
)

// StartForeground runs the agent in the foreground, printing environment
// variables and waiting for a termination signal.
func StartForeground(socketPath string, listener net.Listener, keyring agent.Agent, shell string) int {
	PrintEnv(socketPath, os.Getpid(), shell)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go serveAgent(listener, keyring)

	<-sigCh
	listener.Close()
	cleanupSocket(socketPath)
	return 0
}

func runDaemon(socketPath string, listener net.Listener, keyring agent.Agent, shell string) int {
	if os.Getenv("_SSH_AGENT_DAEMON") != "" {
		return StartForeground(socketPath, listener, keyring, shell)
	}

	listener.Close()

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: %v\n", err)
		return 1
	}

	childArgs := []string{"-D", "-a", socketPath}

	cmd := exec.Command(exe, childArgs...)
	cmd.Env = append(os.Environ(), "_SSH_AGENT_DAEMON=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: %v\n", err)
		return 1
	}

	PrintEnv(socketPath, cmd.Process.Pid, shell)

	cmd.Process.Release()
	return 0
}
