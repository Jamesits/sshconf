package sshagent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/crypto/ssh/agent"
)

// runWithChild starts the agent, runs a command, then cleans up.
func runWithChild(socketPath string, listener net.Listener, keyring agent.Agent, command []string, streams stdio.Streams) int {
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveAgent(listener, keyring)
	}()

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = streams.Stdin
	cmd.Stdout = streams.Stdout
	cmd.Stderr = streams.Stderr
	cmd.Env = append(os.Environ(),
		"SSH_AUTH_SOCK="+socketPath,
		"SSH_AGENT_PID="+strconv.Itoa(os.Getpid()),
	)

	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(streams.Stderr, "ssh-agent: %v\n", err)
			exitCode = 1
		}
	}

	listener.Close()
	cleanupSocket(socketPath)

	return exitCode
}
