package session

import (
	"fmt"
	"os"
	"strings"

	"github.com/jamesits/sshconf/pkg/client"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentHandler implements client.AgentForwarder.
type AgentHandler struct{}

// ForwardAgent enables SSH agent forwarding on a session.
func (h *AgentHandler) ForwardAgent(sshClient *ssh.Client, session *ssh.Session, opts *client.Options) error {
	agentPath := "no"
	if opts.ForwardAgent != nil {
		agentPath = *opts.ForwardAgent
	}

	if agentPath == "no" {
		return nil
	}

	// Determine the agent socket
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	switch {
	case agentPath == "yes":
		// use SSH_AUTH_SOCK
	case strings.HasPrefix(agentPath, "$"):
		socketPath = os.Getenv(agentPath[1:])
	case agentPath != "yes" && agentPath != "no":
		socketPath = agentPath
	}

	if socketPath == "" {
		return fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	if err := agent.RequestAgentForwarding(session); err != nil {
		return fmt.Errorf("requesting agent forwarding: %w", err)
	}

	if err := agent.ForwardToRemote(sshClient, socketPath); err != nil {
		return fmt.Errorf("forwarding to remote: %w", err)
	}

	return nil
}
