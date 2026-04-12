package sshadd

import (
	"fmt"

	"github.com/jamesits/sshconf/pkg/stdio"
	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh/agent"
)

// Run connects to the SSH agent and dispatches to the appropriate action
// based on cfg. Returns a process exit code.
func Run(cfg *Config, streams stdio.TerminalStreams) int {
	if cfg.Version {
		fmt.Fprintf(streams.Stdout, "ssh-add (sshconf) %s\n", version.Version)
		return 0
	}

	agentConn, err := ConnectAgent()
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-add: could not open connection to agent: %v\n", err)
		return 2
	}
	defer agentConn.Close()

	agentClient := agent.NewClient(agentConn)

	switch {
	case cfg.List:
		return List(agentClient, streams.Streams)
	case cfg.ListPub:
		return ListPublicKeys(agentClient, streams.Streams)
	case cfg.DeleteAll:
		return DeleteAll(agentClient, streams.Streams)
	case cfg.Delete:
		return Delete(cfg, agentClient, streams.Streams)
	case cfg.Lock:
		return Lock(agentClient, streams)
	case cfg.Unlock:
		return Unlock(agentClient, streams)
	default:
		return Add(cfg, agentClient, streams)
	}
}
