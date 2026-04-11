package sshadd

import (
	"fmt"
	"os"

	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh/agent"
)

// Run connects to the SSH agent and dispatches to the appropriate action
// based on cfg. Returns a process exit code.
func Run(cfg *Config) int {
	if cfg.Version {
		fmt.Printf("ssh-add (sshconf) %s\n", version.Version)
		return 0
	}

	agentConn, err := ConnectAgent()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: could not open connection to agent: %v\n", err)
		return 2
	}
	defer agentConn.Close()

	agentClient := agent.NewClient(agentConn)

	switch {
	case cfg.List:
		return List(agentClient)
	case cfg.ListPub:
		return ListPublicKeys(agentClient)
	case cfg.DeleteAll:
		return DeleteAll(agentClient)
	case cfg.Delete:
		return Delete(cfg, agentClient)
	case cfg.Lock:
		return Lock(agentClient)
	case cfg.Unlock:
		return Unlock(agentClient)
	default:
		return Add(cfg, agentClient)
	}
}
