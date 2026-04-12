package sshadd

import (
	"fmt"

	"github.com/jamesits/sshconf/pkg/stdio"
	"golang.org/x/crypto/ssh/agent"
)

// Add adds private keys to the agent. If cfg.Files is empty, default
// key files are tried.
func Add(cfg *Config, client agent.ExtendedAgent, streams stdio.TerminalStreams) int {
	files := cfg.Files
	if len(files) == 0 {
		files = DefaultKeyFiles()
	}

	exitCode := 0
	for _, f := range files {
		if err := addKey(client, f, cfg.Confirm, cfg.Lifetime, streams); err != nil {
			fmt.Fprintf(streams.Stderr, "ssh-add: error adding %s: %v\n", f, err)
			exitCode = 1
		} else {
			fmt.Fprintf(streams.Stderr, "Identity added: %s\n", f)
		}
	}

	return exitCode
}
