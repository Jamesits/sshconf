package sshadd

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

// Add adds private keys to the agent. If cfg.Files is empty, default
// key files are tried.
func Add(cfg *Config, client agent.ExtendedAgent) int {
	files := cfg.Files
	if len(files) == 0 {
		files = DefaultKeyFiles()
	}

	exitCode := 0
	for _, f := range files {
		if err := addKey(client, f, cfg.Confirm, cfg.Lifetime); err != nil {
			fmt.Fprintf(os.Stderr, "ssh-add: error adding %s: %v\n", f, err)
			exitCode = 1
		} else {
			fmt.Fprintf(os.Stderr, "Identity added: %s\n", f)
		}
	}

	return exitCode
}
