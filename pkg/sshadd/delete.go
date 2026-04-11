package sshadd

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Delete removes specified keys from the agent. If cfg.Files is empty,
// default key files are tried.
func Delete(cfg *Config, client agent.ExtendedAgent) int {
	files := cfg.Files
	if len(files) == 0 {
		files = DefaultKeyFiles()
	}

	exitCode := 0
	for _, f := range files {
		pubFile := f
		if !strings.HasSuffix(pubFile, ".pub") {
			pubFile = f + ".pub"
		}

		data, err := os.ReadFile(pubFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-add: %v\n", err)
			exitCode = 1
			continue
		}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-add: %s: not a public key file\n", pubFile)
			exitCode = 1
			continue
		}

		if err := client.Remove(pubKey); err != nil {
			fmt.Fprintf(os.Stderr, "ssh-add: could not remove identity \"%s\": %v\n", f, err)
			exitCode = 1
		} else {
			fmt.Fprintf(os.Stderr, "Identity removed: %s\n", f)
		}
	}

	return exitCode
}

// DeleteAll removes all keys from the agent.
func DeleteAll(client agent.ExtendedAgent) int {
	if err := client.RemoveAll(); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: could not remove all identities: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "All identities removed.")
	return 0
}
