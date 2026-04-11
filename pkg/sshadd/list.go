package sshadd

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// List lists keys in the agent with fingerprints.
func List(client agent.ExtendedAgent) int {
	keys, err := client.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: error fetching identities: %v\n", err)
		return 1
	}

	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "The agent has no identities.")
		return 0
	}

	for _, key := range keys {
		pubKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			fmt.Printf("%d %s %s (%s)\n", 0, "???", key.Comment, key.Format)
			continue
		}
		fmt.Printf("%d %s %s (%s)\n", KeySize(pubKey), ssh.FingerprintSHA256(pubKey), key.Comment, KeyTypeName(key.Format))
	}

	return 0
}

// ListPublicKeys lists keys in the agent in authorized_keys format.
func ListPublicKeys(client agent.ExtendedAgent) int {
	keys, err := client.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: error fetching identities: %v\n", err)
		return 1
	}

	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "The agent has no identities.")
		return 0
	}

	for _, key := range keys {
		fmt.Printf("%s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), key.Comment)
	}

	return 0
}
