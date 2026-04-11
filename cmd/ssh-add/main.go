package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := parseArgs(os.Args[1:])

	if args.version {
		fmt.Printf("ssh-add (sshconf) %s\n", version.Version)
		return 0
	}

	agentConn, err := connectAgent()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: could not open connection to agent: %v\n", err)
		return 2
	}
	defer agentConn.Close()

	agentClient := agent.NewClient(agentConn)

	switch {
	case args.list:
		return cmdList(agentClient)
	case args.listPub:
		return cmdListPublicKeys(agentClient)
	case args.deleteAll:
		return cmdDeleteAll(agentClient)
	case args.delete:
		return cmdDelete(agentClient, args.files)
	case args.lock:
		return cmdLock(agentClient)
	case args.unlock:
		return cmdUnlock(agentClient)
	default:
		return cmdAdd(agentClient, args.files, args.confirm, args.lifetime)
	}
}

type addArgs struct {
	list     bool     // -l
	listPub  bool     // -L
	delete   bool     // -d
	deleteAll bool    // -D
	lock     bool     // -x
	unlock   bool     // -X
	confirm  bool     // -c
	lifetime uint32   // -t
	files    []string
	version  bool
}

func parseArgs(args []string) *addArgs {
	a := &addArgs{}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-l":
			a.list = true
		case "-L":
			a.listPub = true
		case "-d":
			a.delete = true
		case "-D":
			a.deleteAll = true
		case "-x":
			a.lock = true
		case "-X":
			a.unlock = true
		case "-c":
			a.confirm = true
		case "-t":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &a.lifetime)
			}
		case "-V":
			a.version = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				a.files = append(a.files, args[i])
			}
		}
	}

	return a
}

func connectAgent() (net.Conn, error) {
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}
	return net.Dial("unix", socketPath)
}

// cmdAdd adds private keys to the agent.
func cmdAdd(agentClient agent.ExtendedAgent, files []string, confirm bool, lifetime uint32) int {
	if len(files) == 0 {
		files = defaultKeyFiles()
	}

	exitCode := 0
	for _, f := range files {
		if err := addKey(agentClient, f, confirm, lifetime); err != nil {
			fmt.Fprintf(os.Stderr, "ssh-add: error adding %s: %v\n", f, err)
			exitCode = 1
		} else {
			fmt.Fprintf(os.Stderr, "Identity added: %s\n", f)
		}
	}

	return exitCode
}

func addKey(agentClient agent.ExtendedAgent, path string, confirm bool, lifetime uint32) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var privKey any

	privKey, err = ssh.ParseRawPrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); !ok {
			return err
		}

		// Key is encrypted — prompt for passphrase
		for attempt := 0; attempt < 3; attempt++ {
			fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", path)
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil {
				return err
			}
			privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pw)
			if err == nil {
				break
			}
			if attempt < 2 {
				fmt.Fprintf(os.Stderr, "Bad passphrase, try again.\n")
			}
		}
		if privKey == nil {
			return fmt.Errorf("bad passphrase")
		}
	}

	addedKey := agent.AddedKey{
		PrivateKey:       privKey,
		Comment:          path,
		ConfirmBeforeUse: confirm,
		LifetimeSecs:     lifetime,
	}

	return agentClient.Add(addedKey)
}

// cmdList lists keys in the agent with fingerprints.
func cmdList(agentClient agent.ExtendedAgent) int {
	keys, err := agentClient.List()
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
		fmt.Printf("%d %s %s (%s)\n", keySize(pubKey), ssh.FingerprintSHA256(pubKey), key.Comment, keyTypeName(key.Format))
	}

	return 0
}

// cmdListPublicKeys lists keys in the agent in authorized_keys format.
func cmdListPublicKeys(agentClient agent.ExtendedAgent) int {
	keys, err := agentClient.List()
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

// cmdDelete removes specified keys from the agent.
func cmdDelete(agentClient agent.ExtendedAgent, files []string) int {
	if len(files) == 0 {
		files = defaultKeyFiles()
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

		if err := agentClient.Remove(pubKey); err != nil {
			fmt.Fprintf(os.Stderr, "ssh-add: could not remove identity \"%s\": %v\n", f, err)
			exitCode = 1
		} else {
			fmt.Fprintf(os.Stderr, "Identity removed: %s\n", f)
		}
	}

	return exitCode
}

// cmdDeleteAll removes all keys from the agent.
func cmdDeleteAll(agentClient agent.ExtendedAgent) int {
	if err := agentClient.RemoveAll(); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: could not remove all identities: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "All identities removed.")
	return 0
}

// cmdLock locks the agent with a passphrase.
func cmdLock(agentClient agent.ExtendedAgent) int {
	fmt.Fprintf(os.Stderr, "Enter lock password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Again: ")
	pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil || string(pw) != string(pw2) {
		fmt.Fprintf(os.Stderr, "Passwords do not match.\n")
		return 1
	}

	if err := agentClient.Lock(pw); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: could not lock agent: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "Agent locked.")
	return 0
}

// cmdUnlock unlocks the agent.
func cmdUnlock(agentClient agent.ExtendedAgent) int {
	fmt.Fprintf(os.Stderr, "Enter lock password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: %v\n", err)
		return 1
	}

	if err := agentClient.Unlock(pw); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-add: could not unlock agent: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "Agent unlocked.")
	return 0
}

func defaultKeyFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var files []string
	for _, name := range []string{"id_rsa", "id_ecdsa", "id_ed25519"} {
		path := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(path); err == nil {
			files = append(files, path)
		}
	}
	return files
}

func keySize(key ssh.PublicKey) int {
	cryptoKey := key.(ssh.CryptoPublicKey).CryptoPublicKey()
	switch k := cryptoKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func keyTypeName(format string) string {
	switch format {
	case "ssh-rsa":
		return "RSA"
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return "ECDSA"
	case "ssh-ed25519":
		return "ED25519"
	default:
		return format
	}
}
