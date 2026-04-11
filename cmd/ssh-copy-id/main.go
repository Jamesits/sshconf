package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jamesits/sshconf/pkg/client"
	"github.com/jamesits/sshconf/pkg/command"
	"github.com/jamesits/sshconf/pkg/logger"
	"github.com/jamesits/sshconf/pkg/sshconfig"
	clienttui "github.com/jamesits/sshconf/pkg/tui/client"
	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := parseArgs(os.Args[1:])

	if args.version {
		fmt.Printf("ssh-copy-id (sshconf) %s\n", version.Version)
		return 0
	}

	if args.destination == "" {
		fmt.Fprintf(os.Stderr, "usage: ssh-copy-id [-i identity_file] [-p port] [-o option] [-f] [-n] [-s] user@host\n")
		return 1
	}

	// Read the public key to install
	pubKeyData, identityName, err := loadPublicKey(args.identityFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: %v\n", err)
		return 1
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: invalid public key: %v\n", err)
		return 1
	}
	pubKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))

	if args.dryRun {
		fmt.Printf("Would install key: %s\n", pubKeyLine)
		return 0
	}

	// Parse destination
	destUser, destHost := client.ParseDestination(args.destination)

	// Build config resolution
	cliDirectives, err := buildDirectives(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: %v\n", err)
		return 1
	}

	uiHandler := clienttui.New()
	uiHandler.Host = destHost
	uiHandler.User = destUser

	lgr := logger.New("", 0, false)

	handlers := client.Handlers{
		UI:              uiHandler,
		CommandExecutor: &command.Executor{},
		Logger:          lgr,
	}

	lookupPort := 0
	if args.port != "" {
		lookupPort, _ = strconv.Atoi(args.port)
	}

	lookup := &client.Lookup{
		Host:                  destHost,
		User:                  destUser,
		Port:                  lookupPort,
		OriginalHost:          args.destination,
		Version:               version.Version,
		CommandLineDirectives: cliDirectives,
		Handlers:              handlers,
	}

	if args.configFile != "" {
		if strings.ToLower(args.configFile) == "none" {
			lookup.UserConfigFile = "/dev/null"
		} else {
			lookup.UserConfigFile = args.configFile
		}
	}

	opts, err := lookup.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: %v\n", err)
		return 1
	}

	// Build SSH client config
	sshConfig, err := opts.SSHClientConfig(handlers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: %v\n", err)
		return 1
	}

	// Dial
	conn, err := opts.Dial(handlers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: connect to host %s port %d: %v\n", *opts.Hostname, *opts.Port, err)
		return 1
	}

	addr := net.JoinHostPort(*opts.Hostname, strconv.Itoa(*opts.Port))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: %v\n", err)
		return 1
	}
	sshClient := ssh.NewClient(sshConn, chans, reqs)
	defer sshClient.Close()

	// Install the key
	installCmd := fmt.Sprintf(
		`exec sh -c 'umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && echo "Key installed successfully"' << 'EOF'
%s
EOF`, pubKeyLine)

	session, err := sshClient.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: session error: %v\n", err)
		return 1
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Run(installCmd); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: failed to install key: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "\nNumber of key(s) added: 1\n\n")
	fmt.Fprintf(os.Stderr, "Now try logging into the machine, with: \"ssh %s\"\n", args.destination)
	_ = identityName

	return 0
}

type copyArgs struct {
	identityFile string
	port         string
	configFile   string
	options      []string // -o
	dryRun       bool     // -n
	forceInstall bool     // -f
	destination  string
	version      bool
}

func parseArgs(args []string) *copyArgs {
	a := &copyArgs{}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			i++
			if i < len(args) {
				a.identityFile = args[i]
			}
		case "-p":
			i++
			if i < len(args) {
				a.port = args[i]
			}
		case "-F":
			i++
			if i < len(args) {
				a.configFile = args[i]
			}
		case "-o":
			i++
			if i < len(args) {
				a.options = append(a.options, args[i])
			}
		case "-n":
			a.dryRun = true
		case "-f":
			a.forceInstall = true
		case "-V":
			a.version = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				a.destination = args[i]
			}
		}
	}

	return a
}

func buildDirectives(args *copyArgs) ([]sshconfig.Directive, error) {
	var dirs []sshconfig.Directive
	if args.port != "" {
		dirs = append(dirs, sshconfig.Directive{Keyword: "Port", Value: args.port})
	}
	for _, opt := range args.options {
		parts := strings.SplitN(opt, "=", 2)
		if len(parts) != 2 {
			parts = strings.SplitN(opt, " ", 2)
		}
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid -o option: %s", opt)
		}
		dirs = append(dirs, sshconfig.Directive{Keyword: strings.TrimSpace(parts[0]), Value: strings.TrimSpace(parts[1])})
	}
	return dirs, nil
}

// loadPublicKey reads the public key to install.
// Tries (in order): specified -i file, agent keys, default key files.
func loadPublicKey(identityFile string) ([]byte, string, error) {
	// If -i specified, use it
	if identityFile != "" {
		pubFile := identityFile
		if !strings.HasSuffix(pubFile, ".pub") {
			pubFile = identityFile + ".pub"
		}
		data, err := os.ReadFile(pubFile)
		if err != nil {
			return nil, "", fmt.Errorf("cannot read public key %s: %w", pubFile, err)
		}
		return data, pubFile, nil
	}

	// Try agent keys
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath != "" {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			defer conn.Close()
			agentClient := agent.NewClient(conn)
			keys, err := agentClient.List()
			if err == nil && len(keys) > 0 {
				// Use the first agent key
				key := keys[0]
				line := ssh.MarshalAuthorizedKey(key)
				return line, key.Comment, nil
			}
		}
	}

	// Fall back to default key files
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	for _, name := range []string{"id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"} {
		path := filepath.Join(home, ".ssh", name)
		data, err := os.ReadFile(path)
		if err == nil {
			return data, path, nil
		}
	}

	return nil, "", fmt.Errorf("no public key found; specify one with -i")
}
