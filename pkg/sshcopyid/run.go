package sshcopyid

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/jamesits/sshconf/pkg/command"
	"github.com/jamesits/sshconf/pkg/logger"
	"github.com/jamesits/sshconf/pkg/sshclient"
	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh"
)

// Run executes the ssh-copy-id action based on cfg and returns a process
// exit code.
func Run(cfg *Config) int {
	if cfg.Version {
		fmt.Printf("ssh-copy-id (sshconf) %s\n", version.Version)
		return 0
	}

	if cfg.Destination == "" {
		fmt.Fprintf(os.Stderr, "usage: ssh-copy-id [-i identity_file] [-p port] [-o option] [-f] [-n] [-s] user@host\n")
		return 1
	}

	pubKeyData, _, err := LoadPublicKey(cfg.IdentityFile)
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

	if cfg.DryRun {
		fmt.Printf("Would install key: %s\n", pubKeyLine)
		return 0
	}

	destUser, destHost := sshclient.ParseDestination(cfg.Destination)

	cliDirectives, err := cfg.buildDirectives()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: %v\n", err)
		return 1
	}

	uiHandler := sshclient.New()
	uiHandler.Host = destHost
	uiHandler.User = destUser

	lgr := logger.New("", 0, false)

	handlers := sshclient.Handlers{
		UI:              uiHandler,
		CommandExecutor: &command.Executor{},
		Logger:          lgr,
	}

	lookupPort := 0
	if cfg.Port != "" {
		lookupPort, _ = strconv.Atoi(cfg.Port)
	}

	lookup := &sshclient.Lookup{
		Host:                  destHost,
		User:                  destUser,
		Port:                  lookupPort,
		OriginalHost:          cfg.Destination,
		Version:               version.Version,
		CommandLineDirectives: cliDirectives,
		Handlers:              handlers,
	}

	if cfg.ConfigFile != "" {
		if strings.ToLower(cfg.ConfigFile) == "none" {
			lookup.UserConfigFile = "/dev/null"
		} else {
			lookup.UserConfigFile = cfg.ConfigFile
		}
	}

	opts, err := lookup.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: %v\n", err)
		return 1
	}

	sshConfig, err := opts.SSHClientConfig(handlers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id: %v\n", err)
		return 1
	}

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
	fmt.Fprintf(os.Stderr, "Now try logging into the machine, with: \"ssh %s\"\n", cfg.Destination)

	return 0
}
