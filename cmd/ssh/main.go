package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/jamesits/sshconf/pkg/command"
	"github.com/jamesits/sshconf/pkg/forward"
	"github.com/jamesits/sshconf/pkg/logger"
	"github.com/jamesits/sshconf/pkg/session"
	"github.com/jamesits/sshconf/pkg/sshclient"
	"github.com/jamesits/sshconf/pkg/stdio"
	"github.com/jamesits/sshconf/pkg/terminal"
	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := &sshclient.CLIArgs{}
	if err := args.Parse(sshclient.ModeOptionsHostCommand, os.Args[1:]...); err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	if args.Version {
		fmt.Printf("ssh (sshconf) %s\n", version.Version)
		return 0
	}

	uiHandler := sshclient.NewTUI(stdio.NewTerminal(os.Stdin, os.Stdout, os.Stderr))

	if args.QueryType != "" {
		if err := uiHandler.RunQuery(args.QueryType); err != nil {
			fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
			return 255
		}
		return 0
	}

	if args.Destination == "" {
		uiHandler.Usage("ssh", sshclient.ModeOptionsHostCommand)
		return 255
	}

	// Parse destination
	destUser, destHost := sshclient.ParseDestination(args.Destination)

	// Build directives from CLI flags
	cliDirectives, err := args.Directives()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// Determine user: user@host wins over -l
	lookupUser := destUser
	if lookupUser == "" {
		lookupUser = args.User
	}

	// Determine port
	lookupPort := 0
	if args.Port != "" {
		p, err := strconv.Atoi(args.Port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh: bad port '%s'\n", args.Port)
			return 255
		}
		lookupPort = p
	}

	// Remote command
	remoteCmd := strings.Join(args.Command, " ")

	// Session type
	sessionType := ""
	if args.NoCommand {
		sessionType = "none"
	} else if args.Subsystem {
		sessionType = "subsystem"
	} else if remoteCmd != "" {
		sessionType = "exec"
	}

	// Logger
	lgr := logger.New(args.LogFile, args.Verbosity, args.Quiet)

	// Session handler (needs to know if there's a command)
	sessHandler := session.NewHandler(remoteCmd != "")

	// Terminal state
	termState := terminal.NewState()

	// Give the TUI the remote identity so its PasswordCallback can render
	// the standard "user@host's password:" prompt.
	uiHandler.Host = destHost
	uiHandler.User = lookupUser

	// Handlers
	handlers := sshclient.Handlers{
		UI:              uiHandler,
		Session:         sessHandler,
		Forwarding:      forward.NewHandler(lgr.Child("forward")),
		AgentForwarding: &session.AgentHandler{},
		Terminal:        terminal.NewHandler(termState),
		CommandExecutor: &command.Executor{},
		Logger:          lgr.Child("sshclient"),
	}

	lookup := &sshclient.Lookup{
		Host:                  destHost,
		User:                  lookupUser,
		Port:                  lookupPort,
		OriginalHost:          args.Destination,
		Command:               remoteCmd,
		Tag:                   args.Tag,
		SessionType:           sessionType,
		Version:               version.Version,
		CommandLineDirectives: cliDirectives,
		Handlers:              handlers,
	}

	if args.ConfigFile != "" {
		if strings.ToLower(args.ConfigFile) == "none" {
			lookup.UserConfigFile = "/dev/null"
		} else {
			lookup.UserConfigFile = args.ConfigFile
		}
	}

	// Resolve config
	opts, err := lookup.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// Post-resolve TTY override
	if args.NoTTY {
		opts.RequestTTY = strPtr("no")
	} else if args.TTYCount >= 2 {
		opts.RequestTTY = strPtr("force")
	} else if args.TTYCount == 1 {
		opts.RequestTTY = strPtr("yes")
	}

	// Post-resolve verbosity
	if args.Quiet {
		opts.LogLevel = strPtr("QUIET")
	} else if args.Verbosity > 0 {
		switch args.Verbosity {
		case 1:
			opts.LogLevel = strPtr("VERBOSE")
		case 2:
			opts.LogLevel = strPtr("DEBUG")
		default:
			opts.LogLevel = strPtr("DEBUG3")
		}
	}

	// Stdio forwarding mode
	if args.StdioFwd != "" {
		opts.SessionType = strPtr("none")
		opts.RequestTTY = strPtr("no")
		v := true
		opts.ClearAllForwardings = &v
		opts.LocalForward = nil
		opts.RemoteForward = nil
		opts.DynamicForward = nil
	}

	// Update logger level from resolved config
	if opts.LogLevel != nil {
		lgr.SetLevel(*opts.LogLevel)
	}

	// -G: print config and exit
	if args.PrintConfig {
		uiHandler.PrintConfig(opts, destHost, args.Destination)
		return 0
	}

	// Build SSH client config
	sshConfig, err := opts.SSHClientConfig(handlers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// Dial
	lgr.Log("VERBOSE", fmt.Sprintf("Connecting to %s port %d", *opts.Hostname, *opts.Port))
	if opts.DialerConfig.Wrapper == nil {
		opts.DialerConfig.Wrapper = handlers.Dialer
	}

	addr := net.JoinHostPort(*opts.Hostname, strconv.Itoa(*opts.Port))
	conn, err := opts.DialerConfig.GetDialer().DialContext(context.Background(), "tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: connect to host %s port %d: %v\n", *opts.Hostname, *opts.Port, err)
		return 255
	}

	// SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}
	sshClient := ssh.NewClient(sshConn, chans, reqs)
	defer sshClient.Close()

	lgr.Log("VERBOSE", "Authentication succeeded")

	// Post-connect: forwarding, multiplex, local command
	if err := opts.PostConnect(sshClient, handlers); err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// Stdio forwarding mode (-W)
	if args.StdioFwd != "" {
		return forward.RunStdioForward(sshClient, args.StdioFwd)
	}

	// No-session mode (-N)
	if opts.SessionType != nil && *opts.SessionType == "none" {
		lgr.Log("VERBOSE", "No session requested, waiting...")
		sshClient.Wait()
		return 0
	}

	// Open session
	sshSession, err := sshClient.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: session error: %v\n", err)
		return 255
	}
	defer sshSession.Close()

	// Store session in terminal state for SIGWINCH
	termState.Session = sshSession

	// Configure session (PTY, env, etc.)
	if err := opts.ConfigureSession(sshClient, sshSession, handlers); err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// If PTY was allocated, set up raw mode and SIGWINCH
	if sessHandler.PTYRequested {
		if err := termState.MakeRaw(); err != nil {
			lgr.Log("DEBUG", fmt.Sprintf("Failed to set raw mode: %v", err))
		} else {
			defer termState.Restore()
		}
		terminal.SetupSIGWINCH(sshSession)
	}

	// Set up I/O
	var stdin io.Reader = os.Stdin
	if opts.StdinNull != nil && *opts.StdinNull {
		stdin = strings.NewReader("")
	} else if sessHandler.PTYRequested && opts.EscapeChar != nil && *opts.EscapeChar != "none" {
		stdin = terminal.NewEscapeReader(os.Stdin, *opts.EscapeChar, func() {
			termState.Restore()
			sshSession.Close()
		})
	}

	sshSession.Stdout = os.Stdout
	sshSession.Stderr = os.Stderr

	stdinPipe, err := sshSession.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// Start stdin copy goroutine
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		io.Copy(stdinPipe, stdin)
		stdinPipe.Close()
	}()

	// Start session
	if remoteCmd != "" {
		if args.Subsystem {
			err = sshSession.RequestSubsystem(remoteCmd)
		} else {
			err = sshSession.Start(remoteCmd)
		}
	} else {
		err = sshSession.Shell()
	}
	if err != nil {
		termState.Restore()
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// Handle SIGINT/SIGTERM for non-PTY sessions
	if !sessHandler.PTYRequested {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for sig := range sigCh {
				switch sig {
				case syscall.SIGINT:
					sshSession.Signal(ssh.SIGINT)
				case syscall.SIGTERM:
					sshSession.Signal(ssh.SIGTERM)
				}
			}
		}()
	}

	// Wait for session to finish
	err = sshSession.Wait()

	termState.Restore()

	return exitCode(err)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitStatus()
		if code != 0 {
			return code
		}
		if exitErr.Signal() != "" {
			return 128 + signalNumber(exitErr.Signal())
		}
		return code
	}
	return 255
}

func signalNumber(sig string) int {
	signals := map[string]int{
		"HUP":  1,
		"INT":  2,
		"QUIT": 3,
		"ABRT": 6,
		"KILL": 9,
		"TERM": 15,
		"USR1": 10,
		"USR2": 12,
	}
	if n, ok := signals[sig]; ok {
		return n
	}
	return 0
}

func strPtr(s string) *string { return &s }
