package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"github.com/jamesits/sshconf/pkg/client"
	"github.com/jamesits/sshconf/pkg/command"
	"github.com/jamesits/sshconf/pkg/forward"
	"github.com/jamesits/sshconf/pkg/logger"
	"github.com/jamesits/sshconf/pkg/session"
	"github.com/jamesits/sshconf/pkg/terminal"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const version = "sshconf_1.0"

func main() {
	os.Exit(run())
}

func run() int {
	args, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	if args.version {
		fmt.Printf("ssh (sshconf) %s\n", version)
		return 0
	}

	if args.queryType != "" {
		if err := runQuery(args.queryType); err != nil {
			fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
			return 255
		}
		return 0
	}

	if args.destination == "" {
		fmt.Fprintf(os.Stderr, "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n"+
			"           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]\n"+
			"           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]\n"+
			"           [-i identity_file] [-J [user@]host[:port]] [-L address]\n"+
			"           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-P tag]\n"+
			"           [-p port] [-Q query_option] [-R address] [-S ctl_path]\n"+
			"           [-W host:port] [-w local_tun[:remote_tun]]\n"+
			"           destination [command [argument ...]]\n")
		return 255
	}

	// Parse destination
	destUser, destHost := parseDestination(args.destination)

	// Build lookup
	cmdOpts := args.buildCommandLineOptions()

	// Determine user: user@host wins over -l
	lookupUser := destUser
	if lookupUser == "" {
		lookupUser = args.user
	}

	// Determine port
	lookupPort := 0
	if args.port != "" {
		p, err := strconv.Atoi(args.port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh: bad port '%s'\n", args.port)
			return 255
		}
		lookupPort = p
	}

	// Remote command
	remoteCmd := strings.Join(args.command, " ")

	// Session type
	sessionType := ""
	if args.noCommand {
		sessionType = "none"
	} else if args.subsystem {
		sessionType = "subsystem"
	} else if remoteCmd != "" {
		sessionType = "exec"
	}

	// Logger
	lgr := logger.New(args.logFile, args.verbosity, args.quiet)

	// Session handler (needs to know if there's a command)
	sessHandler := session.NewHandler(remoteCmd != "")

	// Terminal state
	termState := terminal.NewState()

	// Callbacks
	callbacks := client.Callbacks{
		PasswordCallback:    makePasswordCallback(destHost, lookupUser),
		PassphraseCallback:  passphraseCallback,
		InteractiveCallback: interactiveCallback,
		BannerCallback:      bannerCallback,
		HostKeyConfirm:      hostKeyConfirm,
	}

	// Handlers
	handlers := client.Handlers{
		Session:         sessHandler,
		Forwarding:      forward.NewHandler(lgr),
		AgentForwarding: &session.AgentHandler{},
		Terminal:        terminal.NewHandler(termState),
		CommandExecutor: &command.Executor{},
		Logger:          lgr,
	}

	lookup := &client.Lookup{
		Host:               destHost,
		User:               lookupUser,
		Port:               lookupPort,
		OriginalHost:       args.destination,
		Command:            remoteCmd,
		Tag:                args.tag,
		SessionType:        sessionType,
		Version:            version,
		CommandLineOptions: cmdOpts,
		Callbacks:          callbacks,
		Handlers:           handlers,
	}

	if args.configFile != "" {
		if strings.ToLower(args.configFile) == "none" {
			lookup.UserConfigFile = "/dev/null"
		} else {
			lookup.UserConfigFile = args.configFile
		}
	}

	// Resolve config
	opts, err := lookup.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// Post-resolve TTY override
	if args.noTTY {
		opts.RequestTTY = strPtr("no")
	} else if args.ttyCount >= 2 {
		opts.RequestTTY = strPtr("force")
	} else if args.ttyCount == 1 {
		opts.RequestTTY = strPtr("yes")
	}

	// Post-resolve verbosity
	if args.quiet {
		opts.LogLevel = strPtr("QUIET")
	} else if args.verbosity > 0 {
		switch args.verbosity {
		case 1:
			opts.LogLevel = strPtr("VERBOSE")
		case 2:
			opts.LogLevel = strPtr("DEBUG")
		default:
			opts.LogLevel = strPtr("DEBUG3")
		}
	}

	// Stdio forwarding mode
	if args.stdioFwd != "" {
		opts.SessionType = strPtr("none")
		opts.RequestTTY = strPtr("no")
		opts.ClearAllForwardings = boolPtr(true)
		opts.LocalForward = nil
		opts.RemoteForward = nil
		opts.DynamicForward = nil
	}

	// Update logger level from resolved config
	if opts.LogLevel != nil {
		lgr.SetLevel(*opts.LogLevel)
	}

	// -G: print config and exit
	if args.printConfig {
		printConfig(opts, destHost, args.destination)
		return 0
	}

	// Build SSH client config
	sshConfig, err := opts.SSHClientConfig(callbacks, handlers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		return 255
	}

	// Dial
	lgr.Log("VERBOSE", fmt.Sprintf("Connecting to %s port %d", *opts.Hostname, *opts.Port))

	conn, err := opts.Dial(handlers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh: connect to host %s port %d: %v\n", *opts.Hostname, *opts.Port, err)
		return 255
	}

	// SSH handshake
	addr := net.JoinHostPort(*opts.Hostname, strconv.Itoa(*opts.Port))
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
	if args.stdioFwd != "" {
		return forward.RunStdioForward(sshClient, args.stdioFwd)
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
		if args.subsystem {
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

// Callbacks

func makePasswordCallback(host, user string) func() (string, error) {
	return func() (string, error) {
		fmt.Fprintf(os.Stderr, "%s@%s's password: ", user, host)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintf(os.Stderr, "\n")
		if err != nil {
			return "", err
		}
		return string(pw), nil
	}
}

func passphraseCallback(keyFile string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "Enter passphrase for key '%s': ", keyFile)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		return nil, err
	}
	return pw, nil
}

func interactiveCallback(name, instruction string, questions []string, echos []bool) ([]string, error) {
	if name != "" {
		fmt.Fprintf(os.Stderr, "%s\n", name)
	}
	if instruction != "" {
		fmt.Fprintf(os.Stderr, "%s\n", instruction)
	}

	answers := make([]string, len(questions))
	reader := bufio.NewReader(os.Stdin)

	for i, q := range questions {
		fmt.Fprintf(os.Stderr, "%s", q)
		if echos[i] {
			line, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			answers[i] = strings.TrimRight(line, "\r\n")
		} else {
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil {
				return nil, err
			}
			answers[i] = string(pw)
		}
	}

	return answers, nil
}

func bannerCallback(message string) error {
	fmt.Fprint(os.Stderr, message)
	return nil
}

func hostKeyConfirm(hostname string, remote net.Addr, key ssh.PublicKey) bool {
	fingerprint := ssh.FingerprintSHA256(key)
	fmt.Fprintf(os.Stderr, "The authenticity of host '%s (%s)' can't be established.\n",
		hostname, remote.String())
	fmt.Fprintf(os.Stderr, "%s key fingerprint is %s.\n",
		key.Type(), fingerprint)
	fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")

	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.TrimSpace(answer)

	switch strings.ToLower(answer) {
	case "yes":
		return true
	case "no":
		return false
	default:
		return answer == fingerprint
	}
}

// printConfig prints the resolved configuration in ssh -G format.
func printConfig(opts *client.Options, host, originalHost string) {
	p := func(key string, val any) {
		if val == nil {
			return
		}
		v := reflect.ValueOf(val)
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return
			}
			v = v.Elem()
		}
		switch v.Kind() {
		case reflect.Bool:
			if v.Bool() {
				fmt.Printf("%s yes\n", key)
			} else {
				fmt.Printf("%s no\n", key)
			}
		case reflect.Int:
			fmt.Printf("%s %d\n", key, v.Int())
		case reflect.String:
			fmt.Printf("%s %s\n", key, v.String())
		}
	}

	pSlice := func(key string, vals []string) {
		for _, v := range vals {
			fmt.Printf("%s %s\n", key, v)
		}
	}

	pFwd := func(key string, fwds []client.Forward) {
		for _, f := range fwds {
			bind := f.BindAddress
			if bind != "" {
				bind += ":"
			}
			fmt.Printf("%s %s%s %s:%s\n", key, bind, f.BindPort, f.Host, f.HostPort)
		}
	}

	fmt.Printf("host %s\n", originalHost)

	p("user", opts.User)
	p("hostname", opts.Hostname)
	p("port", opts.Port)
	p("addressfamily", opts.AddressFamily)
	p("bindaddress", opts.BindAddress)
	p("bindinterface", opts.BindInterface)
	p("connecttimeout", opts.ConnectTimeout)
	p("connectionattempts", opts.ConnectionAttempts)
	p("tcpkeepalive", opts.TCPKeepAlive)
	p("serveraliveinterval", opts.ServerAliveInterval)
	p("serveralivecountmax", opts.ServerAliveCountMax)
	p("compression", opts.Compression)
	p("batchmode", opts.BatchMode)

	pSlice("identityfile", opts.IdentityFile)
	pSlice("certificatefile", opts.CertificateFile)
	p("identitiesonly", opts.IdentitiesOnly)
	p("identityagent", opts.IdentityAgent)
	p("passwordauthentication", opts.PasswordAuthentication)
	p("kbdinteractiveauthentication", opts.KbdInteractiveAuthentication)
	p("pubkeyauthentication", opts.PubkeyAuthentication)
	p("preferredauthentications", opts.PreferredAuthentications)
	p("numberofpasswordprompts", opts.NumberOfPasswordPrompts)
	p("hostbasedauthentication", opts.HostbasedAuthentication)
	p("gssapiauthentication", opts.GSSAPIAuthentication)
	p("gssapidelegatecredentials", opts.GSSAPIDelegateCredentials)
	p("addkeystoagent", opts.AddKeysToAgent)

	p("ciphers", opts.Ciphers)
	p("kexalgorithms", opts.KexAlgorithms)
	p("macs", opts.MACs)
	p("hostkeyalgorithms", opts.HostKeyAlgorithms)
	p("pubkeyacceptedalgorithms", opts.PubkeyAcceptedAlgorithms)
	p("casignaturealgorithms", opts.CASignatureAlgorithms)
	p("rekeylimit", opts.RekeyLimit)
	p("requiredrsasize", opts.RequiredRSASize)
	p("fingerprinthash", opts.FingerprintHash)

	p("stricthostkeychecking", opts.StrictHostKeyChecking)
	p("userknownhostsfile", opts.UserKnownHostsFile)
	p("globalknownhostsfile", opts.GlobalKnownHostsFile)
	p("hashknownhosts", opts.HashKnownHosts)
	p("checkhostip", opts.CheckHostIP)
	p("hostkeyalias", opts.HostKeyAlias)
	p("knownhostscommand", opts.KnownHostsCommand)
	p("revokedhostkeys", opts.RevokedHostKeys)
	p("updatehostkeys", opts.UpdateHostKeys)
	p("verifyhostkeydns", opts.VerifyHostKeyDNS)
	p("nohostauthenticationforlocalhost", opts.NoHostAuthenticationForLocalhost)

	p("proxycommand", opts.ProxyCommand)
	p("proxyjump", opts.ProxyJump)
	p("proxyusefdpass", opts.ProxyUseFdpass)

	pFwd("localforward", opts.LocalForward)
	pFwd("remoteforward", opts.RemoteForward)
	pSlice("dynamicforward", opts.DynamicForward)
	p("clearallforwardings", opts.ClearAllForwardings)
	p("exitonforwardfailure", opts.ExitOnForwardFailure)
	p("gatewayports", opts.GatewayPorts)

	p("forwardagent", opts.ForwardAgent)
	p("forwardx11", opts.ForwardX11)
	p("forwardx11trusted", opts.ForwardX11Trusted)
	p("forwardx11timeout", opts.ForwardX11Timeout)
	p("xauthlocation", opts.XAuthLocation)

	p("tunnel", opts.Tunnel)
	p("tunneldevice", opts.TunnelDevice)

	p("requesttty", opts.RequestTTY)
	p("sessiontype", opts.SessionType)
	p("remotecommand", opts.RemoteCommand)
	pSlice("sendenv", opts.SendEnv)
	pSlice("setenv", opts.SetEnv)
	p("escapechar", opts.EscapeChar)
	p("loglevel", opts.LogLevel)
	p("syslogfacility", opts.SyslogFacility)

	p("controlmaster", opts.ControlMaster)
	p("controlpath", opts.ControlPath)
	p("controlpersist", opts.ControlPersist)

	p("permitlocalcommand", opts.PermitLocalCommand)
	p("localcommand", opts.LocalCommand)
	p("visualhostkey", opts.VisualHostKey)
	p("forkafterauthentication", opts.ForkAfterAuthentication)
	p("stdinnull", opts.StdinNull)
	p("enableescapecommandline", opts.EnableEscapeCommandline)
	p("obscurekeystroketiming", opts.ObscureKeystrokeTiming)

	p("canonicalizehostname", opts.CanonicalizeHostname)
	pSlice("canonicaldomains", opts.CanonicalDomains)
	p("canonicalizemaxdots", opts.CanonicalizeMaxDots)
	p("canonicalizefallbacklocal", opts.CanonicalizeFallbackLocal)
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
