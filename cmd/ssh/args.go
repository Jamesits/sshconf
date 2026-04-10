package main

import (
	"fmt"
	"strings"
)

type cliArgs struct {
	// Connection
	port        string // raw string, parsed later
	user        string // from -l
	ipv4Only    bool
	ipv6Only    bool
	bindAddr    string
	bindIface   string
	compression bool
	configFile  string
	options     []string // -o (repeatable)
	jumpHosts   string
	printConfig bool // -G
	queryType   string
	tag         string

	// Auth
	identityFiles []string
	gssapiDeleg   bool
	gssapiNoDeleg bool
	pkcs11        string

	// Forwarding
	localFwd     []string
	remoteFwd    []string
	dynamicFwd   []string
	stdioFwd     string // -W host:port
	tunnelDev    string
	gatewayPorts bool

	// Session
	ttyCount   int
	noTTY      bool
	stdinNull  bool
	noCommand  bool // -N
	subsystem  bool
	escapeChar string
	background bool

	// Debug
	verbosity int
	quiet     bool
	logFile   string
	version   bool
	syslog    bool

	// Crypto
	ciphers string
	macs    string

	// Multiplex
	masterMode bool
	ctlSocket  string
	ctlCmd     string

	// X11/Agent
	x11        bool
	noX11      bool
	x11Trusted bool
	agentFwd   bool
	noAgentFwd bool

	// Positional
	destination string
	command     []string
}

// parseArgs parses ssh command-line arguments.
// args should be os.Args (including argv[0]).
func parseArgs(args []string) (*cliArgs, error) {
	a := &cliArgs{}
	i := 1 // skip argv[0]

	for i < len(args) {
		arg := args[i]

		if arg == "--" {
			i++
			// Next arg is destination if not yet set
			if a.destination == "" && i < len(args) {
				a.destination = args[i]
				i++
			}
			// Rest is command
			a.command = append(a.command, args[i:]...)
			break
		}

		if !strings.HasPrefix(arg, "-") || arg == "-" {
			// Positional: destination, then command
			if a.destination == "" {
				a.destination = arg
				i++
				// Everything remaining is the remote command
				a.command = append(a.command, args[i:]...)
				break
			}
		}

		// Process flag characters
		i++
		flagStr := arg[1:] // strip leading -

		for j := 0; j < len(flagStr); j++ {
			ch := flagStr[j]

			// Helper to get the argument for a flag that requires one.
			// It consumes the rest of flagStr if non-empty, otherwise the next arg.
			getArg := func() (string, error) {
				if j+1 < len(flagStr) {
					val := flagStr[j+1:]
					j = len(flagStr) // consume rest
					return val, nil
				}
				if i < len(args) {
					val := args[i]
					i++
					return val, nil
				}
				return "", fmt.Errorf("option -%c requires an argument", ch)
			}

			switch ch {
			// Boolean flags
			case '4':
				a.ipv4Only = true
			case '6':
				a.ipv6Only = true
			case 'A':
				a.agentFwd = true
			case 'a':
				a.noAgentFwd = true
			case 'C':
				a.compression = true
			case 'f':
				a.background = true
			case 'G':
				a.printConfig = true
			case 'g':
				a.gatewayPorts = true
			case 'K':
				a.gssapiDeleg = true
			case 'k':
				a.gssapiNoDeleg = true
			case 'M':
				a.masterMode = true
			case 'N':
				a.noCommand = true
			case 'n':
				a.stdinNull = true
			case 's':
				a.subsystem = true
			case 'T':
				a.noTTY = true
			case 'V':
				a.version = true
			case 'X':
				a.x11 = true
			case 'x':
				a.noX11 = true
			case 'Y':
				a.x11Trusted = true
			case 'y':
				a.syslog = true
			case 'q':
				a.quiet = true

			// Countable flags
			case 'v':
				a.verbosity++
			case 't':
				a.ttyCount++

			// Flags with arguments
			case 'B':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.bindIface = val
			case 'b':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.bindAddr = val
			case 'c':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.ciphers = val
			case 'D':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.dynamicFwd = append(a.dynamicFwd, val)
			case 'E':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.logFile = val
			case 'e':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.escapeChar = val
			case 'F':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.configFile = val
			case 'I':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.pkcs11 = val
			case 'i':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.identityFiles = append(a.identityFiles, val)
			case 'J':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.jumpHosts = val
			case 'L':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.localFwd = append(a.localFwd, val)
			case 'l':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.user = val
			case 'm':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.macs = val
			case 'O':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.ctlCmd = val
			case 'o':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.options = append(a.options, val)
			case 'P':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.tag = val
			case 'p':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.port = val
			case 'Q':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.queryType = val
			case 'R':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.remoteFwd = append(a.remoteFwd, val)
			case 'S':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.ctlSocket = val
			case 'W':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.stdioFwd = val
			case 'w':
				val, err := getArg()
				if err != nil {
					return nil, err
				}
				a.tunnelDev = val
			default:
				return nil, fmt.Errorf("unknown option -- '%c'", ch)
			}
		}
	}

	return a, nil
}

// parseDestination splits a destination string into user and host components.
// Handles: user@host, host, user@[ipv6], [ipv6]
func parseDestination(dest string) (user, host string) {
	// Handle [ipv6] notation
	if strings.HasPrefix(dest, "[") {
		// No user before bracket
		if idx := strings.Index(dest, "]"); idx >= 0 {
			return "", dest[1:idx]
		}
		return "", dest
	}

	// Check for user@host
	if atIdx := strings.LastIndex(dest, "@"); atIdx >= 0 {
		user = dest[:atIdx]
		host = dest[atIdx+1:]
		// Strip brackets from [ipv6]
		if strings.HasPrefix(host, "[") {
			if idx := strings.Index(host, "]"); idx >= 0 {
				host = host[1:idx]
			}
		}
		return user, host
	}

	return "", dest
}

// buildCommandLineOptions converts parsed CLI flags into -o style options
// for use with client.Lookup.CommandLineOptions.
// Explicit flags come first (highest priority), then user -o entries.
func (a *cliArgs) buildCommandLineOptions() []string {
	var opts []string

	// Explicit flags first (win over -o entries in first-value-wins)
	if a.port != "" {
		opts = append(opts, "Port="+a.port)
	}
	if a.compression {
		opts = append(opts, "Compression=yes")
	}
	if a.ipv4Only {
		opts = append(opts, "AddressFamily=inet")
	}
	if a.ipv6Only {
		opts = append(opts, "AddressFamily=inet6")
	}
	if a.bindAddr != "" {
		opts = append(opts, "BindAddress="+a.bindAddr)
	}
	if a.bindIface != "" {
		opts = append(opts, "BindInterface="+a.bindIface)
	}
	if a.jumpHosts != "" {
		opts = append(opts, "ProxyJump="+a.jumpHosts)
	}
	if a.escapeChar != "" {
		opts = append(opts, "EscapeChar="+a.escapeChar)
	}
	if a.ciphers != "" {
		opts = append(opts, "Ciphers="+a.ciphers)
	}
	if a.macs != "" {
		opts = append(opts, "MACs="+a.macs)
	}
	if a.pkcs11 != "" {
		opts = append(opts, "PKCS11Provider="+a.pkcs11)
	}
	for _, id := range a.identityFiles {
		opts = append(opts, "IdentityFile="+id)
	}
	for _, fwd := range a.localFwd {
		opts = append(opts, "LocalForward="+convertForwardSpec(fwd))
	}
	for _, fwd := range a.remoteFwd {
		opts = append(opts, "RemoteForward="+convertForwardSpec(fwd))
	}
	for _, fwd := range a.dynamicFwd {
		opts = append(opts, "DynamicForward="+fwd)
	}
	if a.gatewayPorts {
		opts = append(opts, "GatewayPorts=yes")
	}
	if a.gssapiDeleg {
		opts = append(opts, "GSSAPIAuthentication=yes")
		opts = append(opts, "GSSAPIDelegateCredentials=yes")
	}
	if a.gssapiNoDeleg {
		opts = append(opts, "GSSAPIDelegateCredentials=no")
	}
	if a.x11 {
		opts = append(opts, "ForwardX11=yes")
	}
	if a.noX11 {
		opts = append(opts, "ForwardX11=no")
	}
	if a.x11Trusted {
		opts = append(opts, "ForwardX11=yes")
		opts = append(opts, "ForwardX11Trusted=yes")
	}
	if a.agentFwd {
		opts = append(opts, "ForwardAgent=yes")
	}
	if a.noAgentFwd {
		opts = append(opts, "ForwardAgent=no")
	}
	if a.stdinNull || a.background {
		opts = append(opts, "StdinNull=yes")
	}
	if a.background {
		opts = append(opts, "ForkAfterAuthentication=yes")
	}
	if a.noCommand {
		opts = append(opts, "SessionType=none")
	}
	if a.subsystem {
		opts = append(opts, "SessionType=subsystem")
	}
	if a.masterMode {
		opts = append(opts, "ControlMaster=yes")
	}
	if a.ctlSocket != "" {
		opts = append(opts, "ControlPath="+a.ctlSocket)
	}
	if a.tunnelDev != "" {
		opts = append(opts, "Tunnel=yes")
		opts = append(opts, "TunnelDevice="+a.tunnelDev)
	}

	// User -o entries come after explicit flags
	opts = append(opts, a.options...)

	return opts
}

// convertForwardSpec converts CLI-style forward specs (colon-separated) to
// config-file format (space-separated bind and target).
// CLI: [bind_addr:]port:host:hostport  or  [bind_addr:]port
// Config: [bind_addr:]port host:hostport
func convertForwardSpec(spec string) string {
	// If already space-separated, return as-is
	if strings.Contains(spec, " ") {
		return spec
	}

	// Handle Unix socket paths
	if strings.Contains(spec, "/") {
		return spec
	}

	// Handle [ipv6]:port:host:hostport
	if strings.HasPrefix(spec, "[") {
		if end := strings.Index(spec, "]:"); end >= 0 {
			rest := spec[end+2:]
			bind := spec[:end+1]
			// rest is port:host:hostport
			parts := strings.SplitN(rest, ":", 3)
			if len(parts) == 3 {
				return bind + ":" + parts[0] + " " + parts[1] + ":" + parts[2]
			}
			return spec
		}
	}

	// Count colons to determine format
	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 1:
		// Just port
		return spec
	case 2:
		// bind:port or port:host (ambiguous — treat as bind:port for dynamic)
		return spec
	case 3:
		// port:host:hostport
		return parts[0] + " " + parts[1] + ":" + parts[2]
	case 4:
		// bind:port:host:hostport
		return parts[0] + ":" + parts[1] + " " + parts[2] + ":" + parts[3]
	default:
		return spec
	}
}
