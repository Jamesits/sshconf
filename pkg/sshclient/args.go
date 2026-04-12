package sshclient

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
)

// ParseMode controls how positional (non-flag) arguments are interpreted.
type ParseMode int

const (
	// ModeOptionsOnly parses flags only. All positional arguments are
	// collected in Rest.
	ModeOptionsOnly ParseMode = iota
	// ModeOptionsHost parses flags and a destination. The first positional
	// argument becomes Destination; any remaining go to Rest.
	ModeOptionsHost
	// ModeOptionsHostCommand parses flags, a destination, and a remote
	// command. The first positional argument becomes Destination; everything
	// after it becomes Command.
	ModeOptionsHostCommand
)

// CLIArgs holds parsed SSH command-line arguments.
type CLIArgs struct {
	// Connection
	Port        string // raw string, parsed later
	User        string // from -l
	ConfigFile  string
	Options     []string // -o (repeatable)
	PrintConfig bool     // -G
	QueryType   string
	Tag         string

	// Auth
	PKCS11 string

	// Forwarding
	StdioFwd string // -W host:port

	// Session
	TTYCount  int
	NoTTY     bool
	NoCommand bool // -N
	Subsystem bool

	// Debug
	Verbosity int
	Quiet     bool
	LogFile   string
	Version   bool
	Syslog    bool

	// Multiplex
	CtlCmd string

	// Positional
	Destination string
	Command     []string
	Rest        []string // unconsumed positional args (mode-dependent)

	// directives collects config directives derived from CLI flags.
	directives []sshconfig.Directive
}

// LookupUser returns the effective user for host lookup and connection setup.
// An explicit user in the destination takes precedence over -l.
func (a *CLIArgs) LookupUser() string {
	destUser, _ := sshconfig.ParseDestination(a.Destination)
	if destUser != "" {
		return destUser
	}

	return a.User
}

// LookupPort returns the explicitly requested port, if any, in numeric form.
func (a *CLIArgs) LookupPort() (int, error) {
	if a.Port == "" {
		return 0, nil
	}

	port, err := strconv.Atoi(a.Port)
	if err != nil {
		return 0, fmt.Errorf("bad port '%s'", a.Port)
	}

	return port, nil
}

// RemoteCommand joins positional command arguments into the exec payload used
// for config resolution and session setup.
func (a *CLIArgs) RemoteCommand() string {
	return strings.Join(a.Command, " ")
}

// SessionType returns the session type implied by the parsed CLI flags.
func (a *CLIArgs) SessionType() string {
	switch {
	case a.NoCommand:
		return "none"
	case a.Subsystem:
		return "subsystem"
	case a.RemoteCommand() != "":
		return "exec"
	default:
		return ""
	}
}

// Directives returns the config directives derived from CLI flags,
// followed by raw -o options parsed as directives.
// Explicit flags come first (highest priority), then user -o entries.
func (a *CLIArgs) Directives() ([]sshconfig.Directive, error) {
	dirs := make([]sshconfig.Directive, len(a.directives))
	copy(dirs, a.directives)

	// Append raw -o entries
	for i, opt := range a.Options {
		keyword, value, err := parseOverride(opt)
		if err != nil {
			return nil, fmt.Errorf("-o option %d: %w", i+1, err)
		}
		dirs = append(dirs, sshconfig.Directive{
			Keyword: keyword,
			Value:   value,
			Source:  sshconfig.SourceInfo{File: "command-line", Line: i + 1},
		})
	}

	return dirs, nil
}

// cliDirective creates a Directive from a CLI flag.
func cliDirective(keyword, value string) sshconfig.Directive {
	return sshconfig.Directive{
		Keyword: keyword,
		Value:   value,
		Source:  sshconfig.SourceInfo{File: "command-line"},
	}
}

// Parse parses ssh command-line arguments into the receiver.
// Fields set before calling Parse are preserved unless overridden by the arguments.
// mode controls how positional (non-flag) arguments are interpreted.
func (a *CLIArgs) Parse(mode ParseMode, args ...string) error {
	i := 0

	for i < len(args) {
		arg := args[i]

		if arg == "--" {
			i++
			a.consumePositional(args[i:], mode)
			break
		}

		if !strings.HasPrefix(arg, "-") || arg == "-" {
			a.consumePositional(args[i:], mode)
			break
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
			// Boolean flags → directives
			case '4':
				a.directives = append(a.directives, cliDirective("AddressFamily", "inet"))
			case '6':
				a.directives = append(a.directives, cliDirective("AddressFamily", "inet6"))
			case 'A':
				a.directives = append(a.directives, cliDirective("ForwardAgent", "yes"))
			case 'a':
				a.directives = append(a.directives, cliDirective("ForwardAgent", "no"))
			case 'C':
				a.directives = append(a.directives, cliDirective("Compression", "yes"))
			case 'g':
				a.directives = append(a.directives, cliDirective("GatewayPorts", "yes"))
			case 'K':
				a.directives = append(a.directives, cliDirective("GSSAPIAuthentication", "yes"))
				a.directives = append(a.directives, cliDirective("GSSAPIDelegateCredentials", "yes"))
			case 'k':
				a.directives = append(a.directives, cliDirective("GSSAPIDelegateCredentials", "no"))
			case 'M':
				a.directives = append(a.directives, cliDirective("ControlMaster", "yes"))
			case 'N':
				a.NoCommand = true
				a.directives = append(a.directives, cliDirective("SessionType", "none"))
			case 'X':
				a.directives = append(a.directives, cliDirective("ForwardX11", "yes"))
			case 'x':
				a.directives = append(a.directives, cliDirective("ForwardX11", "no"))
			case 'Y':
				a.directives = append(a.directives, cliDirective("ForwardX11", "yes"))
				a.directives = append(a.directives, cliDirective("ForwardX11Trusted", "yes"))

			// Session flags (non-directive but need struct field)
			case 'f':
				a.directives = append(a.directives, cliDirective("StdinNull", "yes"))
				a.directives = append(a.directives, cliDirective("ForkAfterAuthentication", "yes"))
			case 'n':
				a.directives = append(a.directives, cliDirective("StdinNull", "yes"))
			case 's':
				a.Subsystem = true
				a.directives = append(a.directives, cliDirective("SessionType", "subsystem"))
			case 'T':
				a.NoTTY = true
			case 'G':
				a.PrintConfig = true
			case 'V':
				a.Version = true
			case 'y':
				a.Syslog = true
			case 'q':
				a.Quiet = true

			// Countable flags
			case 'v':
				a.Verbosity++
			case 't':
				a.TTYCount++

			// Flags with arguments → directives
			case 'B':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("BindInterface", val))
			case 'b':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("BindAddress", val))
			case 'c':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("Ciphers", val))
			case 'D':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("DynamicForward", val))
			case 'e':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("EscapeChar", val))
			case 'I':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.PKCS11 = val
				a.directives = append(a.directives, cliDirective("PKCS11Provider", val))
			case 'i':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("IdentityFile", val))
			case 'J':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("ProxyJump", val))
			case 'L':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("LocalForward", convertForwardSpec(val)))
			case 'l':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.User = val
			case 'm':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("MACs", val))
			case 'O':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.CtlCmd = val
			case 'o':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.Options = append(a.Options, val)
			case 'P':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.Tag = val
			case 'p':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.Port = val
				a.directives = append(a.directives, cliDirective("Port", val))
			case 'Q':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.QueryType = val
			case 'R':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("RemoteForward", convertForwardSpec(val)))
			case 'S':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("ControlPath", val))
			case 'W':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.StdioFwd = val
			case 'w':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.directives = append(a.directives, cliDirective("Tunnel", "yes"))
				a.directives = append(a.directives, cliDirective("TunnelDevice", val))

			// Non-directive flags with arguments
			case 'E':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.LogFile = val
			case 'F':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.ConfigFile = val

			default:
				return fmt.Errorf("unknown option -- '%c'", ch)
			}
		}
	}

	return nil
}

// consumePositional distributes remaining args into Destination, Command, and
// Rest according to the parse mode.
func (a *CLIArgs) consumePositional(args []string, mode ParseMode) {
	if len(args) == 0 {
		return
	}
	switch mode {
	case ModeOptionsOnly:
		a.Rest = append(a.Rest, args...)
	case ModeOptionsHost:
		if a.Destination == "" {
			a.Destination = args[0]
			args = args[1:]
		}
		a.Rest = append(a.Rest, args...)
	case ModeOptionsHostCommand:
		if a.Destination == "" {
			a.Destination = args[0]
			args = args[1:]
		}
		a.Command = append(a.Command, args...)
	}
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
