package sshserver

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
)

// CLIArgs holds parsed sshd command-line arguments matching the invocation
// documented in sshd(8).
type CLIArgs struct {
	// -4 / -6: AddressFamily restriction
	IPv4Only bool
	IPv6Only bool

	// -C connection_spec (repeatable): simulation parameters for -T/-G
	ConnectionSpec []string

	// -c host_certificate_file (repeatable)
	HostCertFiles []string

	// -D: foreground mode (do not daemonize)
	Foreground bool

	// -d: debug mode, bumps log level and forces foreground
	DebugLevel int

	// -E log_file: append logs here
	LogFile string

	// -e: log to stderr
	LogStderr bool

	// -f config_file: config file path
	ConfigFile string

	// -g login_grace_time: LoginGraceTime override
	LoginGraceTime string

	// -h host_key_file (repeatable)
	HostKeyFiles []string

	// -i: inetd mode
	Inetd bool

	// -o option (repeatable): raw -o entries
	Options []string

	// -p port (repeatable): Port overrides
	Ports []int

	// -q: quiet mode
	Quiet bool

	// -T: extended test mode (validate config, print, exit)
	TestMode bool

	// -G: parse-and-print config mode
	PrintConfig bool

	// -t: validate config and keys, exit
	Validate bool

	// -u len: utmp hostname truncation size
	UtmpHostLen *int

	// -V: print version
	Version bool

	// directives collects config directives derived from CLI flags.
	directives []sshconfig.Directive
}

// Directives returns the config directives derived from CLI flags,
// followed by raw -o options parsed as directives.
func (a *CLIArgs) Directives() ([]sshconfig.Directive, error) {
	dirs := make([]sshconfig.Directive, len(a.directives))
	copy(dirs, a.directives)

	for i, opt := range a.Options {
		keyword, value, err := sshconfig.ParseOverride(opt)
		if err != nil {
			return nil, fmt.Errorf("-o option %d: %w", i+1, err)
		}
		dirs = append(dirs, sshconfig.Directive{
			Keyword: keyword,
			Value:   value,
			Source: sshconfig.SourceInfo{
				File: "command-line",
				Line: i + 1,
			},
		})
	}
	return dirs, nil
}

// cliDirective constructs a directive with a synthetic "command-line" source.
func cliDirective(keyword, value string) sshconfig.Directive {
	return sshconfig.Directive{
		Keyword: keyword,
		Value:   value,
		Source:  sshconfig.SourceInfo{File: "command-line"},
	}
}

// Parse parses sshd command-line arguments into the receiver.
// Fields set before calling Parse are preserved unless overridden.
func (a *CLIArgs) Parse(args ...string) error {
	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			return fmt.Errorf("unexpected positional argument: %s", arg)
		}
		i++
		flagStr := arg[1:]

		for j := 0; j < len(flagStr); j++ {
			ch := flagStr[j]

			getArg := func() (string, error) {
				if j+1 < len(flagStr) {
					val := flagStr[j+1:]
					j = len(flagStr)
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
			case '4':
				a.IPv4Only = true
				a.directives = append(a.directives, cliDirective("AddressFamily", "inet"))
			case '6':
				a.IPv6Only = true
				a.directives = append(a.directives, cliDirective("AddressFamily", "inet6"))
			case 'D':
				a.Foreground = true
			case 'd':
				a.DebugLevel++
				a.Foreground = true
			case 'e':
				a.LogStderr = true
			case 'G':
				a.PrintConfig = true
			case 'i':
				a.Inetd = true
			case 'q':
				a.Quiet = true
				a.directives = append(a.directives, cliDirective("LogLevel", "QUIET"))
			case 'T':
				a.TestMode = true
			case 't':
				a.Validate = true
			case 'V':
				a.Version = true

			case 'C':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.ConnectionSpec = append(a.ConnectionSpec, val)
			case 'c':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.HostCertFiles = append(a.HostCertFiles, val)
				a.directives = append(a.directives, cliDirective("HostCertificate", val))
			case 'E':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.LogFile = val
			case 'f':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.ConfigFile = val
			case 'g':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.LoginGraceTime = val
				a.directives = append(a.directives, cliDirective("LoginGraceTime", val))
			case 'h':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.HostKeyFiles = append(a.HostKeyFiles, val)
				a.directives = append(a.directives, cliDirective("HostKey", val))
			case 'o':
				val, err := getArg()
				if err != nil {
					return err
				}
				a.Options = append(a.Options, val)
			case 'p':
				val, err := getArg()
				if err != nil {
					return err
				}
				n, err := strconv.Atoi(val)
				if err != nil {
					return fmt.Errorf("invalid port: %s", val)
				}
				a.Ports = append(a.Ports, n)
				a.directives = append(a.directives, cliDirective("Port", val))
			case 'u':
				val, err := getArg()
				if err != nil {
					return err
				}
				n, err := strconv.Atoi(val)
				if err != nil {
					return fmt.Errorf("invalid -u value: %s", val)
				}
				a.UtmpHostLen = &n

			default:
				return fmt.Errorf("unknown option -- '%c'", ch)
			}
		}
	}
	return nil
}

// ParseConnectionSpec parses a single -C argument (comma-separated
// key=value pairs) into a MatchContext overlay. Used by -T/-G test modes
// to simulate a connection for Match block evaluation.
func ParseConnectionSpec(specs []string) map[string]string {
	out := make(map[string]string)
	for _, spec := range specs {
		for _, kv := range strings.Split(spec, ",") {
			kv = strings.TrimSpace(kv)
			if kv == "" {
				continue
			}
			if idx := strings.Index(kv, "="); idx > 0 {
				out[strings.ToLower(kv[:idx])] = kv[idx+1:]
			} else {
				// Flag-only keys like "invalid-user".
				out[strings.ToLower(kv)] = "true"
			}
		}
	}
	return out
}
