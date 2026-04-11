package sshagent

import (
	"os"
	"strings"
)

// Config holds parsed ssh-agent command-line arguments.
type Config struct {
	Kill       bool     // -k
	Foreground bool     // -D or -d
	Shell      string   // "csh" or "bourne", auto-detected if empty
	BindAddr   string   // -a
	Command    []string // command to run as child
	Version    bool     // -V
}

// Parse populates cfg from command-line arguments.
// Fields set before calling Parse are preserved unless overridden.
// If Shell is empty after parsing, DetectShell() is called automatically.
func (cfg *Config) Parse(args ...string) error {
	if cfg.Shell == "" {
		cfg.Shell = DetectShell()
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-k":
			cfg.Kill = true
		case "-D":
			cfg.Foreground = true
		case "-d":
			cfg.Foreground = true
		case "-s":
			cfg.Shell = "bourne"
		case "-c":
			cfg.Shell = "csh"
		case "-a":
			i++
			if i < len(args) {
				cfg.BindAddr = args[i]
			}
		case "-V":
			cfg.Version = true
		case "--":
			if i+1 < len(args) {
				cfg.Command = args[i+1:]
			}
			i = len(args)
		default:
			if !strings.HasPrefix(args[i], "-") {
				cfg.Command = args[i:]
				i = len(args)
			}
		}
	}
	return nil
}

// DetectShell returns "csh" if the current SHELL environment variable
// ends with csh/tcsh/fish, otherwise returns "bourne".
func DetectShell() string {
	shell := os.Getenv("SHELL")
	if strings.HasSuffix(shell, "csh") || strings.HasSuffix(shell, "tcsh") || strings.HasSuffix(shell, "fish") {
		return "csh"
	}
	return "bourne"
}
