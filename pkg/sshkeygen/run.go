package sshkeygen

import (
	"fmt"

	"github.com/jamesits/sshconf/pkg/stdio"
	"github.com/jamesits/sshconf/pkg/version"
)

// Run dispatches to the appropriate action based on cfg and returns a
// process exit code.
func Run(cfg *Config, streams stdio.TerminalStreams) int {
	if cfg.Version {
		fmt.Fprintf(streams.Stdout, "ssh-keygen (sshconf) %s\n", version.Version)
		return 0
	}

	switch {
	case cfg.Fingerprint:
		return Fingerprint(cfg, streams)
	case cfg.ChangePass:
		return ChangePassphrase(cfg, streams)
	case cfg.ShowPub:
		return ShowPublicKey(cfg, streams)
	case cfg.ChangeComment:
		return ChangeComment(cfg, streams)
	default:
		return Generate(cfg, streams)
	}
}
