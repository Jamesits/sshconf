package sshkeygen

import (
	"fmt"

	"github.com/jamesits/sshconf/pkg/version"
)

// Run dispatches to the appropriate action based on cfg and returns a
// process exit code.
func Run(cfg *Config) int {
	if cfg.Version {
		fmt.Printf("ssh-keygen (sshconf) %s\n", version.Version)
		return 0
	}

	switch {
	case cfg.Fingerprint:
		return Fingerprint(cfg)
	case cfg.ChangePass:
		return ChangePassphrase(cfg)
	case cfg.ShowPub:
		return ShowPublicKey(cfg)
	case cfg.ChangeComment:
		return ChangeComment(cfg)
	default:
		return Generate(cfg)
	}
}
