package sshkeygen

import (
	"strconv"
	"strings"
)

// Config holds parsed ssh-keygen command-line arguments.
type Config struct {
	KeyType       string // -t
	Bits          int    // -b
	Comment       string // -C
	KeyFile       string // -f
	NewPass       string // -N
	OldPass       string // -P (old passphrase for -p)
	Fingerprint   bool   // -l
	ChangePass    bool   // -p
	ChangeComment bool   // -c
	ShowPub       bool   // -y
	HashAlgo      string // -E (md5 or sha256)
	Quiet         bool   // -q
	Version       bool   // -V
}

// Parse populates cfg from command-line arguments.
// Fields set before calling Parse are preserved unless overridden.
// Default values: KeyType="ed25519", HashAlgo="sha256".
func (cfg *Config) Parse(args ...string) error {
	if cfg.KeyType == "" {
		cfg.KeyType = "ed25519"
	}
	if cfg.HashAlgo == "" {
		cfg.HashAlgo = "sha256"
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t":
			i++
			if i < len(args) {
				cfg.KeyType = args[i]
			}
		case "-b":
			i++
			if i < len(args) {
				cfg.Bits, _ = strconv.Atoi(args[i])
			}
		case "-C":
			i++
			if i < len(args) {
				cfg.Comment = args[i]
			}
		case "-f":
			i++
			if i < len(args) {
				cfg.KeyFile = args[i]
			}
		case "-N":
			i++
			if i < len(args) {
				cfg.NewPass = args[i]
			}
		case "-P":
			i++
			if i < len(args) {
				cfg.OldPass = args[i]
			}
		case "-l":
			cfg.Fingerprint = true
		case "-c":
			cfg.ChangeComment = true
		case "-p":
			cfg.ChangePass = true
		case "-y":
			cfg.ShowPub = true
		case "-E":
			i++
			if i < len(args) {
				cfg.HashAlgo = args[i]
			}
		case "-q":
			cfg.Quiet = true
		case "-V":
			cfg.Version = true
		case "--":
			i = len(args)
		}
	}
	return nil
}

// ParseKeyTypes translates user-friendly type names to SSH algorithm names.
func ParseKeyTypes(spec string) []string {
	var result []string
	for _, t := range strings.Split(spec, ",") {
		t = strings.TrimSpace(t)
		switch strings.ToLower(t) {
		case "rsa":
			result = append(result, "ssh-rsa")
		case "ecdsa":
			result = append(result, "ecdsa-sha2-nistp256")
		case "ed25519":
			result = append(result, "ssh-ed25519")
		default:
			result = append(result, t)
		}
	}
	return result
}
