package client

import (
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
	"golang.org/x/crypto/ssh"
)

// Algorithm name constants matching OpenSSH names.
// These are used for mapping between OpenSSH config names and x/crypto/ssh constants.

// AllSupportedCiphers returns both secure and insecure ciphers supported by x/crypto/ssh.
func AllSupportedCiphers() []string {
	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()
	return append(supported.Ciphers, insecure.Ciphers...)
}

// AllSupportedKexAlgorithms returns all key exchange algorithms.
func AllSupportedKexAlgorithms() []string {
	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()
	return append(supported.KeyExchanges, insecure.KeyExchanges...)
}

// AllSupportedMACs returns all MAC algorithms.
func AllSupportedMACs() []string {
	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()
	return append(supported.MACs, insecure.MACs...)
}

// AllSupportedHostKeyAlgorithms returns all host key algorithms.
func AllSupportedHostKeyAlgorithms() []string {
	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()
	return append(supported.HostKeys, insecure.HostKeys...)
}

// AllSupportedPublicKeyAlgorithms returns all public key auth algorithms.
func AllSupportedPublicKeyAlgorithms() []string {
	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()
	return append(supported.PublicKeyAuths, insecure.PublicKeyAuths...)
}

// resolveAlgorithmList processes a raw algorithm option value (which may have
// +/-/^ prefix) against the appropriate defaults and filters the result to
// only include algorithms actually supported by x/crypto/ssh.
func resolveAlgorithmList(raw string, opensshDefaults string, supported []string) []string {
	defaults := splitAlgList(opensshDefaults)
	resolved := sshconfig.ApplyListOp(raw, defaults)
	return filterSupported(resolved, supported)
}

// ResolveCiphers resolves the Ciphers option to a list of supported cipher names.
func ResolveCiphers(raw string) []string {
	return resolveAlgorithmList(raw, defaultCiphers, AllSupportedCiphers())
}

// ResolveKexAlgorithms resolves the KexAlgorithms option.
func ResolveKexAlgorithms(raw string) []string {
	return resolveAlgorithmList(raw, defaultKexAlgorithms, AllSupportedKexAlgorithms())
}

// ResolveMACs resolves the MACs option.
func ResolveMACs(raw string) []string {
	return resolveAlgorithmList(raw, defaultMACs, AllSupportedMACs())
}

// ResolveHostKeyAlgorithms resolves the HostKeyAlgorithms option.
func ResolveHostKeyAlgorithms(raw string) []string {
	return resolveAlgorithmList(raw, defaultHostKeyAlgorithms, AllSupportedHostKeyAlgorithms())
}

// ResolvePubkeyAcceptedAlgorithms resolves the PubkeyAcceptedAlgorithms option.
func ResolvePubkeyAcceptedAlgorithms(raw string) []string {
	return resolveAlgorithmList(raw, defaultPubkeyAcceptedAlgorithms, AllSupportedPublicKeyAlgorithms())
}

// ResolveHostbasedAcceptedAlgorithms resolves the HostbasedAcceptedAlgorithms option.
func ResolveHostbasedAcceptedAlgorithms(raw string) []string {
	return resolveAlgorithmList(raw, defaultHostbasedAcceptedAlgorithms, AllSupportedPublicKeyAlgorithms())
}

// ResolveCASignatureAlgorithms resolves the CASignatureAlgorithms option.
func ResolveCASignatureAlgorithms(raw string) []string {
	return resolveAlgorithmList(raw, defaultCASignatureAlgorithms, AllSupportedPublicKeyAlgorithms())
}

// filterSupported returns only the algorithms from candidates that appear
// in the supported set. If a candidate uses wildcard patterns, it matches
// against the supported set.
func filterSupported(candidates, supported []string) []string {
	supportedSet := make(map[string]bool, len(supported))
	for _, s := range supported {
		supportedSet[s] = true
	}

	var result []string
	for _, c := range candidates {
		if supportedSet[c] {
			result = append(result, c)
		} else if strings.ContainsAny(c, "*?") {
			// Wildcard in candidates (unusual but possible after list ops)
			for _, s := range supported {
				if sshconfig.MatchPattern(c, s) && !contains(result, s) {
					result = append(result, s)
				}
			}
		}
	}
	return result
}

func contains(slice []string, value string) bool {
	for _, s := range slice {
		if s == value {
			return true
		}
	}
	return false
}

func splitAlgList(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// parseRekeyLimit parses the RekeyLimit value into bytes and seconds.
// Format: "bytes [time]" or "default [time]"
func parseRekeyLimit(value string) (bytes uint64, seconds int) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, 0
	}

	// Parse bytes
	bytesStr := fields[0]
	if strings.ToLower(bytesStr) == "default" {
		bytes = 0 // use library default
	} else {
		bytes = parseSize(bytesStr)
	}

	// Parse optional time
	if len(fields) >= 2 {
		timeStr := fields[1]
		if strings.ToLower(timeStr) != "none" {
			seconds = parseTimeSeconds(timeStr)
		}
	}

	return bytes, seconds
}

// parseSize parses a size string with optional K/M/G suffix.
func parseSize(s string) uint64 {
	if len(s) == 0 {
		return 0
	}
	multiplier := uint64(1)
	last := s[len(s)-1]
	switch last {
	case 'K', 'k':
		multiplier = 1024
		s = s[:len(s)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	var n uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + uint64(c-'0')
		}
	}
	return n * multiplier
}

// parseTimeSeconds parses an OpenSSH time value into seconds.
// Supports: plain seconds, or Nh/Nm/Ns suffixes.
func parseTimeSeconds(s string) int {
	if len(s) == 0 {
		return 0
	}

	total := 0
	current := 0
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			current = current*10 + int(c-'0')
		case c == 's' || c == 'S':
			total += current
			current = 0
		case c == 'm' || c == 'M':
			total += current * 60
			current = 0
		case c == 'h' || c == 'H':
			total += current * 3600
			current = 0
		case c == 'd' || c == 'D':
			total += current * 86400
			current = 0
		case c == 'w' || c == 'W':
			total += current * 604800
			current = 0
		}
	}
	// If no suffix, treat as seconds
	total += current
	return total
}
