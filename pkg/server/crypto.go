package server

import (
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
	"golang.org/x/crypto/ssh"
)

// Supported algorithm accessors. These mirror the client package helpers but
// live in server because the import path is namespaced to the consumer.
//
// Rather than duplicate the +/-/^ resolution logic, they reuse
// sshconfig.ApplyListOp and then filter by what x/crypto/ssh actually supports.

// AllSupportedCiphers returns both secure and insecure ciphers.
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

// AllSupportedHostKeyAlgorithms returns all host key signing algorithms.
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

// ResolveCiphers resolves the Ciphers option.
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

func resolveAlgorithmList(raw string, opensshDefaults string, supported []string) []string {
	defaults := sshconfig.SplitAlgList(opensshDefaults)
	resolved := sshconfig.ApplyListOp(raw, defaults)
	return filterSupported(resolved, supported)
}

// filterSupported returns only the algorithms from candidates that appear
// in the supported set, expanding any wildcard patterns.
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
