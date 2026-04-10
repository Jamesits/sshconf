package client

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// buildHostKeyCallback constructs an ssh.HostKeyCallback from the resolved
// configuration options. It layers multiple verification policies:
//
//  1. NoHostAuthenticationForLocalhost bypass
//  2. HostKeyAlias substitution
//  3. Known hosts file verification (UserKnownHostsFile + GlobalKnownHostsFile)
//  4. Revoked host keys check
//  5. StrictHostKeyChecking policy (ask/accept-new/yes/no/off)
func buildHostKeyCallback(opts *Options, callbacks Callbacks, handlers Handlers) (ssh.HostKeyCallback, error) {
	// If caller provides a custom callback, use it directly
	if callbacks.HostKeyCallback != nil {
		return callbacks.HostKeyCallback, nil
	}

	// Collect known hosts files
	var knownHostFiles []string

	if opts.UserKnownHostsFile != nil {
		for _, path := range strings.Fields(*opts.UserKnownHostsFile) {
			if strings.ToLower(path) == "none" {
				continue
			}
			knownHostFiles = append(knownHostFiles, path)
		}
	}
	if opts.GlobalKnownHostsFile != nil {
		for _, path := range strings.Fields(*opts.GlobalKnownHostsFile) {
			knownHostFiles = append(knownHostFiles, path)
		}
	}

	// Filter to existing files
	var existingFiles []string
	for _, f := range knownHostFiles {
		if _, err := os.Stat(f); err == nil {
			existingFiles = append(existingFiles, f)
		}
	}

	// Build the base known_hosts callback
	var baseCallback ssh.HostKeyCallback
	if len(existingFiles) > 0 {
		cb, err := knownhosts.New(existingFiles...)
		if err != nil {
			return nil, fmt.Errorf("loading known hosts: %w", err)
		}
		baseCallback = cb
	}

	// Load revoked keys if configured
	var revokedKeys []ssh.PublicKey
	if opts.RevokedHostKeys != nil && *opts.RevokedHostKeys != "" {
		revoked, err := loadRevokedKeys(*opts.RevokedHostKeys)
		if err != nil {
			return nil, fmt.Errorf("loading revoked host keys: %w", err)
		}
		revokedKeys = revoked
	}

	// Load additional host keys from HostKeySource handler (KnownHostsCommand, etc.)
	var extraHostKeys []ssh.PublicKey
	if handlers.HostKeySource != nil && opts.Hostname != nil {
		lookupName := *opts.Hostname
		if opts.HostKeyAlias != nil {
			lookupName = *opts.HostKeyAlias
		}
		extra, err := handlers.HostKeySource.HostKeys(lookupName, opts)
		if err == nil {
			extraHostKeys = extra
		}
	}

	strictMode := "ask"
	if opts.StrictHostKeyChecking != nil {
		strictMode = *opts.StrictHostKeyChecking
	}

	noAuthLocalhost := opts.NoHostAuthenticationForLocalhost != nil && *opts.NoHostAuthenticationForLocalhost
	hostKeyAlias := ""
	if opts.HostKeyAlias != nil {
		hostKeyAlias = *opts.HostKeyAlias
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// 1. NoHostAuthenticationForLocalhost
		if noAuthLocalhost && isLocalhost(hostname, remote) {
			return nil
		}

		// 2. HostKeyAlias substitution
		lookupHost := hostname
		if hostKeyAlias != "" {
			lookupHost = hostKeyAlias
		}

		// 3. Check revoked keys
		if isRevoked(key, revokedKeys) {
			return fmt.Errorf("host key for %s is revoked", lookupHost)
		}

		// 4. Check extra host keys from HostKeySource handler
		if isKnownExtraKey(key, extraHostKeys) {
			return nil
		}

		// 5. Known hosts verification
		if baseCallback != nil {
			err := baseCallback(lookupHost, remote, key)
			if err == nil {
				return nil // known and trusted
			}

			// Check if it's a "key changed" vs "key unknown" error
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
				// Key changed - always reject unless strict=no/off
				switch strictMode {
				case "no", "off":
					return nil
				default:
					return fmt.Errorf("host key for %s has changed: %w", lookupHost, err)
				}
			}

			// Key is unknown - apply StrictHostKeyChecking policy
			switch strictMode {
			case "yes":
				return fmt.Errorf("host key for %s not found in known hosts", lookupHost)
			case "no", "off":
				return nil
			case "accept-new":
				// Accept new keys, but would reject changed keys (handled above)
				return nil
			case "ask":
				if callbacks.HostKeyConfirm != nil {
					if callbacks.HostKeyConfirm(lookupHost, remote, key) {
						return nil
					}
				}
				return fmt.Errorf("host key for %s not verified", lookupHost)
			default:
				return fmt.Errorf("host key for %s not found in known hosts", lookupHost)
			}
		}

		// No known hosts files at all
		switch strictMode {
		case "yes":
			return fmt.Errorf("no known hosts files and StrictHostKeyChecking=yes")
		case "no", "off", "accept-new":
			return nil
		case "ask":
			if callbacks.HostKeyConfirm != nil {
				if callbacks.HostKeyConfirm(hostname, remote, key) {
					return nil
				}
			}
			return fmt.Errorf("host key for %s not verified", hostname)
		default:
			return fmt.Errorf("host key for %s not verified (no known hosts files)", hostname)
		}
	}, nil
}

// isLocalhost checks if the connection target is a loopback address.
func isLocalhost(hostname string, remote net.Addr) bool {
	if hostname == "localhost" {
		return true
	}
	if tcpAddr, ok := remote.(*net.TCPAddr); ok {
		return tcpAddr.IP.IsLoopback()
	}
	// Parse hostname as IP
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// isKnownExtraKey checks if the key matches any key from the HostKeySource handler.
func isKnownExtraKey(key ssh.PublicKey, extraKeys []ssh.PublicKey) bool {
	if len(extraKeys) == 0 {
		return false
	}
	keyBytes := key.Marshal()
	for _, extra := range extraKeys {
		if string(keyBytes) == string(extra.Marshal()) {
			return true
		}
	}
	return false
}

// isRevoked checks if a key matches any revoked key by comparing marshalled bytes.
func isRevoked(key ssh.PublicKey, revokedKeys []ssh.PublicKey) bool {
	if len(revokedKeys) == 0 {
		return false
	}
	keyBytes := key.Marshal()
	for _, revoked := range revokedKeys {
		if string(keyBytes) == string(revoked.Marshal()) {
			return true
		}
	}
	return false
}

// loadRevokedKeys loads revoked keys from a file. The file may contain
// one public key per line in authorized_keys format.
func loadRevokedKeys(path string) ([]ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var keys []ssh.PublicKey
	rest := data
	for len(rest) > 0 {
		key, _, _, r, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		keys = append(keys, key)
		rest = r
	}

	return keys, nil
}
