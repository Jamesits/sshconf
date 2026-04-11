package sshserver

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// AuthorizedKeysAuthenticator is a minimal PublicKeyAuthenticator that reads
// keys from the target user's AuthorizedKeysFile paths and accepts any
// matching public key. It does NOT currently evaluate key options
// (from=, command=, etc.) — callers needing those semantics should wrap
// this implementation.
type AuthorizedKeysAuthenticator struct{}

// AuthenticatePublicKey implements PublicKeyAuthenticator.
func (a *AuthorizedKeysAuthenticator) AuthenticatePublicKey(meta ssh.ConnMetadata, key ssh.PublicKey, opts *Options) (*ssh.Permissions, error) {
	usr, err := user.Lookup(meta.User())
	if err != nil {
		return nil, fmt.Errorf("unknown user: %w", err)
	}

	files := opts.AuthorizedKeysFile
	if len(files) == 0 {
		files = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
	}

	keyBytes := key.Marshal()
	for _, relPath := range files {
		path := relPath
		if !filepath.IsAbs(path) {
			path = filepath.Join(usr.HomeDir, path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		rest := data
		for len(rest) > 0 {
			auth, _, _, next, err := ssh.ParseAuthorizedKey(rest)
			if err != nil {
				break
			}
			rest = next
			if bytes.Equal(auth.Marshal(), keyBytes) {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(key),
					},
				}, nil
			}
		}
	}
	return nil, errors.New("public key not authorized")
}

// DenyPasswordAuthenticator is a PasswordAuthenticator that rejects every
// attempt. It is a safe default for deployments that rely solely on
// public-key authentication.
type DenyPasswordAuthenticator struct{}

// AuthenticatePassword always returns an error.
func (DenyPasswordAuthenticator) AuthenticatePassword(_ ssh.ConnMetadata, _ []byte, _ *Options) (*ssh.Permissions, error) {
	return nil, errors.New("password authentication disabled")
}

// StaticPasswordAuthenticator authenticates by looking up the user/password
// in an in-memory map. It is intended for tests and simple deployments
// only — production should use PAM or a dedicated backend.
type StaticPasswordAuthenticator struct {
	// Users maps usernames to their passwords.
	Users map[string]string
}

// AuthenticatePassword implements PasswordAuthenticator.
func (s *StaticPasswordAuthenticator) AuthenticatePassword(meta ssh.ConnMetadata, password []byte, _ *Options) (*ssh.Permissions, error) {
	want, ok := s.Users[meta.User()]
	if !ok {
		return nil, errors.New("unknown user")
	}
	if want == "" || want != string(password) {
		return nil, errors.New("password mismatch")
	}
	return &ssh.Permissions{}, nil
}

// SimpleAccessController enforces AllowUsers/DenyUsers against the
// authenticated username. It does not consult group membership — callers
// needing AllowGroups/DenyGroups should compose their own controller.
type SimpleAccessController struct{}

// CheckAccess implements AccessController.
func (SimpleAccessController) CheckAccess(meta ssh.ConnMetadata, _ *ssh.Permissions, opts *Options) error {
	if opts.RefuseConnection != nil && *opts.RefuseConnection != "" {
		return fmt.Errorf("connection refused: %s", *opts.RefuseConnection)
	}
	user := meta.User()
	if len(opts.DenyUsers) > 0 && matchAnyWord(user, opts.DenyUsers) {
		return fmt.Errorf("user %s denied by DenyUsers", user)
	}
	if len(opts.AllowUsers) > 0 && !matchAnyWord(user, opts.AllowUsers) {
		return fmt.Errorf("user %s not in AllowUsers", user)
	}
	return nil
}

// matchAnyWord tests whether v matches any pattern in list. Patterns are
// plain comparisons with '*'/'?' glob semantics handled inline.
func matchAnyWord(v string, list []string) bool {
	for _, p := range list {
		// Strip USER@HOST form — we only compare the user portion here.
		if idx := strings.Index(p, "@"); idx >= 0 {
			p = p[:idx]
		}
		if matchEnvPattern(p, v) {
			return true
		}
	}
	return false
}
