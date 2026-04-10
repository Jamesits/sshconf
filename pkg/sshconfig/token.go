package sshconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// ExpandTokens replaces %-tokens in value using the provided context.
// Unknown tokens are left as-is. A nil context causes no expansion.
func ExpandTokens(value string, ctx *TokenContext) string {
	if ctx == nil || !strings.Contains(value, "%") {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' || i+1 >= len(value) {
			b.WriteByte(value[i])
			continue
		}
		next := value[i+1]
		replacement, ok := tokenReplacement(next, ctx)
		if ok {
			b.WriteString(replacement)
			i++ // skip the token character
		} else {
			b.WriteByte(value[i])
		}
	}
	return b.String()
}

func tokenReplacement(ch byte, ctx *TokenContext) (string, bool) {
	switch ch {
	case '%':
		return "%", true
	case 'C':
		return connHash(ctx), true
	case 'd':
		return ctx.HomeDir, true
	case 'f':
		return ctx.ServerKeyFingerprint, true
	case 'H':
		return ctx.KnownHostsHost, true
	case 'h':
		return ctx.RemoteHost, true
	case 'I':
		return ctx.KnownHostsReason, true
	case 'i':
		return ctx.LocalUserID, true
	case 'j':
		return ctx.ProxyJump, true
	case 'K':
		return ctx.HostKeyBase64, true
	case 'k':
		return ctx.HostKeyAlias, true
	case 'L':
		return ctx.LocalHost, true
	case 'l':
		return ctx.LocalHostFQDN, true
	case 'n':
		return ctx.OriginalHost, true
	case 'p':
		return ctx.RemotePort, true
	case 'r':
		return ctx.RemoteUser, true
	case 'T':
		return ctx.TunnelInterface, true
	case 't':
		return ctx.HostKeyType, true
	case 'u':
		return ctx.LocalUser, true
	default:
		return "", false
	}
}

func connHash(ctx *TokenContext) string {
	if ctx.ConnHash != "" {
		return ctx.ConnHash
	}
	// %C = hash of %l%h%p%r%j
	data := ctx.LocalHostFQDN + ctx.RemoteHost + ctx.RemotePort + ctx.RemoteUser + ctx.ProxyJump
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// ExpandEnvVars expands ${VAR} references in value. Returns an error if a
// referenced variable is not set.
func ExpandEnvVars(value string) (string, error) {
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if i+1 < len(value) && value[i] == '$' && value[i+1] == '{' {
			end := strings.Index(value[i+2:], "}")
			if end < 0 {
				return "", fmt.Errorf("unterminated ${} in %q", value)
			}
			varName := value[i+2 : i+2+end]
			val, ok := os.LookupEnv(varName)
			if !ok {
				return "", fmt.Errorf("environment variable %q not set", varName)
			}
			b.WriteString(val)
			i = i + 2 + end // skip past }
		} else {
			b.WriteByte(value[i])
		}
	}
	return b.String(), nil
}

// ExpandTilde replaces a leading ~ or ~user with the appropriate home directory.
func ExpandTilde(path string, homeDir string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		return filepath.Join(homeDir, path[1:])
	}
	// ~user/... form
	sep := strings.IndexByte(path, '/')
	var username string
	if sep < 0 {
		username = path[1:]
	} else {
		username = path[1:sep]
	}
	u, err := user.Lookup(username)
	if err != nil {
		return path // leave as-is if user not found
	}
	if sep < 0 {
		return u.HomeDir
	}
	return filepath.Join(u.HomeDir, path[sep:])
}
