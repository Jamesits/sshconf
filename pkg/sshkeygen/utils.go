package sshkeygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"strings"

	"golang.org/x/crypto/ssh"
)

// FingerprintString returns the fingerprint string for a public key using
// the specified hash algorithm ("md5" or "sha256").
func FingerprintString(key ssh.PublicKey, algo string) string {
	switch strings.ToLower(algo) {
	case "md5":
		return ssh.FingerprintLegacyMD5(key)
	default:
		return ssh.FingerprintSHA256(key)
	}
}

// KeySize returns the key size in bits for the given public key.
func KeySize(key ssh.PublicKey) int {
	cryptoKey := key.(ssh.CryptoPublicKey).CryptoPublicKey()
	switch k := cryptoKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// KeyTypeName returns a human-readable name for the SSH key type.
func KeyTypeName(key ssh.PublicKey) string {
	switch key.Type() {
	case "ssh-rsa":
		return "RSA"
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return "ECDSA"
	case "ssh-ed25519":
		return "ED25519"
	default:
		return key.Type()
	}
}
