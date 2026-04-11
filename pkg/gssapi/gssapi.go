package gssapi

import "golang.org/x/crypto/ssh"

// Verify interface compliance at compile time.
var _ ssh.GSSAPIClient = (*Krb5Client)(nil)
