// Package gssapi provides implementations of [golang.org/x/crypto/ssh.GSSAPIClient]
// for SSH GSSAPI-with-MIC authentication (RFC 4462).
//
// Two implementations are available:
//
//   - [Krb5Client]: Pure Go implementation using gokrb5/v8. No CGO required.
//   - [CGOClient]: System GSSAPI library via CGO. Requires libgssapi_krb5 headers
//     and is only compiled when CGO is enabled (//go:build cgo).
//
// Both implement [ssh.GSSAPIClient] and can be passed directly to
// [github.com/jamesits/sshconf/pkg/client.Callbacks.GSSAPIClient].
package gssapi

import "golang.org/x/crypto/ssh"

// Verify interface compliance at compile time.
var _ ssh.GSSAPIClient = (*Krb5Client)(nil)
