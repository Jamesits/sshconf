//go:build !cgo

package gssapi

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// Verify interface compliance at compile time.
var _ ssh.GSSAPIClient = (*CGOClient)(nil)

// CGOClient is a stub implementation of [ssh.GSSAPIClient] for builds
// without CGO. All methods return an error indicating that CGO is required.
//
// To use the system GSSAPI library, rebuild with CGO_ENABLED=1 and
// ensure libgssapi_krb5 development headers are installed:
//
//	# Debian/Ubuntu
//	apt install libkrb5-dev
//
//	# RHEL/Fedora
//	dnf install krb5-devel
//
//	# macOS (built-in GSS.framework is used automatically)
//
//	CGO_ENABLED=1 go build ./...
type CGOClient struct{}

var errNoCGO = errors.New("gssapi: CGOClient requires CGO (rebuild with CGO_ENABLED=1)")

// NewCGOClient returns a stub CGOClient. All operations will return
// [errNoCGO] at runtime.
func NewCGOClient() *CGOClient {
	return &CGOClient{}
}

func (c *CGOClient) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	return nil, false, errNoCGO
}

func (c *CGOClient) GetMIC(micField []byte) ([]byte, error) {
	return nil, errNoCGO
}

func (c *CGOClient) DeleteSecContext() error {
	return nil
}
