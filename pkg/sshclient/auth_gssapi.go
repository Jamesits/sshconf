package sshclient

import (
	"golang.org/x/crypto/ssh"
)

// gssapiClientWrapper wraps a GSSAPIClient to handle credential delegation.
type gssapiClientWrapper struct {
	inner      ssh.GSSAPIClient
	delegCreds bool
}

func (g *gssapiClientWrapper) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	return g.inner.InitSecContext(target, token, g.delegCreds)
}

func (g *gssapiClientWrapper) GetMIC(micField []byte) ([]byte, error) {
	return g.inner.GetMIC(micField)
}

func (g *gssapiClientWrapper) DeleteSecContext() error {
	return g.inner.DeleteSecContext()
}
