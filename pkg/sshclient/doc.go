// Package sshclient provides OpenSSH client configuration parsing and resolution.
// It reads ssh_config(5) files, applies Host/Match blocks, command-line
// overrides (-o), and defaults to produce a resolved configuration that
// can be converted to golang.org/x/crypto/ssh.ClientConfig.
package sshclient
