// Package sshserver provides OpenSSH daemon configuration parsing and resolution.
// It reads sshd_config(5) files, applies Match blocks, command-line overrides
// (-o), and defaults to produce a resolved configuration that can be converted
// to golang.org/x/crypto/ssh.ServerConfig.
//
// Optional features are surfaced through handler interfaces defined in
// handlers.go; a caller supplies only the handlers it cares about and the
// rest are ignored.
package sshserver
