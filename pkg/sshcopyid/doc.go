// Package sshcopyid provides the ssh-copy-id utility — install a public key
// on a remote server's authorized_keys file.
//
// It exposes a Config struct with a Parse method for command-line argument
// parsing, and a Run function that copies the key using an SSH connection
// resolved through pkg/sshclient.
package sshcopyid
