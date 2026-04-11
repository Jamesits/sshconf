// Package sshkeygen provides the ssh-keygen utility — generate, manage, and
// convert SSH keys.
//
// It exposes a Config struct with a Parse method for command-line argument
// parsing, individual action functions (Generate, Fingerprint,
// ChangePassphrase, ShowPublicKey, ChangeComment), and a Run dispatcher.
package sshkeygen
