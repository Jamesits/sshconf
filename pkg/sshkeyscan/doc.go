// Package sshkeyscan provides the ssh-keyscan utility — retrieve public host
// keys from remote SSH servers.
//
// It exposes a Config struct with a Parse method for command-line argument
// parsing, a ScanHostKey function for scanning a single host/key-type pair,
// and a Run function that orchestrates the full scan.
package sshkeyscan
