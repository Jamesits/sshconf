// Package sshagent provides the ssh-agent utility — an SSH authentication agent.
//
// It exposes a Config struct with a Parse method for command-line argument
// parsing, individual action functions (Start, Kill), and a Run dispatcher
// that selects the appropriate action.
package sshagent
