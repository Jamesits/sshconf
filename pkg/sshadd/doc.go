// Package sshadd provides the ssh-add utility — manage SSH agent keys.
//
// It exposes a Config struct with a Parse method for command-line argument
// parsing, individual action functions (Add, List, ListPublicKeys, Delete,
// DeleteAll, Lock, Unlock), and a Run dispatcher that connects to the
// agent and executes the requested action.
package sshadd
