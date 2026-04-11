package client

import (
	"fmt"
	"strings"

	sshclient "github.com/jamesits/sshconf/pkg/client"
)

// Usage writes a usage string for the given program name and parse mode to Stderr.
func (t *TUI) Usage(program string, mode sshclient.ParseMode) {
	indent := strings.Repeat(" ", len("usage: "+program+" "))
	var positional string
	switch mode {
	case sshclient.ModeOptionsOnly:
		positional = ""
	case sshclient.ModeOptionsHost:
		positional = "\n" + indent + "destination"
	case sshclient.ModeOptionsHostCommand:
		positional = "\n" + indent + "destination [command [argument ...]]"
	}
	fmt.Fprintf(t.Stderr, "usage: %s [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n"+
		"%s[-b bind_address] [-c cipher_spec] [-D [bind_address:]port]\n"+
		"%s[-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]\n"+
		"%s[-i identity_file] [-J [user@]host[:port]] [-L address]\n"+
		"%s[-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-P tag]\n"+
		"%s[-p port] [-Q query_option] [-R address] [-S ctl_path]\n"+
		"%s[-W host:port] [-w local_tun[:remote_tun]]%s\n",
		program, indent, indent, indent, indent, indent, indent, positional)
}
