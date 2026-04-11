package sshclient

import "fmt"

// BannerCallback prints an SSH server banner.
func (t *TUI) BannerCallback(message string) error {
	fmt.Fprint(t.Stderr, message)
	return nil
}
