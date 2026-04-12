// Package dialer contains shared SSH-oriented network helpers.
//
// The main entry point is DialConfig, which captures the connection
// customisation parsed from OpenSSH-style config and can produce a
// concrete dialer or wrap that dialer with caller-provided behaviour
// such as tracing, proxying, or transport substitution.
package dialer
