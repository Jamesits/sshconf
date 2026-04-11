package sshclient

import "golang.org/x/crypto/ssh"

// GSSAPIClient is an alias for ssh.GSSAPIClient, re-exported for convenience.
// Callers must provide an implementation of this interface to enable
// GSSAPI/Kerberos authentication. The interface requires:
//
//   - InitSecContext: Initialize or continue a security context exchange
//   - GetMIC: Generate a MIC (Message Integrity Code) for verification
//   - DeleteSecContext: Clean up the security context
//
// Two ready-made implementations are provided in the [github.com/jamesits/sshconf/pkg/gssapi] package:
//
//   - [gssapi.Krb5Client]: Pure Go implementation using gokrb5/v8. No CGO required.
//   - [gssapi.CGOClient]: System GSSAPI library via CGO. Only available when CGO is enabled.
//
// Example:
//
//	// Pure Go (always available):
//	krb5, err := gssapi.NewKrb5ClientFromCCache("", gssapi.Krb5Config{})
//	handlers.GSSAPIClient = krb5
//
//	// CGO (requires CGO_ENABLED=1 and libgssapi_krb5):
//	handlers.GSSAPIClient = gssapi.NewCGOClient()
type GSSAPIClient = ssh.GSSAPIClient

// GSSAPIConfig holds configuration for GSSAPI authentication derived from
// ssh_config options.
type GSSAPIConfig struct {
	// Enabled is true when GSSAPIAuthentication is "yes".
	Enabled bool

	// DelegateCredentials is true when GSSAPIDelegateCredentials is "yes".
	DelegateCredentials bool

	// Target is the GSSAPI service principal name, typically "host@<hostname>".
	// Constructed from the resolved Hostname.
	Target string
}

// gssapiConfigFromOptions extracts GSSAPI configuration from resolved options.
func gssapiConfigFromOptions(opts *Options) GSSAPIConfig {
	cfg := GSSAPIConfig{}
	if opts.GSSAPIAuthentication != nil {
		cfg.Enabled = *opts.GSSAPIAuthentication
	}
	if opts.GSSAPIDelegateCredentials != nil {
		cfg.DelegateCredentials = *opts.GSSAPIDelegateCredentials
	}
	if opts.Hostname != nil {
		cfg.Target = "host@" + *opts.Hostname
	}
	return cfg
}
