package sshclient

// applyDefaults fills in all unset fields in opts with OpenSSH default values.
// This is called as the final step of resolution, acting as a pseudo-include
// at the end of the config chain.
func applyDefaults(opts *Options) {
	// Connection
	setDefaultStr(&opts.AddressFamily, "any")
	setDefault(&opts.BatchMode, false)
	setDefaultInt(&opts.ConnectTimeout, 0)
	setDefaultInt(&opts.ConnectionAttempts, 1)
	setDefault(&opts.TCPKeepAlive, true)
	setDefaultInt(&opts.ServerAliveInterval, 0)
	setDefaultInt(&opts.ServerAliveCountMax, 3)
	setDefault(&opts.Compression, false)

	// Host resolution
	setDefaultInt(&opts.Port, 22)
	setDefault(&opts.CanonicalizeFallbackLocal, true)
	setDefaultStr(&opts.CanonicalizeHostname, "no")
	setDefaultInt(&opts.CanonicalizeMaxDots, 1)

	// Authentication
	setDefault(&opts.IdentitiesOnly, false)
	setDefault(&opts.PasswordAuthentication, true)
	setDefault(&opts.KbdInteractiveAuthentication, true)
	setDefaultStr(&opts.PubkeyAuthentication, "yes")
	setDefaultStr(&opts.PreferredAuthentications, "gssapi-with-mic,hostbased,publickey,keyboard-interactive,password")
	setDefaultInt(&opts.NumberOfPasswordPrompts, 3)
	setDefault(&opts.HostbasedAuthentication, false)
	setDefault(&opts.EnableSSHKeysign, false)
	setDefault(&opts.GSSAPIAuthentication, false)
	setDefault(&opts.GSSAPIDelegateCredentials, false)
	setDefaultStr(&opts.AddKeysToAgent, "no")

	// Default identity files (only if none configured)
	if len(opts.IdentityFile) == 0 {
		opts.IdentityFile = []string{
			"~/.ssh/id_rsa",
			"~/.ssh/id_ecdsa",
			"~/.ssh/id_ecdsa_sk",
			"~/.ssh/id_ed25519",
			"~/.ssh/id_ed25519_sk",
		}
	}

	// Crypto - raw values; list ops are resolved later against algorithm defaults
	setDefaultStr(&opts.Ciphers, defaultCiphers)
	setDefaultStr(&opts.KexAlgorithms, defaultKexAlgorithms)
	setDefaultStr(&opts.MACs, defaultMACs)
	setDefaultStr(&opts.CASignatureAlgorithms, defaultCASignatureAlgorithms)
	setDefaultStr(&opts.HostKeyAlgorithms, defaultHostKeyAlgorithms)
	setDefaultStr(&opts.PubkeyAcceptedAlgorithms, defaultPubkeyAcceptedAlgorithms)
	setDefaultStr(&opts.HostbasedAcceptedAlgorithms, defaultHostbasedAcceptedAlgorithms)
	setDefaultStr(&opts.RekeyLimit, "default none")
	setDefaultInt(&opts.RequiredRSASize, 1024)
	setDefaultStr(&opts.FingerprintHash, "sha256")
	setDefaultStr(&opts.WarnWeakCrypto, "yes")

	// Host key verification
	setDefault(&opts.CheckHostIP, false)
	setDefaultStr(&opts.GlobalKnownHostsFile, "/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2")
	setDefaultStr(&opts.UserKnownHostsFile, "~/.ssh/known_hosts ~/.ssh/known_hosts2")
	setDefault(&opts.HashKnownHosts, false)
	setDefaultStr(&opts.StrictHostKeyChecking, "ask")
	setDefaultStr(&opts.UpdateHostKeys, "no")
	setDefaultStr(&opts.VerifyHostKeyDNS, "no")
	setDefault(&opts.NoHostAuthenticationForLocalhost, false)

	// Proxy
	setDefault(&opts.ProxyUseFdpass, false)

	// Forwarding
	setDefault(&opts.ClearAllForwardings, false)
	setDefault(&opts.ExitOnForwardFailure, false)
	setDefault(&opts.GatewayPorts, false)
	setDefault(&opts.StreamLocalBindUnlink, false)
	setDefaultStr(&opts.StreamLocalBindMask, "0177")

	// Agent
	setDefaultStr(&opts.ForwardAgent, "no")

	// X11
	setDefault(&opts.ForwardX11, false)
	setDefault(&opts.ForwardX11Trusted, false)
	setDefaultStr(&opts.XAuthLocation, "/usr/bin/xauth")

	// Tunnel
	setDefaultStr(&opts.Tunnel, "no")
	setDefaultStr(&opts.TunnelDevice, "any:any")

	// Session
	setDefaultStr(&opts.RequestTTY, "auto")
	setDefaultStr(&opts.SessionType, "default")
	setDefaultStr(&opts.EscapeChar, "~")
	setDefaultStr(&opts.IPQoS, "ef none") // interactive=ef, non-interactive=none
	setDefaultStr(&opts.LogLevel, "INFO")
	setDefaultStr(&opts.SyslogFacility, "USER")

	// Control
	setDefaultStr(&opts.ControlMaster, "no")
	setDefaultStr(&opts.ControlPersist, "no")

	// Misc
	setDefault(&opts.PermitLocalCommand, false)
	setDefault(&opts.VisualHostKey, false)
	setDefault(&opts.ForkAfterAuthentication, false)
	setDefault(&opts.StdinNull, false)
	setDefault(&opts.EnableEscapeCommandline, false)
	setDefaultStr(&opts.ObscureKeystrokeTiming, "yes")
	setDefaultStr(&opts.VersionAddendum, "none")
	setDefaultStr(&opts.PKCS11Provider, "none")
}

func setDefault(p **bool, v bool) {
	if *p == nil {
		*p = &v
	}
}

func setDefaultInt(p **int, v int) {
	if *p == nil {
		*p = &v
	}
}

func setDefaultStr(p **string, v string) {
	if *p == nil {
		*p = &v
	}
}

// Default algorithm lists matching current OpenSSH defaults.
const (
	defaultCiphers = "chacha20-poly1305@openssh.com," +
		"aes128-gcm@openssh.com,aes256-gcm@openssh.com," +
		"aes128-ctr,aes192-ctr,aes256-ctr"

	defaultKexAlgorithms = "mlkem768x25519-sha256," +
		"sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com," +
		"curve25519-sha256,curve25519-sha256@libssh.org," +
		"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521," +
		"diffie-hellman-group-exchange-sha256," +
		"diffie-hellman-group16-sha512," +
		"diffie-hellman-group18-sha512," +
		"diffie-hellman-group14-sha256"

	defaultMACs = "umac-64-etm@openssh.com,umac-128-etm@openssh.com," +
		"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com," +
		"hmac-sha1-etm@openssh.com," +
		"umac-64@openssh.com,umac-128@openssh.com," +
		"hmac-sha2-256,hmac-sha2-512,hmac-sha1"

	defaultCASignatureAlgorithms = "ssh-ed25519," +
		"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521," +
		"sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
		"rsa-sha2-512,rsa-sha2-256"

	defaultHostKeyAlgorithms = "ssh-ed25519-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp384-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp521-cert-v01@openssh.com," +
		"sk-ssh-ed25519-cert-v01@openssh.com," +
		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"rsa-sha2-512-cert-v01@openssh.com," +
		"rsa-sha2-256-cert-v01@openssh.com," +
		"ssh-ed25519," +
		"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521," +
		"sk-ecdsa-sha2-nistp256@openssh.com," +
		"sk-ssh-ed25519@openssh.com," +
		"rsa-sha2-512,rsa-sha2-256"

	defaultPubkeyAcceptedAlgorithms = "ssh-ed25519-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp384-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp521-cert-v01@openssh.com," +
		"sk-ssh-ed25519-cert-v01@openssh.com," +
		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"rsa-sha2-512-cert-v01@openssh.com," +
		"rsa-sha2-256-cert-v01@openssh.com," +
		"ssh-ed25519," +
		"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521," +
		"sk-ssh-ed25519@openssh.com," +
		"sk-ecdsa-sha2-nistp256@openssh.com," +
		"rsa-sha2-512,rsa-sha2-256"

	defaultHostbasedAcceptedAlgorithms = defaultPubkeyAcceptedAlgorithms
)
