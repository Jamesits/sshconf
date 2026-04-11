package sshserver

// applyDefaults fills in all unset fields in opts with OpenSSH defaults.
// This is called as the final step of resolution.
func applyDefaults(opts *Options) {
	// --- Listening ---
	setDefaultStr(&opts.AddressFamily, "any")
	setDefaultInt(&opts.LoginGraceTime, 120)
	if len(opts.Ports) == 0 {
		opts.Ports = []int{22}
	}
	if len(opts.HostKey) == 0 {
		// OpenSSH defaults in order of preference.
		opts.HostKey = []string{
			"/etc/ssh/ssh_host_ed25519_key",
			"/etc/ssh/ssh_host_ecdsa_key",
			"/etc/ssh/ssh_host_rsa_key",
		}
	}

	// --- Crypto ---
	setDefaultStr(&opts.Ciphers, defaultCiphers)
	setDefaultStr(&opts.KexAlgorithms, defaultKexAlgorithms)
	setDefaultStr(&opts.MACs, defaultMACs)
	setDefaultStr(&opts.HostKeyAlgorithms, defaultHostKeyAlgorithms)
	setDefaultStr(&opts.CASignatureAlgorithms, defaultCASignatureAlgorithms)
	setDefaultStr(&opts.PubkeyAcceptedAlgorithms, defaultPubkeyAcceptedAlgorithms)
	setDefaultStr(&opts.HostbasedAcceptedAlgorithms, defaultHostbasedAcceptedAlgorithms)
	setDefaultStr(&opts.RekeyLimit, "default none")
	setDefaultInt(&opts.RequiredRSASize, 1024)
	setDefaultStr(&opts.FingerprintHash, "sha256")

	// --- Authentication ---
	setDefaultStr(&opts.PermitRootLogin, "prohibit-password")
	setDefaultBool(&opts.PasswordAuthentication, true)
	setDefaultBool(&opts.PermitEmptyPasswords, false)
	setDefaultBool(&opts.KbdInteractiveAuthentication, true)
	setDefaultBool(&opts.PubkeyAuthentication, true)
	setDefaultStr(&opts.PubkeyAuthOptions, "none")
	setDefaultBool(&opts.HostbasedAuthentication, false)
	setDefaultBool(&opts.HostbasedUsesNameFromPacketOnly, false)
	setDefaultStr(&opts.IgnoreRhosts, "yes")
	setDefaultBool(&opts.IgnoreUserKnownHosts, false)
	setDefaultBool(&opts.GSSAPIAuthentication, false)
	setDefaultBool(&opts.GSSAPICleanupCredentials, true)
	setDefaultBool(&opts.GSSAPIStrictAcceptorCheck, true)
	setDefaultBool(&opts.KerberosAuthentication, false)
	setDefaultBool(&opts.KerberosGetAFSToken, false)
	setDefaultBool(&opts.KerberosOrLocalPasswd, true)
	setDefaultBool(&opts.KerberosTicketCleanup, true)
	setDefaultBool(&opts.UsePAM, false)
	setDefaultStr(&opts.PAMServiceName, "sshd")
	setDefaultInt(&opts.MaxAuthTries, 6)
	setDefaultBool(&opts.StrictModes, true)
	setDefaultBool(&opts.ExposeAuthInfo, false)
	setDefaultStr(&opts.PermitUserEnvironment, "no")
	setDefaultBool(&opts.PermitUserRC, true)

	// Default authorized_keys lookup is the user's home relative path.
	if len(opts.AuthorizedKeysFile) == 0 {
		opts.AuthorizedKeysFile = []string{
			".ssh/authorized_keys",
			".ssh/authorized_keys2",
		}
	}

	// --- Session / Forwarding ---
	setDefaultBool(&opts.AllowAgentForwarding, true)
	setDefaultStr(&opts.AllowTcpForwarding, "yes")
	setDefaultStr(&opts.AllowStreamLocalForwarding, "yes")
	setDefaultBool(&opts.DisableForwarding, false)
	setDefaultStr(&opts.GatewayPorts, "no")
	setDefaultBool(&opts.PermitTTY, true)
	setDefaultStr(&opts.PermitTunnel, "no")
	setDefaultBool(&opts.X11Forwarding, false)
	setDefaultInt(&opts.X11DisplayOffset, 10)
	setDefaultBool(&opts.X11UseLocalhost, true)
	setDefaultStr(&opts.XAuthLocation, "/usr/bin/xauth")
	setDefaultStr(&opts.StreamLocalBindMask, "0177")
	setDefaultBool(&opts.StreamLocalBindUnlink, false)
	setDefaultStr(&opts.ChrootDirectory, "none")
	setDefaultStr(&opts.ForceCommand, "none")
	setDefaultStr(&opts.Banner, "none")
	setDefaultBool(&opts.PrintLastLog, true)
	setDefaultBool(&opts.PrintMotd, true)

	// --- Connection Lifetime ---
	setDefaultBool(&opts.TCPKeepAlive, true)
	setDefaultInt(&opts.ClientAliveInterval, 0)
	setDefaultInt(&opts.ClientAliveCountMax, 3)
	setDefaultStr(&opts.UnusedConnectionTimeout, "none")
	setDefaultInt(&opts.MaxSessions, 10)
	setDefaultStr(&opts.MaxStartups, "10:30:100")
	setDefaultStr(&opts.PerSourceMaxStartups, "none")
	setDefaultStr(&opts.PerSourceNetBlockSize, "32:128")
	setDefaultStr(&opts.IPQoS, "af21 cs1")

	// --- Logging ---
	setDefaultStr(&opts.LogLevel, "INFO")
	setDefaultStr(&opts.SyslogFacility, "AUTH")

	// --- Protocol ---
	setDefaultStr(&opts.Compression, "yes")
	setDefaultStr(&opts.VersionAddendum, "none")
	setDefaultStr(&opts.ModuliFile, "/etc/ssh/moduli")
	setDefaultBool(&opts.UseDNS, false)

	// --- Daemon ---
	setDefaultStr(&opts.PidFile, "/run/sshd.pid")
	setDefaultStr(&opts.SshdAuthPath, "/usr/lib/ssh/sshd-auth")
	setDefaultStr(&opts.SshdSessionPath, "/usr/lib/ssh/sshd-session")
}

func setDefaultBool(p **bool, v bool) {
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

// Default algorithm lists matching current OpenSSH sshd defaults.
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

	defaultCASignatureAlgorithms = "ssh-ed25519," +
		"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521," +
		"sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
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
