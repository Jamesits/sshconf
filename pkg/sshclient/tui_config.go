package sshclient

import (
	"fmt"
	"reflect"
	"strings"
)

// RunQuery prints the results of an ssh -Q query to Stdout.
func (t *TUI) RunQuery(queryType string) error {
	var algs []string

	switch strings.ToLower(queryType) {
	case "cipher":
		algs = AllSupportedCiphers()
	case "cipher-auth":
		for _, c := range AllSupportedCiphers() {
			if strings.Contains(c, "gcm") || strings.Contains(c, "chacha20") {
				algs = append(algs, c)
			}
		}
	case "mac":
		algs = AllSupportedMACs()
	case "kex":
		algs = AllSupportedKexAlgorithms()
	case "key", "hostkeytype":
		algs = AllSupportedHostKeyAlgorithms()
	case "key-cert":
		for _, k := range AllSupportedHostKeyAlgorithms() {
			if strings.Contains(k, "-cert-") {
				algs = append(algs, k)
			}
		}
	case "key-plain":
		for _, k := range AllSupportedHostKeyAlgorithms() {
			if !strings.Contains(k, "-cert-") {
				algs = append(algs, k)
			}
		}
	case "key-sig", "sig":
		algs = AllSupportedPublicKeyAlgorithms()
	case "protocol-version":
		algs = []string{"2"}
	case "compression":
		algs = []string{"none", "zlib@openssh.com"}
	default:
		return fmt.Errorf("unknown query type: %s", queryType)
	}

	for _, a := range algs {
		fmt.Fprintln(t.Stdout, a)
	}
	return nil
}

// PrintConfig writes the resolved configuration in ssh -G format to Stdout.
func (t *TUI) PrintConfig(opts *Options, host, originalHost string) {
	p := func(key string, val any) {
		if val == nil {
			return
		}
		v := reflect.ValueOf(val)
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return
			}
			v = v.Elem()
		}
		switch v.Kind() {
		case reflect.Bool:
			if v.Bool() {
				fmt.Fprintf(t.Stdout, "%s yes\n", key)
			} else {
				fmt.Fprintf(t.Stdout, "%s no\n", key)
			}
		case reflect.Int:
			fmt.Fprintf(t.Stdout, "%s %d\n", key, v.Int())
		case reflect.String:
			fmt.Fprintf(t.Stdout, "%s %s\n", key, v.String())
		}
	}

	pSlice := func(key string, vals []string) {
		for _, v := range vals {
			fmt.Fprintf(t.Stdout, "%s %s\n", key, v)
		}
	}

	pFwd := func(key string, fwds []Forward) {
		for _, f := range fwds {
			bind := f.BindAddress
			if bind != "" {
				bind += ":"
			}
			fmt.Fprintf(t.Stdout, "%s %s%s %s:%s\n", key, bind, f.BindPort, f.Host, f.HostPort)
		}
	}

	fmt.Fprintf(t.Stdout, "host %s\n", originalHost)

	p("user", opts.User)
	p("hostname", opts.Hostname)
	p("port", opts.Port)
	p("addressfamily", opts.AddressFamily)
	p("bindaddress", opts.BindAddress)
	p("bindinterface", opts.BindInterface)
	p("connecttimeout", opts.ConnectTimeout)
	p("connectionattempts", opts.ConnectionAttempts)
	p("tcpkeepalive", opts.TCPKeepAlive)
	p("serveraliveinterval", opts.ServerAliveInterval)
	p("serveralivecountmax", opts.ServerAliveCountMax)
	p("compression", opts.Compression)
	p("batchmode", opts.BatchMode)

	pSlice("identityfile", opts.IdentityFile)
	pSlice("certificatefile", opts.CertificateFile)
	p("identitiesonly", opts.IdentitiesOnly)
	p("identityagent", opts.IdentityAgent)
	p("passwordauthentication", opts.PasswordAuthentication)
	p("kbdinteractiveauthentication", opts.KbdInteractiveAuthentication)
	p("pubkeyauthentication", opts.PubkeyAuthentication)
	p("preferredauthentications", opts.PreferredAuthentications)
	p("numberofpasswordprompts", opts.NumberOfPasswordPrompts)
	p("hostbasedauthentication", opts.HostbasedAuthentication)
	p("gssapiauthentication", opts.GSSAPIAuthentication)
	p("gssapidelegatecredentials", opts.GSSAPIDelegateCredentials)
	p("addkeystoagent", opts.AddKeysToAgent)

	p("ciphers", opts.Ciphers)
	p("kexalgorithms", opts.KexAlgorithms)
	p("macs", opts.MACs)
	p("hostkeyalgorithms", opts.HostKeyAlgorithms)
	p("pubkeyacceptedalgorithms", opts.PubkeyAcceptedAlgorithms)
	p("casignaturealgorithms", opts.CASignatureAlgorithms)
	p("rekeylimit", opts.RekeyLimit)
	p("requiredrsasize", opts.RequiredRSASize)
	p("fingerprinthash", opts.FingerprintHash)

	p("stricthostkeychecking", opts.StrictHostKeyChecking)
	p("userknownhostsfile", opts.UserKnownHostsFile)
	p("globalknownhostsfile", opts.GlobalKnownHostsFile)
	p("hashknownhosts", opts.HashKnownHosts)
	p("checkhostip", opts.CheckHostIP)
	p("hostkeyalias", opts.HostKeyAlias)
	p("knownhostscommand", opts.KnownHostsCommand)
	p("revokedhostkeys", opts.RevokedHostKeys)
	p("updatehostkeys", opts.UpdateHostKeys)
	p("verifyhostkeydns", opts.VerifyHostKeyDNS)
	p("nohostauthenticationforlocalhost", opts.NoHostAuthenticationForLocalhost)

	p("proxycommand", opts.ProxyCommand)
	p("proxyjump", opts.ProxyJump)
	p("proxyusefdpass", opts.ProxyUseFdpass)

	pFwd("localforward", opts.LocalForward)
	pFwd("remoteforward", opts.RemoteForward)
	pSlice("dynamicforward", opts.DynamicForward)
	p("clearallforwardings", opts.ClearAllForwardings)
	p("exitonforwardfailure", opts.ExitOnForwardFailure)
	p("gatewayports", opts.GatewayPorts)

	p("forwardagent", opts.ForwardAgent)
	p("forwardx11", opts.ForwardX11)
	p("forwardx11trusted", opts.ForwardX11Trusted)
	p("forwardx11timeout", opts.ForwardX11Timeout)
	p("xauthlocation", opts.XAuthLocation)

	p("tunnel", opts.Tunnel)
	p("tunneldevice", opts.TunnelDevice)

	p("requesttty", opts.RequestTTY)
	p("sessiontype", opts.SessionType)
	p("remotecommand", opts.RemoteCommand)
	pSlice("sendenv", opts.SendEnv)
	pSlice("setenv", opts.SetEnv)
	p("escapechar", opts.EscapeChar)
	p("loglevel", opts.LogLevel)
	p("syslogfacility", opts.SyslogFacility)

	p("controlmaster", opts.ControlMaster)
	p("controlpath", opts.ControlPath)
	p("controlpersist", opts.ControlPersist)

	p("permitlocalcommand", opts.PermitLocalCommand)
	p("localcommand", opts.LocalCommand)
	p("visualhostkey", opts.VisualHostKey)
	p("forkafterauthentication", opts.ForkAfterAuthentication)
	p("stdinnull", opts.StdinNull)
	p("enableescapecommandline", opts.EnableEscapeCommandline)
	p("obscurekeystroketiming", opts.ObscureKeystrokeTiming)

	p("canonicalizehostname", opts.CanonicalizeHostname)
	pSlice("canonicaldomains", opts.CanonicalDomains)
	p("canonicalizemaxdots", opts.CanonicalizeMaxDots)
	p("canonicalizefallbacklocal", opts.CanonicalizeFallbackLocal)
}
