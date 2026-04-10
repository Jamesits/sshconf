package client

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
)

// applyDirective sets the appropriate field in opts based on the directive.
// For scalar (first-value-wins) options, the field is only set if currently nil.
// For multi-value options, the value is appended.
func applyDirective(opts *Options, dir sshconfig.Directive) error {
	keyword := strings.ToLower(dir.Keyword)
	value := dir.Value

	// Check IgnoreUnknown before rejecting unknown keywords
	if opts.ignoredKeywords != nil && opts.ignoredKeywords[keyword] {
		return nil
	}

	switch keyword {
	// --- Connection ---
	case "addressfamily":
		setStr(&opts.AddressFamily, value)
	case "batchmode":
		setBool(&opts.BatchMode, value)
	case "bindaddress":
		setStr(&opts.BindAddress, value)
	case "bindinterface":
		setStr(&opts.BindInterface, value)
	case "connecttimeout":
		setInt(&opts.ConnectTimeout, value)
	case "connectionattempts":
		setInt(&opts.ConnectionAttempts, value)
	case "tcpkeepalive":
		setBool(&opts.TCPKeepAlive, value)
	case "serveraliveinterval":
		setInt(&opts.ServerAliveInterval, value)
	case "serveralivecountmax":
		setInt(&opts.ServerAliveCountMax, value)
	case "compression":
		setBool(&opts.Compression, value)

	// --- Host Resolution ---
	case "hostname":
		setStr(&opts.Hostname, value)
	case "port":
		setInt(&opts.Port, value)
	case "canonicaldomains":
		if opts.CanonicalDomains == nil {
			opts.CanonicalDomains = strings.Fields(value)
		}
	case "canonicalizefallbacklocal":
		setBool(&opts.CanonicalizeFallbackLocal, value)
	case "canonicalizehostname":
		setStr(&opts.CanonicalizeHostname, value)
	case "canonicalizemaxdots":
		setInt(&opts.CanonicalizeMaxDots, value)
	case "canonicalizepermittedcnames":
		if opts.CanonicalizePermittedCNAMEs == nil {
			opts.CanonicalizePermittedCNAMEs = strings.Fields(value)
		}

	// --- Authentication ---
	case "user":
		setStr(&opts.User, value)
	case "identityfile":
		// Multi-value: always append. "none" clears.
		if strings.ToLower(value) == "none" {
			opts.IdentityFile = []string{}
		} else {
			opts.IdentityFile = append(opts.IdentityFile, value)
		}
	case "identitiesonly":
		setBool(&opts.IdentitiesOnly, value)
	case "identityagent":
		setStr(&opts.IdentityAgent, value)
	case "certificatefile":
		// Multi-value: always append.
		opts.CertificateFile = append(opts.CertificateFile, value)
	case "passwordauthentication":
		setBool(&opts.PasswordAuthentication, value)
	case "kbdinteractiveauthentication", "challengeresponseauthentication":
		setBool(&opts.KbdInteractiveAuthentication, value)
	case "kbdinteractivedevices":
		setStr(&opts.KbdInteractiveDevices, value)
	case "pubkeyauthentication":
		setStr(&opts.PubkeyAuthentication, value)
	case "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes":
		setStr(&opts.PubkeyAcceptedAlgorithms, value)
	case "preferredauthentications":
		setStr(&opts.PreferredAuthentications, value)
	case "numberofpasswordprompts":
		setInt(&opts.NumberOfPasswordPrompts, value)
	case "hostbasedauthentication":
		setBool(&opts.HostbasedAuthentication, value)
	case "hostbasedacceptedalgorithms", "hostbasedkeytypes":
		setStr(&opts.HostbasedAcceptedAlgorithms, value)
	case "enablesshkeysign":
		setBool(&opts.EnableSSHKeysign, value)
	case "gssapiauthentication":
		setBool(&opts.GSSAPIAuthentication, value)
	case "gssapidelegatecredentials":
		setBool(&opts.GSSAPIDelegateCredentials, value)
	case "addkeystoagent":
		setStr(&opts.AddKeysToAgent, value)

	// --- Crypto ---
	case "ciphers":
		setStr(&opts.Ciphers, value)
	case "kexalgorithms":
		setStr(&opts.KexAlgorithms, value)
	case "macs":
		setStr(&opts.MACs, value)
	case "casignaturealgorithms":
		setStr(&opts.CASignatureAlgorithms, value)
	case "hostkeyalgorithms":
		setStr(&opts.HostKeyAlgorithms, value)
	case "rekeylimit":
		setStr(&opts.RekeyLimit, value)
	case "requiredrsasize":
		setInt(&opts.RequiredRSASize, value)
	case "fingerprinthash":
		setStr(&opts.FingerprintHash, value)
	case "warnweakcrypto":
		setStr(&opts.WarnWeakCrypto, value)

	// --- Host Key Verification ---
	case "checkhostip":
		setBool(&opts.CheckHostIP, value)
	case "globalknownhostsfile":
		setStr(&opts.GlobalKnownHostsFile, value)
	case "userknownhostsfile":
		setStr(&opts.UserKnownHostsFile, value)
	case "hashknownhosts":
		setBool(&opts.HashKnownHosts, value)
	case "stricthostkeychecking":
		setStr(&opts.StrictHostKeyChecking, value)
	case "hostkeyalias":
		setStr(&opts.HostKeyAlias, value)
	case "knownhostscommand":
		setStr(&opts.KnownHostsCommand, value)
	case "revokedhostkeys":
		setStr(&opts.RevokedHostKeys, value)
	case "updatehostkeys":
		setStr(&opts.UpdateHostKeys, value)
	case "verifyhostkeydns":
		setStr(&opts.VerifyHostKeyDNS, value)
	case "nohostauthenticationforlocalhost":
		setBool(&opts.NoHostAuthenticationForLocalhost, value)

	// --- Proxy ---
	case "proxycommand":
		setStr(&opts.ProxyCommand, value)
	case "proxyjump":
		setStr(&opts.ProxyJump, value)
	case "proxyusefdpass":
		setBool(&opts.ProxyUseFdpass, value)

	// --- Forwarding ---
	case "localforward":
		fwd, err := parseForward(value)
		if err != nil {
			return &sshconfig.ParseError{Source: dir.Source, Msg: fmt.Sprintf("LocalForward: %v", err)}
		}
		opts.LocalForward = append(opts.LocalForward, fwd)
	case "remoteforward":
		fwd, err := parseForward(value)
		if err != nil {
			return &sshconfig.ParseError{Source: dir.Source, Msg: fmt.Sprintf("RemoteForward: %v", err)}
		}
		opts.RemoteForward = append(opts.RemoteForward, fwd)
	case "dynamicforward":
		opts.DynamicForward = append(opts.DynamicForward, value)
	case "clearallforwardings":
		setBool(&opts.ClearAllForwardings, value)
	case "exitonforwardfailure":
		setBool(&opts.ExitOnForwardFailure, value)
	case "gatewayports":
		setBool(&opts.GatewayPorts, value)
	case "permitremoteopen":
		if opts.PermitRemoteOpen == nil {
			opts.PermitRemoteOpen = strings.Fields(value)
		}
	case "streamlocalbindmask":
		setStr(&opts.StreamLocalBindMask, value)
	case "streamlocalbindunlink":
		setBool(&opts.StreamLocalBindUnlink, value)

	// --- Agent ---
	case "forwardagent":
		setStr(&opts.ForwardAgent, value)

	// --- X11 ---
	case "forwardx11":
		setBool(&opts.ForwardX11, value)
	case "forwardx11timeout":
		setInt(&opts.ForwardX11Timeout, value)
	case "forwardx11trusted":
		setBool(&opts.ForwardX11Trusted, value)
	case "xauthlocation":
		setStr(&opts.XAuthLocation, value)

	// --- Tunnel ---
	case "tunnel":
		setStr(&opts.Tunnel, value)
	case "tunneldevice":
		setStr(&opts.TunnelDevice, value)

	// --- Session ---
	case "requesttty":
		setStr(&opts.RequestTTY, value)
	case "sessiontype":
		setStr(&opts.SessionType, value)
	case "remotecommand":
		setStr(&opts.RemoteCommand, value)
	case "sendenv":
		// Multi-value: accumulated. '-' prefix clears matching previous entries.
		opts.SendEnv = appendSendEnv(opts.SendEnv, value)
	case "setenv":
		// Multi-value: accumulated.
		opts.SetEnv = append(opts.SetEnv, value)
	case "escapechar":
		setStr(&opts.EscapeChar, value)
	case "ipqos":
		setStr(&opts.IPQoS, value)
	case "loglevel":
		setStr(&opts.LogLevel, value)
	case "logverbose":
		opts.LogVerbose = append(opts.LogVerbose, value)
	case "tag":
		setStr(&opts.Tag, value)
	case "channeltimeout":
		opts.ChannelTimeout = append(opts.ChannelTimeout, strings.Fields(value)...)

	// --- Connection Sharing ---
	case "controlmaster":
		setStr(&opts.ControlMaster, value)
	case "controlpath":
		setStr(&opts.ControlPath, value)
	case "controlpersist":
		setStr(&opts.ControlPersist, value)

	// --- Misc ---
	case "permitlocalcommand":
		setBool(&opts.PermitLocalCommand, value)
	case "localcommand":
		setStr(&opts.LocalCommand, value)
	case "visualhostkey":
		setBool(&opts.VisualHostKey, value)
	case "forkafterauthentication":
		setBool(&opts.ForkAfterAuthentication, value)
	case "stdinnull":
		setBool(&opts.StdinNull, value)
	case "enableescapecommandline":
		setBool(&opts.EnableEscapeCommandline, value)
	case "obscurekeystroketiming":
		setStr(&opts.ObscureKeystrokeTiming, value)
	case "versionaddendum":
		setStr(&opts.VersionAddendum, value)
	case "pkcs11provider":
		setStr(&opts.PKCS11Provider, value)
	case "securitykeyprovider":
		setStr(&opts.SecurityKeyProvider, value)
	case "ignoreunknown":
		setStr(&opts.IgnoreUnknown, value)
		// Update the ignored keywords set immediately
		if opts.ignoredKeywords == nil {
			opts.ignoredKeywords = make(map[string]bool)
		}
		for _, pattern := range strings.Split(value, ",") {
			pattern = strings.TrimSpace(strings.ToLower(pattern))
			if pattern != "" {
				opts.ignoredKeywords[pattern] = true
			}
		}
	case "refuseconnection":
		setStr(&opts.RefuseConnection, value)
	case "syslogfacility":
		setStr(&opts.SyslogFacility, value)

	// Host and Match are handled by the parser, not here
	case "host", "match", "include":
		// Silently skip — these are structural directives handled by the parser

	default:
		// Check if it matches IgnoreUnknown patterns
		if opts.ignoredKeywords != nil {
			for pattern := range opts.ignoredKeywords {
				if sshconfig.MatchPattern(pattern, keyword) {
					return nil
				}
			}
		}
		return &sshconfig.ParseError{
			Source: dir.Source,
			Msg:    fmt.Sprintf("unknown option: %s", dir.Keyword),
		}
	}
	return nil
}

// setStr sets *p to value if *p is currently nil (first-value-wins).
func setStr(p **string, value string) {
	if *p == nil {
		*p = &value
	}
}

// setBool parses a yes/no value and sets *p if *p is currently nil.
func setBool(p **bool, value string) {
	if *p != nil {
		return
	}
	switch strings.ToLower(value) {
	case "yes", "true":
		v := true
		*p = &v
	case "no", "false":
		v := false
		*p = &v
	}
}

// setInt parses an integer value and sets *p if *p is currently nil.
func setInt(p **int, value string) {
	if *p != nil {
		return
	}
	v, err := strconv.Atoi(value)
	if err != nil {
		return
	}
	*p = &v
}

// parseForward parses a port forwarding specification.
// Formats:
//
//	[bind_address:]port host:hostport
//	[bind_address:]port (for remote forwards acting as SOCKS proxy)
//	Unix socket paths (containing '/')
func parseForward(value string) (Forward, error) {
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return Forward{}, fmt.Errorf("empty forwarding specification")
	}

	var fwd Forward

	// Parse bind spec
	bindSpec := parts[0]
	if strings.Contains(bindSpec, "/") {
		// Unix socket path
		fwd.BindPort = bindSpec
	} else {
		host, port, ok := splitHostPort(bindSpec)
		if ok {
			fwd.BindAddress = host
			fwd.BindPort = port
		} else {
			fwd.BindPort = bindSpec
		}
	}

	// Parse destination if present
	if len(parts) >= 2 {
		destSpec := parts[1]
		if strings.Contains(destSpec, "/") {
			// Unix socket path
			fwd.HostPort = destSpec
		} else {
			host, port, ok := splitHostPort(destSpec)
			if ok {
				fwd.Host = host
				fwd.HostPort = port
			} else {
				fwd.HostPort = destSpec
			}
		}
	}

	return fwd, nil
}

// splitHostPort splits host:port, handling [IPv6]:port notation.
func splitHostPort(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		// [IPv6]:port
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", false
		}
		host = s[1:end]
		rest := s[end+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port, true
	}

	// Count colons — if more than 1, it's an IPv6 address without brackets
	if strings.Count(s, ":") > 1 {
		return s, "", false
	}

	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

// appendSendEnv handles SendEnv's special accumulation rules:
// values without '-' prefix are added, values with '-' prefix remove
// matching previously set entries.
func appendSendEnv(existing []string, value string) []string {
	fields := strings.Fields(value)
	for _, f := range fields {
		if strings.HasPrefix(f, "-") {
			// Remove matching entries
			pattern := f[1:]
			var kept []string
			for _, e := range existing {
				if !sshconfig.MatchPattern(pattern, e) {
					kept = append(kept, e)
				}
			}
			existing = kept
		} else {
			existing = append(existing, f)
		}
	}
	return existing
}
