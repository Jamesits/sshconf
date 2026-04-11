package client

import (
	"fmt"
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
)

// directiveHandler applies a config directive value to Options.
type directiveHandler func(opts *Options, value string, source sshconfig.SourceInfo) error

// directiveTable maps lowercase SSH config keywords to their handlers.
var directiveTable map[string]directiveHandler

func init() {
	directiveTable = map[string]directiveHandler{
		// --- Connection ---
		"addressfamily":      strField(func(o *Options) **string { return &o.AddressFamily }),
		"batchmode":          boolField(func(o *Options) **bool { return &o.BatchMode }),
		"bindaddress":        strField(func(o *Options) **string { return &o.BindAddress }),
		"bindinterface":      strField(func(o *Options) **string { return &o.BindInterface }),
		"connecttimeout":     intField(func(o *Options) **int { return &o.ConnectTimeout }),
		"connectionattempts": intField(func(o *Options) **int { return &o.ConnectionAttempts }),
		"tcpkeepalive":       boolField(func(o *Options) **bool { return &o.TCPKeepAlive }),
		"serveraliveinterval": intField(func(o *Options) **int { return &o.ServerAliveInterval }),
		"serveralivecountmax": intField(func(o *Options) **int { return &o.ServerAliveCountMax }),
		"compression":        boolField(func(o *Options) **bool { return &o.Compression }),

		// --- Host Resolution ---
		"hostname":                    strField(func(o *Options) **string { return &o.Hostname }),
		"port":                        intField(func(o *Options) **int { return &o.Port }),
		"canonicaldomains":            firstFields(func(o *Options) *[]string { return &o.CanonicalDomains }),
		"canonicalizefallbacklocal":   boolField(func(o *Options) **bool { return &o.CanonicalizeFallbackLocal }),
		"canonicalizehostname":        strField(func(o *Options) **string { return &o.CanonicalizeHostname }),
		"canonicalizemaxdots":         intField(func(o *Options) **int { return &o.CanonicalizeMaxDots }),
		"canonicalizepermittedcnames": firstFields(func(o *Options) *[]string { return &o.CanonicalizePermittedCNAMEs }),

		// --- Authentication ---
		"user":                         strField(func(o *Options) **string { return &o.User }),
		"identityfile":                 identityFileHandler,
		"identitiesonly":               boolField(func(o *Options) **bool { return &o.IdentitiesOnly }),
		"identityagent":                strField(func(o *Options) **string { return &o.IdentityAgent }),
		"certificatefile":              appendField(func(o *Options) *[]string { return &o.CertificateFile }),
		"passwordauthentication":       boolField(func(o *Options) **bool { return &o.PasswordAuthentication }),
		"kbdinteractiveauthentication": boolField(func(o *Options) **bool { return &o.KbdInteractiveAuthentication }),
		"challengeresponseauthentication": boolField(func(o *Options) **bool { return &o.KbdInteractiveAuthentication }), // alias
		"kbdinteractivedevices":        strField(func(o *Options) **string { return &o.KbdInteractiveDevices }),
		"pubkeyauthentication":         strField(func(o *Options) **string { return &o.PubkeyAuthentication }),
		"pubkeyacceptedalgorithms":     strField(func(o *Options) **string { return &o.PubkeyAcceptedAlgorithms }),
		"pubkeyacceptedkeytypes":       strField(func(o *Options) **string { return &o.PubkeyAcceptedAlgorithms }), // alias
		"preferredauthentications":     strField(func(o *Options) **string { return &o.PreferredAuthentications }),
		"numberofpasswordprompts":      intField(func(o *Options) **int { return &o.NumberOfPasswordPrompts }),
		"hostbasedauthentication":      boolField(func(o *Options) **bool { return &o.HostbasedAuthentication }),
		"hostbasedacceptedalgorithms":  strField(func(o *Options) **string { return &o.HostbasedAcceptedAlgorithms }),
		"hostbasedkeytypes":            strField(func(o *Options) **string { return &o.HostbasedAcceptedAlgorithms }), // alias
		"enablesshkeysign":             boolField(func(o *Options) **bool { return &o.EnableSSHKeysign }),
		"gssapiauthentication":         boolField(func(o *Options) **bool { return &o.GSSAPIAuthentication }),
		"gssapidelegatecredentials":    boolField(func(o *Options) **bool { return &o.GSSAPIDelegateCredentials }),
		"addkeystoagent":               strField(func(o *Options) **string { return &o.AddKeysToAgent }),

		// --- Crypto ---
		"ciphers":               strField(func(o *Options) **string { return &o.Ciphers }),
		"kexalgorithms":         strField(func(o *Options) **string { return &o.KexAlgorithms }),
		"macs":                  strField(func(o *Options) **string { return &o.MACs }),
		"casignaturealgorithms": strField(func(o *Options) **string { return &o.CASignatureAlgorithms }),
		"hostkeyalgorithms":     strField(func(o *Options) **string { return &o.HostKeyAlgorithms }),
		"rekeylimit":            strField(func(o *Options) **string { return &o.RekeyLimit }),
		"requiredrsasize":       intField(func(o *Options) **int { return &o.RequiredRSASize }),
		"fingerprinthash":       strField(func(o *Options) **string { return &o.FingerprintHash }),
		"warnweakcrypto":        strField(func(o *Options) **string { return &o.WarnWeakCrypto }),

		// --- Host Key Verification ---
		"checkhostip":                      boolField(func(o *Options) **bool { return &o.CheckHostIP }),
		"globalknownhostsfile":             strField(func(o *Options) **string { return &o.GlobalKnownHostsFile }),
		"userknownhostsfile":               strField(func(o *Options) **string { return &o.UserKnownHostsFile }),
		"hashknownhosts":                   boolField(func(o *Options) **bool { return &o.HashKnownHosts }),
		"stricthostkeychecking":            strField(func(o *Options) **string { return &o.StrictHostKeyChecking }),
		"hostkeyalias":                     strField(func(o *Options) **string { return &o.HostKeyAlias }),
		"knownhostscommand":                strField(func(o *Options) **string { return &o.KnownHostsCommand }),
		"revokedhostkeys":                  strField(func(o *Options) **string { return &o.RevokedHostKeys }),
		"updatehostkeys":                   strField(func(o *Options) **string { return &o.UpdateHostKeys }),
		"verifyhostkeydns":                 strField(func(o *Options) **string { return &o.VerifyHostKeyDNS }),
		"nohostauthenticationforlocalhost": boolField(func(o *Options) **bool { return &o.NoHostAuthenticationForLocalhost }),

		// --- Proxy ---
		"proxycommand":   strField(func(o *Options) **string { return &o.ProxyCommand }),
		"proxyjump":      strField(func(o *Options) **string { return &o.ProxyJump }),
		"proxyusefdpass": boolField(func(o *Options) **bool { return &o.ProxyUseFdpass }),

		// --- Forwarding ---
		"localforward":        localForwardHandler,
		"remoteforward":       remoteForwardHandler,
		"dynamicforward":      appendField(func(o *Options) *[]string { return &o.DynamicForward }),
		"clearallforwardings": boolField(func(o *Options) **bool { return &o.ClearAllForwardings }),
		"exitonforwardfailure": boolField(func(o *Options) **bool { return &o.ExitOnForwardFailure }),
		"gatewayports":        boolField(func(o *Options) **bool { return &o.GatewayPorts }),
		"permitremoteopen":    firstFields(func(o *Options) *[]string { return &o.PermitRemoteOpen }),
		"streamlocalbindmask": strField(func(o *Options) **string { return &o.StreamLocalBindMask }),
		"streamlocalbindunlink": boolField(func(o *Options) **bool { return &o.StreamLocalBindUnlink }),

		// --- Agent ---
		"forwardagent": strField(func(o *Options) **string { return &o.ForwardAgent }),

		// --- X11 ---
		"forwardx11":        boolField(func(o *Options) **bool { return &o.ForwardX11 }),
		"forwardx11timeout": intField(func(o *Options) **int { return &o.ForwardX11Timeout }),
		"forwardx11trusted": boolField(func(o *Options) **bool { return &o.ForwardX11Trusted }),
		"xauthlocation":     strField(func(o *Options) **string { return &o.XAuthLocation }),

		// --- Tunnel ---
		"tunnel":       strField(func(o *Options) **string { return &o.Tunnel }),
		"tunneldevice": strField(func(o *Options) **string { return &o.TunnelDevice }),

		// --- Session ---
		"requesttty":     strField(func(o *Options) **string { return &o.RequestTTY }),
		"sessiontype":    strField(func(o *Options) **string { return &o.SessionType }),
		"remotecommand":  strField(func(o *Options) **string { return &o.RemoteCommand }),
		"sendenv":        sendEnvHandler,
		"setenv":         appendField(func(o *Options) *[]string { return &o.SetEnv }),
		"escapechar":     strField(func(o *Options) **string { return &o.EscapeChar }),
		"ipqos":          strField(func(o *Options) **string { return &o.IPQoS }),
		"loglevel":       strField(func(o *Options) **string { return &o.LogLevel }),
		"logverbose":     appendField(func(o *Options) *[]string { return &o.LogVerbose }),
		"tag":            strField(func(o *Options) **string { return &o.Tag }),
		"channeltimeout": channelTimeoutHandler,

		// --- Connection Sharing ---
		"controlmaster":  strField(func(o *Options) **string { return &o.ControlMaster }),
		"controlpath":    strField(func(o *Options) **string { return &o.ControlPath }),
		"controlpersist": strField(func(o *Options) **string { return &o.ControlPersist }),

		// --- Misc ---
		"permitlocalcommand":      boolField(func(o *Options) **bool { return &o.PermitLocalCommand }),
		"localcommand":            strField(func(o *Options) **string { return &o.LocalCommand }),
		"visualhostkey":           boolField(func(o *Options) **bool { return &o.VisualHostKey }),
		"forkafterauthentication": boolField(func(o *Options) **bool { return &o.ForkAfterAuthentication }),
		"stdinnull":               boolField(func(o *Options) **bool { return &o.StdinNull }),
		"enableescapecommandline": boolField(func(o *Options) **bool { return &o.EnableEscapeCommandline }),
		"obscurekeystroketiming":  strField(func(o *Options) **string { return &o.ObscureKeystrokeTiming }),
		"versionaddendum":         strField(func(o *Options) **string { return &o.VersionAddendum }),
		"pkcs11provider":          strField(func(o *Options) **string { return &o.PKCS11Provider }),
		"securitykeyprovider":     strField(func(o *Options) **string { return &o.SecurityKeyProvider }),
		"ignoreunknown":           ignoreUnknownHandler,
		"refuseconnection":        strField(func(o *Options) **string { return &o.RefuseConnection }),
		"syslogfacility":          strField(func(o *Options) **string { return &o.SyslogFacility }),

		// Structural directives handled by the parser, not here.
		"host":    skipDirective,
		"match":   skipDirective,
		"include": skipDirective,
	}
}

// strField returns a handler that sets a first-value-wins *string field.
func strField(field func(*Options) **string) directiveHandler {
	return func(opts *Options, value string, _ sshconfig.SourceInfo) error {
		setStr(field(opts), value)
		return nil
	}
}

// boolField returns a handler that sets a first-value-wins *bool field.
func boolField(field func(*Options) **bool) directiveHandler {
	return func(opts *Options, value string, _ sshconfig.SourceInfo) error {
		setBool(field(opts), value)
		return nil
	}
}

// intField returns a handler that sets a first-value-wins *int field.
func intField(field func(*Options) **int) directiveHandler {
	return func(opts *Options, value string, _ sshconfig.SourceInfo) error {
		setInt(field(opts), value)
		return nil
	}
}

// appendField returns a handler that always appends to a []string field.
func appendField(field func(*Options) *[]string) directiveHandler {
	return func(opts *Options, value string, _ sshconfig.SourceInfo) error {
		p := field(opts)
		*p = append(*p, value)
		return nil
	}
}

// firstFields returns a handler that sets a []string field (via strings.Fields)
// only if currently nil (first-value-wins for slice fields).
func firstFields(field func(*Options) *[]string) directiveHandler {
	return func(opts *Options, value string, _ sshconfig.SourceInfo) error {
		p := field(opts)
		if *p == nil {
			*p = strings.Fields(value)
		}
		return nil
	}
}

// skipDirective silently ignores structural directives (host, match, include).
func skipDirective(_ *Options, _ string, _ sshconfig.SourceInfo) error {
	return nil
}

// identityFileHandler handles IdentityFile: "none" clears, otherwise appends.
func identityFileHandler(opts *Options, value string, _ sshconfig.SourceInfo) error {
	if strings.ToLower(value) == "none" {
		opts.IdentityFile = []string{}
	} else {
		opts.IdentityFile = append(opts.IdentityFile, value)
	}
	return nil
}

// localForwardHandler parses and appends a LocalForward specification.
func localForwardHandler(opts *Options, value string, source sshconfig.SourceInfo) error {
	fwd, err := parseForward(value)
	if err != nil {
		return &sshconfig.ParseError{Source: source, Msg: fmt.Sprintf("LocalForward: %v", err)}
	}
	opts.LocalForward = append(opts.LocalForward, fwd)
	return nil
}

// remoteForwardHandler parses and appends a RemoteForward specification.
func remoteForwardHandler(opts *Options, value string, source sshconfig.SourceInfo) error {
	fwd, err := parseForward(value)
	if err != nil {
		return &sshconfig.ParseError{Source: source, Msg: fmt.Sprintf("RemoteForward: %v", err)}
	}
	opts.RemoteForward = append(opts.RemoteForward, fwd)
	return nil
}

// sendEnvHandler handles SendEnv's special accumulation with '-' prefix removal.
func sendEnvHandler(opts *Options, value string, _ sshconfig.SourceInfo) error {
	opts.SendEnv = appendSendEnv(opts.SendEnv, value)
	return nil
}

// channelTimeoutHandler appends whitespace-split fields to ChannelTimeout.
func channelTimeoutHandler(opts *Options, value string, _ sshconfig.SourceInfo) error {
	opts.ChannelTimeout = append(opts.ChannelTimeout, strings.Fields(value)...)
	return nil
}

// ignoreUnknownHandler sets IgnoreUnknown and updates the ignored keywords set.
func ignoreUnknownHandler(opts *Options, value string, _ sshconfig.SourceInfo) error {
	setStr(&opts.IgnoreUnknown, value)
	if opts.ignoredKeywords == nil {
		opts.ignoredKeywords = make(map[string]bool)
	}
	for _, pattern := range strings.Split(value, ",") {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if pattern != "" {
			opts.ignoredKeywords[pattern] = true
		}
	}
	return nil
}
