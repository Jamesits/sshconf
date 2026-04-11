package sshserver

import (
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
)

// directiveHandler applies a config directive value to Options.
type directiveHandler func(opts *Options, value string, source sshconfig.SourceInfo) error

// directiveTable maps lowercase sshd_config keywords to their handlers.
var directiveTable map[string]directiveHandler

func init() {
	directiveTable = map[string]directiveHandler{
		// --- Listening ---
		"addressfamily":  strField(func(o *Options) **string { return &o.AddressFamily }),
		"listenaddress":  appendField(func(o *Options) *[]string { return &o.ListenAddress }),
		"port":           parsePortDirective,
		"rdomain":        strField(func(o *Options) **string { return &o.RDomain }),
		"logingracetime": timeField(func(o *Options) **int { return &o.LoginGraceTime }),

		// --- Host Keys ---
		"hostkey":           appendField(func(o *Options) *[]string { return &o.HostKey }),
		"hostkeyagent":      strField(func(o *Options) **string { return &o.HostKeyAgent }),
		"hostcertificate":   appendField(func(o *Options) *[]string { return &o.HostCertificate }),
		"trustedusercakeys": strField(func(o *Options) **string { return &o.TrustedUserCAKeys }),
		"revokedkeys":       strField(func(o *Options) **string { return &o.RevokedKeys }),

		// --- Crypto ---
		"ciphers":                     strField(func(o *Options) **string { return &o.Ciphers }),
		"kexalgorithms":               strField(func(o *Options) **string { return &o.KexAlgorithms }),
		"macs":                        strField(func(o *Options) **string { return &o.MACs }),
		"hostkeyalgorithms":           strField(func(o *Options) **string { return &o.HostKeyAlgorithms }),
		"casignaturealgorithms":       strField(func(o *Options) **string { return &o.CASignatureAlgorithms }),
		"pubkeyacceptedalgorithms":    strField(func(o *Options) **string { return &o.PubkeyAcceptedAlgorithms }),
		"pubkeyacceptedkeytypes":      strField(func(o *Options) **string { return &o.PubkeyAcceptedAlgorithms }), // alias
		"hostbasedacceptedalgorithms": strField(func(o *Options) **string { return &o.HostbasedAcceptedAlgorithms }),
		"hostbasedacceptedkeytypes":   strField(func(o *Options) **string { return &o.HostbasedAcceptedAlgorithms }), // alias
		"rekeylimit":                  strField(func(o *Options) **string { return &o.RekeyLimit }),
		"requiredrsasize":             intField(func(o *Options) **int { return &o.RequiredRSASize }),
		"fingerprinthash":             strField(func(o *Options) **string { return &o.FingerprintHash }),

		// --- Authentication ---
		"authenticationmethods":           strField(func(o *Options) **string { return &o.AuthenticationMethods }),
		"permitrootlogin":                 strField(func(o *Options) **string { return &o.PermitRootLogin }),
		"passwordauthentication":          boolField(func(o *Options) **bool { return &o.PasswordAuthentication }),
		"permitemptypasswords":            boolField(func(o *Options) **bool { return &o.PermitEmptyPasswords }),
		"kbdinteractiveauthentication":    boolField(func(o *Options) **bool { return &o.KbdInteractiveAuthentication }),
		"challengeresponseauthentication": boolField(func(o *Options) **bool { return &o.KbdInteractiveAuthentication }), // alias
		"pubkeyauthentication":            boolField(func(o *Options) **bool { return &o.PubkeyAuthentication }),
		"pubkeyauthoptions":               strField(func(o *Options) **string { return &o.PubkeyAuthOptions }),
		"hostbasedauthentication":         boolField(func(o *Options) **bool { return &o.HostbasedAuthentication }),
		"hostbasedusesnamefrompacketonly": boolField(func(o *Options) **bool { return &o.HostbasedUsesNameFromPacketOnly }),
		"ignorerhosts":                    strField(func(o *Options) **string { return &o.IgnoreRhosts }),
		"ignoreuserknownhosts":            boolField(func(o *Options) **bool { return &o.IgnoreUserKnownHosts }),
		"gssapiauthentication":            boolField(func(o *Options) **bool { return &o.GSSAPIAuthentication }),
		"gssapicleanupcredentials":        boolField(func(o *Options) **bool { return &o.GSSAPICleanupCredentials }),
		"gssapistrictacceptorcheck":       boolField(func(o *Options) **bool { return &o.GSSAPIStrictAcceptorCheck }),
		"kerberosauthentication":          boolField(func(o *Options) **bool { return &o.KerberosAuthentication }),
		"kerberosgetafstoken":             boolField(func(o *Options) **bool { return &o.KerberosGetAFSToken }),
		"kerberosorlocalpasswd":           boolField(func(o *Options) **bool { return &o.KerberosOrLocalPasswd }),
		"kerberosticketcleanup":           boolField(func(o *Options) **bool { return &o.KerberosTicketCleanup }),
		"usepam":                          boolField(func(o *Options) **bool { return &o.UsePAM }),
		"pamservicename":                  strField(func(o *Options) **string { return &o.PAMServiceName }),
		"maxauthtries":                    intField(func(o *Options) **int { return &o.MaxAuthTries }),
		"strictmodes":                     boolField(func(o *Options) **bool { return &o.StrictModes }),
		"exposeauthinfo":                  boolField(func(o *Options) **bool { return &o.ExposeAuthInfo }),
		"permituserenvironment":           strField(func(o *Options) **string { return &o.PermitUserEnvironment }),
		"permituserrc":                    boolField(func(o *Options) **bool { return &o.PermitUserRC }),

		// --- Access control ---
		"allowusers":       wordAppendField(func(o *Options) *[]string { return &o.AllowUsers }),
		"denyusers":        wordAppendField(func(o *Options) *[]string { return &o.DenyUsers }),
		"allowgroups":      wordAppendField(func(o *Options) *[]string { return &o.AllowGroups }),
		"denygroups":       wordAppendField(func(o *Options) *[]string { return &o.DenyGroups }),
		"refuseconnection": strField(func(o *Options) **string { return &o.RefuseConnection }),

		// --- Authorized keys ---
		"authorizedkeysfile":              wordAppendField(func(o *Options) *[]string { return &o.AuthorizedKeysFile }),
		"authorizedkeyscommand":           strField(func(o *Options) **string { return &o.AuthorizedKeysCommand }),
		"authorizedkeyscommanduser":       strField(func(o *Options) **string { return &o.AuthorizedKeysCommandUser }),
		"authorizedprincipalsfile":        strField(func(o *Options) **string { return &o.AuthorizedPrincipalsFile }),
		"authorizedprincipalscommand":     strField(func(o *Options) **string { return &o.AuthorizedPrincipalsCommand }),
		"authorizedprincipalscommanduser": strField(func(o *Options) **string { return &o.AuthorizedPrincipalsCommandUser }),

		// --- Session / forwarding ---
		"allowagentforwarding":       boolField(func(o *Options) **bool { return &o.AllowAgentForwarding }),
		"allowtcpforwarding":         strField(func(o *Options) **string { return &o.AllowTcpForwarding }),
		"allowstreamlocalforwarding": strField(func(o *Options) **string { return &o.AllowStreamLocalForwarding }),
		"disableforwarding":          boolField(func(o *Options) **bool { return &o.DisableForwarding }),
		"gatewayports":               strField(func(o *Options) **string { return &o.GatewayPorts }),
		"permitopen":                 wordAppendField(func(o *Options) *[]string { return &o.PermitOpen }),
		"permitlisten":               wordAppendField(func(o *Options) *[]string { return &o.PermitListen }),
		"permittty":                  boolField(func(o *Options) **bool { return &o.PermitTTY }),
		"permittunnel":               strField(func(o *Options) **string { return &o.PermitTunnel }),
		"x11forwarding":              boolField(func(o *Options) **bool { return &o.X11Forwarding }),
		"x11displayoffset":           intField(func(o *Options) **int { return &o.X11DisplayOffset }),
		"x11uselocalhost":            boolField(func(o *Options) **bool { return &o.X11UseLocalhost }),
		"xauthlocation":              strField(func(o *Options) **string { return &o.XAuthLocation }),
		"streamlocalbindmask":        strField(func(o *Options) **string { return &o.StreamLocalBindMask }),
		"streamlocalbindunlink":      boolField(func(o *Options) **bool { return &o.StreamLocalBindUnlink }),
		"chrootdirectory":            strField(func(o *Options) **string { return &o.ChrootDirectory }),
		"forcecommand":               strField(func(o *Options) **string { return &o.ForceCommand }),
		"banner":                     strField(func(o *Options) **string { return &o.Banner }),
		"printlastlog":               boolField(func(o *Options) **bool { return &o.PrintLastLog }),
		"printmotd":                  boolField(func(o *Options) **bool { return &o.PrintMotd }),

		// --- Session env ---
		"acceptenv": wordAppendField(func(o *Options) *[]string { return &o.AcceptEnv }),
		"setenv":    appendField(func(o *Options) *[]string { return &o.SetEnv }),

		// --- Connection lifetime ---
		"tcpkeepalive":               boolField(func(o *Options) **bool { return &o.TCPKeepAlive }),
		"clientaliveinterval":        timeField(func(o *Options) **int { return &o.ClientAliveInterval }),
		"clientalivecountmax":        intField(func(o *Options) **int { return &o.ClientAliveCountMax }),
		"unusedconnectiontimeout":    strField(func(o *Options) **string { return &o.UnusedConnectionTimeout }),
		"maxsessions":                intField(func(o *Options) **int { return &o.MaxSessions }),
		"maxstartups":                strField(func(o *Options) **string { return &o.MaxStartups }),
		"persourcemaxstartups":       strField(func(o *Options) **string { return &o.PerSourceMaxStartups }),
		"persourcenetblocksize":      strField(func(o *Options) **string { return &o.PerSourceNetBlockSize }),
		"persourcepenalties":         strField(func(o *Options) **string { return &o.PerSourcePenalties }),
		"persourcepenaltyexemptlist": strField(func(o *Options) **string { return &o.PerSourcePenaltyExemptList }),
		"ipqos":                      strField(func(o *Options) **string { return &o.IPQoS }),
		"channeltimeout":             channelTimeoutHandler,

		// --- Logging ---
		"loglevel":       strField(func(o *Options) **string { return &o.LogLevel }),
		"logverbose":     appendField(func(o *Options) *[]string { return &o.LogVerbose }),
		"syslogfacility": strField(func(o *Options) **string { return &o.SyslogFacility }),

		// --- Protocol ---
		"compression":     strField(func(o *Options) **string { return &o.Compression }),
		"versionaddendum": strField(func(o *Options) **string { return &o.VersionAddendum }),
		"modulifile":      strField(func(o *Options) **string { return &o.ModuliFile }),
		"usedns":          boolField(func(o *Options) **bool { return &o.UseDNS }),

		// --- Subsystems ---
		"subsystem": appendSubsystem,

		// --- Daemon ---
		"pidfile":             strField(func(o *Options) **string { return &o.PidFile }),
		"securitykeyprovider": strField(func(o *Options) **string { return &o.SecurityKeyProvider }),
		"sshdauthpath":        strField(func(o *Options) **string { return &o.SshdAuthPath }),
		"sshdsessionpath":     strField(func(o *Options) **string { return &o.SshdSessionPath }),

		// --- Misc ---
		"ignoreunknown": ignoreUnknownHandler,

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

// timeField returns a handler for time-valued options (LoginGraceTime,
// ClientAliveInterval). Values may use OpenSSH time suffixes (s/m/h/d/w).
func timeField(field func(*Options) **int) directiveHandler {
	return func(opts *Options, value string, _ sshconfig.SourceInfo) error {
		p := field(opts)
		if *p != nil {
			return nil
		}
		v := sshconfig.ParseTimeSeconds(value)
		*p = &v
		return nil
	}
}

// appendField returns a handler that always appends the raw value to a
// []string field (one line = one entry).
func appendField(field func(*Options) *[]string) directiveHandler {
	return func(opts *Options, value string, _ sshconfig.SourceInfo) error {
		p := field(opts)
		*p = append(*p, value)
		return nil
	}
}

// wordAppendField returns a handler that splits the value on whitespace
// and appends each word to a []string field. Used for directives like
// AllowUsers, AcceptEnv, AuthorizedKeysFile where multiple values can be
// given on one line.
func wordAppendField(field func(*Options) *[]string) directiveHandler {
	return func(opts *Options, value string, _ sshconfig.SourceInfo) error {
		p := field(opts)
		*p = append(*p, strings.Fields(value)...)
		return nil
	}
}

// channelTimeoutHandler appends whitespace-split fields to ChannelTimeout.
func channelTimeoutHandler(opts *Options, value string, _ sshconfig.SourceInfo) error {
	opts.ChannelTimeout = append(opts.ChannelTimeout, strings.Fields(value)...)
	return nil
}

// skipDirective silently ignores structural directives (host, match, include).
func skipDirective(_ *Options, _ string, _ sshconfig.SourceInfo) error {
	return nil
}

// ignoreUnknownHandler sets IgnoreUnknown and records the pattern list so
// ApplyDirective can suppress unknown keywords.
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
