# Unsupported Server Features

This document lists `sshd_config(5)` directives that `pkg/server` parses but
does not fully enforce, along with algorithms recognized by OpenSSH but absent
from `golang.org/x/crypto/ssh`. Unless noted otherwise, affected directives
are silently accepted — the resolved `Options` value carries them for
inspection, but the runtime behavior matches OpenSSH defaults instead.

## Algorithms Not Supported by `golang.org/x/crypto/ssh`

The same gaps apply here as on the client side: algorithms listed in these
tables are filtered out of the resolved list before it reaches the SSH
handshake. Clients offering only filtered algorithms will fail to connect.

### Key Exchange

| Algorithm | Notes |
|---|---|
| `sntrup761x25519-sha512` | Hybrid post-quantum (NTRU Prime) |
| `sntrup761x25519-sha512@openssh.com` | OpenSSH-specific name |
| `curve25519-sha256@libssh.org` | Alias for `curve25519-sha256` |
| `diffie-hellman-group18-sha512` | DH group 18 |
| `diffie-hellman-group-exchange-sha1` | SHA-1 group exchange |
| `diffie-hellman-group14-sha1` | SHA-1 variant |
| `diffie-hellman-group1-sha1` | Legacy |

### Ciphers

| Algorithm | Notes |
|---|---|
| `aes192-cbc` | AES-192 in CBC mode |
| `aes256-cbc` | AES-256 in CBC mode |
| `3des-cbc` | Legacy |

### MACs

| Algorithm | Notes |
|---|---|
| `umac-64-etm@openssh.com` | UMAC-64 encrypt-then-MAC |
| `umac-128-etm@openssh.com` | UMAC-128 encrypt-then-MAC |
| `hmac-sha1-etm@openssh.com` | HMAC-SHA1 encrypt-then-MAC |
| `umac-64@openssh.com` | UMAC-64 |
| `umac-128@openssh.com` | UMAC-128 |
| `hmac-md5`, `hmac-md5-96`, `hmac-md5-etm@openssh.com`, `hmac-md5-96-etm@openssh.com` | MD5 variants |

### Host Key Algorithms

| Algorithm | Notes |
|---|---|
| `sk-ssh-ed25519@openssh.com` | FIDO/U2F security key (Ed25519) |
| `sk-ecdsa-sha2-nistp256@openssh.com` | FIDO/U2F security key (ECDSA) |
| `sk-ssh-ed25519-cert-v01@openssh.com` | Certificate variant |
| `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` | Certificate variant |
| `webauthn-sk-ecdsa-sha2-nistp256*` | WebAuthn variants |

## Directives Parsed But Not Enforced

The parser accepts these keywords and stores them on `Options`, but
`pkg/server` does not change its runtime behavior based on their values.
A handler implementation can consult `Options` directly if it wants to
honor the configured policy.

### Authentication

| Directive | Status |
|---|---|
| `AuthenticationMethods` | Parsed; `x/crypto/ssh` enforces its own ordering via enabled callbacks |
| `UsePAM`, `PAMServiceName` | Parsed; no PAM integration |
| `KerberosAuthentication`, `KerberosGetAFSToken`, `KerberosOrLocalPasswd`, `KerberosTicketCleanup` | Parsed; no Kerberos integration |
| `GSSAPICleanupCredentials`, `GSSAPIStrictAcceptorCheck` | Parsed; `Handlers.GSSAPIServer` is the extension point |
| `PubkeyAuthOptions` (`touch-required`, `verify-required`) | Parsed; not applied to FIDO keys |
| `HostbasedAuthentication`, `HostbasedAcceptedAlgorithms`, `HostbasedUsesNameFromPacketOnly` | Interface defined (`HostbasedAuthenticator`), not wired into `ssh.ServerConfig` — `x/crypto/ssh` does not expose a hostbased auth callback |
| `IgnoreRhosts`, `IgnoreUserKnownHosts` | Parsed; consulted only by a hostbased implementation |
| `PermitRootLogin` values `prohibit-password` and `forced-commands-only` | Parsed; only `no` is enforced by `SimpleAccessController` |
| `TrustedUserCAKeys`, `RevokedKeys` | Parsed; `AuthorizedKeysAuthenticator` does not consult them |
| `AuthorizedKeysCommand`, `AuthorizedKeysCommandUser`, `AuthorizedPrincipalsFile`, `AuthorizedPrincipalsCommand`, `AuthorizedPrincipalsCommandUser` | Parsed; `AuthorizedKeysAuthenticator` only reads plain `authorized_keys` files |
| `authorized_keys` option fields (`from=`, `command=`, `environment=`, ...) | Not evaluated by `AuthorizedKeysAuthenticator` |
| `MaxAuthTries` | Enforced by `x/crypto/ssh` |
| `RequiredRSASize` | Not enforced |
| `ExposeAuthInfo` | Parsed; `SSH_USER_AUTH` is not written |

### Access Control

| Directive | Status |
|---|---|
| `AllowGroups`, `DenyGroups` | Parsed; `SimpleAccessController` ignores groups |
| `AllowUsers` / `DenyUsers` with `USER@HOST` form | Only the `USER` portion is compared |
| `Match Invalid-User` | Evaluated against `Lookup.InvalidUser`; caller must set the flag |
| `Match Group` | Evaluated against `Lookup.Groups`; caller must populate it |
| `Match RDomain` | Parsed; callers must supply the routing domain (no Linux rdomain(4) integration) |
| `StrictModes` | Parsed; no mode/ownership checks performed on user files |

### Session / Environment

| Directive | Status |
|---|---|
| `ChrootDirectory` | Parsed; no chroot is performed |
| `ForceCommand` | Enforced for `exec` requests only; `shell` and `subsystem` requests ignore it |
| `PermitUserEnvironment` | Parsed; `~/.ssh/environment` is never read |
| `PermitUserRC` | Parsed; `~/.ssh/rc` is never executed |
| `Banner` | Read from file and sent; no token expansion |
| `PrintMotd`, `PrintLastLog` | Parsed; no motd/lastlog is displayed |
| `SetEnv` | Parsed; `DefaultSessionHandler` does not apply it to the child environment |
| `AcceptEnv` | Enforced by `DefaultSessionHandler` for `env` requests |
| `PermitTTY` | Enforced: `pty-req` is rejected when `no` |

### Forwarding

| Directive | Status |
|---|---|
| `GatewayPorts` (`yes`, `clientspecified`) | Parsed; `DefaultTcpForwarder` binds exactly the address the client requested without differentiating the two |
| `PermitOpen`, `PermitListen` | Enforced via exact-string match only (no wildcards, CIDR, or port-range syntax) |
| `StreamLocalBindMask`, `StreamLocalBindUnlink` | Parsed; not consulted (`StreamLocalForwarder` is caller-supplied) |
| `PermitTunnel` | Parsed; no built-in `TunnelForwarder` implementation |
| `X11Forwarding`, `X11DisplayOffset`, `X11UseLocalhost`, `XAuthLocation` | Parsed; no built-in `X11Forwarder` implementation |
| `AllowAgentForwarding` | Parsed; no built-in `AgentForwarder` implementation |
| `DisableForwarding` | Enforced for TCP and StreamLocal dispatch |

### Connection Lifetime

| Directive | Status |
|---|---|
| `ClientAliveInterval`, `ClientAliveCountMax` | Parsed; `x/crypto/ssh` does not expose a mechanism to inject keepalive requests |
| `UnusedConnectionTimeout` | Parsed; no idle tracking |
| `ChannelTimeout` | Parsed; no per-channel idle tracking |
| `MaxSessions` | Parsed; no session counting |
| `MaxStartups`, `PerSourceMaxStartups`, `PerSourceNetBlockSize`, `PerSourcePenalties`, `PerSourcePenaltyExemptList` | Parsed; no rate-limiting or penalty tracking |
| `LoginGraceTime` | Enforced via a `SetReadDeadline` before handshake completes |
| `TCPKeepAlive` | Applied to accepted TCP connections |
| `IPQoS` | Parsed; no DSCP tagging |
| `RekeyLimit` | Byte limit applied; time-based rekey not |

### Logging

| Directive | Status |
|---|---|
| `LogVerbose` | Parsed; no per-file/function filtering |
| `SyslogFacility` | Parsed; `pkg/logger` writes to stderr or a file, not syslog |
| `FingerprintHash` | Parsed; internal logging does not use it |

### Protocol

| Directive | Status |
|---|---|
| `Compression` | Parsed; `x/crypto/ssh` does not implement zlib compression |
| `UseDNS` | Parsed; no reverse DNS lookup is performed on the client address |
| `ModuliFile` | Parsed; `x/crypto/ssh` does not support `diffie-hellman-group-exchange-*` moduli loading |
| `VersionAddendum` | Applied to `ssh.ServerConfig.ServerVersion` |

### Host Keys

| Directive | Status |
|---|---|
| `HostKey` | Loaded from disk; RSA/ECDSA/Ed25519 supported |
| `HostCertificate` | Loaded when it matches a `HostKey` (also auto-discovers `<key>-cert.pub`) |
| `HostKeyAgent` | Parsed; no agent-backed host key implementation |

### Listening

| Directive | Status |
|---|---|
| `ListenAddress` with `rdomain` qualifier | Qualifier is silently stripped |
| `RDomain` | Parsed; no Linux `rdomain(4)` binding |
| Multiple `Port` entries | All ports are opened (matches OpenSSH) |

### Daemon

| Directive | Status |
|---|---|
| `PidFile` | Parsed; `cmd/sshd` does not write a PID file |
| `SecurityKeyProvider` | Parsed; no FIDO authenticator loader |
| `SshdAuthPath`, `SshdSessionPath` | Parsed; no auth/session binary split |

## Extension Points

Features in the tables above can be supplied externally by implementing the
relevant interface from `pkg/server/handlers.go`:

- `PasswordAuthenticator`, `PublicKeyAuthenticator`,
  `KeyboardInteractiveAuthenticator`, `HostbasedAuthenticator`
- `AccessController`
- `HostKeyProvider`
- `SessionHandler` (plus `SubsystemHandler` for in-process subsystems)
- `TcpForwarder`, `StreamLocalForwarder`, `AgentForwarder`,
  `X11Forwarder`, `TunnelForwarder`
- `CommandExecutor`
- `Logger`

The resolved `*Options` value is passed to every handler call, so a caller
that wants to honor an unenforced directive can read it from `Options`
directly and apply the policy in its own code.
