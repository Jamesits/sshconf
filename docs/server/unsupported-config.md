# Unsupported Server Features

This document lists `sshd_config(5)` directives that `pkg/sshserver` does not
implement, only partially enforces, or handles differently from OpenSSH.
Unless noted otherwise, affected directives are still parsed and stored on the
resolved `Options` value so caller-supplied handlers can inspect them.

## Important Runtime Caveats

The default `cmd/sshd` binary wires together intentionally small reference
components. They are useful as embedding examples, but they are not a full
OpenSSH-equivalent runtime.

- `cmd/sshd` resolves `sshd_config` once at startup and reuses that single
  `*Options` value for every connection. `Match` criteria that depend on the
  authenticated user, peer address, local address, local port, groups, or
  invalid-user state therefore require a caller to re-resolve config per
  connection; the stock daemon does not.
- The default session path uses `DefaultSessionHandler` with
  `ExecProcessLauncher`. That launcher runs commands in the daemon's current OS
  user context; it does not switch uid/gid, allocate a real PTY, or enforce
  `ChrootDirectory`. Treat it as a reference launcher for simple deployments,
  not a safe multi-user `sshd` replacement.
- The default auth path is also intentionally minimal: `AuthorizedKeysAuthenticator`
  only checks plain `authorized_keys` files and `SimpleAccessController` only
  enforces basic allow/deny user rules.

## Unsupported Or Partial Behavior

The parser accepts all of the directives below, but the built-in runtime either
does not enforce them, only applies part of their behavior, or requires a
custom handler to honor them fully.

### Authentication

| Directive | Status |
|---|---|
| `AuthenticationMethods` | Parsed; not enforced. `x/crypto/ssh` only exposes whichever auth callbacks are wired, not OpenSSH's multi-step method lists |
| `UsePAM`, `PAMServiceName` | Parsed; no PAM integration |
| `KerberosAuthentication`, `KerberosGetAFSToken`, `KerberosOrLocalPasswd`, `KerberosTicketCleanup` | Parsed; no Kerberos integration |
| `GSSAPICleanupCredentials`, `GSSAPIStrictAcceptorCheck` | Parsed; `Handlers.GSSAPIServer` is the extension point |
| `PubkeyAuthOptions` (`touch-required`, `verify-required`) | Parsed; not applied to FIDO keys |
| `HostbasedAuthentication`, `HostbasedAcceptedAlgorithms`, `HostbasedUsesNameFromPacketOnly` | Interface defined (`HostbasedAuthenticator`), not wired into `ssh.ServerConfig` — `x/crypto/ssh` does not expose a hostbased auth callback |
| `IgnoreRhosts`, `IgnoreUserKnownHosts` | Parsed; consulted only by a hostbased implementation |
| `PermitRootLogin` | Parsed; the built-in access controller does not consult it |
| `TrustedUserCAKeys`, `RevokedKeys` | Parsed; `AuthorizedKeysAuthenticator` does not consult them |
| `AuthorizedKeysCommand`, `AuthorizedKeysCommandUser`, `AuthorizedPrincipalsFile`, `AuthorizedPrincipalsCommand`, `AuthorizedPrincipalsCommandUser` | Parsed; `AuthorizedKeysAuthenticator` only reads plain `authorized_keys` files |
| `authorized_keys` option fields (`from=`, `command=`, `environment=`, ...) | Not evaluated by `AuthorizedKeysAuthenticator` |
| `RequiredRSASize` | Parsed but not enforced by the built-in public-key authenticator |
| `ExposeAuthInfo` | Parsed; `SSH_USER_AUTH` is not written |

### Access Control

| Directive | Status |
|---|---|
| `AllowGroups`, `DenyGroups` | Parsed; `SimpleAccessController` ignores groups |
| `AllowUsers` / `DenyUsers` with `USER@HOST` form | Only the `USER` portion is compared |
| `Match User`, `Match Group`, `Match Address`, `Match LocalAddress`, `Match LocalPort` | Supported by the parser/resolver, but only if the caller re-resolves options per connection. `cmd/sshd` resolves once at startup, so these criteria are effectively static there |
| `Match Invalid-User` | Evaluated against `Lookup.InvalidUser`; caller must set the flag |
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

### Forwarding

| Directive | Status |
|---|---|
| `AllowTcpForwarding` | Enforced only as a coarse local/remote gate; actual TCP forwarding still depends on a `TcpForwarder` implementation |
| `AllowStreamLocalForwarding` | Enforced only as a coarse local/remote gate; actual StreamLocal forwarding still depends on a `StreamLocalForwarder` implementation |
| `GatewayPorts` (`no`, `yes`, `clientspecified`) | Parsed; `DefaultTcpForwarder` binds exactly the address the client requested, so the default `GatewayPorts no` behavior is not enforced |
| `PermitOpen`, `PermitListen` | Enforced via exact-string match only (no wildcards, CIDR, or port-range syntax) |
| `StreamLocalBindMask`, `StreamLocalBindUnlink` | Parsed; not consulted (`StreamLocalForwarder` is caller-supplied) |
| `PermitTunnel` | Only gates whether `tun@openssh.com` is rejected; no built-in `TunnelForwarder` implementation |
| `X11Forwarding`, `X11DisplayOffset`, `X11UseLocalhost`, `XAuthLocation` | Parsed; no built-in `X11Forwarder` implementation, and `DefaultSessionHandler` does not consume `x11-req` requests |
| `AllowAgentForwarding` | Parsed; no built-in `AgentForwarder` implementation, and `DefaultSessionHandler` does not consume `auth-agent-req@openssh.com` requests |
| `DisableForwarding` | Enforced for TCP and StreamLocal dispatch only |

### Connection Lifetime

| Directive | Status |
|---|---|
| `ClientAliveInterval`, `ClientAliveCountMax` | Parsed; `x/crypto/ssh` does not expose a mechanism to inject keepalive requests |
| `UnusedConnectionTimeout` | Parsed; no idle tracking |
| `ChannelTimeout` | Parsed; no per-channel idle tracking |
| `MaxSessions` | Parsed; no session counting |
| `MaxStartups`, `PerSourceMaxStartups`, `PerSourceNetBlockSize`, `PerSourcePenalties`, `PerSourcePenaltyExemptList` | Parsed; no rate-limiting or penalty tracking |
| `IPQoS` | Parsed; no DSCP tagging |
| `RekeyLimit` | Byte limit applied; time-based rekey not |

### Logging

| Directive | Status |
|---|---|
| `LogLevel` | Parsed; internal logging does not filter or downgrade messages based on the configured level |
| `LogVerbose` | Parsed; no per-file/function filtering |
| `SyslogFacility` | Parsed; `pkg/logger` writes to stderr or a file, not syslog |
| `FingerprintHash` | Parsed; internal logging does not use it |

### Protocol

| Directive | Status |
|---|---|
| `Compression` | Parsed; `x/crypto/ssh` does not implement zlib compression |
| `UseDNS` | Parsed; no reverse DNS lookup is performed on the client address |
| `ModuliFile` | Parsed; `x/crypto/ssh` does not support `diffie-hellman-group-exchange-*` moduli loading |

### Host Keys

| Directive | Status |
|---|---|
| `HostKeyAgent` | Parsed; no agent-backed host key implementation |

### Listening

| Directive | Status |
|---|---|
| `ListenAddress` with `rdomain` qualifier | Qualifier is silently stripped |
| `RDomain` | Parsed; no Linux `rdomain(4)` binding |

### Daemon

| Directive | Status |
|---|---|
| `PidFile` | Parsed; `cmd/sshd` does not write a PID file |
| `SecurityKeyProvider` | Parsed; no FIDO authenticator loader |
| `SshdAuthPath`, `SshdSessionPath` | Parsed; no auth/session binary split |

## Extension Points

Features in the tables above can be supplied externally by implementing the
relevant interface from `pkg/sshserver/handlers.go`:

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
