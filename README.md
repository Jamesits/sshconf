# SSHConf

Parse `ssh_config` into Golang SSH library so the end users don't have to write another config file.

![Project Status - Development](https://img.shields.io/badge/Project_Status-Development-red)
![100% AI Code](https://img.shields.io/badge/AI_Code-100%25-blue)
[![Go Reference](https://pkg.go.dev/badge/github.com/jamesits/sshconf.svg)](https://pkg.go.dev/github.com/jamesits/sshconf)

## Feature Parity

### Config Parser

- [x] Generic parser for OpenSSH config files: `pkg/sshconfig`
- [x] `ssh_config`: `pkg/sshclient`
- [x] `sshd_config`: `pkg/sshserver`

### Command Line Arguments Parser

- [ ] `scp`
- [ ] `sftp`
- [x] `ssh`: `pkg/sshclient`
- [x] `ssh-add`: `pkg/sshadd`
- [x] `ssh-agent`: `pkg/sshagent`
- [x] `ssh-copy-id`: `pkg/sshcopyid`
- [x] `ssh-keygen`: `pkg/sshkeygen`
- [x] `ssh-keyscan`: `pkg/sshkeyscan`
- [x] `sshd`: `pkg/sshserver` (reference implementation only, see [Unsupported Config](/docs/server/unsupported-config.md))

### Algorithms

The following algorithms are recognized by OpenSSH but have no implementation
in `golang.org/x/crypto/ssh`. If configured, they are silently filtered out.

#### Key Exchange

| Algorithm | Notes |
|---|---|
| `sntrup761x25519-sha512` | Hybrid post-quantum (NTRU Prime) |
| `sntrup761x25519-sha512@openssh.com` | OpenSSH-specific name |
| `curve25519-sha256@libssh.org` | Alias for `curve25519-sha256` |
| `diffie-hellman-group18-sha512` | DH group 18 |

#### Ciphers

| Algorithm | Notes |
|---|---|
| `aes192-cbc` | AES-192 in CBC mode |
| `aes256-cbc` | AES-256 in CBC mode |

#### MACs

| Algorithm | Notes |
|---|---|
| `umac-64-etm@openssh.com` | UMAC-64 encrypt-then-MAC |
| `umac-128-etm@openssh.com` | UMAC-128 encrypt-then-MAC |
| `hmac-sha1-etm@openssh.com` | HMAC-SHA1 encrypt-then-MAC |
| `umac-64@openssh.com` | UMAC-64 |
| `umac-128@openssh.com` | UMAC-128 |

#### Host Key Algorithms

| Algorithm | Notes |
|---|---|
| `sk-ssh-ed25519@openssh.com` | FIDO/U2F security key (Ed25519) |
| `sk-ecdsa-sha2-nistp256@openssh.com` | FIDO/U2F security key (ECDSA) |
| `sk-ssh-ed25519-cert-v01@openssh.com` | Certificate variant |
| `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` | Certificate variant |
