# Unsupported Helper Features

This document lists OpenSSH flags and features that the `cmd/ssh-keygen`,
`cmd/ssh-keyscan`, `cmd/ssh-agent`, `cmd/ssh-add`, and `cmd/ssh-copy-id`
replacements do not implement. Unless noted otherwise, passing an unsupported
flag is silently ignored or produces an "unknown option" error.

---

## ssh-keygen

### Key Types

Only `ed25519`, `ecdsa`, and `rsa` are supported. DSA keys (`-t dsa`) and
`ecdsa-sk`/`ed25519-sk` (FIDO) key types are not available.

### Certificate Operations

| Flag | Feature | Status |
|---|---|---|
| `-s ca_key` | Sign a public key to create a certificate | Not implemented |
| `-I cert_identity` | Certificate identity string | Not implemented |
| `-h` | Create a host certificate (with `-s`) | Not implemented |
| `-n principals` | Certificate principals | Not implemented |
| `-V validity` | Certificate validity interval | Incompatible: `ssh-keygen -V` is treated as a version flag, not certificate validity |
| `-z serial` | Certificate serial number | Not implemented |
| `-O option` | Certificate options / constraints | Not implemented |
| `-L` | Print certificate contents | Not implemented |
| `-U` | Use agent key for certificate signing | Not implemented |

### Key Revocation Lists (KRL)

| Flag | Feature | Status |
|---|---|---|
| `-k` | Generate a KRL | Not implemented |
| `-Q` | Test whether keys are revoked by a KRL | Not implemented |
| `-u` | Update an existing KRL | Not implemented |

### Key Conversion and Import/Export

| Flag | Feature | Status |
|---|---|---|
| `-e` | Export key to RFC 4716 / PKCS8 / PEM format | Not implemented |
| `-i` | Import key from foreign format | Not implemented |
| `-m format` | Key format for `-e` / `-i` | Not implemented |

### Known Hosts Operations

| Flag | Feature | Status |
|---|---|---|
| `-F hostname` | Find hostname in known_hosts | Not implemented |
| `-H` | Hash all hostnames in a known_hosts file | Not implemented |
| `-R hostname` | Remove hostname entries from known_hosts | Not implemented |

### FIDO / PKCS#11

| Flag | Feature | Status |
|---|---|---|
| `-K` | Download FIDO resident keys from a token | Not implemented |
| `-D pkcs11` | Download public keys from a PKCS#11 device | Not implemented |
| `-Y` | FIDO signing / verification operations | Not implemented |
| `-w provider` | FIDO/security key provider library path | Not implemented |

### Miscellaneous

| Flag | Feature | Status |
|---|---|---|
| `-A` | Generate all default host key types | Not implemented |
| `-a rounds` | KDF rounds for bcrypt/argon2 key derivation | Not implemented |
| `-B` | Bubble babble fingerprint format | Not implemented |
| `-r` | Print DNS SSHFP resource record | Not implemented |
| `-M generate/screen` | Diffie-Hellman moduli generation and screening | Not implemented |
| `-W generator` | DH generator for moduli screening | Not implemented |
| `-J num_lines` | Lines to process per pass during moduli screening | Not implemented |
| `-Z cipher` | Cipher for private key encryption format | Not implemented |

---

## ssh-keyscan

| Flag | Feature | Status |
|---|---|---|
| `-c` | Request certificates instead of plain host keys | Not implemented |
| `-D` | Connect via a SOCKS proxy | Not implemented |
| `-O option` | Scanner options | Not implemented |
| `-4` | Force IPv4 | Parsed; not enforced by dialer |
| `-6` | Force IPv6 | Parsed; not enforced by dialer |

---

## ssh-agent

| Flag | Feature | Status |
|---|---|---|
| `-E hash` | Hash algorithm for key fingerprints | Not implemented |
| `-P provider` | PKCS#11/FIDO provider whitelist | Not implemented |
| `-t lifetime` | Default key lifetime (seconds) for all added keys | Not implemented |
| `-O option` | Agent options (`no-restrict`, `allow-*`) | Not implemented |

### Other Limitations

- Daemon mode (`-d`/`-D` absent) re-execs the binary with an environment
  marker instead of calling `fork(2)`. This is functionally equivalent but
  means the child is a fresh process, not a true fork.

---

## ssh-add

| Flag | Feature | Status |
|---|---|---|
| `-E hash` | Hash algorithm for fingerprint display | Not implemented; always SHA-256 |
| `-K` | Load FIDO resident keys from a token | Not implemented |
| `-k` | Load keys from all default locations plus FIDO | Not implemented |
| `-q` | Quiet mode | Not implemented |
| `-s pkcs11` | Add keys stored on a PKCS#11 device | Not implemented |
| `-e pkcs11` | Remove keys provided by a PKCS#11 device | Not implemented |
| `-S provider` | Specify FIDO/PKCS#11 provider library | Not implemented |
| `-T pubkey` | Test whether keys in the agent match a public key file | Not implemented |
| `-H` | Add host-key constraint to a key | Not implemented |
| `-h` | Add destination constraint to a key | Not implemented |

---

## ssh-copy-id

| Flag | Feature | Status |
|---|---|---|
| `-s` | Use SFTP for file transfer instead of `cat >>` | Not implemented |
| `-h` / `--help` | Print usage help | Not implemented |

### Other Limitations

- Key installation uses `sh -c 'cat >> ~/.ssh/authorized_keys'` via an exec
  channel. The real `ssh-copy-id` also deduplicates keys already present in
  `authorized_keys`; this implementation always appends.
- `-f` is accepted but currently has no effect because the implementation
  never checks whether the key is already present before appending it.

---

## Common Gaps

Several limitations are shared across all five helpers:

| Area | Details |
|---|---|
| FIDO/U2F security keys | `golang.org/x/crypto/ssh` has no `sk-*` key type support. FIDO key generation, resident key download, and attestation are unavailable. |
| PKCS#11 | No `dlopen`-based PKCS#11 provider loading. Keys on hardware tokens cannot be accessed. |
| DSA keys | `golang.org/x/crypto/ssh` does not expose DSA key generation; existing DSA keys can still be parsed. |
| Bubble babble | Only SHA-256 and MD5 fingerprint formats are supported. |
