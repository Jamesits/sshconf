# SSHConf Agent Notes

DO NOT read README.md; all you need is already here.

## Package Structure

Config file parsers:

- `pkg/sshconfig`: a generic parser for OpenSSH config file format
- `pkg/client`: a parser for `ssh_config` that configures Golang SSH client library accordingly; read the specs with `man ssh_config`
- `pkg/server`: a parser for `sshd_config` that configures Golang SSH server library accordingly; read the specs with `man sshd_config`

## Code Style
- Document the higher intention with comments
- DO NOT write unit tests unless explicitly instructed to do so

## Compilation
Always full recompile with `goreleaser build --snapshot --clean` and use the artifacts under `dist/`.
