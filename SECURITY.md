# Security Policy

## Authorized use only

RouterXPL-Forge is an Android controller for EmbedXPL-Forge. It is intended
exclusively for security testing on systems you own or have explicit written
permission to assess. Unauthorized scanning or exploitation is illegal.

## What this project does NOT do

- No target is stored in the repository.
- No auto-scan runs on app launch.
- No credentials, tokens, or lab IPs are committed.
- `allowed_networks.json` is git-ignored and must be created locally.
- Exploit execution requires a target inside your own allowlist and an explicit
  confirmation where you retype the target IP.

## Reporting a vulnerability

Open a private security advisory or email the maintainers. Do not include
exploitable details in a public issue.

## Hardening checklist before publishing

- Keep the repository private unless you intentionally want public disclosure.
- Enable secret scanning and dependency alerts.
- Rotate any token used for CI or publishing.
- Review GitHub Actions permissions (`contents: read` by default).
