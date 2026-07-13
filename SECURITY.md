# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories (or the
contact in the repository metadata). Do not open a public issue for
undisclosed vulnerabilities. We aim to acknowledge within a few business days.

## Security model

BlakHound processes security-sensitive AWS metadata. It enforces:

- **Local-only storage.** SQLite at `~/.blakhound/blakhound.db`, created `0600`.
- **No credential persistence.** AWS secret keys are never written to the
  database or config.
- **Read-only AWS access.** No mutating API is ever called.
- **No secret retrieval.** Secret and SecureString *values* are never fetched;
  only references/metadata are stored.
- **Secret redaction.** Likely secret values and access-key ids are redacted
  from collected documents and logs.
- **No telemetry / analytics / remote service.**
- **MCP is read-only**, binds localhost for HTTP (localhost-only unless
  `--allow-remote`), exposes no shell or SQL, and validates all input.
- **Explicit confirmation** is required before destructive local actions
  (`db reset --yes`).

## Optional future hardening

- At-rest database encryption (documented as a future feature).
- Signed release checksums (provided via GoReleaser).
