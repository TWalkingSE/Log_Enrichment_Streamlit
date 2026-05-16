# Security Policy

## Supported Versions

Security fix focus is on the main branch and the most recent published version on GitHub.

## Reporting a Vulnerability

Do not open a public issue to report vulnerabilities.

Use a private channel to the maintainer or, if the repository has GitHub Security Advisories enabled, open a private report there. In the report, include:

- Observed impact
- Minimal reproduction steps
- Affected version or commit
- Relevant dependencies
- Sanitized evidence, without sensitive data

## Response Expectations

- Initial acknowledgment: up to 5 business days
- Initial triage: up to 10 business days
- Fix or mitigation: according to severity and reproducibility

## Application authentication (Streamlit)

Optional UI authentication via `.env`:

- **`AUTH_PASSWORD_HASH` (recommended):** set an **Argon2** or **bcrypt** hash produced locally (passlib). Never store a plaintext password here.
- **Legacy:** a **SHA-256** hexadecimal digest (64 chars) of the UTF-8 password is still accepted; comparison uses `secrets.compare_digest`.
- **`AUTH_PASSWORD`:** plaintext in `.env` — development only; verification uses SHA-256 digests with a timing-safe comparison. **Do not use in production.**

Generate an Argon2 hash for `.env`:

```bash
python -c "from passlib.hash import argon2; print(argon2.hash(input('Password: ')))"
```

Or use the repo script:

```bash
python scripts/gen_auth_password_hash.py
```

## Scope Notes

This project processes potentially sensitive data. When reporting issues:

- Remove real IPs, personal identifiers, and credentials
- Do not attach production files without sanitization
- Describe the operational context only to the extent necessary for reproduction
