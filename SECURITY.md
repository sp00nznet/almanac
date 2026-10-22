# Security

almanac stores other people's passwords. Reports are welcome and taken seriously.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository (Security tab →
"Report a vulnerability"). Please don't open a public issue for anything exploitable. Expect a
first reply within a week. almanac is alpha software maintained in spare time, and there's
no bounty.

## What protects what

| Threat | Mitigation | Where |
|---|---|---|
| Stolen database file | Secrets are AES-256-GCM encrypted; the key comes from a passphrase via scrypt (n=2^15) and is never stored | `almanac/vault.py` |
| Ciphertext moved to another row | The slot (`kind/id/field`) is GCM associated data, so a moved ciphertext fails to decrypt | `vault.py` |
| Reuse report leaking values | It compares HMAC fingerprints under a derived key, so nothing is decrypted | `vault.py` |
| Password sniffing | Basic auth only over TLS off-loopback: the server refuses to start otherwise | `server.serve` |
| Stolen login database | User passwords are salted scrypt hashes | `server.py` |
| Customer A seeing customer B | Every query is scoped through `App.scope`; out-of-scope is a 404, and reuse is filtered per viewer | `server.py` |
| Cross-site requests | POST only for changes; requests with a foreign `Origin` are refused | `server.do_POST` |
| Malicious import data or uploads | All output is HTML-escaped; uploads are served only as `application/octet-stream` with `nosniff` | `server.py` |
| Untracked access | Every item view, reveal, edit, upload and export is written to `audit` | `vault.audit` |

## Known limits

- **One vault key for all orgs.** Anyone with the passphrase and the file can read every
  secret. Per-org keys are on the [roadmap](ROADMAP.md).
- **The passphrase lives in the server's memory** while it runs (that's what makes reveal
  work). Protect the host accordingly.
- **No CSRF token.** Protection relies on the `Origin` check and on browsers sending
  `Origin` on cross-site POSTs, which all current browsers do.
- **No rate limiting or lockout** on login. Put it behind a VPN or a reverse proxy that limits
  rates if it faces the internet.
- `almanac-export --secrets` writes every secret decrypted into a zip. That's on purpose (a
  departing customer is owed their passwords), and protecting the zip is up to whoever holds it.
