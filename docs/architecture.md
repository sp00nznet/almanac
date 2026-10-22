# Architecture

One Python package, one SQLite file. Every command opens the same database; there is no daemon
besides the web server, and the feeds are run on a schedule (Task Scheduler, cron).

```
  vendor CSV export ─┐
  almanac export.zip ┴─> almanac-import ──┐
                                          │
  lineage state tree ──> almanac-sync-lineage ──┤
                                          ├──> almanac.db (SQLite) <── almanac-server ──> browser
  TLS endpoints ──────> almanac-sweep-certs ────┤                  (Basic auth, audited)
                                          │
                       almanac-export <───┘  ──> export.zip (same CSV layout)
```

| Module | Owns |
|---|---|
| `almanac/importer.py` | The `items`, `orgs`, `refs`, `flags`, `attachments` schema; CSV import; `scan()`, the pasted-password detector shared with the UI's edit path |
| `almanac/vault.py` | `secrets`, `meta`, `audit`; AES-256-GCM encryption, fingerprints for the reuse report, `audit()` |
| `almanac/server.py` | `users`, `members`; the web UI, roles and scoping (`App.scope` / `App.visible`) |
| `almanac/export.py` | The export zip; the importer reads it back |
| `almanac/lineage.py` | Writes lineage-reported fields onto configurations |
| `almanac/certs.py` | The TLS sweep, certificate checks, `expiring()` used by `/expiring` |
| `almanac/demo.py` | Builds a demo database of made-up customers by running the real importer |

## Why it looks like this

- **One generic `items` table.** Vendor exports flatten core types and custom ("flexible")
  asset types to the same shape: a kind, an org, a name and some fields. Keeping that shape
  means a new asset type needs no migration, and the export can be written back in the same
  layout it came in.
- **Stdlib except `cryptography`.** The stdlib has no authenticated encryption, and a vault
  is the one place you don't roll your own. Key derivation is stdlib `hashlib.scrypt`.
- **Server-rendered HTML on `http.server`.** No build step, no JS framework, nothing to
  patch except Python. Every value is passed through `html.escape`, because imported data
  is untrusted.
- **Scoping in one place.** Every page asks `App.scope(user)` for its SQL filter, so a new
  page can't forget to filter by org.
