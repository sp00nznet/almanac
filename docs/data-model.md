# Data model

All tables live in one SQLite file. They are created by `CREATE TABLE IF NOT EXISTS` in the
module that owns them (see [architecture.md](architecture.md)), so any command can open a fresh file.

| Table | Columns | What it's for |
|---|---|---|
| `orgs` | `id`, `name` (unique), `fields` JSON | Customers / sites. Items refer to an org **by name**, as the exports do. |
| `items` | `kind`, `id`, `org`, `name`, `fields` JSON; PK (`kind`, `id`) | Everything else: configurations, passwords, domains, certificates, custom asset types. `fields` holds every non-secret column. |
| `refs` | `kind`, `id`, `field`, `target`, `target_id` | A field that names configurations ("AD Servers: DC01, DC02"). `target_id` is NULL when the name didn't resolve. |
| `flags` | `kind`, `id`, `org`, `name`, `field`, `reason` | A known secret found outside the vault: `password pasted in notes` (redacted) or `weak: password derived from this field` (left alone). |
| `attachments` | `kind`, `id`, `filename`, `size`, `data` BLOB, `uploaded_by`, `ts` | Files on an item, stored in the database. Capped at 25 MB per upload. |
| `secrets` | `kind`, `id`, `field`, `blob`, `fp`; PK (`kind`, `id`, `field`) | Encrypted values. `blob` = nonce + AES-GCM ciphertext with the slot as associated data. `fp` = HMAC fingerprint for the reuse report. Org-level secrets use `kind = 'organizations'`. |
| `meta` | `k`, `v` | Vault salt and the passphrase check value. |
| `audit` | `ts`, `user`, `action`, `kind`, `id`, `field` | Every item view, reveal, edit, upload and export. |
| `users` | `name`, `salt`, `hash`, `role` | Logins. `hash` is scrypt. `role` is one of admin, staff, member, disabled. |
| `members` | `user`, `org` | Which orgs a `member` can see. Ignored for admin and staff. |

Feeds add a few fields to an item's `fields` JSON: `source` (`lineage`, `cert sweep`),
`last_seen`, `lineage_agent_id`, and for certificates `valid_until`, `issues`. These are the
only fields a feed overwrites. Anything a person typed is left alone.
