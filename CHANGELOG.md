# Changelog

## Unreleased

- `almanac-demo`: a demo database of made-up customers, built through the real importer.
- The importer command is now `almanac-import` (module `almanac.importer`).
- Restyled UI: header bar, readable tables, dark mode, mobile viewport.
- Fixed: the `·` separators in the page title and header were double-encoded and showed as `Â·`.
- Fixed: flags on records with no `name` column were labelled with the record id instead of its title.
- Fixed: a certificate test that broke once its hard-coded date passed.
- Docs: `docs/` (architecture, importing, data model, running), SECURITY.md, CONTRIBUTING.md, screenshots.

## 0.1.0 - 2026-10-02

- CSV export importer: secrets to the vault (or dropped), pasted passwords redacted and
  flagged, configuration references resolved, attachments imported.
- Encrypted vault (AES-256-GCM, scrypt), audited reveal, reuse report from fingerprints.
- Web UI with roles (admin, staff, member, disabled) and per-org scoping; editing, new
  items, file uploads, org-level secrets.
- Complete export, per org or whole, that the importer reads back losslessly.
- `almanac-sync-lineage`: configurations fed from a lineage inventory.
- `almanac-sweep-certs` and `/expiring`: TLS certificate sweep and expiry tracking.
