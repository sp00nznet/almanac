# Importing

`almanac-import SOURCE OUT.db [--vault]` takes a directory or a `.zip` of CSV files in the
layout most IT documentation platforms export, and the layout `almanac-export` writes:

```
organizations.csv                 id, name, then any columns
<kind>.csv                        id, organization, then any columns  (one file per kind)
attachments/<kind>/<id>/<file>    optional; become files on that item
secrets.csv                       almanac's own export only: kind, id, field, value
flags.csv                         almanac's own export only
```

The file name (minus `.csv`) becomes the item's kind. `logs.csv` and `audit.csv` are skipped:
another system's audit trail isn't something almanac should rewrite as its own.

## Secrets

These columns are treated as secrets wherever they appear (`SECRET_COLUMNS` in
`almanac/importer.py`):

`password`, `Pre-Shared Key`, `Management Password`, `License Key(s)`, `Recovery Key`,
`private_key`, `certificate_signing_request`

With `--vault` they are encrypted into the vault. Without it they are **dropped**: the
metadata (name, username, URL) is imported and the value is not. Values in `secrets.csv`
(almanac's own export) are always secrets, including custom secret fields.

## Pasted passwords

Every known secret of 8 characters or more is searched for in every other field of every record:

- **In a free-text field** (notes, description, information...): the value is replaced with
  `[withheld]`, the original note is vaulted so nothing is lost, and a flag
  `password pasted in notes` is recorded.
- **In any other field** (username, email, city, hostname): the password was *derived from*
  that value. That's a weak password to rotate, not a leak, so it gets flagged as
  `weak: password derived from this field` and the data is left alone.

Shorter values aren't searched: matching on "admin" would gut the data. A short password
pasted into notes will therefore get through. The same check runs on every edit made in the UI.

On the real migration this found 95 pasted passwords across 71 records, and 647 derived ones.

## References

Columns that name configurations, such as `AD Servers`, `DNS Servers`, `Firewall` and
`Virtual Machines` (`REF_COLUMNS`), are split on commas, semicolons and newlines. Each name
is resolved to a configuration **in the same org**, first by name and then by hostname.
Unresolved names are kept with a NULL target, so nothing is lost. On the real migration,
161 of 163 resolved.

## Round trip

`almanac-export --secrets` followed by `almanac-import --vault` under a different passphrase
gives back the same items, secrets, flags and files. `tests/test_export.py` covers this, and
it was checked on the real 4,952-item migration.
