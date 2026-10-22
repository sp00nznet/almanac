"""Import a CSV documentation export (organizations.csv plus one CSV per kind)
into an almanac SQLite store.

One generic `items` table: the core types (configurations, contacts, ...)
and its flexible assets are all "a kind, an org, a name, some fields", and the
export flattens them that way anyway.

Two things the export does badly, handled here:
  * Secrets. Passwords, PSKs, licence keys and BitLocker keys arrive in plain
    CSV. With a vault passphrase they go into the encrypted vault; without one
    they are WITHHELD -- metadata (name, username, url) imported, value dropped.
    Every other field is checked for those values and each hit lands in
    `flags`: pasted into notes (redacted, original note vaulted -- the real
    export had 95 of these across 22 customers) or derived from a
    username/email/city (weak, left alone -- 647 of those). Values shorter than
    MIN_SCRUB are not scrubbed (ponytail: "admin" would gut the data; a short
    password pasted in a note still leaks -- a secret scanner is the upgrade).
  * Relationships. Flexible-asset fields that pointed at a configuration are
    exported as its display name ("AD Servers: DC01, DC02"), not its id. They
    are resolved back by name/hostname within the same organization.

attachments/<kind>/<id>/<file> come in as files on their item. Not imported:
logs.csv (the old tenant's audit trail).
"""
import csv
import json
import re
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path

from .vault import Vault, ask_passphrase

csv.field_size_limit(2**31 - 1)

SECRET_COLUMNS = {
    "password", "Pre-Shared Key", "Management Password", "License Key(s)",
    "Recovery Key", "private_key", "certificate_signing_request",
}
# Flexible-asset columns that hold configuration names.
REF_COLUMNS = {
    "AD Servers", "DNS Servers", "DHCP Servers", "DHCP Server", "Application Server(s)",
    "Protected Servers", "Local Backup Server(s)", "Servers", "Firewall", "Switch(es)",
    "Router", "Switches", "Router/Firewall", "Email Servers", "Devices", "Firewall Devices",
    "Virtualization Hosts", "Virtual Machines", "Access Point(s)", "Wireless Controller(s)",
}
MIN_SCRUB = 8
# Free-text fields. A secret found here was pasted in: redact it. Anywhere else
# (username, email, city, hostname) the password was *derived from* that value --
# a weak password to rotate, not a leak, so flag it and leave the data alone.
NOTE_FIELD = re.compile(r"notes|information|description|issues|items|remote desktop", re.I)

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs  (id TEXT PRIMARY KEY, name TEXT UNIQUE, fields TEXT);
CREATE TABLE IF NOT EXISTS items (kind TEXT, id TEXT, org TEXT, name TEXT, fields TEXT,
                                  PRIMARY KEY (kind, id));
CREATE TABLE IF NOT EXISTS refs  (kind TEXT, id TEXT, field TEXT, target TEXT,
                                  target_id TEXT);  -- target_id NULL = unresolved
CREATE TABLE IF NOT EXISTS flags (kind TEXT, id TEXT, org TEXT, name TEXT, field TEXT, reason TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS flags_once ON flags (kind, id, field, reason);
CREATE TABLE IF NOT EXISTS attachments (kind TEXT, id TEXT, filename TEXT, size INTEGER, data BLOB,
                                        uploaded_by TEXT, ts TEXT);
"""


def _rows(path):
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        return list(csv.DictReader(f))


def scan(db, vault, secrets, kind, item_id, org, name, fields):
    """Flag every field a known secret turns up in; redact it from free text and
    vault the original. `secrets` longest first, so a substring can't split a
    longer one. Mutates `fields`; returns how many were pasted into notes.
    Shared by the importer and by edits in the UI."""
    pasted_hits = 0
    for col, v in fields.items():
        original = v
        for s in secrets:
            if v and s in v:
                pasted = bool(NOTE_FIELD.search(col))
                db.execute("INSERT OR IGNORE INTO flags VALUES (?,?,?,?,?,?)",
                           (kind, item_id, org, name, col,
                            "password pasted in notes" if pasted else "weak: password derived from this field"))
                if pasted:
                    v = v.replace(s, "[withheld]")
                    pasted_hits += 1
        if vault and v != original:
            vault.put(kind, item_id, col, original)  # the whole note, recoverable by reveal
        fields[col] = v
    return pasted_hits


def import_export(export_dir, db_path, passphrase=None):
    """A vendor CSV export, or almanac's own export (same layout plus secrets.csv) -- a dir or a .zip."""
    if zipfile.is_zipfile(export_dir):
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(export_dir) as z:
                z.extractall(tmp)  # extractall drops absolute paths and '..'
            return import_export(tmp, db_path, passphrase)
    export_dir = Path(export_dir)
    db = sqlite3.connect(db_path)
    db.executescript(SCHEMA)
    vault = Vault(db, passphrase) if passphrase else None
    report = {"items": {}, "secrets": 0, "secrets_vaulted": bool(vault)}

    files = {p.stem: _rows(p) for p in sorted(export_dir.glob("*.csv"))
             if p.name not in ("logs.csv", "audit.csv")}
    secrets = set()
    # almanac's own export: every vaulted value by slot, including custom secret
    # fields and the originals of redacted notes, which no column list could know.
    for r in files.pop("flags", []):
        db.execute("INSERT OR IGNORE INTO flags VALUES (?,?,?,?,?,?)",
                   (r["kind"], r["id"], r["org"], r["name"], r["field"], r["reason"]))
    for r in files.pop("secrets", []):
        if len(r["value"]) >= MIN_SCRUB:
            secrets.add(r["value"])
        if vault:
            vault.put(r["kind"], r["id"], r["field"], r["value"])
        report["secrets"] += 1
    for kind, rows in files.items():
        for r in rows:
            for col in SECRET_COLUMNS & r.keys():
                if r[col]:
                    if len(r[col]) >= MIN_SCRUB:
                        secrets.add(r[col])
                    if vault:
                        vault.put(kind, r.get("id", ""), col, r[col])
                    r[col] = ""  # not None: CSV cannot carry the difference, and exports must round-trip
                    report["secrets"] += 1
    secrets = sorted(secrets, key=len, reverse=True)  # longest first, so a substring can't split a longer one

    def scrub(kind, r):
        org = r.get("name", "") if kind == "organizations" else r.get("organization", "")
        scan(db, vault, secrets, kind, r.get("id", ""), org,
             r.get("name") or next((v for c, v in r.items() if c not in ("id", "organization")), ""), r)

    for r in files.pop("organizations", []):
        scrub("organizations", r)
        db.execute("INSERT OR REPLACE INTO orgs VALUES (?,?,?)",
                   (r.pop("id"), r.pop("name"), json.dumps(r)))

    for kind, rows in files.items():
        for r in rows:
            scrub(kind, r)
            item_id, org = r.pop("id", ""), r.pop("organization", "")
            # Core types have `name`; flexible assets lead with their title column.
            name = r.get("name") or next(iter(r.values()), "")
            db.execute("INSERT OR REPLACE INTO items VALUES (?,?,?,?,?)",
                       (kind, item_id, org, name, json.dumps(r)))
            for col in REF_COLUMNS & r.keys():
                for target in filter(None, (t.strip() for t in re.split(r"[,;\n]", r[col] or ""))):
                    db.execute("INSERT INTO refs VALUES (?,?,?,?,NULL)", (kind, item_id, col, target))
        report["items"][kind] = len(rows)
    report["attachments"] = 0
    for f in sorted((export_dir / "attachments").glob("*/*/*")):
        if f.is_file():
            db.execute("INSERT INTO attachments VALUES (?,?,?,?,?,'import',datetime('now'))",
                       (f.parent.parent.name, f.parent.name, f.name, f.stat().st_size, f.read_bytes()))
            report["attachments"] += 1
    report["flags"] = dict(db.execute("SELECT reason, count(*) FROM flags GROUP BY reason"))

    # Resolve names back to configurations in the same org: name first, then hostname.
    db.execute("""
        UPDATE refs SET target_id = (
            SELECT c.id FROM items c, items src
            WHERE c.kind = 'configurations' AND src.kind = refs.kind AND src.id = refs.id
              AND c.org = src.org
              AND (lower(c.name) = lower(refs.target)
                   OR lower(json_extract(c.fields, '$.hostname')) = lower(refs.target))
            LIMIT 1)
        WHERE target_id IS NULL""")
    report["refs_resolved"], report["refs_unresolved"] = db.execute(
        "SELECT count(target_id), count(*) - count(target_id) FROM refs").fetchone()
    db.commit()
    db.close()
    return report


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    use_vault = "--vault" in argv
    argv = [a for a in argv if a != "--vault"]
    if len(argv) != 2:
        sys.exit("usage: almanac-import EXPORT_DIR OUT.db [--vault]")
    print(json.dumps(import_export(*argv, ask_passphrase() if use_vault else None), indent=2))


if __name__ == "__main__":
    main()
