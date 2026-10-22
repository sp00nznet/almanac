"""Export everything, per org or whole -- complete, unlike the exports
almanac usually migrates from.

The usual vendor export drops document bodies, so leaving costs you your runbooks. The
rule here is the opposite: an export is complete, and the importer takes it back.
Round-tripped in the tests.

Layout, one zip -- the same CSV shape almanac imports, so a human can open it in a
spreadsheet and the same importer reads both:
  organizations.csv, <kind>.csv   id, organization, then every field
  secrets.csv                     kind, id, field, value  (only when asked for)
  attachments/<kind>/<id>/<file>
  flags.csv                       passwords found outside the vault (re-imported: the
                                  notes are already redacted, so a re-scan can't find them)
  audit.csv                       who viewed, revealed and edited what (not re-imported)

Secrets in the clear are the point -- a customer leaving needs their passwords --
so they are opt-in, and the export itself is audited per org. Protecting the zip
is the receiver's job, the same as for any vendor export.
"""
import csv
import io
import json
import sqlite3
import sys
import zipfile

from .vault import Vault, ask_passphrase, audit

# Kinds the export layout reserves for itself; the UI refuses to create items of these kinds.
RESERVED_KINDS = {"organizations", "secrets", "flags", "audit", "logs"}


def _csv(rows, header):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def export(db, out, orgs=None, vault=None, user="cli"):
    """Write a zip to `out` (path or file object). orgs=None means every org.
    With a vault, secrets.csv holds every secret in scope, decrypted."""
    all_orgs = [o for o, in db.execute("SELECT DISTINCT org FROM items UNION SELECT name FROM orgs")]
    scope = set(all_orgs if orgs is None else orgs)
    counts = {"items": 0, "secrets": 0, "attachments": 0}

    def org_of(kind, id):
        q = ("SELECT name FROM orgs WHERE id=?" if kind == "organizations"
             else "SELECT org FROM items WHERE kind=? AND id=?")
        row = db.execute(q, (id,) if kind == "organizations" else (kind, id)).fetchone()
        return row[0] if row else None

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        known = {n: (i, json.loads(f)) for i, n, f in db.execute("SELECT id, name, fields FROM orgs")}
        org_rows = [(known.get(o, (o, {}))[0], o, known.get(o, (o, {}))[1]) for o in sorted(scope)]
        cols = list(dict.fromkeys(k for _, _, f in org_rows for k in f))
        z.writestr("organizations.csv", _csv(
            ([i, n, *(f.get(c) for c in cols)] for i, n, f in org_rows), ["id", "name", *cols]))

        for kind, in db.execute("SELECT DISTINCT kind FROM items ORDER BY kind").fetchall():
            rows = [(i, o, json.loads(f)) for i, o, f in db.execute(
                "SELECT id, org, fields FROM items WHERE kind=? ORDER BY org, id", (kind,)) if o in scope]
            if rows:
                cols = list(dict.fromkeys(k for _, _, f in rows for k in f))
                z.writestr(f"{kind}.csv", _csv(
                    ([i, o, *(f.get(c) for c in cols)] for i, o, f in rows), ["id", "organization", *cols]))
                counts["items"] += len(rows)

        if vault:
            slots = [s for s in db.execute("SELECT kind, id, field FROM secrets ORDER BY kind, id, field")
                     if org_of(s[0], s[1]) in scope]
            z.writestr("secrets.csv", _csv(((k, i, f, vault.value(k, i, f)) for k, i, f in slots),
                                           ["kind", "id", "field", "value"]))
            counts["secrets"] = len(slots)

        seen = set()
        for n, kind, id, filename, data in db.execute(
                "SELECT rowid, kind, id, filename, data FROM attachments ORDER BY rowid"):
            if org_of(kind, id) in scope:
                path = f"attachments/{kind}/{id}/{filename}"
                if path in seen:  # two uploads with one name: keep both
                    path = f"attachments/{kind}/{id}/{n}-{filename}"
                seen.add(path)
                z.writestr(path, data, compress_type=zipfile.ZIP_STORED)  # mostly installers and PDFs: already compressed
                counts["attachments"] += 1

        z.writestr("flags.csv", _csv(
            db.execute(f"SELECT kind, id, org, name, field, reason FROM flags WHERE org IN "
                       f"({','.join('?' * len(scope)) or 'NULL'})", tuple(scope)),
            ["kind", "id", "org", "name", "field", "reason"]))

        z.writestr("audit.csv", _csv(
            (r for r in db.execute("SELECT ts, user, action, kind, id, field FROM audit ORDER BY rowid")
             if r[3] and org_of(r[3], r[4]) in scope),
            ["ts", "user", "action", "kind", "id", "field"]))

    for o in sorted(scope):
        audit(db, user, "org exported with secrets" if vault else "org exported", "organizations",
              known.get(o, (o,))[0])
    return counts


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="almanac-export")
    ap.add_argument("db")
    ap.add_argument("out", help="zip to write")
    ap.add_argument("--org", action="append", help="limit to this org (repeatable); default every org")
    ap.add_argument("--secrets", action="store_true", help="include every secret, decrypted")
    a = ap.parse_args(argv)
    db = sqlite3.connect(a.db)
    vault = Vault(db, ask_passphrase()) if a.secrets else None
    print(json.dumps(export(db, a.out, a.org, vault), indent=2))


if __name__ == "__main__":
    main()
