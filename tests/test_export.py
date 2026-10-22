import io
import sqlite3
import zipfile

from almanac.export import export
from almanac.importer import import_export
from almanac.vault import Vault
from test_importer import _csv
from test_roles import site, status  # noqa: F401  (fixture)


def _build(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _csv(src / "organizations.csv", ["id", "name", "quick_notes"], ["1", "Acme", "vip"], ["2", "Other", ""])
    _csv(src / "configurations.csv", ["id", "organization", "name", "notes"],
         ["10", "Acme", "acme-dc", "admin pw is hunter2-SECRET"], ["11", "Other", "other-dc", ""])
    _csv(src / "passwords.csv", ["id", "organization", "name", "password"],
         ["30", "Acme", "acme admin", "hunter2-SECRET"], ["31", "Other", "other admin", "other-SECRET"])
    (src / "attachments" / "configurations" / "10").mkdir(parents=True)
    (src / "attachments" / "configurations" / "10" / "diagram.pdf").write_bytes(b"%PDF-1")
    db = sqlite3.connect(tmp_path / "a.db")
    import_export(src, tmp_path / "a.db", passphrase="pp")
    # Things only almanac has: a custom secret field, an org-level secret, a duplicate filename, a UI item.
    v = Vault(db, "pp")
    v.put("configurations", "10", "ilo", "ilo-SECRET")
    v.put("organizations", "1", "wifi", "wifi-SECRET")
    db.execute("INSERT INTO attachments VALUES ('configurations','10','diagram.pdf',6,?,'alice','now')", (b"%PDF-2",))
    db.execute("""INSERT INTO items VALUES ('printers','p1','Acme','hp','{"name": "hp"}')""")
    db.commit()
    return db, v


def _snapshot(db, v):
    items = sorted(db.execute("SELECT kind, id, org, name, fields FROM items"))
    secrets = sorted((k, i, f, v.value(k, i, f)) for k, i, f in db.execute("SELECT kind, id, field FROM secrets"))
    files = sorted(db.execute("SELECT kind, id, data FROM attachments"))
    orgs = sorted(db.execute("SELECT id, name, fields FROM orgs"))
    flags = sorted(db.execute("SELECT kind, id, org, name, field, reason FROM flags"))
    return items, secrets, files, orgs, flags


def test_round_trip_is_lossless(tmp_path):
    db, v = _build(tmp_path)
    counts = export(db, tmp_path / "out.zip", vault=v)
    assert counts == {"items": 5, "secrets": 5, "attachments": 2}
    import_export(tmp_path / "out.zip", tmp_path / "b.db", passphrase="a different one")
    db2 = sqlite3.connect(tmp_path / "b.db")
    assert _snapshot(db, v) == _snapshot(db2, Vault(db2, "a different one"))
    assert db.execute("SELECT action FROM audit").fetchall() == [("org exported with secrets",)] * 2


def test_scoped_export_holds_only_that_org(tmp_path):
    db, v = _build(tmp_path)
    buf = io.BytesIO()
    export(db, buf, ["Acme"], vault=v)
    z = zipfile.ZipFile(buf)
    everything = b"".join(z.read(n) for n in z.namelist())
    assert b"other" not in everything.lower() and b"wifi-SECRET" in everything
    export(db, buf := io.BytesIO(), ["Acme"])
    assert "secrets.csv" not in zipfile.ZipFile(buf).namelist()


def test_member_export_edit_scan_and_org_secrets(site):
    zipped = site("acme-it", "/export", {"org": "Acme", "secrets": "1"})
    assert zipped.startswith("PK")
    assert status(site, "acme-it", "/export", {"org": "Other"}) == 404
    # Pasting a known password into notes during an edit gets it redacted and vaulted.
    page = site("acme-it", "/item/save", {"kind": "configurations", "id": "10",
                                          "f:name": "acme-dc", "f:notes": "login: shared-SECRET-1 ok"})
    assert "1 known password(s) were pasted" in page and "shared-SECRET-1" not in page
    assert "shared-SECRET-1" in site("acme-it", "/reveal", {"kind": "configurations", "id": "10", "field": "notes"})
    # Org-level secrets live on the org page.
    page = site("acme-it", "/org?org=Acme")
    assert "<h2>Secrets</h2>" in page
    assert status(site, "tech", "/org?org=Nonexistent") == 404
    assert status(site, "acme-it", "/item/new", {"org": "Acme", "kind": "secrets", "name": "x"}) == 200
    assert "Kind must be" in site("acme-it", "/item/new", {"org": "Acme", "kind": "../x", "name": "x"})
