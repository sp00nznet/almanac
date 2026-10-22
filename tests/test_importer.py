import csv
import sqlite3

from almanac.importer import import_export


def _csv(path, header, *rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def test_import_withholds_secrets_and_resolves_refs(tmp_path):
    _csv(tmp_path / "organizations.csv", ["id", "name"], ["1", "Acme"], ["2", "Other"])
    _csv(tmp_path / "configurations.csv", ["id", "organization", "name", "hostname"],
         ["10", "Acme", "DC 1", "ACME-DC01"], ["11", "Other", "DC02", "dc02"])
    _csv(tmp_path / "active-directory.csv", ["id", "organization", "AD Full Name", "AD Servers"],
         ["20", "Acme", "acme.local", "acme-dc01, DC02"])  # DC02 belongs to another org
    _csv(tmp_path / "passwords.csv", ["id", "organization", "name", "username", "password"],
         ["30", "Acme", "Domain admin", "administrator", "hunter2-SECRET"])
    _csv(tmp_path / "applications.csv", ["id", "organization", "Name", "Other Notes"],
         ["40", "Acme", "QuickBooks", "admin login is hunter2-SECRET, do not share"])
    _csv(tmp_path / "logs.csv", ["created_at", "action"], ["2017-01-01", "Password accessed"])

    db = tmp_path / "out.db"
    report = import_export(tmp_path, db)

    assert report["secrets"] == 1
    assert report["flags"] == {"password pasted in notes": 1}
    assert b"hunter2-SECRET" not in db.read_bytes()
    assert report["refs_resolved"] == 1 and report["refs_unresolved"] == 1
    assert "logs" not in report["items"]
    con = sqlite3.connect(db)
    assert con.execute("SELECT target_id FROM refs WHERE target='acme-dc01'").fetchone() == ("10",)
    assert con.execute("SELECT name FROM items WHERE kind='passwords'").fetchone() == ("Domain admin",)
    assert con.execute("SELECT name FROM flags").fetchone() == ("QuickBooks",)  # the title, not the id
