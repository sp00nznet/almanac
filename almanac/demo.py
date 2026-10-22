"""A demo database of made-up customers, for a first look and for the README screenshots.

It writes a small CSV export -- the same layout `almanac-import` reads -- and imports it
with the vault on, so the demo goes through the real importer: a password pasted in
notes gets redacted and flagged, a reused password shows on /reuse, references resolve.
Every name here is fictional.

    almanac-demo demo.db        # vault passphrase "demo", admin login demo / demo
"""
import csv
import sqlite3
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

from .importer import import_export
from .server import add_user

PASSPHRASE = "demo"


def _days(n):
    return f"{date.today() + timedelta(days=n)} 00:00:00 UTC"


DATA = {
    "organizations": (["id", "name", "short_name", "Quick Notes"], [
        ["1", "Harbor Dental Group", "HDG", "Three clinics. Front desk opens 7:30, patch after 18:00."],
        ["2", "Kestrel Logistics", "KES", "Warehouse Wi-Fi is the usual ticket."],
        ["3", "Maple Street Law", "MSL", "Partners want MFA prompts kept to a minimum."],
    ]),
    "configurations": (["id", "organization", "name", "hostname", "configuration_type",
                        "operating_system", "ip", "notes"], [
        ["10", "Harbor Dental Group", "HDG-DC01", "hdg-dc01", "Server", "Windows Server 2022", "10.20.0.10", ""],
        ["11", "Harbor Dental Group", "HDG-DC02", "hdg-dc02", "Server", "Windows Server 2022", "10.20.0.11", ""],
        ["12", "Harbor Dental Group", "HDG-FW", "hdg-fw", "Firewall", "FortiOS 7.4", "10.20.0.1", ""],
        ["13", "Harbor Dental Group", "Front desk 1", "hdg-fd01", "Workstation", "Windows 11 Pro", "10.20.1.21", ""],
        ["14", "Harbor Dental Group", "Imaging PC", "hdg-img01", "Workstation", "", "10.20.1.40",
         "Vendor remotes in for X-ray software updates."],
        ["20", "Kestrel Logistics", "KES-HV01", "kes-hv01", "Server", "Windows Server 2019", "10.30.0.5", ""],
        ["21", "Kestrel Logistics", "KES-SW-CORE", "kes-sw-core", "Switch", "", "10.30.0.2", ""],
        ["22", "Kestrel Logistics", "Warehouse AP 3", "kes-ap03", "Access Point", "", "10.30.5.13", ""],
        ["30", "Maple Street Law", "MSL-NAS", "msl-nas", "NAS", "DSM 7.2", "10.40.0.20", ""],
    ]),
    "active-directory": (["id", "organization", "AD Full Name", "AD Servers", "Notes"], [
        ["40", "Harbor Dental Group", "hdg.local", "HDG-DC01, HDG-DC02", "FSMO roles on DC01."],
    ]),
    "passwords": (["id", "organization", "name", "username", "url", "password", "notes"], [
        ["50", "Harbor Dental Group", "Domain admin", "hdg\\itadmin", "", "Tide-Lantern-4417", ""],
        ["51", "Harbor Dental Group", "Firewall admin", "admin", "https://10.20.0.1", "Tide-Lantern-4417", ""],
        ["52", "Kestrel Logistics", "Hyper-V host local admin", "Administrator", "", "Gravel!Orbit-82", ""],
        ["53", "Kestrel Logistics", "Warehouse Wi-Fi", "", "", "forklift-season-2026", ""],
        ["54", "Maple Street Law", "NAS admin", "msladmin", "https://10.40.0.20:5001", "Quill&Ledger-903", ""],
    ]),
    "applications": (["id", "organization", "Name", "Vendor contact", "Other Notes"], [
        ["60", "Harbor Dental Group", "Practice management", "support line in the vendor portal",
         "Server login is itadmin / Tide-Lantern-4417 until we move it to the vault"],
        ["61", "Maple Street Law", "Document management", "account rep", "Backs up to MSL-NAS nightly."],
    ]),
    "domains": (["id", "organization", "name", "registrar", "expires_on"], [
        ["70", "Harbor Dental Group", "harbordental.example", "", _days(19)],
        ["71", "Kestrel Logistics", "kestrel-logistics.example", "", _days(240)],
        ["72", "Maple Street Law", "maplestreetlaw.example", "", _days(-3)],
    ]),
    "ssl-certificates": (["id", "organization", "name", "host", "valid_until"], [
        ["80", "Harbor Dental Group", "Patient portal", "portal.harbordental.example", _days(9)],
        ["81", "Maple Street Law", "Client file share", "files.maplestreetlaw.example", _days(75)],
    ]),
}


def build(db_path):
    with tempfile.TemporaryDirectory() as tmp:
        for kind, (header, rows) in DATA.items():
            with open(Path(tmp) / f"{kind}.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(header)
                w.writerows(rows)
        report = import_export(tmp, db_path, PASSPHRASE)
    db = sqlite3.connect(db_path)
    add_user(db, "demo", "demo")
    add_user(db, "kestrel-it", "demo", "member", ["Kestrel Logistics"])
    return report


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1 or Path(argv[0]).exists():
        sys.exit("usage: almanac-demo NEW.db   (refuses to touch an existing file)")
    build(argv[0])
    print(f"wrote {argv[0]}. Run:  ALMANAC_PASSPHRASE={PASSPHRASE} almanac-server {argv[0]}\n"
          "then open http://127.0.0.1:8771/ and log in as demo / demo")


if __name__ == "__main__":
    main()
