import sqlite3
import threading
import urllib.error
from urllib.parse import urlencode

import pytest

from almanac.importer import import_export
from almanac.server import add_user, serve
from test_importer import _csv
from test_server import _get


@pytest.fixture
def site(tmp_path):
    _csv(tmp_path / "configurations.csv", ["id", "organization", "name"],
         ["10", "Acme", "acme-dc"], ["11", "Other", "other-dc"])
    _csv(tmp_path / "passwords.csv", ["id", "organization", "name", "password"],
         ["30", "Acme", "acme admin", "shared-SECRET-1"], ["31", "Other", "other admin", "shared-SECRET-1"])
    db = tmp_path / "a.db"
    import_export(tmp_path, db, passphrase="pp")
    con = sqlite3.connect(db)
    add_user(con, "boss", "pw", "admin")
    add_user(con, "tech", "pw", "staff")
    add_user(con, "acme-it", "pw", "member", ["Acme"])
    add_user(con, "gone", "pw", "disabled")
    httpd = serve(db, port=0, passphrase="pp")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def get(user, path, data=None, **kw):
        body = urlencode(data).encode() if isinstance(data, dict) else data
        return _get(base + path, auth=f"{user}:pw", data=body, **kw)
    yield get
    httpd.shutdown()


def status(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return 200
    except urllib.error.HTTPError as err:
        return err.code


def test_member_sees_only_their_org(site):
    assert "Acme" in site("acme-it", "/") and "Other" not in site("acme-it", "/")
    assert status(site, "acme-it", "/item?kind=configurations&id=11") == 404
    assert status(site, "acme-it", "/org?org=Other") == 404
    assert status(site, "acme-it", "/reveal", {"kind": "passwords", "id": "31", "field": "password"}) == 404
    assert "other-dc" not in site("acme-it", "/search?q=dc")
    # The same password at two customers must not be disclosed to either customer.
    assert "0 secret values" in site("acme-it", "/reuse")
    assert "1 secret values" in site("tech", "/reuse")
    assert status(site, "acme-it", "/users") == 404


def test_member_can_work_in_their_org(site):
    site("acme-it", "/item/save", {"kind": "configurations", "id": "10", "f:name": "acme-dc01",
                                   "newfield": "notes", "newvalue": "rebuilt"})
    page = site("acme-it", "/item?kind=configurations&id=10")
    assert "acme-dc01" in page and "rebuilt" in page
    site("acme-it", "/secret/set", {"kind": "configurations", "id": "10", "field": "ilo", "value": "ilo-SECRET"})
    assert "ilo-SECRET" in site("acme-it", "/reveal", {"kind": "configurations", "id": "10", "field": "ilo"})
    assert "acme printer" in site("acme-it", "/item/new", {"org": "Acme", "kind": "printers", "name": "acme printer"})
    assert status(site, "acme-it", "/item/new", {"org": "Other", "kind": "x", "name": "y"}) == 404
    assert status(site, "acme-it", "/item/save", {"kind": "configurations", "id": "11", "f:name": "pwned"}) == 404

    boundary = "XyZ"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=kind\r\n\r\nconfigurations\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=id\r\n\r\n10\r\n"
            f'--{boundary}\r\nContent-Disposition: form-data; name=file; filename="../evil.html"\r\n'
            f"Content-Type: text/html\r\n\r\n<script>x</script>\r\n--{boundary}--\r\n").encode()
    page = site("acme-it", "/upload", body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    assert "evil.html" in page and "../" not in page
    audit = site("acme-it", "/audit")
    assert "file uploaded" in audit and "secret set" in audit


def test_staff_admin_disabled(site):
    assert "Other" in site("tech", "/") and status(site, "tech", "/users") == 404
    assert status(site, "gone", "/") == 401
    site("boss", "/users/save", {"name": "other-it", "password": "pw", "role": "member", "org": "Other"})
    assert "other-dc" in site("other-it", "/search?q=dc") and "acme-dc" not in site("other-it", "/search?q=dc")
