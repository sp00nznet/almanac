import base64
import sqlite3
import threading
import urllib.error
import urllib.request

import pytest

from almanac.importer import import_export
from almanac.server import add_user, serve
from test_importer import _csv


def _get(url, auth=None, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    with urllib.request.urlopen(req) as r:
        return r.read().decode(errors="replace")


def test_auth_reveal_audit_and_escaping(tmp_path):
    _csv(tmp_path / "configurations.csv", ["id", "organization", "name", "notes"],
         ["10", "Acme", "<script>x</script>", "fine"])
    _csv(tmp_path / "passwords.csv", ["id", "organization", "name", "password"],
         ["30", "Acme", "Domain admin", "hunter2-SECRET"])
    db = tmp_path / "a.db"
    import_export(tmp_path, db, passphrase="pp")
    add_user(sqlite3.connect(db), "alice", "pw")

    httpd = serve(db, port=0, passphrase="pp")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        with pytest.raises(urllib.error.HTTPError) as err:
            _get(base + "/")
        assert err.value.code == 401
        with pytest.raises(urllib.error.HTTPError):
            _get(base + "/", auth="alice:wrong")

        page = _get(base + "/org?org=Acme", auth="alice:pw")
        assert "&lt;script&gt;" in page and "<script>x" not in page

        item = _get(base + "/item?kind=passwords&id=30", auth="alice:pw")
        assert "hunter2-SECRET" not in item and "reveal (audited)" in item

        body = b"kind=passwords&id=30&field=password"
        with pytest.raises(urllib.error.HTTPError) as err:
            _get(base + "/reveal", auth="alice:pw", data=body, headers={"Origin": "http://evil.example"})
        assert err.value.code == 403
        assert "hunter2-SECRET" in _get(base + "/reveal", auth="alice:pw", data=body)
        assert "secret revealed" in _get(base + "/audit", auth="alice:pw")
    finally:
        httpd.shutdown()


def test_refuses_offloopback_without_tls(tmp_path):
    with pytest.raises(SystemExit):
        serve(tmp_path / "x.db", host="0.0.0.0", passphrase="pp")
