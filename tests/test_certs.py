import json
import socket
import sqlite3
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from almanac.certs import analyse, expiring, run
from almanac.importer import import_export
from test_importer import _csv

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def _cert(cn, issuer_key, issuer_cn, key, days, sans=(), not_after=None):
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - timedelta(days=400))
         .not_valid_after(not_after or NOW + timedelta(days=days)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def test_analyse_flags_what_matters():
    ca, inter, leaf = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    intermediate = _cert("Acme Issuing CA", ca, "Acme Root", inter, 10)
    good = _cert("www.acme.com", inter, "Acme Issuing CA", leaf, 200, ["www.acme.com", "*.acme.com"])
    r = analyse("mail.acme.com", 443, [good, intermediate], NOW)
    assert "intermediate 'Acme Issuing CA' expires first" in r["issues"] and "mismatch" not in r["issues"]
    assert r["chain_expires"].startswith("2026-10-12") and r["valid_until"].startswith("2027-04-20")

    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    old = _cert("old.acme.com", weak, "old.acme.com", weak, -5)
    r = analyse("intranet.acme.com", 8443, [old], NOW)
    for issue in ("EXPIRED 5 days ago", "RSA key 1024 bits", "self-signed", "name mismatch: serves old.acme.com"):
        assert issue in r["issues"]
    assert r["host"] == "intranet.acme.com:8443"
    assert "mismatch" not in analyse("10.0.0.5", 443, [old], NOW)["issues"]  # IPs aren't name-checked


@pytest.fixture
def tls_server(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    # real clock, not NOW: the sweep judges a live server against today
    cert = _cert("localhost", key, "localhost", key, 0, ["localhost"],
                 not_after=datetime.now(timezone.utc) + timedelta(days=12))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return  # socket closed by teardown
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()


def test_sweep_stores_into_the_org_and_updates_imported_records(tmp_path, tls_server):
    port = tls_server
    _csv(tmp_path / "ssl-certificates.csv", ["id", "organization", "name", "host", "valid_until"],
         ["50", "Acme", "intranet", f"localhost:{port}", "2018-01-01 00:00:00 UTC"])
    _csv(tmp_path / "domains.csv", ["id", "organization", "name", "expires_on"],
         ["60", "Acme", "acme.invalid", "2026-10-20 00:00:00 UTC"])
    import_export(tmp_path, tmp_path / "a.db")
    db = sqlite3.connect(tmp_path / "a.db")

    with pytest.raises(ValueError):
        run(db, targets=["127.0.0.1"])  # no --org: refuse to guess the customer
    r = run(db, org="Lab", targets=[f"127.0.0.1:{port}", "127.0.0.1:1"], timeout=2)
    assert r["probed"] == 4 and r["found"] == 2  # imported host + target found; domain + closed port not
    f = json.loads(db.execute("SELECT fields FROM items WHERE id='50'").fetchone()[0])
    assert f["host"] == f"localhost:{port}" and f["source"] == "cert sweep" and "self-signed" in f["issues"]
    assert f["valid_until"] > "2026"  # the 2017 hand-entered date is replaced by what was actually served
    assert db.execute("SELECT org FROM items WHERE id=?", (f"cert-127.0.0.1-{port}",)).fetchone() == ("Lab",)
    soon = [(kind, org) for left, org, kind, *_ in expiring(db, 30)]
    assert ("ssl-certificates", "Lab") in soon and ("domains", "Acme") in soon


def test_exit_code_pages_only_for_live_certs(tmp_path, tls_server):
    from almanac.certs import main
    _csv(tmp_path / "domains.csv", ["id", "organization", "name", "expires_on"],
         ["60", "Acme", "acme.invalid", "2018-01-01 00:00:00 UTC"])  # long dead, hand-entered
    import_export(tmp_path, tmp_path / "a.db")
    args = [str(tmp_path / "a.db"), "--org", "Lab", "--only-targets", "--target", f"127.0.0.1:{tls_server}"]
    with pytest.raises(SystemExit) as code:
        main(args + ["--warn", "30"])  # served cert has 12 days left
    assert code.value.code == 2
    with pytest.raises(SystemExit) as code:
        main(args + ["--warn", "5"])  # the stale domain alone must not page anyone
    assert code.value.code == 0
