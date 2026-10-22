"""#18: certificate expiry tracking, as an almanac feed.

Enterprise certificate managers are six-figure products; the free tier of this problem is a
spreadsheet and an outage. A real-world export we migrated held 59 hand-pasted certificates,
the newest long expired. So: connect, handshake, read the chain, hang up, and
write what was seen into the org's ssl-certificates.

Targets, from three places:
  * almanac itself -- every ssl-certificates `host` and every domain (as :443).
    These carry their org.
  * --target host[:port], repeatable           -- needs --org
  * --sweep CIDR, across the common TLS ports  -- needs --org. Discovery is the
    point: the cert that causes the outage is the one nobody wrote down.

Verification is OFF on purpose -- the invalid ones are the ones worth seeing.
Each result also gets checked for what a parsed certificate gives for free: expiry,
an intermediate expiring first, SHA-1/MD5, RSA under 2048, self-signed, and a name
that doesn't match the host serving it.

Exit code 2 when a certificate a live endpoint is serving right now is inside
--warn days, so Task Scheduler or the monitoring of your choice can alert on it.
Hand-entered dates nothing has confirmed go on /expiring, not in the exit code. ponytail: no mailer -- email/webhook
when someone runs this unattended and wants a push instead of a check.
"""
import ipaddress
import json
import socket
import sqlite3
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .importer import SCHEMA as ITEMS_SCHEMA
from .vault import SCHEMA as VAULT_SCHEMA, audit

PORTS = (443, 8443, 8006, 9443, 636, 993, 995, 465, 5986)  # 8006: Proxmox
FMT = "%Y-%m-%d %H:%M:%S UTC"  # the import format's, so imported and swept certs sort together


def _cn(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def _org(name):
    attrs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return attrs[0].value if attrs else ""


def _sans(cert):
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def _name_matches(host, names):
    host = host.lower().rstrip(".")
    for n in (n.lower() for n in names):
        if n == host or (n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]):
            return True
    return False


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def probe(host, port=443, timeout=3.0):
    """Handshake, read the chain unverified, hang up. None if nothing speaks TLS there."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=None if _is_ip(host) else host) as tls:
                leaf = tls.getpeercert(binary_form=True)
                chain = tls.get_unverified_chain() if hasattr(tls, "get_unverified_chain") else []
    except (OSError, ssl.SSLError, ValueError):
        return None
    ders = [c if isinstance(c, bytes) else c.public_bytes(ssl._ssl.ENCODING_DER) for c in chain] or [leaf]
    return analyse(host, port, [x509.load_der_x509_certificate(d) for d in ders])


def analyse(host, port, chain, now=None):
    """Fields for an ssl-certificates item, plus the issues worth a human's attention."""
    now = now or datetime.now(timezone.utc)
    cert = chain[0]
    until = cert.not_valid_after_utc
    sans = _sans(cert)
    issues = []
    days = (until - now).days
    if days < 0:
        issues.append(f"EXPIRED {-days} days ago")
    elif days <= 30:
        issues.append(f"expires in {days} days")
    first = min(chain[1:], key=lambda c: c.not_valid_after_utc, default=None)
    if first is not None and first.not_valid_after_utc < until:
        issues.append(f"intermediate '{_cn(first.subject)}' expires first, "
                      f"{first.not_valid_after_utc:%Y-%m-%d}")
    algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "none"
    if algo in ("sha1", "md5"):
        issues.append(f"weak signature: {algo}")
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
        issues.append(f"RSA key {key.key_size} bits")
    if cert.issuer == cert.subject:
        issues.append("self-signed")
    if not _is_ip(host) and not _name_matches(host, sans or [_cn(cert.subject)]):
        issues.append(f"name mismatch: serves {', '.join(sans) or _cn(cert.subject)}")
    return {
        "host": f"{host}:{port}",
        "name": _cn(cert.subject) or host,
        "issued_by": _cn(cert.issuer),
        "issuer_organization": _org(cert.issuer),
        "valid_from": cert.not_valid_before_utc.strftime(FMT),
        "valid_until": until.strftime(FMT),
        "subject_alternative_name": ", ".join(sans),
        "signature_algorithm": algo,
        "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "chain_expires": min(c.not_valid_after_utc for c in chain).strftime(FMT),
        "issues": "; ".join(issues),
        "source": "cert sweep",
        "last_seen": now.strftime(FMT),
    }


def targets_from_almanac(db):
    """(org, host, port) for every ssl-certificates host and every domain already documented."""
    out = set()
    for org, f in db.execute("SELECT org, fields FROM items WHERE kind='ssl-certificates'"):
        h = (json.loads(f).get("host") or "").strip().removeprefix("https://").split("/")[0]
        if h:
            host, _, port = h.partition(":")
            out.add((org, host, int(port) if port.isdigit() else 443))
    for org, name in db.execute("SELECT org, name FROM items WHERE kind='domains'"):
        if name and "." in name:
            out.add((org, name.strip().lower(), 443))
    return sorted(out)


def store(db, org, result):
    """Upsert into the org's ssl-certificates, matched on host (host:port, or bare host for 443)."""
    host, _, port = result["host"].rpartition(":")
    keys = {result["host"].lower()} | ({host.lower()} if port == "443" else set())
    for id, f in db.execute("SELECT id, fields FROM items WHERE kind='ssl-certificates' AND org=?", (org,)).fetchall():
        fields = json.loads(f)
        if (fields.get("host") or "").strip().lower() in keys:
            fields.update({k: v for k, v in result.items() if k != "host"})  # keep their spelling of host
            db.execute("UPDATE items SET fields=? WHERE kind='ssl-certificates' AND id=?", (json.dumps(fields), id))
            break
    else:
        id = "cert-" + result["host"].replace(":", "-")
        db.execute("INSERT OR REPLACE INTO items VALUES ('ssl-certificates',?,?,?,?)",
                   (id, org, f"{result['name']} ({result['host']})", json.dumps(result)))
    audit(db, "cert sweep", "certificate seen", "ssl-certificates", id)


def run(db, org=None, targets=(), sweep=None, ports=PORTS, from_almanac=True, workers=128, timeout=3.0):
    db.executescript(ITEMS_SCHEMA + VAULT_SCHEMA)
    todo = targets_from_almanac(db) if from_almanac else []
    if (targets or sweep) and not org:
        raise ValueError("--target and --sweep need --org: which customer do these belong to?")
    for t in targets:
        host, _, port = t.partition(":")
        todo.append((org, host, int(port) if port else 443))
    if sweep:
        todo += [(org, str(ip), p) for ip in ipaddress.ip_network(sweep, strict=False).hosts() for p in ports]
    with ThreadPoolExecutor(workers) as pool:
        results = list(pool.map(lambda t: (t[0], probe(t[1], t[2], timeout)), todo))
    found = [(o, r) for o, r in results if r]
    for o, r in found:
        store(db, o, r)
    db.commit()
    return {"probed": len(todo), "found": len(found), "results": found}


def expiring(db, days, where="1", args=()):
    """(days left, org, kind, id, name, date) for certs and domains inside `days`, soonest first."""
    now = datetime.now(timezone.utc)
    out = []
    for kind, field in (("ssl-certificates", "valid_until"), ("domains", "expires_on")):
        for id, org, name, f in db.execute(
                f"SELECT id, org, name, fields FROM items WHERE kind=? AND {where}", (kind, *args)):
            date = (json.loads(f).get(field) or "")[:10]
            try:
                left = (datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc) - now).days
            except ValueError:
                continue
            if left <= days:
                out.append((left, org, kind, id, name, date))
    return sorted(out)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="almanac-sweep-certs")
    ap.add_argument("db")
    ap.add_argument("--org", help="org for --target / --sweep results")
    ap.add_argument("--target", action="append", default=[], help="host[:port], repeatable")
    ap.add_argument("--sweep", metavar="CIDR", help=f"probe every address on ports {','.join(map(str, PORTS))}")
    ap.add_argument("--only-targets", action="store_true", help="skip hosts already documented in almanac")
    ap.add_argument("--warn", type=int, default=30, help="exit 2 if anything expires within this many days")
    a = ap.parse_args(argv)
    db = sqlite3.connect(a.db)
    t = time.time()
    try:
        r = run(db, a.org, a.target, a.sweep, from_almanac=not a.only_targets)
    except ValueError as err:
        sys.exit(str(err))
    print(f"probed {r['probed']} endpoints in {time.time() - t:.0f}s, {r['found']} speak TLS")
    now = datetime.now(timezone.utc)
    live = []
    for o, res in sorted(r["results"], key=lambda x: x[1]["valid_until"]):
        left = (datetime.strptime(res["valid_until"], FMT).replace(tzinfo=timezone.utc) - now).days
        live += [res] if left <= a.warn else []
        print(f"  {res['host']:28} {res['valid_until'][:10]}  {o[:20]:20} {res['name'][:36]:36} {res['issues']}")
    stale = [x for x in expiring(db, a.warn) if x[2] == "domains" or not json.loads(db.execute(
        "SELECT fields FROM items WHERE kind=? AND id=?", (x[2], x[3])).fetchone()[0]).get("last_seen")]
    if stale:
        print(f"{len(stale)} documented certificates/domains are past due or within {a.warn} days by a "
              f"hand-entered date nothing has confirmed -- see /expiring in the UI")
    # Only what a live endpoint is serving right now pages anyone. Hand-entered dates rot
    # (the migrated export's lesson), and a check that always fails is a check nobody reads.
    sys.exit(2 if live else 0)


if __name__ == "__main__":
    main()
