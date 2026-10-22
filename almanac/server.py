"""almanac web UI: orgs, items, search, editing, uploads, secret reveal, reports.

Stdlib http.server, server-rendered HTML, like lineage. Unlike lineage it has
authentication from day one, because it serves passwords:
  * HTTP Basic against a users table (scrypt hashes). Basic sends the password
    on every request, so off-loopback it REFUSES to start without TLS.
  * Every secret reveal, item view, edit and upload is written to the audit table.
  * Imported data and uploads are untrusted: everything rendered goes through
    html.escape, and files are only ever served as downloads.

Roles -- the MSP shape:
  admin   your employees who run it: every org, plus /users.
  staff   your employees: every org, read and write.
  member  a customer's own IT person: only the orgs in `members`, read and write
          there -- reveal, edit, set secrets, upload. Can see who looked at them.
  disabled  offboarded; login refused, history kept.
Anything a user cannot see is a 404, not a 403: a member cannot probe which
other customers exist.
"""
import hashlib
import hmac
import html
import io
import ipaddress
import json
import os
import re
import sqlite3
import ssl
import sys
import threading
import uuid
from base64 import b64decode
from collections import namedtuple
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlparse

from .certs import expiring
from .export import RESERVED_KINDS, export
from .importer import MIN_SCRUB, scan
from .importer import SCHEMA as ITEMS_SCHEMA
from .vault import Vault, ask_passphrase, audit, reuse

SCHEMA = """
CREATE TABLE IF NOT EXISTS users   (name TEXT PRIMARY KEY, salt BLOB, hash BLOB, role TEXT DEFAULT 'admin');
CREATE TABLE IF NOT EXISTS members (user TEXT, org TEXT, PRIMARY KEY (user, org));
"""
ROLES = ("admin", "staff", "member", "disabled")
MAX_UPLOAD = 25 * 1024 * 1024
User = namedtuple("User", "name role orgs")  # orgs: None = every org
e = html.escape


def _hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def init(db):
    db.executescript(ITEMS_SCHEMA + SCHEMA)
    if "role" not in [c[1] for c in db.execute("PRAGMA table_info(users)")]:
        # Users from before roles existed had full access; keep it that way.
        db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'admin'")


def add_user(db, name, password=None, role="admin", orgs=None):
    """Create or update a user. password=None keeps the existing one; orgs=None keeps memberships."""
    init(db)
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if password:
        salt = os.urandom(16)
        db.execute("""INSERT INTO users VALUES (?,?,?,?) ON CONFLICT(name)
                      DO UPDATE SET salt=excluded.salt, hash=excluded.hash, role=excluded.role""",
                   (name, salt, _hash(password, salt), role))
    elif not db.execute("UPDATE users SET role=? WHERE name=?", (role, name)).rowcount:
        raise ValueError("a new user needs a password")
    if orgs is not None:
        db.execute("DELETE FROM members WHERE user=?", (name,))
        db.executemany("INSERT INTO members VALUES (?,?)", [(name, o) for o in orgs])
    db.commit()


# Basic auth re-sends the password on every request, and scrypt is slow on purpose.
# Remember passwords already verified, as an HMAC under a per-process key, keyed by
# the stored hash -- a password change or a restart invalidates the entry.
_PROCESS_KEY = os.urandom(32)
_verified = {}


def check_user(db, name, password):
    row = db.execute("SELECT salt, hash, role FROM users WHERE name=?", (name,)).fetchone()
    if not row or row[2] == "disabled":
        return None
    tag = hmac.new(_PROCESS_KEY, password.encode(), hashlib.sha256).digest()
    cached = _verified.get((name, row[1]))
    if not (cached and hmac.compare_digest(cached, tag)):
        if not hmac.compare_digest(_hash(password, row[0]), row[1]):
            return None
        _verified[(name, row[1])] = tag
    orgs = None if row[2] in ("admin", "staff") else {
        o for o, in db.execute("SELECT org FROM members WHERE user=?", (name,))}
    return User(name, row[2], orgs)


def can(user, org):
    return user.orgs is None or org in user.orgs


def _q(**kw):
    return urlencode(kw)


def page(title, body, user=None):
    nav = '<a href="/users">users</a>' if user and user.role == "admin" else ""
    who = f'<span class=who>{e(user.name)} · {e(user.role)}</span>' if user else ""
    return f"""<!doctype html><meta charset=utf-8><title>{e(title)} · almanac</title>
<meta name=viewport content="width=device-width,initial-scale=1"><style>
:root{{--bg:#fff;--fg:#1d232b;--mute:#5f6b78;--line:#dde2e8;--soft:#f4f6f8;--accent:#2457c5}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14181d;--fg:#e3e7ec;--mute:#93a0ae;--line:#2c333b;--soft:#1c2228;--accent:#7aa5ff}}}}
body{{font:14px/1.5 system-ui,sans-serif;margin:0;background:var(--bg);color:var(--fg)}}
main{{padding:1.5em;max-width:72em}}a{{color:var(--accent)}}h1{{margin:.2em 0 .6em;font-size:1.6em}}
h2{{font-size:1.05em;margin:1.4em 0 .3em;color:var(--mute);text-transform:uppercase;letter-spacing:.04em}}
nav{{display:flex;flex-wrap:wrap;gap:.3em 1.2em;align-items:center;padding:.7em 1.5em;background:var(--soft);border-bottom:1px solid var(--line)}}
nav b{{margin-right:.6em}}nav a{{text-decoration:none}}nav .who{{margin-left:auto;color:var(--mute)}}
table{{border-collapse:collapse}}td,th{{border-bottom:1px solid var(--line);padding:.35em .7em;text-align:left;vertical-align:top}}
th{{background:var(--soft)}}td{{white-space:pre-wrap}}code{{background:var(--soft);padding:0 .3em;border-radius:3px}}
input,textarea,button{{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:.2em .5em}}
button,input[type=submit]{{background:var(--soft);cursor:pointer}}textarea{{width:min(40em,100%);height:3em}}form{{margin:.3em 0}}</style>
<nav><b>almanac</b><a href="/">orgs</a><a href="/flags">flags</a><a href="/expiring">expiring</a><a href="/reuse">reuse</a><a href="/audit">audit</a>{nav}
<form action=/search style=display:inline><input name=q placeholder=search></form>{who}</nav>
<main><h1>{e(title)}</h1>{body}</main>"""


def table(headers, rows):
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    return f"<table><tr>{head}</tr>" + "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</table>"


def item_link(kind, id, name, label=None):
    """Link to an item -- or, for org-level secrets/audit rows, to the org page (name = org name)."""
    href = f"/org?{_q(org=name)}" if kind == "organizations" else f"/item?{_q(kind=kind, id=id)}"
    return f'<a href="{href}">{e(label or name or id)}</a>'


def hidden(**kw):
    return "".join(f'<input type=hidden name="{e(k)}" value="{e(v)}">' for k, v in kw.items())


class App:
    def __init__(self, db, vault):
        self.db, self.vault = db, vault
        self.lock = threading.Lock()  # ponytail: one sqlite connection, global lock; per-thread connections if it ever gets busy

    # -- scoping: every read and write goes through these ---------------------
    def org_of(self, kind, id):
        if kind == "organizations":
            row = self.db.execute("SELECT name FROM orgs WHERE id=?", (id,)).fetchone()
        else:
            row = self.db.execute("SELECT org FROM items WHERE kind=? AND id=?", (kind, id)).fetchone()
        return row[0] if row else None

    def visible(self, user, kind, id):
        org = self.org_of(kind, id)
        return org is not None and can(user, org)

    def scope(self, user, col="org"):
        if user.orgs is None:
            return "1", ()
        return f"{col} IN ({','.join('?' * len(user.orgs)) or 'NULL'})", tuple(user.orgs)

    def _name(self, kind, id):
        if kind == "organizations":
            row = self.db.execute("SELECT name FROM orgs WHERE id=?", (id,)).fetchone()
        else:
            row = self.db.execute("SELECT name FROM items WHERE kind=? AND id=?", (kind, id)).fetchone()
        return row[0] if row else id

    def org_id(self, org):
        """The orgs row backing an org name; created on first need (orgs made in the UI have none)."""
        row = self.db.execute("SELECT id FROM orgs WHERE name=?", (org,)).fetchone()
        if row:
            return row[0]
        id = uuid.uuid4().hex[:12]
        self.db.execute("INSERT INTO orgs VALUES (?,?,'{}')", (id, org))
        return id

    def org_secrets(self, org):
        """Plaintext of every secret in one org, longest first, for scanning edits. Not audited
        per value: nothing is shown to anyone, and what the scan finds is flagged."""
        slots = [s for s in self.db.execute("SELECT kind, id, field FROM secrets").fetchall()
                 if self.org_of(s[0], s[1]) == org]
        values = {self.vault.value(*s) for s in slots}
        return sorted((v for v in values if v and len(v) >= MIN_SCRUB), key=len, reverse=True)

    def secrets_block(self, kind, id):
        rows = self.db.execute("SELECT field FROM secrets WHERE kind=? AND id=?", (kind, id)).fetchall()
        return "<h2>Secrets</h2>" + "".join(
            f'<form method=post action=/reveal>{hidden(kind=kind, id=id, field=f)}'
            f'<code>{e(f)}</code> <button>reveal (audited)</button></form>' for f, in rows) + (
            f'<form method=post action=/secret/set>{hidden(kind=kind, id=id)}'
            f'<input name=field placeholder="field, e.g. password" required> '
            f'<input name=value type=password placeholder=value required> <button>set secret</button></form>')

    # -- reads ----------------------------------------------------------------
    def orgs(self, q, user):
        where, args = self.scope(user)
        rows = self.db.execute(f"SELECT org, count(*) FROM items WHERE {where} GROUP BY org ORDER BY org", args)
        return page("Organizations", table(["org", "items"], (
            (f'<a href="/org?{_q(org=o)}">{e(o or "(none)")}</a>', n) for o, n in rows)), user)

    def org(self, q, user):
        org = q.get("org", "")
        if not can(user, org) or not self.db.execute(
                "SELECT 1 FROM items WHERE org=? UNION SELECT 1 FROM orgs WHERE name=?", (org, org)).fetchone():
            return None
        out = []
        for kind, in self.db.execute("SELECT DISTINCT kind FROM items WHERE org=? ORDER BY kind", (org,)).fetchall():
            items = self.db.execute("SELECT id, name FROM items WHERE org=? AND kind=? ORDER BY name",
                                    (org, kind)).fetchall()
            out.append(f"<h2>{e(kind)} ({len(items)})</h2>" + ", ".join(item_link(kind, i, n) for i, n in items))
        kinds = "".join(f"<option>{e(k)}" for k, in self.db.execute("SELECT DISTINCT kind FROM items ORDER BY 1"))
        out.append(f"<h2>Add</h2><form method=post action=/item/new>{hidden(org=org)}"
                   f"<input name=kind list=kinds placeholder=kind required><datalist id=kinds>{kinds}</datalist> "
                   f"<input name=name placeholder=name required> <button>add item</button></form>")
        out.append(self.secrets_block("organizations", self.org_id(org)))
        out.append(f"<h2>Export</h2><form method=post action=/export>{hidden(org=org)}"
                   f"<label><input type=checkbox name=secrets value=1> include every secret, decrypted</label> "
                   f"<button>download zip</button></form><p>Everything: items, files, audit trail. "
                   f"The importer reads it back. Exports are audited.</p>")
        return page(org or "(none)", "".join(out), user)

    def item(self, q, user, notice=""):
        kind, id = q.get("kind", ""), q.get("id", "")
        row = self.db.execute("SELECT org, name, fields FROM items WHERE kind=? AND id=?", (kind, id)).fetchone()
        if not row or not can(user, row[0]):
            return None
        audit(self.db, user.name, "item viewed", kind, id)
        org, name, fields = row
        body = f'<p><b>{e(notice)}</b></p>' if notice else ""
        body += f'<p>{e(kind)} in <a href="/org?{_q(org=org)}">{e(org)}</a></p>'
        body += table(["field", "value"], ((e(k), e(v or "")) for k, v in json.loads(fields).items() if v))
        body += self.secrets_block(kind, id)

        files = self.db.execute("SELECT rowid, filename, size, uploaded_by, ts FROM attachments "
                                "WHERE kind=? AND id=?", (kind, id)).fetchall()
        body += "<h2>Files</h2>" + (table(["file", "size", "by", "when"], (
            (f'<a href="/file?n={n}">{e(fn)}</a>', f"{s // 1024} KB", e(b), e(t)) for n, fn, s, b, t in files))
            if files else "")
        body += (f'<form method=post action=/upload enctype=multipart/form-data>{hidden(kind=kind, id=id)}'
                 f'<input type=file name=file required> <button>upload</button></form>')

        out = self.db.execute("""SELECT r.field, r.target, c.id, c.name FROM refs r
                                 LEFT JOIN items c ON c.kind='configurations' AND c.id=r.target_id
                                 WHERE r.kind=? AND r.id=?""", (kind, id)).fetchall()
        if out:
            body += "<h2>References</h2>" + table(["field", "target"], (
                (e(f), item_link("configurations", cid, cname) if cid else e(t) + " (unresolved)")
                for f, t, cid, cname in out))
        back = self.db.execute("""SELECT r.kind, r.id, s.name, r.field FROM refs r
                                  JOIN items s ON s.kind=r.kind AND s.id=r.id
                                  WHERE r.target_id=? AND ?='configurations' AND s.org=?""", (id, kind, org)).fetchall()
        if back:
            body += "<h2>Referenced by</h2>" + table(["item", "as"], (
                (item_link(k, i, n), e(f)) for k, i, n, f in back))

        edit = "".join(f"<tr><td>{e(k)}</td><td><textarea name=\"f:{e(k)}\">{e(v or '')}</textarea></td></tr>"
                       for k, v in json.loads(fields).items())
        body += (f"<h2>Edit</h2><form method=post action=/item/save>{hidden(kind=kind, id=id)}<table>{edit}"
                 f"<tr><td><input name=newfield placeholder='new field'></td>"
                 f"<td><textarea name=newvalue></textarea></td></tr></table><button>save</button></form>")
        return page(name or id, body, user)

    def search(self, q, user):
        term = q.get("q", "")
        where, args = self.scope(user)
        rows = self.db.execute(f"""SELECT kind, id, org, name FROM items
                                   WHERE (name LIKE ? OR fields LIKE ?) AND {where} LIMIT 200""",
                               (f"%{term}%", f"%{term}%", *args))
        return page(f"Search: {term}", table(["item", "kind", "org"], (
            (item_link(k, i, n), e(k), e(o)) for k, i, o, n in rows)), user)

    def flags(self, q, user):
        where, args = self.scope(user)
        rows = self.db.execute(f"SELECT reason, org, kind, id, name, field FROM flags WHERE {where} "
                               "ORDER BY reason, org, kind", args)
        return page("Flags", "<p>Passwords found outside the vault. <b>Pasted in notes</b> were redacted on "
                    "import; <b>weak</b> means the password is (part of) another field on the record.</p>" +
                    table(["reason", "org", "item", "field"], (
                        (e(r), e(o), item_link(k, i, n), e(f)) for r, o, k, i, n, f in rows)), user)

    def expiring(self, q, user):
        days = int(q["days"]) if q.get("days", "").lstrip("-").isdigit() else 90
        where, args = self.scope(user)
        rows = []
        for left, org, kind, id, name, date in expiring(self.db, days, where, args):
            f = json.loads(self.db.execute("SELECT fields FROM items WHERE kind=? AND id=?", (kind, id)).fetchone()[0])
            rows.append((not f.get("last_seen"), left, (
                ("EXPIRED" if left < 0 else f"{left} days"), e(date), e(org), item_link(kind, id, name),
                e(f.get("issues", "")), e(f.get("last_seen", "never checked")))))
        # What a live endpoint is serving comes first; unconfirmed hand-entered dates after.
        rows = [r for *_, r in sorted(rows, key=lambda r: r[:2])]
        return page(f"Expiring within {days} days", f'<p><a href="/expiring?days=30">30</a> · '
                    f'<a href="/expiring?days=90">90</a> · <a href="/expiring?days=365">365</a> days. Certificates '
                    f"come from the TLS sweep (<code>almanac-sweep-certs</code>); <b>never checked</b> means a "
                    f"hand-entered record nobody has verified.</p>" +
                    table(["left", "date", "org", "item", "issues", "last seen"], rows), user)

    def reuse(self, q, user):
        # Only slots this user can see, and only groups still >1 after filtering --
        # a member must not learn that a password of theirs is also some other customer's.
        groups = [g for g in ([s for s in g if self.visible(user, s[0], s[1])] for g in reuse(self.db))
                  if len(g) > 1]
        body = f"<p>{len(groups)} secret values are stored in more than one place. Nothing was decrypted to find them.</p>"
        for g in groups:
            body += f"<h2>{len(g)} places</h2>" + ", ".join(
                f"{item_link(k, i, self._name(k, i))} <code>{e(f)}</code>" for k, i, f in g)
        return page("Reuse", body, user)

    def audit(self, q, user):
        rows = [r for r in self.db.execute(
            "SELECT ts, user, action, kind, id, field FROM audit ORDER BY rowid DESC LIMIT 5000")
            if user.orgs is None or (r[3] and self.visible(user, r[3], r[4]))][:500]
        return page("Audit", table(["when", "user", "action", "item", "field"], (
            (e(t), e(u), e(a), item_link(k, i, self._name(k, i)) if k else "", e(f))
            for t, u, a, k, i, f in rows)), user)

    def users(self, q, user):
        if user.role != "admin":
            return None
        members = {}
        for u, o in self.db.execute("SELECT user, org FROM members"):
            members.setdefault(u, []).append(o)
        rows = self.db.execute("SELECT name, role FROM users ORDER BY role, name").fetchall()
        orgs = [o for o, in self.db.execute("SELECT DISTINCT org FROM items ORDER BY 1")]
        opts = "".join(f"<option>{e(o)}" for o in orgs)
        roles = "".join(f"<option>{r}" for r in ROLES)
        return page("Users", table(["user", "role", "orgs (members only)"], (
            (e(n), e(r), e(", ".join(members.get(n, [])))) for n, r in rows)) +
            f"""<h2>Add or update</h2><form method=post action=/users/save>
            <p><input name=name placeholder=username required>
            <input name=password type=password placeholder="password (blank = keep)">
            <select name=role>{roles}</select></p>
            <p>Orgs, for members (ctrl-click for several):<br><select name=org multiple size=10>{opts}</select></p>
            <button>save</button></form><p>Set the role to <b>disabled</b> to offboard someone; their audit history stays.</p>""",
            user)

    # -- writes ---------------------------------------------------------------
    def reveal(self, q, user):
        if not self.visible(user, q.get("kind", ""), q.get("id", "")):
            return None
        value = self.vault.reveal(q["kind"], q["id"], q.get("field", ""), user.name)
        if value is None:
            return None
        back = item_link(q["kind"], q["id"], self._name(q["kind"], q["id"]), "back")
        return page(q["field"], f"<p>{back} · "
                    f"this reveal is in the audit log</p><pre>{e(value)}</pre>", user)

    def item_save(self, q, user):
        kind, id = q.get("kind", ""), q.get("id", "")
        row = self.db.execute("SELECT org, fields FROM items WHERE kind=? AND id=?", (kind, id)).fetchone()
        if not row or not can(user, row[0]):
            return None
        fields = json.loads(row[1])
        edited = {k[2:]: v for k, v in q.items() if k.startswith("f:")}
        if q.get("newfield"):
            edited[q["newfield"]] = q.get("newvalue", "")
        name = edited.get("name") or fields.get("name") or self._name(kind, id)
        # Same scan as the importer: a known password pasted into a note is redacted and vaulted.
        pasted = scan(self.db, self.vault, self.org_secrets(row[0]), kind, id, row[0], name, edited)
        fields.update(edited)
        self.db.execute("UPDATE items SET fields=?, name=? WHERE kind=? AND id=?",
                        (json.dumps(fields), name, kind, id))
        audit(self.db, user.name, "item edited", kind, id)
        notice = (f"{pasted} known password(s) were pasted into notes: redacted, and the original "
                  f"note vaulted. See flags.") if pasted else ""
        return self.item(q, user, notice)

    def item_new(self, q, user):
        org, kind, name = q.get("org", ""), q.get("kind", "").strip(), q.get("name", "").strip()
        if not (kind and name and org) or not can(user, org):
            return None
        # A kind is a file name in the export; keep it one, and off the names the export reserves.
        if not re.fullmatch(r"[\w .()-]{1,60}", kind) or kind.lower() in RESERVED_KINDS:
            return page("Add item", "<p>Kind must be letters, digits, spaces or <code>._()-</code>, and not one of "
                        f"{e(', '.join(sorted(RESERVED_KINDS)))}.</p>", user)
        id = uuid.uuid4().hex[:12]
        self.db.execute("INSERT INTO items VALUES (?,?,?,?,?)", (kind, id, org, name, json.dumps({"name": name})))
        audit(self.db, user.name, "item created", kind, id)
        return self.item({"kind": kind, "id": id}, user)

    def secret_set(self, q, user):
        kind, id, field = q.get("kind", ""), q.get("id", ""), q.get("field", "").strip()
        if not field or not self.visible(user, kind, id):
            return None
        self.vault.put(kind, id, field, q.get("value", ""))
        audit(self.db, user.name, "secret set", kind, id, field)
        if kind == "organizations":
            return self.org({"org": self._name(kind, id)}, user)
        return self.item(q, user)

    def upload(self, q, user):
        kind, id, f = q.get("kind", ""), q.get("id", ""), q.get("file")
        if not f or not self.visible(user, kind, id):
            return None
        filename, data = f
        self.db.execute("INSERT INTO attachments VALUES (?,?,?,?,?,?,datetime('now'))",
                        (kind, id, filename, len(data), data, user.name))
        audit(self.db, user.name, "file uploaded", kind, id, filename)
        return self.item(q, user)

    def users_save(self, q, user):
        if user.role != "admin":
            return None
        try:
            add_user(self.db, q.get("name", "").strip(), q.get("password") or None,
                     q.get("role", "member"), q["_all"].get("org", []))
        except ValueError as err:
            return page("Users", f"<p>{e(str(err))}</p>", user)
        audit(self.db, user.name, f"user saved: {q['name']} as {q.get('role')}")
        return self.users(q, user)

    def export(self, q, user):
        org = q.get("org", "")
        if not can(user, org) or not self.db.execute(
                "SELECT 1 FROM items WHERE org=? UNION SELECT 1 FROM orgs WHERE name=?", (org, org)).fetchone():
            return None
        buf = io.BytesIO()
        export(self.db, buf, [org], self.vault if q.get("secrets") else None, user.name)
        return f"almanac-{org}.zip", buf.getvalue()

    def file(self, q, user):
        """Returns (filename, bytes); the handler sends it as a download, never inline."""
        row = self.db.execute("SELECT kind, id, filename, data FROM attachments WHERE rowid=?",
                              (q.get("n", ""),)).fetchone()
        if not row or not self.visible(user, row[0], row[1]):
            return None
        audit(self.db, user.name, "file downloaded", row[0], row[1], row[2])
        return row[2], row[3]

    GET = {"/": "orgs", "/org": "org", "/item": "item", "/search": "search", "/flags": "flags",
           "/expiring": "expiring", "/reuse": "reuse", "/audit": "audit", "/users": "users", "/file": "file"}
    POST = {"/reveal": "reveal", "/item/save": "item_save", "/item/new": "item_new",
            "/secret/set": "secret_set", "/upload": "upload", "/users/save": "users_save",
            "/export": "export"}


def _multipart(ctype, body):
    """multipart/form-data -> {name: value}, with file parts as (filename, bytes). (cgi is gone in 3.13.)"""
    msg = BytesParser(policy=HTTP).parsebytes(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + body)
    out = {}
    for part in msg.iter_parts():
        name, filename = part.get_param("name", header="content-disposition"), part.get_filename()
        data = part.get_payload(decode=True) or b""
        out[name] = (os.path.basename(filename), data) if filename else data.decode(errors="replace")
    return out


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def _user(self):
            try:
                kind, _, cred = self.headers.get("Authorization", "").partition(" ")
                name, _, pw = b64decode(cred).decode().partition(":")
                if kind == "Basic":
                    return check_user(app.db, name, pw)
            except Exception:
                pass
            return None

        def _send(self, code, body, extra=(), ctype="text/html; charset=utf-8"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            for k, v in [("Content-Type", ctype), ("Cache-Control", "no-store"),
                         ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"),
                         ("Content-Length", str(len(data))),
                         ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"),
                         *extra]:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _route(self, routes, q):
            with app.lock:
                user = self._user()
                if not user:
                    return self._send(401, "login required", [("WWW-Authenticate", 'Basic realm="almanac"')])
                name = routes.get(urlparse(self.path).path)
                result = getattr(app, name)(q, user) if name else None
                if result is None:
                    self._send(404, page("Not found", "", user))
                elif isinstance(result, tuple):  # a file
                    filename, data = result
                    self._send(200, data, [("Content-Disposition", f"attachment; filename*=UTF-8''{quote(filename)}")],
                               ctype="application/octet-stream")
                else:
                    self._send(200, result)

        def do_GET(self):
            params = parse_qs(urlparse(self.path).query)
            self._route(App.GET, {**{k: v[0] for k, v in params.items()}, "_all": params})

        def do_POST(self):
            # Basic-auth credentials ride along on cross-site POSTs; refuse any from elsewhere.
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc != self.headers.get("Host"):
                return self._send(403, "cross-origin request refused")
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_UPLOAD:
                return self._send(413, f"too large; limit is {MAX_UPLOAD // 2**20} MB")
            body, ctype = self.rfile.read(length), self.headers.get("Content-Type", "")
            if ctype.startswith("multipart/form-data"):
                q = _multipart(ctype, body)
                q["_all"] = {k: [v] for k, v in q.items()}
            else:
                params = parse_qs(body.decode())
                q = {**{k: v[0] for k, v in params.items()}, "_all": params}
            self._route(App.POST, q)

        def log_message(self, fmt, *args):
            pass  # the audit table is the log

    return Handler


def serve(db_path, host="127.0.0.1", port=8771, cert=None, key=None, passphrase=None):
    if not ipaddress.ip_address(host).is_loopback and not cert:
        sys.exit("refusing to serve off-loopback without TLS: Basic auth would send passwords in the clear. "
                 "Pass --cert and --key.")
    db = sqlite3.connect(db_path, check_same_thread=False)
    init(db)
    if not db.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        sys.exit(f"no admin yet: almanac-server {db_path} --add-user NAME")
    app = App(db, Vault(db, passphrase or ask_passphrase()))
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def main(argv=None):
    import argparse
    import getpass
    ap = argparse.ArgumentParser(prog="almanac-server")
    ap.add_argument("db")
    ap.add_argument("--add-user", metavar="NAME", help="create or update a user, then exit")
    ap.add_argument("--role", choices=ROLES, default="admin")
    ap.add_argument("--org", action="append", help="org a member can see (repeatable)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8771)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    a = ap.parse_args(argv)
    if a.add_user:
        add_user(sqlite3.connect(a.db), a.add_user,
                 getpass.getpass(f"password for {a.add_user}: ") or None, a.role, a.org)
        return print(f"saved {a.add_user} as {a.role}")
    httpd = serve(a.db, a.host, a.port, a.cert, a.key)
    print(f"[almanac] http{'s' if a.cert else ''}://{a.host}:{httpd.server_address[1]}/")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
