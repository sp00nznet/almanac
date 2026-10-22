"""Secret fields, encrypted at rest. Any item can have one -- a secret is a field
type, not a module, because a real migrated export showed PSKs, licence keys and
BitLocker keys living in ordinary asset columns.

AES-256-GCM, key from the passphrase via scrypt. The slot (kind/id/field) is the
GCM associated data, so a ciphertext copied into another row fails to decrypt.
Each value also gets an HMAC fingerprint under a derived key: equal secrets get
equal fingerprints, which makes the reuse report a GROUP BY with nothing decrypted
and nothing guessable from the database alone.

ponytail: one vault key for everything. Per-org keys / key rotation when the
first multi-tenant install needs a customer's secrets made unreadable on exit.
"""
import getpass
import hashlib
import hmac
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta    (k TEXT PRIMARY KEY, v BLOB);
CREATE TABLE IF NOT EXISTS secrets (kind TEXT, id TEXT, field TEXT, blob BLOB, fp TEXT,
                                    PRIMARY KEY (kind, id, field));
CREATE TABLE IF NOT EXISTS audit   (ts TEXT, user TEXT, action TEXT, kind TEXT, id TEXT, field TEXT);
"""
CHECK = b"almanac vault"


class WrongPassphrase(Exception):
    pass


def _slot(kind, id, field):
    return f"{kind}/{id}/{field}".encode()


class Vault:
    def __init__(self, db, passphrase):
        self.db = db
        db.executescript(SCHEMA)
        row = db.execute("SELECT v FROM meta WHERE k='salt'").fetchone()
        salt = row[0] if row else os.urandom(16)
        key = hashlib.scrypt(passphrase.encode(), salt=salt, n=2**15, r=8, p=1,
                             maxmem=64 * 1024 * 1024, dklen=64)
        self._aead, self._fp_key = AESGCM(key[:32]), key[32:]
        if row:
            try:
                self._open(db.execute("SELECT v FROM meta WHERE k='check'").fetchone()[0], b"check")
            except Exception:
                raise WrongPassphrase("vault passphrase is wrong") from None
        else:
            db.execute("INSERT INTO meta VALUES ('salt', ?)", (salt,))
            db.execute("INSERT INTO meta VALUES ('check', ?)", (self._seal(CHECK, b"check"),))
            db.commit()

    def _seal(self, data, aad):
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, data, aad)

    def _open(self, blob, aad):
        return self._aead.decrypt(blob[:12], blob[12:], aad)

    def put(self, kind, id, field, value):
        fp = hmac.new(self._fp_key, value.encode(), hashlib.sha256).hexdigest()
        self.db.execute("INSERT OR REPLACE INTO secrets VALUES (?,?,?,?,?)",
                        (kind, id, field, self._seal(value.encode(), _slot(kind, id, field)), fp))

    def value(self, kind, id, field):
        """Decrypt without auditing -- for internal use (export, scanning edits),
        whose callers audit the operation as a whole. People go through reveal()."""
        row = self.db.execute("SELECT blob FROM secrets WHERE kind=? AND id=? AND field=?",
                              (kind, id, field)).fetchone()
        return self._open(row[0], _slot(kind, id, field)).decode() if row else None

    def reveal(self, kind, id, field, user):
        """Decrypt one secret for a person. Every call is audited -- that log is the product."""
        value = self.value(kind, id, field)
        if value is not None:
            audit(self.db, user, "secret revealed", kind, id, field)
        return value


def audit(db, user, action, kind="", id="", field=""):
    db.execute("INSERT INTO audit VALUES (?,?,?,?,?,?)",
               (time.strftime("%Y-%m-%d %H:%M:%S"), user, action, kind, id, field))
    db.commit()


def reuse(db):
    """Groups of slots sharing one secret value, biggest first. Nothing decrypted."""
    groups = {}
    for fp, kind, id, field in db.execute("""
            SELECT fp, kind, id, field FROM secrets WHERE fp IN
              (SELECT fp FROM secrets GROUP BY fp HAVING count(*) > 1)"""):
        groups.setdefault(fp, []).append((kind, id, field))
    return sorted(groups.values(), key=len, reverse=True)


def ask_passphrase():
    """ALMANAC_PASSPHRASE for scripts, otherwise prompt. Never a command-line argument."""
    return os.environ.get("ALMANAC_PASSPHRASE") or getpass.getpass("vault passphrase: ")
