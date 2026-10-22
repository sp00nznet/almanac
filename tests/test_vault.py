import sqlite3

import pytest

from almanac.vault import Vault, WrongPassphrase, reuse


def test_roundtrip_audit_reuse_and_tamper(tmp_path):
    db = sqlite3.connect(tmp_path / "v.db")
    v = Vault(db, "correct horse")
    v.put("passwords", "1", "password", "s3cret-value")
    v.put("wireless", "9", "Pre-Shared Key", "s3cret-value")
    v.put("passwords", "2", "password", "other")
    db.commit()
    assert b"s3cret-value" not in (tmp_path / "v.db").read_bytes()

    assert Vault(db, "correct horse").reveal("passwords", "1", "password", "alice") == "s3cret-value"
    assert db.execute("SELECT user, action FROM audit").fetchall() == [("alice", "secret revealed")]
    assert reuse(db) == [[("passwords", "1", "password"), ("wireless", "9", "Pre-Shared Key")]]

    with pytest.raises(WrongPassphrase):
        Vault(db, "wrong")

    # A ciphertext moved to another slot must not decrypt there.
    db.execute("UPDATE secrets SET blob=(SELECT blob FROM secrets WHERE id='1') WHERE id='2'")
    with pytest.raises(Exception):
        v.reveal("passwords", "2", "password", "alice")
