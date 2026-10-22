import json
import sqlite3

from almanac.importer import import_export
from almanac.lineage import sync
from test_importer import _csv


def _report(root, host, agent, probe, value, status="ok", ts=1786266364):
    d = root / "state" / host / probe
    d.mkdir(parents=True, exist_ok=True)
    (d / "latest.json").write_text(json.dumps({
        "host": {"name": host, "agent_id": agent}, "probe": probe, "captured_at": ts,
        "result": {"status": status, "data": {"kind": "inventory", "value": value}}}))


def test_sync_matches_creates_and_keeps_human_fields(tmp_path):
    _csv(tmp_path / "configurations.csv", ["id", "organization", "name", "hostname", "operating_system", "notes"],
         ["10", "Acme", "Front desk", "ACME-WS01", "Windows 7", "taped to the desk"])
    db_path = tmp_path / "a.db"
    import_export(tmp_path, db_path)
    db = sqlite3.connect(db_path)
    state = tmp_path / "lineage"
    _report(state, "acme-ws01", "agent-1", "os-name", "Windows 11 Pro")
    _report(state, "acme-ws01", "agent-1", "smbv1-enabled", False)
    _report(state, "acme-ws01", "agent-1", "chrome-version", None, status="error")
    _report(state, "newbox", "agent-2", "os-name", "Windows 10 Pro")

    r = sync(db, state)
    assert r["updated"] == ["acme-ws01 (Acme)"] and r["created"] == [] and len(r["unmatched"]) == 1
    f = json.loads(db.execute("SELECT fields FROM items WHERE id='10'").fetchone()[0])
    assert f["operating_system"] == "Windows 11 Pro" and f["smbv1-enabled"] == "false"
    assert f["notes"] == "taped to the desk" and "chrome-version" not in f and f["source"] == "lineage"

    assert sync(db, state, org="Acme")["created"] == ["newbox (Acme)"]
    # Renamed machine: the agent id still finds it.
    _report(state, "acme-ws01-renamed", "agent-1", "os-name", "Windows 11 Pro", ts=1786300000)
    r = sync(db, state, org="Acme")
    assert "acme-ws01-renamed (Acme)" in r["updated"] and len(r["updated"]) == 2  # renamed + newbox, not the stale name
    f = json.loads(db.execute("SELECT fields FROM items WHERE id='10'").fetchone()[0])
    assert f["hostname"] == "acme-ws01-renamed"
    assert db.execute("SELECT count(*) FROM items WHERE kind='configurations'").fetchone()[0] == 2
    assert db.execute("SELECT count(*) FROM audit WHERE user='lineage'").fetchone()[0] >= 3
