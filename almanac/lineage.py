"""Feed configurations from lineage's inventory.

The lesson of a real migrated export: hand-entered fields rot (873 configurations, 346
with no OS, not one warranty date). So the fields a machine can report about
itself come from the machine. lineage already collects them; this reads its
state tree directly -- <state>/state/<host>/<probe>/latest.json -- no API.

Matching, in order: the lineage agent id recorded on a previous sync, then the
hostname against existing configurations in any org (the import already holds
the hosts; this is how they start updating themselves). A host matching neither
is created in --org, or reported and skipped when no --org is given -- guessing
which customer a machine belongs to is how documentation goes wrong.

lineage owns only the fields it reports, plus `source`/`last_seen`/`lineage_agent_id`.
Everything a person typed stays theirs.

ponytail: reads files, so almanac and the lineage server share a disk (or the
state dir is synced). An HTTP pull when they don't. Run on a schedule with Task
Scheduler / cron; no daemon.
"""
import json
import sqlite3
import sys
import time
import uuid
from pathlib import Path

from .importer import SCHEMA as ITEMS_SCHEMA
from .vault import SCHEMA as VAULT_SCHEMA, audit

# lineage probe -> almanac field, where the import format already had a name for it.
FIELD_FOR = {"os-name": "operating_system", "os-build": "os_build", "os-arch": "os_arch",
             "ad-domain": "ad_domain"}


def read_hosts(state_root):
    """{host: {"agent_id", "last_seen", "fields"}} from lineage's latest.json files."""
    hosts = {}
    for latest in sorted(Path(state_root, "state").glob("*/*/latest.json")):
        try:
            w = json.loads(latest.read_text())
        except (OSError, json.JSONDecodeError):
            continue  # a half-written report is skipped, not fatal
        r = w.get("result") or {}
        if r.get("status") != "ok":
            continue
        name = (w.get("host") or {}).get("name") or latest.parent.parent.name
        h = hosts.setdefault(name, {"agent_id": "", "last_seen": 0, "fields": {}})
        h["agent_id"] = (w.get("host") or {}).get("agent_id") or h["agent_id"]
        h["last_seen"] = max(h["last_seen"], w.get("captured_at") or 0)
        value = (r.get("data") or {}).get("value")
        probe = w.get("probe") or latest.parent.name
        h["fields"][FIELD_FOR.get(probe, probe)] = value if isinstance(value, str) else json.dumps(value)
    # A renamed machine leaves its old host dir behind under the same agent id:
    # one machine, so keep only the most recently seen name.
    newest = {}
    for name, h in sorted(hosts.items(), key=lambda kv: kv[1]["last_seen"]):
        newest[h["agent_id"] or name] = name
    return {name: hosts[name] for name in newest.values()}


def sync(db, state_root, org=None):
    db.executescript(ITEMS_SCHEMA + VAULT_SCHEMA)
    report = {"updated": [], "created": [], "unmatched": []}
    configs = [(i, o, json.loads(f)) for i, o, f in
               db.execute("SELECT id, org, fields FROM items WHERE kind='configurations'")]
    for host, h in read_hosts(state_root).items():
        match = ([c for c in configs if h["agent_id"] and c[2].get("lineage_agent_id") == h["agent_id"]]
                 or [c for c in configs if host.lower() in
                     ((c[2].get("hostname") or "").lower(), (c[2].get("name") or "").lower())])
        if len(match) > 1:
            report["unmatched"].append(f"{host}: matches {len(match)} configurations, fix the duplicates")
            continue
        fields = {**h["fields"], "hostname": host, "source": "lineage", "lineage_agent_id": h["agent_id"],
                  "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["last_seen"]))}
        if match:
            id, item_org, existing = match[0]
            existing.update(fields)
            db.execute("UPDATE items SET fields=? WHERE kind='configurations' AND id=?", (json.dumps(existing), id))
            report["updated"].append(f"{host} ({item_org})")
        elif org:
            id = "lineage-" + (h["agent_id"] or uuid.uuid4().hex)[:12]
            db.execute("INSERT INTO items VALUES ('configurations',?,?,?,?)",
                       (id, org, host, json.dumps({"name": host, **fields})))
            report["created"].append(f"{host} ({org})")
        else:
            report["unmatched"].append(f"{host}: no configuration with that hostname; pass --org to create it")
            continue
        audit(db, "lineage", "synced from lineage", "configurations", id)
    db.commit()
    return report


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="almanac-sync-lineage")
    ap.add_argument("db")
    ap.add_argument("state", help="lineage server state root (the dir holding state/)")
    ap.add_argument("--org", help="org for hosts that match no existing configuration")
    a = ap.parse_args(argv)
    print(json.dumps(sync(sqlite3.connect(a.db), a.state, a.org), indent=2))


if __name__ == "__main__":
    main()
