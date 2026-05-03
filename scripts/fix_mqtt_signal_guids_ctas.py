#!/usr/bin/env python3
"""Backfill signal_guid in an MQTT signals DuckDB to match the graph's ICSSignal
GUID scheme — CTAS variant.

Existing DB values are computed from generate_signal_guid("mqtt", host, port,
topic, clean_field) which produces "ICSSignal|mqtt|<host>|<port>|<topic>|<field>"
— two separate identifiers separated by '|'. The graph uses
generate_signal_guid("mqtt", host, port, signal_name) where signal_name is the
already-joined "topic.field" — one combined identifier. The two recipes hash to
different GUIDs even when host/port/topic/field are identical.

Additionally, BlackEnergy's MQTT collector labels the broker as 'FT-MQTT-01'
while the graph builder resolves the same IP to 'FT-HMI-01'. The mapping below
is taken from the graph's NetworkEndpoint nodes (server_ip → graph hostname),
so the join works regardless of what synthetic name the DB collector chose.

The fix parses each MQTT ICSSignal node from the cypher (signalKey:
'mqtt|<host>|<port>|<signal_name>'), builds a (signal_name → graph_guid) map,
and CTAS-rewrites the DB's signal_guid column.

Usage:
    python scripts/fix_mqtt_signal_guids_ctas.py <cypher_path> <duckdb_path>
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import duckdb
import pandas as pd

KEY_RE = re.compile(r"signalKey: '([^']+)'")
GUID_RE = re.compile(r"guid: '(\{[^}]+\})'")


def parse_mqtt_ics_signals(cypher_path: Path) -> dict[str, str]:
    """Return {signal_name -> guid} for every MQTT ICSSignal node."""
    mapping: dict[str, str] = {}
    with cypher_path.open() as fh:
        for line in fh:
            m_key = KEY_RE.search(line)
            m_guid = GUID_RE.search(line)
            if not (m_key and m_guid):
                continue
            sk = m_key.group(1)
            if not sk.startswith("mqtt|"):
                continue
            parts = sk.split("|", 3)
            if len(parts) != 4:
                continue
            _, _host, _port, signal_name = parts
            mapping[signal_name] = m_guid.group(1)
    return mapping


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    cypher_path = Path(sys.argv[1])
    db_path = Path(sys.argv[2])
    if not cypher_path.exists() or not db_path.exists():
        raise SystemExit("Missing cypher or duckdb path")

    new_db_path = db_path.with_suffix(".duckdb.new")
    old_db_path = db_path.with_suffix(".duckdb.preCTAS")
    if new_db_path.exists():
        new_db_path.unlink()

    t0 = time.monotonic()
    graph_signals = parse_mqtt_ics_signals(cypher_path)
    print(f"[{time.monotonic()-t0:6.1f}s] parsed {len(graph_signals)} MQTT ICSSignal nodes from graph", flush=True)

    con = duckdb.connect(str(db_path))
    con.execute("PRAGMA threads=8")
    con.execute("PRAGMA preserve_insertion_order=false")
    con.execute("PRAGMA memory_limit='40GB'")

    distinct_names = [r[0] for r in con.execute(
        "SELECT DISTINCT signal_name FROM signal_observations"
    ).fetchall()]
    print(f"[{time.monotonic()-t0:6.1f}s] DB has {len(distinct_names)} distinct signal_names", flush=True)

    update_rows: list[tuple[str, str]] = []
    unmatched: list[str] = []
    for sn in distinct_names:
        new_guid = graph_signals.get(sn)
        if new_guid is None:
            unmatched.append(sn)
        else:
            update_rows.append((sn, new_guid))
    print(f"[{time.monotonic()-t0:6.1f}s] matched {len(update_rows)}/{len(distinct_names)} (unmatched={len(unmatched)})", flush=True)
    if unmatched:
        print(f"  first 5 unmatched: {unmatched[:5]}", flush=True)
    if not update_rows:
        print("nothing to map; aborting"); con.close(); return 1

    guid_df = pd.DataFrame(update_rows, columns=["signal_name", "new_guid"])
    con.register("guid_map", guid_df)

    print(f"[{time.monotonic()-t0:6.1f}s] attaching {new_db_path.name} for CTAS output...", flush=True)
    con.execute(f"ATTACH '{new_db_path}' AS new_db")

    print(f"[{time.monotonic()-t0:6.1f}s] running CTAS...", flush=True)
    con.execute(
        """
        CREATE TABLE new_db.signal_observations AS
        SELECT o.* REPLACE (COALESCE(m.new_guid, o.signal_guid) AS signal_guid)
        FROM signal_observations o
        LEFT JOIN guid_map m ON o.signal_name = m.signal_name
        """
    )
    print(f"[{time.monotonic()-t0:6.1f}s] CTAS complete", flush=True)

    new_count = con.execute("SELECT COUNT(*) FROM new_db.signal_observations").fetchone()[0]
    old_count = con.execute("SELECT COUNT(*) FROM signal_observations").fetchone()[0]
    new_distinct = con.execute(
        "SELECT COUNT(DISTINCT signal_guid) FROM new_db.signal_observations"
    ).fetchone()[0]
    print(f"[{time.monotonic()-t0:6.1f}s] sanity: old_rows={old_count:,}  new_rows={new_count:,}  distinct_guids_new={new_distinct}", flush=True)
    if new_count != old_count:
        raise SystemExit("row count mismatch; aborting before swap")

    print(f"[{time.monotonic()-t0:6.1f}s] recreating indexes on new table...", flush=True)
    for stmt in [
        "CREATE INDEX idx_mqtt_signal_guid  ON new_db.signal_observations(signal_guid)",
        "CREATE INDEX idx_mqtt_access_type  ON new_db.signal_observations(access_type)",
        'CREATE INDEX idx_mqtt_timestamp    ON new_db.signal_observations("timestamp")',
        "CREATE INDEX idx_mqtt_topic        ON new_db.signal_observations(topic, field_name)",
    ]:
        con.execute(stmt)
    print(f"[{time.monotonic()-t0:6.1f}s] indexes built", flush=True)

    con.execute("DETACH new_db")
    con.close()

    print(f"[{time.monotonic()-t0:6.1f}s] swapping files...", flush=True)
    if old_db_path.exists():
        old_db_path.unlink()
    db_path.rename(old_db_path)
    new_db_path.rename(db_path)
    print(f"[{time.monotonic()-t0:6.1f}s] done. Old DB moved to {old_db_path.name}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
