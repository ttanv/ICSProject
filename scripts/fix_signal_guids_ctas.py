#!/usr/bin/env python3
"""Backfill signal_container_guid in a Modbus signals DuckDB to match the graph's
ICSSignal GUID scheme — CTAS variant.

Faster than the UPDATE variant because CTAS bulk-writes a new column-store table
instead of forcing DuckDB's MVCC engine to track per-row version pairs for 100M+
rows. Writes the rebuilt table to a fresh DB file (via ATTACH) so the output
storage is fully compacted, then swaps files atomically once the CTAS completes
and verifies.

Usage:
    python scripts/fix_signal_guids_ctas.py <cypher_path> <duckdb_path>
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

import duckdb
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from network_aug.modbus_helpers import register_type_from_function  # noqa: E402

KEY_RE = re.compile(r"signalKey: '([^']+)'")
GUID_RE = re.compile(r"guid: '(\{[^}]+\})'")


def parse_modbus_ics_signals(cypher_path: Path) -> dict[tuple, str]:
    mapping: dict[tuple, str] = {}
    with cypher_path.open() as fh:
        for line in fh:
            m_key = KEY_RE.search(line)
            m_guid = GUID_RE.search(line)
            if not (m_key and m_guid):
                continue
            signal_key = m_key.group(1)
            if not signal_key.startswith("modbus|"):
                continue
            parts = signal_key.split("|")
            if len(parts) != 6:
                continue
            _, host, _port, unit_id, reg_type, addr = parts
            try:
                key = (host.lower(), int(addr), int(unit_id), reg_type)
            except ValueError:
                continue
            mapping[key] = m_guid.group(1)
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
    graph_signals = parse_modbus_ics_signals(cypher_path)
    print(f"[{time.monotonic()-t0:6.1f}s] parsed {len(graph_signals)} ICSSignal modbus nodes", flush=True)

    con = duckdb.connect(str(db_path))
    con.execute("PRAGMA threads=8")
    con.execute("PRAGMA preserve_insertion_order=false")
    con.execute("PRAGMA memory_limit='40GB'")
    temp_dir = Path(os.environ.get("DUCKDB_TEMP_DIRECTORY", ROOT / ".duckdb_tmp"))
    temp_dir.mkdir(parents=True, exist_ok=True)
    con.execute(f"PRAGMA temp_directory='{temp_dir}'")

    print(f"[{time.monotonic()-t0:6.1f}s] gathering distinct (server_host, addr, unit_id, function_code)...", flush=True)
    distinct_rows = con.execute(
        """
        SELECT DISTINCT server_host, register_address, unit_id, function_code
        FROM signal_observations
        """
    ).fetchall()
    print(f"[{time.monotonic()-t0:6.1f}s]   {len(distinct_rows)} distinct tuples", flush=True)

    update_rows: list[tuple] = []
    unmatched = 0
    for srv, addr, uid, fc in distinct_rows:
        rt = register_type_from_function(fc)
        if rt is None or srv is None or uid is None:
            unmatched += 1
            continue
        key = (srv.lower(), int(addr), int(uid), rt)
        new_guid = graph_signals.get(key)
        if new_guid is None:
            unmatched += 1
            continue
        update_rows.append((srv, int(addr), int(uid), int(fc), new_guid))
    print(f"[{time.monotonic()-t0:6.1f}s] matched {len(update_rows)}/{len(distinct_rows)} (unmatched={unmatched})", flush=True)

    if not update_rows:
        print("nothing to map; aborting")
        con.close()
        return 1

    guid_df = pd.DataFrame(
        update_rows,
        columns=["server_host", "register_address", "unit_id", "function_code", "new_guid"],
    )
    con.register("guid_map", guid_df)

    print(f"[{time.monotonic()-t0:6.1f}s] attaching {new_db_path.name} for CTAS output...", flush=True)
    con.execute(f"ATTACH '{new_db_path}' AS new_db")

    print(f"[{time.monotonic()-t0:6.1f}s] running CTAS...", flush=True)
    con.execute(
        """
        CREATE TABLE new_db.signal_observations AS
        SELECT
            o.timestamp,
            o.register_address,
            o.value,
            o.access_type,
            o.function_code,
            o.unit_id,
            o.client_host,
            o.server_host,
            o.client_ip,
            o.server_ip,
            o.transaction_id,
            o.request_timestamp,
            o.response_timestamp,
            o.write_acknowledged,
            COALESCE(m.new_guid, o.signal_container_guid) AS signal_container_guid,
            o.pcap_file
        FROM signal_observations o
        LEFT JOIN guid_map m
            ON o.server_host = m.server_host
           AND o.register_address = m.register_address
           AND o.unit_id = m.unit_id
           AND o.function_code = m.function_code
        """
    )
    print(f"[{time.monotonic()-t0:6.1f}s] CTAS complete", flush=True)

    print(f"[{time.monotonic()-t0:6.1f}s] sanity check on new table...", flush=True)
    new_count = con.execute("SELECT COUNT(*) FROM new_db.signal_observations").fetchone()[0]
    old_count = con.execute("SELECT COUNT(*) FROM signal_observations").fetchone()[0]
    new_distinct = con.execute(
        "SELECT COUNT(DISTINCT signal_container_guid) FROM new_db.signal_observations"
    ).fetchone()[0]
    print(f"[{time.monotonic()-t0:6.1f}s]   old rows={old_count:,}  new rows={new_count:,}  distinct guids in new={new_distinct}", flush=True)
    if new_count != old_count:
        raise SystemExit(f"row count mismatch ({old_count} vs {new_count}); aborting before swap")

    print(f"[{time.monotonic()-t0:6.1f}s] creating index on new table...", flush=True)
    con.execute(
        "CREATE INDEX idx_signal_container_guid ON new_db.signal_observations(signal_container_guid)"
    )
    print(f"[{time.monotonic()-t0:6.1f}s] index created", flush=True)

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
