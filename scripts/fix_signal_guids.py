#!/usr/bin/env python3
"""Backfill signal_container_guid in a Modbus signals DuckDB to match the graph's
ICSSignal GUID scheme.

Existing values use SignalContainer|<client_host>|<addr>|<unit_id> (md5/uuid),
keyed by the requesting client. The graph keys signals by the server where they
live: ICSSignal|<protocol>|<server_host>|<port>|<unit_id>|<reg_type>|<addr>.
This script parses the cypher file's ICSSignal nodes, builds a lookup keyed by
(server_host, register_address, unit_id, register_type), and rewrites each
DB row's signal_container_guid to the matching graph GUID.

Usage:
    python scripts/fix_signal_guids.py <cypher_path> <duckdb_path>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from network_aug.modbus_helpers import register_type_from_function  # noqa: E402

KEY_RE = re.compile(r"signalKey: '([^']+)'")
GUID_RE = re.compile(r"guid: '(\{[^}]+\})'")


def parse_modbus_ics_signals(cypher_path: Path) -> dict[tuple, str]:
    """Return mapping (host_lower, addr, unit_id, reg_type) -> ICSSignal guid."""
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

    if not cypher_path.exists():
        raise SystemExit(f"Missing cypher: {cypher_path}")
    if not db_path.exists():
        raise SystemExit(f"Missing duckdb: {db_path}")

    graph_signals = parse_modbus_ics_signals(cypher_path)
    print(f"Parsed {len(graph_signals)} ICSSignal modbus nodes from {cypher_path.name}")

    con = duckdb.connect(str(db_path))

    distinct_rows = con.execute(
        """
        SELECT DISTINCT server_host, register_address, unit_id, function_code
        FROM signal_observations
        """
    ).fetchall()
    print(
        f"DB has {len(distinct_rows)} distinct (server_host, addr, unit_id, function_code) tuples"
    )

    update_rows: list[tuple] = []
    unmatched: list[tuple] = []
    for srv, addr, uid, fc in distinct_rows:
        reg_type = register_type_from_function(fc)
        if reg_type is None or srv is None:
            unmatched.append(("no_reg_type_or_host", srv, addr, uid, fc))
            continue
        key = (srv.lower(), int(addr), int(uid) if uid is not None else None, reg_type)
        if key[2] is None:
            # signalKey requires unit_id; rows without one cannot map.
            unmatched.append(("null_unit_id", srv, addr, uid, fc))
            continue
        new_guid = graph_signals.get(key)
        if new_guid is None:
            unmatched.append(("no_match", srv, addr, uid, fc))
            continue
        update_rows.append((srv, addr, uid, fc, new_guid))

    print(f"Matched: {len(update_rows)} / {len(distinct_rows)}")
    if unmatched:
        print(f"Unmatched: {len(unmatched)} (showing first 5)")
        for u in unmatched[:5]:
            print("  ", u)

    if not update_rows:
        print("Nothing to update; aborting.")
        con.close()
        return 1

    con.execute("DROP TABLE IF EXISTS guid_map")
    con.execute(
        """
        CREATE TABLE guid_map (
            server_host VARCHAR,
            register_address INTEGER,
            unit_id INTEGER,
            function_code INTEGER,
            new_guid VARCHAR
        )
        """
    )
    con.executemany(
        "INSERT INTO guid_map VALUES (?, ?, ?, ?, ?)",
        update_rows,
    )

    print("Running UPDATE...")
    con.execute(
        """
        UPDATE signal_observations
        SET signal_container_guid = m.new_guid
        FROM guid_map m
        WHERE signal_observations.server_host = m.server_host
          AND signal_observations.register_address = m.register_address
          AND signal_observations.unit_id = m.unit_id
          AND signal_observations.function_code = m.function_code
        """
    )

    con.execute("DROP TABLE guid_map")
    con.execute("CHECKPOINT")

    new_distinct = con.execute(
        "SELECT COUNT(DISTINCT signal_container_guid) FROM signal_observations"
    ).fetchone()[0]
    print(f"Distinct signal_container_guid values after update: {new_distinct}")

    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
