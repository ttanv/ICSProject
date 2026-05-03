"""Standalone OPC UA invariant extraction from an OPC UA signal DuckDB.

This intentionally runs beside the Modbus-oriented invariant pipeline instead
of forcing OPC UA node IDs into Modbus register fields.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


REQUIRED_COLUMNS = {
    "timestamp",
    "node_id",
    "display_name",
    "value",
    "access_type",
    "service_type",
    "client_host",
    "server_host",
    "client_ip",
    "server_ip",
    "request_id",
    "secure_channel_id",
    "signal_guid",
    "pcap_file",
}

VALID_SIGNAL_PREDICATE = "isfinite(value) AND node_id NOT LIKE '%;s='"


@dataclass(frozen=True)
class OpcUaInvariantConfig:
    """Configuration for standalone OPC UA invariant extraction."""

    signal_db: Path
    output: Path = Path("opcua_invariants.json")
    baseline_hours: Optional[float] = None
    min_observations: int = 10
    correlation_threshold: float = 0.7
    max_signals_per_server: int = 50
    skip_correlations: bool = False
    exclude_binary_value_ranges: bool = False
    include_binary_correlations: bool = False
    max_pair_lag_seconds: Optional[float] = 5.0


def _json_number(value: Any, digits: int = 6) -> Optional[float]:
    if value is None:
        return None
    result = float(value)
    if not math.isfinite(result):
        return None
    return round(result, digits)


def _csv_set(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return sorted({item for item in value.split(",") if item})


def _ensure_schema(conn: Any) -> None:
    tables = {row[0] for row in conn.execute("SHOW TABLES").fetchall()}
    if "signal_observations" not in tables:
        raise ValueError("DuckDB file does not contain signal_observations")

    rows = conn.execute("DESCRIBE signal_observations").fetchall()
    columns = {row[0] for row in rows}
    missing = sorted(REQUIRED_COLUMNS - columns)
    if missing:
        raise ValueError(
            "signal_observations is not an OPC UA signal table; "
            f"missing columns: {', '.join(missing)}"
        )


def _time_window(
    conn: Any,
    baseline_hours: Optional[float],
) -> Tuple[Optional[float], Optional[float], int]:
    row = conn.execute(
        f"""
        SELECT MIN(timestamp), MAX(timestamp), COUNT(*)
        FROM signal_observations
        WHERE {VALID_SIGNAL_PREDICATE}
        """
    ).fetchone()
    if row is None or row[2] == 0:
        return None, None, 0

    start_ts = float(row[0])
    end_ts = float(row[1])
    if baseline_hours is not None:
        end_ts = min(end_ts, start_ts + baseline_hours * 3600.0)

    total = conn.execute(
        f"""
        SELECT COUNT(*)
        FROM signal_observations
        WHERE timestamp >= ? AND timestamp <= ? AND {VALID_SIGNAL_PREDICATE}
        """,
        [start_ts, end_ts],
    ).fetchone()[0]
    return start_ts, end_ts, int(total)


def mine_value_ranges(
    conn: Any,
    start_ts: float,
    end_ts: float,
    *,
    min_observations: int = 10,
    exclude_binary: bool = False,
) -> List[Dict[str, Any]]:
    """Mine per-OPC-UA-node value range invariants."""

    binary_filter = ""
    if exclude_binary:
        binary_filter = "AND NOT (MIN(value) IN (0, 1) AND MAX(value) IN (0, 1))"

    rows = conn.execute(
        f"""
        SELECT
            signal_guid,
            ANY_VALUE(node_id) AS node_id,
            ANY_VALUE(display_name) AS display_name,
            ANY_VALUE(server_host) AS server_host,
            STRING_AGG(DISTINCT client_host, ',') AS client_hosts,
            STRING_AGG(DISTINCT service_type, ',') AS service_types,
            MIN(value) AS min_val,
            MAX(value) AS max_val,
            AVG(value) AS mean_val,
            STDDEV_SAMP(value) AS stddev_val,
            COUNT(*) AS obs_count,
            COUNT(DISTINCT value) AS distinct_values,
            SUM(CASE WHEN access_type = 'read' THEN 1 ELSE 0 END) AS read_count,
            SUM(CASE WHEN access_type = 'write' THEN 1 ELSE 0 END) AS write_count,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen
        FROM signal_observations
        WHERE timestamp >= ? AND timestamp <= ? AND {VALID_SIGNAL_PREDICATE}
        GROUP BY signal_guid
        HAVING COUNT(*) >= ?
        {binary_filter}
        ORDER BY server_host, display_name, signal_guid
        """,
        [start_ts, end_ts, min_observations],
    ).fetchall()

    invariants: List[Dict[str, Any]] = []
    for row in rows:
        (
            signal_guid,
            node_id,
            display_name,
            server_host,
            client_hosts,
            service_types,
            min_val,
            max_val,
            mean_val,
            stddev_val,
            obs_count,
            distinct_values,
            read_count,
            write_count,
            first_seen,
            last_seen,
        ) = row

        invariants.append(
            {
                "type": "value_range",
                "protocol": "opcua",
                "signal_guid": signal_guid,
                "node_id": node_id,
                "display_name": display_name,
                "server_host": server_host,
                "client_hosts": _csv_set(client_hosts),
                "confidence": min(1.0, int(obs_count) / 100.0),
                "observation_count": int(obs_count),
                "parameters": {
                    "min": _json_number(min_val),
                    "max": _json_number(max_val),
                    "mean": _json_number(mean_val),
                    "stddev": _json_number(stddev_val),
                    "distinct_values": int(distinct_values),
                    "read_count": int(read_count),
                    "write_count": int(write_count),
                    "first_seen": _json_number(first_seen),
                    "last_seen": _json_number(last_seen),
                    "service_types": _csv_set(service_types),
                    "binary_like": min_val in (0, 1) and max_val in (0, 1),
                    "constant": min_val == max_val,
                },
            }
        )

    return invariants


def _eligible_correlation_signals(
    conn: Any,
    start_ts: float,
    end_ts: float,
    *,
    min_observations: int,
    max_signals_per_server: int,
    include_binary: bool,
) -> List[Tuple[str, str, str, str, int]]:
    binary_filter = ""
    if not include_binary:
        binary_filter = "AND NOT (MIN(value) IN (0, 1) AND MAX(value) IN (0, 1))"

    effective_min_observations = max(min_observations, 30)
    rows = conn.execute(
        f"""
        WITH signal_counts AS (
            SELECT
                signal_guid,
                ANY_VALUE(node_id) AS node_id,
                ANY_VALUE(display_name) AS display_name,
                ANY_VALUE(server_host) AS server_host,
                COUNT(*) AS obs_count,
                COUNT(DISTINCT value) AS distinct_values,
                STDDEV_SAMP(value) AS stddev_val
            FROM signal_observations
            WHERE timestamp >= ? AND timestamp <= ? AND {VALID_SIGNAL_PREDICATE}
            GROUP BY signal_guid
            HAVING COUNT(*) >= ?
               AND COUNT(DISTINCT value) > 1
               AND STDDEV_SAMP(value) > 0
               {binary_filter}
        ),
        ranked AS (
            SELECT *, ROW_NUMBER() OVER (
                PARTITION BY server_host
                ORDER BY obs_count DESC, display_name, signal_guid
            ) AS rn
            FROM signal_counts
        )
        SELECT signal_guid, node_id, display_name, server_host, obs_count
        FROM ranked
        WHERE rn <= ?
        ORDER BY server_host, display_name, signal_guid
        """,
        [start_ts, end_ts, effective_min_observations, max_signals_per_server],
    ).fetchall()

    return [
        (str(guid), str(node_id), str(display_name), str(server_host), int(obs_count))
        for guid, node_id, display_name, server_host, obs_count in rows
    ]


def mine_inter_signal_correlations(
    conn: Any,
    start_ts: float,
    end_ts: float,
    *,
    min_observations: int = 10,
    correlation_threshold: float = 0.7,
    max_signals_per_server: int = 50,
    include_binary: bool = False,
    max_pair_lag_seconds: Optional[float] = 5.0,
) -> List[Dict[str, Any]]:
    """Mine Pearson correlations between OPC UA signals on the same server."""

    eligible = _eligible_correlation_signals(
        conn,
        start_ts,
        end_ts,
        min_observations=min_observations,
        max_signals_per_server=max_signals_per_server,
        include_binary=include_binary,
    )

    by_server: Dict[str, List[Tuple[str, str, str, int]]] = {}
    for signal_guid, node_id, display_name, server_host, obs_count in eligible:
        by_server.setdefault(server_host, []).append(
            (signal_guid, node_id, display_name, obs_count)
        )

    lag_filter = ""
    query_args_with_lag = max_pair_lag_seconds is not None
    if query_args_with_lag:
        lag_filter = "AND a.ts - b.ts <= ?"

    invariants: List[Dict[str, Any]] = []
    for server_host, signals in sorted(by_server.items()):
        for i, signal_a in enumerate(signals):
            for signal_b in signals[i + 1 :]:
                guid_a, node_a, name_a, _ = signal_a
                guid_b, node_b, name_b, _ = signal_b

                params: List[Any] = [
                    guid_a,
                    start_ts,
                    end_ts,
                    guid_b,
                    start_ts,
                    end_ts,
                ]
                if query_args_with_lag:
                    params.append(max_pair_lag_seconds)

                result = conn.execute(
                    f"""
                    WITH a AS (
                        SELECT timestamp AS ts, value AS val_a
                        FROM signal_observations
                        WHERE signal_guid = ?
                          AND timestamp >= ? AND timestamp <= ?
                          AND {VALID_SIGNAL_PREDICATE}
                        ORDER BY timestamp
                    ),
                    b AS (
                        SELECT timestamp AS ts, value AS val_b
                        FROM signal_observations
                        WHERE signal_guid = ?
                          AND timestamp >= ? AND timestamp <= ?
                          AND {VALID_SIGNAL_PREDICATE}
                        ORDER BY timestamp
                    ),
                    paired AS (
                        SELECT a.ts AS ts_a, b.ts AS ts_b, a.val_a, b.val_b
                        FROM a ASOF JOIN b ON a.ts >= b.ts
                        WHERE b.val_b IS NOT NULL
                        {lag_filter}
                    )
                    SELECT
                        CORR(val_a, val_b) AS pearson_r,
                        REGR_SLOPE(val_b, val_a) AS slope,
                        REGR_INTERCEPT(val_b, val_a) AS intercept,
                        COUNT(*) AS pair_count,
                        AVG(ts_a - ts_b) AS avg_lag_seconds,
                        MAX(ts_a - ts_b) AS max_lag_seconds
                    FROM paired
                    """,
                    params,
                ).fetchone()

                if result is None:
                    continue
                pearson_r, slope, intercept, pair_count, avg_lag, max_lag = result
                if (
                    pearson_r is None
                    or not math.isfinite(float(pearson_r))
                    or int(pair_count) < min_observations
                    or abs(float(pearson_r)) < correlation_threshold
                ):
                    continue

                relationship = "positive" if pearson_r > 0 else "negative"
                invariants.append(
                    {
                        "type": "inter_signal",
                        "protocol": "opcua",
                        "server_host": server_host,
                        "signals": [
                            {
                                "signal_guid": guid_a,
                                "node_id": node_a,
                                "display_name": name_a,
                            },
                            {
                                "signal_guid": guid_b,
                                "node_id": node_b,
                                "display_name": name_b,
                            },
                        ],
                        "confidence": min(1.0, int(pair_count) / 100.0),
                        "observation_count": int(pair_count),
                        "parameters": {
                            "signal_guid_a": guid_a,
                            "signal_guid_b": guid_b,
                            "node_id_a": node_a,
                            "node_id_b": node_b,
                            "display_name_a": name_a,
                            "display_name_b": name_b,
                            "pearson_r": _json_number(pearson_r, 4),
                            "slope": _json_number(slope, 6),
                            "intercept": _json_number(intercept),
                            "relationship": relationship,
                            "avg_pair_lag_seconds": _json_number(avg_lag),
                            "max_pair_lag_seconds": _json_number(max_lag),
                        },
                    }
                )

    return invariants


def _build_correlation_graph(
    value_ranges: Sequence[Dict[str, Any]],
    correlations: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: Dict[str, Any] = {}
    for inv in value_ranges:
        params = inv["parameters"]
        nodes[inv["signal_guid"]] = {
            "node_id": inv["node_id"],
            "display_name": inv["display_name"],
            "server_host": inv["server_host"],
            "min": params["min"],
            "max": params["max"],
            "observation_count": inv["observation_count"],
        }

    edges = []
    for inv in correlations:
        params = inv["parameters"]
        edges.append(
            {
                "source": params["signal_guid_a"],
                "target": params["signal_guid_b"],
                "pearson_r": params["pearson_r"],
                "slope": params["slope"],
                "intercept": params["intercept"],
                "relationship": params["relationship"],
            }
        )

    return {"nodes": nodes, "edges": edges}


def _summarize_signals(
    conn: Any,
    start_ts: float,
    end_ts: float,
    *,
    min_observations: int,
) -> Dict[str, Any]:
    row = conn.execute(
        f"""
        WITH per_signal AS (
            SELECT
                signal_guid,
                MIN(value) AS min_val,
                MAX(value) AS max_val,
                COUNT(*) AS obs_count
            FROM signal_observations
            WHERE timestamp >= ? AND timestamp <= ? AND {VALID_SIGNAL_PREDICATE}
            GROUP BY signal_guid
        )
        SELECT
            COUNT(*) AS signal_count,
            SUM(CASE WHEN obs_count >= ? THEN 1 ELSE 0 END) AS signals_with_min_obs,
            SUM(CASE WHEN min_val <> max_val THEN 1 ELSE 0 END) AS varying_signals,
            SUM(CASE WHEN obs_count >= ? AND min_val <> max_val THEN 1 ELSE 0 END)
                AS varying_signals_with_min_obs,
            SUM(CASE WHEN min_val IN (0, 1) AND max_val IN (0, 1) THEN 1 ELSE 0 END)
                AS binary_like_signals
        FROM per_signal
        """,
        [start_ts, end_ts, min_observations, min_observations],
    ).fetchone()

    access_rows = conn.execute(
        f"""
        SELECT access_type, COUNT(*)
        FROM signal_observations
        WHERE timestamp >= ? AND timestamp <= ? AND {VALID_SIGNAL_PREDICATE}
        GROUP BY access_type
        ORDER BY COUNT(*) DESC
        """,
        [start_ts, end_ts],
    ).fetchall()

    server_rows = conn.execute(
        f"""
        SELECT server_host, COUNT(DISTINCT signal_guid) AS signal_count, COUNT(*) AS obs_count
        FROM signal_observations
        WHERE timestamp >= ? AND timestamp <= ? AND {VALID_SIGNAL_PREDICATE}
        GROUP BY server_host
        ORDER BY obs_count DESC
        """,
        [start_ts, end_ts],
    ).fetchall()

    return {
        "signals": int(row[0] or 0),
        "signals_with_min_observations": int(row[1] or 0),
        "varying_signals": int(row[2] or 0),
        "varying_signals_with_min_observations": int(row[3] or 0),
        "binary_like_signals": int(row[4] or 0),
        "observations_by_access_type": {
            str(access_type): int(count) for access_type, count in access_rows
        },
        "servers": [
            {
                "server_host": str(server_host),
                "signal_count": int(signal_count),
                "observation_count": int(obs_count),
            }
            for server_host, signal_count, obs_count in server_rows
        ],
    }


def mine_opcua_invariants(config: OpcUaInvariantConfig) -> Dict[str, Any]:
    """Run OPC UA invariant mining and return a JSON-serializable report."""
    try:
        import duckdb
    except ImportError as exc:
        raise ImportError(
            "DuckDB is required for OPC UA invariant extraction. "
            "Install it with: pip install duckdb"
        ) from exc

    conn = duckdb.connect(str(config.signal_db), read_only=True)
    try:
        _ensure_schema(conn)
        start_ts, end_ts, total_obs = _time_window(conn, config.baseline_hours)
        if start_ts is None or end_ts is None:
            return {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "protocol": "opcua",
                "signal_db_path": str(config.signal_db),
                "baseline_hours": config.baseline_hours,
                "total_observations_used": 0,
                "signal_summary": {},
                "correlation_graph": {"nodes": {}, "edges": []},
                "invariants": [],
            }

        value_ranges = mine_value_ranges(
            conn,
            start_ts,
            end_ts,
            min_observations=config.min_observations,
            exclude_binary=config.exclude_binary_value_ranges,
        )
        correlations: List[Dict[str, Any]] = []
        if not config.skip_correlations:
            correlations = mine_inter_signal_correlations(
                conn,
                start_ts,
                end_ts,
                min_observations=config.min_observations,
                correlation_threshold=config.correlation_threshold,
                max_signals_per_server=config.max_signals_per_server,
                include_binary=config.include_binary_correlations,
                max_pair_lag_seconds=config.max_pair_lag_seconds,
            )

        invariants = value_ranges + correlations
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "protocol": "opcua",
            "signal_db_path": str(config.signal_db),
            "baseline_hours": config.baseline_hours,
            "time_window": {
                "start": _json_number(start_ts),
                "end": _json_number(end_ts),
            },
            "total_observations_used": total_obs,
            "miner_config": {
                "min_observations": config.min_observations,
                "correlation_threshold": config.correlation_threshold,
                "max_signals_per_server": config.max_signals_per_server,
                "skip_correlations": config.skip_correlations,
                "exclude_binary_value_ranges": config.exclude_binary_value_ranges,
                "include_binary_correlations": config.include_binary_correlations,
                "max_pair_lag_seconds": config.max_pair_lag_seconds,
            },
            "signal_summary": _summarize_signals(
                conn,
                start_ts,
                end_ts,
                min_observations=config.min_observations,
            ),
            "correlation_graph": _build_correlation_graph(value_ranges, correlations),
            "invariants": invariants,
        }
    finally:
        conn.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract SAIN-style invariants from an OPC UA signal DuckDB."
    )
    parser.add_argument(
        "signal_db",
        type=Path,
        help="Path to an OPC UA *_signals.duckdb file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("opcua_invariants.json"),
        help="Output JSON path (default: opcua_invariants.json).",
    )
    parser.add_argument(
        "--baseline-hours",
        type=float,
        default=None,
        help="Use the first N hours of observations as baseline.",
    )
    parser.add_argument(
        "--min-observations",
        type=int,
        default=10,
        help="Minimum observations per signal or signal pair (default: 10).",
    )
    parser.add_argument(
        "--correlation-threshold",
        type=float,
        default=0.7,
        help="Minimum absolute Pearson r for correlations (default: 0.7).",
    )
    parser.add_argument(
        "--max-signals-per-server",
        type=int,
        default=50,
        help="Cap correlation search to the top N observed signals per server.",
    )
    parser.add_argument(
        "--skip-correlations",
        action="store_true",
        help="Only mine value-range invariants.",
    )
    parser.add_argument(
        "--exclude-binary-value-ranges",
        action="store_true",
        help="Drop value-range invariants whose observed range is only 0/1.",
    )
    parser.add_argument(
        "--include-binary-correlations",
        action="store_true",
        help="Allow 0/1-like signals in correlation mining.",
    )
    parser.add_argument(
        "--max-pair-lag-seconds",
        type=float,
        default=5.0,
        help="ASOF pair lag cap for correlation samples (default: 5.0).",
    )
    parser.add_argument(
        "--disable-pair-lag-cap",
        action="store_true",
        help="Disable the default ASOF pair lag cap for correlation samples.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = OpcUaInvariantConfig(
        signal_db=args.signal_db,
        output=args.output,
        baseline_hours=args.baseline_hours,
        min_observations=args.min_observations,
        correlation_threshold=args.correlation_threshold,
        max_signals_per_server=args.max_signals_per_server,
        skip_correlations=args.skip_correlations,
        exclude_binary_value_ranges=args.exclude_binary_value_ranges,
        include_binary_correlations=args.include_binary_correlations,
        max_pair_lag_seconds=(
            None if args.disable_pair_lag_cap else args.max_pair_lag_seconds
        ),
    )
    result = mine_opcua_invariants(config)

    config.output.parent.mkdir(parents=True, exist_ok=True)
    config.output.write_text(json.dumps(result, indent=2))

    invariant_types: Dict[str, int] = {}
    for inv in result["invariants"]:
        invariant_types[inv["type"]] = invariant_types.get(inv["type"], 0) + 1
    print(
        f"Wrote {len(result['invariants'])} OPC UA invariants to {config.output} "
        f"from {result['total_observations_used']} observations "
        f"({invariant_types})"
    )


if __name__ == "__main__":
    main()
