"""Validate benign invariants against a potentially attacked signal database.

The validator accepts the invariant JSON produced by the Modbus, MQTT, and
OPC UA miners in this repository. It preserves the original CLI/report shape
while adding a protocol-neutral ``violations`` list for downstream consumers.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import duckdb


MIN_CORRELATION_PAIRS = 10
KNOWN_INVARIANT_TYPES = ["value_range", "inter_register", "inter_signal", "state_transition"]


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _json_number(value: Any, digits: int = 6) -> Optional[float]:
    if value is None:
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(result):
        return None
    return round(result, digits)


def _db_columns(conn: duckdb.Connection) -> set[str]:
    tables = {row[0] for row in conn.execute("SHOW TABLES").fetchall()}
    if "signal_observations" not in tables:
        raise ValueError("DuckDB file does not contain signal_observations")
    return {row[0] for row in conn.execute("DESCRIBE signal_observations").fetchall()}


def _infer_db_protocol(columns: set[str]) -> str:
    if {"signal_container_guid", "register_address", "function_code"} <= columns:
        return "modbus"
    if {"signal_guid", "topic", "field_name", "signal_name"} <= columns:
        return "mqtt"
    if {"signal_guid", "node_id", "display_name", "service_type"} <= columns:
        return "opcua"
    return "unknown"


def _infer_invariant_protocol(inv: dict, db_protocol: str) -> str:
    protocol = inv.get("protocol")
    if isinstance(protocol, str) and protocol:
        return protocol.lower()

    params = inv.get("parameters") or {}
    inv_type = inv.get("type")
    if inv_type == "inter_register" or "signal_container_guid" in inv:
        return "modbus"
    if "registers" in inv and ("unit_id" in inv or "register_a" in params):
        return "modbus"
    if "topic" in inv or "field_name" in inv or "topic_a" in params:
        return "mqtt"
    if "node_id" in inv or "display_name" in inv or "node_id_a" in params:
        return "opcua"
    return db_protocol


def _valid_signal_predicate(protocol: str, columns: set[str]) -> str:
    if protocol == "mqtt" and {"topic", "field_name", "signal_name"} <= columns:
        return (
            "isfinite(CAST(value AS DOUBLE)) "
            "AND topic <> '' AND field_name <> '' AND signal_name <> ''"
        )
    if protocol == "opcua" and "node_id" in columns:
        return "isfinite(CAST(value AS DOUBLE)) AND node_id NOT LIKE '%;s='"
    return "isfinite(CAST(value AS DOUBLE))"


def _signal_id(protocol: str, guid: Optional[str], server_host: Optional[str]) -> Optional[str]:
    if not guid:
        return None
    if protocol == "modbus" and server_host:
        return f"{guid}@{server_host}"
    return guid


def _signal_aliases(protocol: str, guid: Optional[str], server_host: Optional[str]) -> List[str]:
    aliases: List[str] = []
    primary = _signal_id(protocol, guid, server_host)
    if primary:
        aliases.append(primary)
    if guid and guid not in aliases:
        aliases.append(guid)
    return aliases


def _edge_key(guid_a: str, guid_b: str) -> Tuple[str, str]:
    """Canonical edge key so correlation lookup is direction-independent."""
    return (min(guid_a, guid_b), max(guid_a, guid_b))


def _where_sql(parts: List[str], predicate: str) -> str:
    clauses = list(parts)
    if predicate:
        clauses.append(predicate)
    return " AND ".join(f"({part})" for part in clauses) if clauses else "TRUE"


def _aggregate_values(
    conn: duckdb.Connection,
    where_parts: List[str],
    params: List[Any],
    predicate: str,
) -> Optional[Tuple[float, float, Optional[float], Optional[float], int]]:
    row = conn.execute(
        f"""
        SELECT
            MIN(CAST(value AS DOUBLE)),
            MAX(CAST(value AS DOUBLE)),
            AVG(CAST(value AS DOUBLE)),
            STDDEV_SAMP(CAST(value AS DOUBLE)),
            COUNT(*)
        FROM signal_observations
        WHERE {_where_sql(where_parts, predicate)}
        """,
        params,
    ).fetchone()
    if row is None or row[4] == 0:
        return None
    return row


def _first_value_violation_time(
    conn: duckdb.Connection,
    where_parts: List[str],
    params: List[Any],
    predicate: str,
    benign_min: float,
    benign_max: float,
) -> Optional[float]:
    row = conn.execute(
        f"""
        SELECT MIN(timestamp)
        FROM signal_observations
        WHERE {_where_sql(where_parts, predicate)}
          AND (CAST(value AS DOUBLE) < ? OR CAST(value AS DOUBLE) > ?)
        """,
        [*params, benign_min, benign_max],
    ).fetchone()
    return float(row[0]) if row and row[0] is not None else None


def _fallback_signal_id(protocol: str, identity: dict) -> str:
    if protocol == "modbus":
        return (
            f"modbus:{identity.get('server_host') or ''}:"
            f"unit:{identity.get('unit_id')}:reg:{identity.get('register')}"
        )
    return f"{protocol}:{identity}"


def _skip(inv: dict, protocol: str, reason: str) -> dict:
    return {
        "type": inv.get("type", "unknown"),
        "protocol": protocol,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Invariant identity helpers
# ---------------------------------------------------------------------------


def _value_identity(inv: dict, protocol: str) -> dict:
    if protocol == "modbus":
        registers = inv.get("registers") or []
        return {
            "signal_container_guid": inv.get("signal_container_guid"),
            "server_host": inv.get("server_host"),
            "register": registers[0] if registers else None,
            "unit_id": inv.get("unit_id"),
        }
    if protocol == "mqtt":
        return {
            "signal_guid": inv.get("signal_guid"),
            "server_host": inv.get("server_host"),
            "topic": inv.get("topic"),
            "field_name": inv.get("field_name"),
            "signal_name": inv.get("signal_name"),
        }
    if protocol == "opcua":
        return {
            "signal_guid": inv.get("signal_guid"),
            "server_host": inv.get("server_host"),
            "node_id": inv.get("node_id"),
            "display_name": inv.get("display_name"),
        }
    return dict(inv)


def _value_name(inv: dict, protocol: str) -> str:
    params = inv.get("parameters") or {}
    if protocol == "modbus":
        registers = inv.get("registers") or []
        reg = registers[0] if registers else None
        variable_names = params.get("variable_names") or {}
        return params.get("variable_name") or variable_names.get(str(reg)) or f"reg_{reg}"
    if protocol == "mqtt":
        return (
            inv.get("signal_name")
            or ".".join(part for part in [inv.get("topic"), inv.get("field_name")] if part)
            or inv.get("signal_guid")
            or "mqtt_signal"
        )
    if protocol == "opcua":
        return inv.get("display_name") or inv.get("node_id") or inv.get("signal_guid") or "opcua_signal"
    return inv.get("name") or "signal"


def _value_lookup_attempts(
    inv: dict,
    protocol: str,
    columns: set[str],
) -> List[Tuple[List[str], List[Any], dict, List[str]]]:
    identity = _value_identity(inv, protocol)
    attempts: List[Tuple[List[str], List[Any], dict, List[str]]] = []

    if protocol == "modbus":
        guid = identity.get("signal_container_guid")
        server_host = identity.get("server_host")
        if guid and "signal_container_guid" in columns:
            where = ["signal_container_guid = ?"]
            params: List[Any] = [guid]
            if server_host and "server_host" in columns:
                where.append("server_host = ?")
                params.append(server_host)
            aliases = _signal_aliases(protocol, guid, server_host)
            attempts.append((where, params, identity, aliases))

        register = identity.get("register")
        unit_id = identity.get("unit_id")
        if register is not None and "register_address" in columns:
            where = ["register_address = ?"]
            params = [register]
            if unit_id is not None and "unit_id" in columns:
                where.append("unit_id = ?")
                params.append(unit_id)
            if server_host and "server_host" in columns:
                where.append("server_host = ?")
                params.append(server_host)
            if "function_code" in columns:
                where.append("function_code NOT IN (1, 2, 5, 15)")
            aliases = _signal_aliases(protocol, guid, server_host)
            if not aliases:
                aliases = [_fallback_signal_id(protocol, identity)]
            attempts.append((where, params, identity, aliases))

    elif protocol in {"mqtt", "opcua"}:
        guid = identity.get("signal_guid")
        server_host = identity.get("server_host")
        if guid and "signal_guid" in columns:
            where = ["signal_guid = ?"]
            params = [guid]
            if server_host and "server_host" in columns:
                where.append("server_host = ?")
                params.append(server_host)
            attempts.append((where, params, identity, _signal_aliases(protocol, guid, server_host)))

    return attempts


# ---------------------------------------------------------------------------
# Value range checks
# ---------------------------------------------------------------------------


def _check_value_range(
    conn: duckdb.Connection,
    inv: dict,
    protocol: str,
    columns: set[str],
) -> Tuple[bool, Optional[dict], Optional[dict]]:
    params = inv.get("parameters") or {}
    benign_min = params.get("min")
    benign_max = params.get("max")
    if benign_min is None or benign_max is None:
        return False, None, _skip(inv, protocol, "value_range invariant is missing min/max")

    attempts = _value_lookup_attempts(inv, protocol, columns)
    if not attempts:
        return False, None, _skip(inv, protocol, "value_range invariant has no usable signal identity")

    predicate = _valid_signal_predicate(protocol, columns)
    selected = None
    stats = None
    for where, query_params, identity, aliases in attempts:
        stats = _aggregate_values(conn, where, query_params, predicate)
        if stats is not None:
            selected = (where, query_params, identity, aliases)
            break

    if selected is None or stats is None:
        return True, None, None

    where, query_params, identity, aliases = selected
    atk_min, atk_max, atk_mean, atk_std, atk_count = stats
    benign_mean = params.get("mean")
    benign_std = params.get("stddev") or 0

    violations: dict[str, str] = {}
    if atk_min < benign_min:
        violations["below_min"] = f"{atk_min} < {benign_min}"
    if atk_max > benign_max:
        violations["above_max"] = f"{atk_max} > {benign_max}"
    if benign_mean is not None and benign_std > 0 and atk_mean is not None:
        mean_shift = abs(atk_mean - benign_mean) / benign_std
        if mean_shift > 3.0:
            violations["mean_shift"] = (
                f"{mean_shift:.1f} sigma ({float(benign_mean):.1f} -> {float(atk_mean):.1f})"
            )

    if not violations:
        return True, None, None

    first_time = _first_value_violation_time(
        conn, where, query_params, predicate, float(benign_min), float(benign_max)
    )
    signal_id = aliases[0] if aliases else _fallback_signal_id(protocol, identity)
    name = _value_name(inv, protocol)
    violation = {
        "type": "value_range",
        "protocol": protocol,
        "name": name,
        "signal_ids": [signal_id],
        "signal_aliases": aliases or [signal_id],
        "identity": identity,
        "violations": violations,
        "first_violation_time": first_time,
        "benign": {
            "min": benign_min,
            "max": benign_max,
            "mean": benign_mean,
            "stddev": params.get("stddev"),
        },
        "attack": {
            "min": _json_number(atk_min),
            "max": _json_number(atk_max),
            "mean": _json_number(atk_mean),
            "stddev": _json_number(atk_std),
        },
        "observation_count": int(atk_count),
        # Backwards-compatible fields used by the original report.
        "benign_range": [benign_min, benign_max],
        "attack_range": [_json_number(atk_min), _json_number(atk_max)],
        "attack_obs": int(atk_count),
    }

    if protocol == "modbus":
        violation.update(
            {
                "register": identity.get("register"),
                "unit_id": identity.get("unit_id"),
                "signal_container_guid": identity.get("signal_container_guid"),
            }
        )
    elif protocol == "mqtt":
        violation.update(
            {
                "signal_guid": identity.get("signal_guid"),
                "topic": identity.get("topic"),
                "field_name": identity.get("field_name"),
                "signal_name": identity.get("signal_name"),
            }
        )
    elif protocol == "opcua":
        violation.update(
            {
                "signal_guid": identity.get("signal_guid"),
                "node_id": identity.get("node_id"),
                "display_name": identity.get("display_name"),
            }
        )

    return True, violation, None


# ---------------------------------------------------------------------------
# Correlation checks
# ---------------------------------------------------------------------------


def _correlation_signal_info(inv: dict, protocol: str) -> Optional[Tuple[dict, dict]]:
    params = inv.get("parameters") or {}
    if protocol == "modbus":
        reg_a = params.get("register_a")
        reg_b = params.get("register_b")
        return (
            {
                "signal_id": params.get("signal_guid_a"),
                "server_host": params.get("server_host_a") or inv.get("server_host"),
                "register": reg_a,
                "name": (params.get("variable_names") or {}).get(str(reg_a), f"reg_{reg_a}"),
            },
            {
                "signal_id": params.get("signal_guid_b"),
                "server_host": params.get("server_host_b") or inv.get("server_host"),
                "register": reg_b,
                "name": (params.get("variable_names") or {}).get(str(reg_b), f"reg_{reg_b}"),
            },
        )
    if protocol == "mqtt":
        return (
            {
                "signal_id": params.get("signal_guid_a"),
                "server_host": inv.get("server_host"),
                "topic": params.get("topic_a"),
                "field_name": params.get("field_name_a"),
                "name": params.get("signal_name_a") or params.get("topic_a") or "mqtt_signal_a",
            },
            {
                "signal_id": params.get("signal_guid_b"),
                "server_host": inv.get("server_host"),
                "topic": params.get("topic_b"),
                "field_name": params.get("field_name_b"),
                "name": params.get("signal_name_b") or params.get("topic_b") or "mqtt_signal_b",
            },
        )
    if protocol == "opcua":
        return (
            {
                "signal_id": params.get("signal_guid_a"),
                "server_host": inv.get("server_host"),
                "node_id": params.get("node_id_a"),
                "name": params.get("display_name_a") or params.get("node_id_a") or "opcua_signal_a",
            },
            {
                "signal_id": params.get("signal_guid_b"),
                "server_host": inv.get("server_host"),
                "node_id": params.get("node_id_b"),
                "name": params.get("display_name_b") or params.get("node_id_b") or "opcua_signal_b",
            },
        )
    return None


def _signal_where(
    protocol: str,
    columns: set[str],
    signal_guid: Optional[str],
    server_host: Optional[str],
) -> Optional[Tuple[List[str], List[Any]]]:
    if protocol == "modbus":
        signal_column = "signal_container_guid"
    else:
        signal_column = "signal_guid"
    if not signal_guid or signal_column not in columns:
        return None

    where = [f"{signal_column} = ?"]
    params: List[Any] = [signal_guid]
    if server_host and "server_host" in columns:
        where.append("server_host = ?")
        params.append(server_host)
    return where, params


def _correlation_stats(
    conn: duckdb.Connection,
    protocol: str,
    columns: set[str],
    source: dict,
    target: dict,
    max_pair_lag_seconds: Optional[float],
) -> Optional[Tuple[Optional[float], Optional[float], Optional[float], int]]:
    source_where = _signal_where(
        protocol, columns, source.get("signal_id"), source.get("server_host")
    )
    target_where = _signal_where(
        protocol, columns, target.get("signal_id"), target.get("server_host")
    )
    if source_where is None or target_where is None:
        return None

    predicate = _valid_signal_predicate(protocol, columns)
    where_a, params_a = source_where
    where_b, params_b = target_where
    lag_filter = ""
    lag_params: List[Any] = []
    if max_pair_lag_seconds is not None:
        lag_filter = "AND a.ts - b.ts <= ?"
        lag_params.append(max_pair_lag_seconds)

    row = conn.execute(
        f"""
        WITH a AS (
            SELECT timestamp AS ts, CAST(value AS DOUBLE) AS val_a
            FROM signal_observations
            WHERE {_where_sql(where_a, predicate)}
            ORDER BY timestamp
        ),
        b AS (
            SELECT timestamp AS ts, CAST(value AS DOUBLE) AS val_b
            FROM signal_observations
            WHERE {_where_sql(where_b, predicate)}
            ORDER BY timestamp
        ),
        paired AS (
            SELECT a.ts AS ts_a, b.ts AS ts_b, a.val_a, b.val_b
            FROM a ASOF JOIN b ON a.ts >= b.ts
            WHERE b.val_b IS NOT NULL
            {lag_filter}
        )
        SELECT
            CORR(val_a, val_b),
            REGR_SLOPE(val_b, val_a),
            REGR_INTERCEPT(val_b, val_a),
            COUNT(*)
        FROM paired
        """,
        [*params_a, *params_b, *lag_params],
    ).fetchone()
    if row is None:
        return None
    return row


def _check_correlation(
    conn: duckdb.Connection,
    inv: dict,
    protocol: str,
    columns: set[str],
) -> Tuple[bool, Optional[dict], Optional[dict]]:
    params = inv.get("parameters") or {}
    benign_r = params.get("pearson_r")
    if benign_r is None:
        return False, None, _skip(inv, protocol, "correlation invariant is missing pearson_r")

    info = _correlation_signal_info(inv, protocol)
    if info is None:
        return False, None, _skip(inv, protocol, "correlation invariant has unsupported protocol")
    source, target = info
    if not source.get("signal_id") or not target.get("signal_id"):
        return False, None, _skip(inv, protocol, "correlation invariant is missing signal IDs")

    max_lag = params.get("max_pair_lag_seconds")
    stats = _correlation_stats(conn, protocol, columns, source, target, max_lag)
    if stats is None:
        return True, None, None

    atk_r, atk_slope, atk_intercept, pair_count = stats
    if pair_count < MIN_CORRELATION_PAIRS:
        return True, None, None
    if atk_r is None or not math.isfinite(float(atk_r)):
        return True, None, None

    benign_slope = params.get("slope")
    benign_intercept = params.get("intercept")
    violations: dict[str, str] = {}

    r_drop = abs(float(benign_r)) - abs(float(atk_r))
    if r_drop > 0.1:
        violations["correlation_drop"] = (
            f"|r| {abs(float(benign_r)):.4f} -> {abs(float(atk_r)):.4f} "
            f"(drop={r_drop:.4f})"
        )
    if benign_slope is not None and atk_slope is not None and benign_slope != 0:
        slope_change = abs(float(atk_slope) - float(benign_slope)) / abs(float(benign_slope))
        if slope_change > 0.2:
            violations["slope_change"] = (
                f"{float(benign_slope):.4f} -> {float(atk_slope):.4f} "
                f"({slope_change * 100:.1f}% change)"
            )
    if benign_intercept is not None and atk_intercept is not None:
        int_change = abs(float(atk_intercept) - float(benign_intercept))
        if int_change > 50:
            violations["intercept_shift"] = (
                f"{float(benign_intercept):.2f} -> {float(atk_intercept):.2f} "
                f"(delta={int_change:.2f})"
            )

    if not violations:
        return True, None, None

    source_aliases = _signal_aliases(protocol, source.get("signal_id"), source.get("server_host"))
    target_aliases = _signal_aliases(protocol, target.get("signal_id"), target.get("server_host"))
    signal_ids = [source_aliases[0], target_aliases[0]]
    inv_type = inv.get("type", "inter_signal")
    name = f"{source['name']} ~ {target['name']}"
    violation = {
        "type": inv_type,
        "protocol": protocol,
        "name": name,
        "signal_ids": signal_ids,
        "signal_aliases": [source_aliases, target_aliases],
        "identity": {"source": source, "target": target},
        "violations": violations,
        "first_violation_time": None,
        "benign": {
            "pearson_r": benign_r,
            "slope": benign_slope,
            "intercept": benign_intercept,
            "relationship": params.get("relationship"),
        },
        "attack": {
            "pearson_r": _json_number(atk_r, 4),
            "slope": _json_number(atk_slope, 6),
            "intercept": _json_number(atk_intercept),
        },
        "observation_count": int(pair_count),
        # Backwards-compatible correlation fields.
        "signal_guid_a": source.get("signal_id"),
        "signal_guid_b": target.get("signal_id"),
        "benign_r": benign_r,
        "attack_r": _json_number(atk_r, 4),
        "attack_pairs": int(pair_count),
    }
    if protocol == "modbus":
        violation["registers"] = [source.get("register"), target.get("register")]
    return True, violation, None


# ---------------------------------------------------------------------------
# State transition checks
# ---------------------------------------------------------------------------


def _check_state_transition(
    conn: duckdb.Connection,
    inv: dict,
    protocol: str,
    columns: set[str],
) -> Tuple[bool, Optional[dict], Optional[dict]]:
    if protocol != "modbus":
        return False, None, _skip(inv, protocol, "state_transition is only supported for Modbus signals")
    if "register_address" not in columns:
        return False, None, _skip(inv, protocol, "state_transition requires register_address")

    params = inv.get("parameters") or {}
    from_state = params.get("from_state")
    to_state = params.get("to_state")
    registers = inv.get("registers") or params.get("guard_registers") or []
    state_register = registers[0] if registers else None
    if from_state is None or to_state is None or state_register is None:
        return False, None, _skip(inv, protocol, "state_transition is missing from/to/register")

    where = ["register_address = ?"]
    query_params: List[Any] = [state_register]
    if inv.get("unit_id") is not None and "unit_id" in columns:
        where.append("unit_id = ?")
        query_params.append(inv["unit_id"])
    if inv.get("server_host") and "server_host" in columns:
        where.append("server_host = ?")
        query_params.append(inv["server_host"])

    predicate = _valid_signal_predicate(protocol, columns)
    row = conn.execute(
        f"""
        WITH ordered AS (
            SELECT
                timestamp,
                CAST(value AS DOUBLE) AS value,
                LAG(CAST(value AS DOUBLE)) OVER (ORDER BY timestamp) AS prev_value
            FROM signal_observations
            WHERE {_where_sql(where, predicate)}
        )
        SELECT timestamp, prev_value, value
        FROM ordered
        WHERE prev_value = ?
          AND value <> ?
          AND value <> ?
        ORDER BY timestamp
        LIMIT 1
        """,
        [*query_params, from_state, from_state, to_state],
    ).fetchone()

    if row is None:
        return True, None, None

    count_row = conn.execute(
        f"SELECT COUNT(*) FROM signal_observations WHERE {_where_sql(where, predicate)}",
        query_params,
    ).fetchone()
    obs_count = int(count_row[0]) if count_row else 0
    name = inv.get("state_name") or f"state_{from_state}_to_{to_state}"
    identity = {
        "register": state_register,
        "unit_id": inv.get("unit_id"),
        "server_host": inv.get("server_host"),
        "from_state": from_state,
        "to_state": to_state,
    }
    signal_id = _fallback_signal_id(protocol, identity)
    violation = {
        "type": "state_transition",
        "protocol": protocol,
        "name": name,
        "signal_ids": [signal_id],
        "signal_aliases": [signal_id],
        "identity": identity,
        "violations": {
            "unexpected_transition": f"{row[1]} -> {row[2]} expected {from_state} -> {to_state}"
        },
        "first_violation_time": float(row[0]),
        "benign": {"from_state": from_state, "to_state": to_state},
        "attack": {"from_state": _json_number(row[1]), "to_state": _json_number(row[2])},
        "observation_count": obs_count,
        "register": state_register,
        "unit_id": inv.get("unit_id"),
    }
    return True, violation, None


# ---------------------------------------------------------------------------
# Correlation adjacency and tree construction
# ---------------------------------------------------------------------------


def _build_adjacency(data: dict, db_protocol: str) -> Dict[str, List[dict]]:
    """Build signal-id adjacency from correlation_graph or flat invariants."""
    adj: Dict[str, List[dict]] = {}

    graph = data.get("correlation_graph")
    if graph and graph.get("edges"):
        for edge in graph["edges"]:
            src, tgt = edge["source"], edge["target"]
            info = {
                "pearson_r": edge.get("pearson_r"),
                "relationship": edge.get("relationship"),
            }
            adj.setdefault(src, []).append({"peer": tgt, **info})
            adj.setdefault(tgt, []).append({"peer": src, **info})
        return adj

    for inv in data.get("invariants", []):
        if inv.get("type") not in {"inter_register", "inter_signal"}:
            continue
        protocol = _infer_invariant_protocol(inv, db_protocol)
        info = _correlation_signal_info(inv, protocol)
        if info is None:
            continue
        source, target = info
        source_id = _signal_id(protocol, source.get("signal_id"), source.get("server_host"))
        target_id = _signal_id(protocol, target.get("signal_id"), target.get("server_host"))
        if not source_id or not target_id:
            continue
        params = inv.get("parameters") or {}
        edge_info = {
            "pearson_r": params.get("pearson_r"),
            "relationship": params.get("relationship"),
        }
        adj.setdefault(source_id, []).append({"peer": target_id, **edge_info})
        adj.setdefault(target_id, []).append({"peer": source_id, **edge_info})
    return adj


def _store_correlation_violation(
    correlation_violations: Dict[Tuple[str, str], dict],
    violation: dict,
) -> None:
    aliases = violation.get("signal_aliases") or []
    if len(aliases) != 2:
        ids = violation.get("signal_ids") or []
        if len(ids) == 2:
            correlation_violations[_edge_key(ids[0], ids[1])] = violation
        return

    left_aliases = aliases[0] if isinstance(aliases[0], list) else [aliases[0]]
    right_aliases = aliases[1] if isinstance(aliases[1], list) else [aliases[1]]
    for left in left_aliases:
        for right in right_aliases:
            correlation_violations[_edge_key(left, right)] = violation


def _build_violation_forest(
    value_violations: Iterable[dict],
    adjacency: Dict[str, List[dict]],
    correlation_violations: Dict[Tuple[str, str], dict],
) -> Tuple[List[dict], List[dict]]:
    """Build a causal forest from value-range violations and correlation edges."""
    nodes = []
    for violation in value_violations:
        if violation.get("first_violation_time") is None:
            continue
        signal_ids = violation.get("signal_ids") or []
        if not signal_ids:
            continue
        node = {
            "signal_id": signal_ids[0],
            "aliases": violation.get("signal_aliases") or signal_ids,
            "first_violation_time": violation["first_violation_time"],
            "variable_name": violation.get("name"),
            "violation": violation,
            "children": [],
            "evidence": None,
        }
        nodes.append(node)

    if not nodes:
        return [], []

    sorted_nodes = sorted(nodes, key=lambda n: n["first_violation_time"])
    alias_lookup: Dict[str, dict] = {}
    for node in sorted_nodes:
        for alias in node["aliases"]:
            alias_lookup[alias] = node

    for node in sorted_nodes:
        neighbors = []
        seen_peers = set()
        for alias in node["aliases"]:
            for neighbor in adjacency.get(alias, []):
                peer = neighbor["peer"]
                if peer in seen_peers:
                    continue
                seen_peers.add(peer)
                neighbors.append(neighbor)

        best_parent = None
        best_time = -float("inf")
        best_edge_info: dict = {}
        for nb in neighbors:
            peer = alias_lookup.get(nb["peer"])
            if peer is None or peer is node:
                continue
            if peer["first_violation_time"] < node["first_violation_time"]:
                if peer["first_violation_time"] > best_time:
                    best_time = peer["first_violation_time"]
                    best_parent = peer
                    best_edge_info = nb

        if best_parent is not None:
            delay = node["first_violation_time"] - best_parent["first_violation_time"]
            corr_viol = None
            for parent_alias in best_parent["aliases"]:
                for node_alias in node["aliases"]:
                    corr_viol = correlation_violations.get(_edge_key(parent_alias, node_alias))
                    if corr_viol is not None:
                        break
                if corr_viol is not None:
                    break

            node["evidence"] = {
                "parent_guid": best_parent["signal_id"],
                "parent_variable": best_parent["variable_name"],
                "benign_correlation": best_edge_info.get("pearson_r"),
                "relationship": best_edge_info.get("relationship"),
                "delay_seconds": round(delay, 6),
                "correlation_violated": corr_viol is not None,
                "correlation_violation_detail": corr_viol,
            }
            best_parent["children"].append(node)

    roots = [n for n in sorted_nodes if n["evidence"] is None]
    violated_aliases = set(alias_lookup)
    true_roots = []
    orphans = []
    for root in roots:
        has_violated_neighbor = any(
            neighbor["peer"] in violated_aliases
            for alias in root["aliases"]
            for neighbor in adjacency.get(alias, [])
        )
        if root["children"] or has_violated_neighbor:
            true_roots.append(root)
        else:
            orphans.append(root)

    return true_roots, orphans


def _node_to_dict(node: dict) -> dict:
    result = dict(node["violation"])
    if node["evidence"] is not None:
        result["evidence"] = node["evidence"]
    if node["children"]:
        result["downstream"] = [_node_to_dict(child) for child in node["children"]]
    return result


# ---------------------------------------------------------------------------
# Main validation
# ---------------------------------------------------------------------------


def validate(
    invariants_path: Path,
    attack_db_path: Path,
    *,
    print_report: bool = True,
) -> dict:
    """Validate invariants against attack data and return a structured report."""
    with open(invariants_path) as f:
        data = json.load(f)

    conn = duckdb.connect(str(attack_db_path), read_only=True)
    columns = _db_columns(conn)
    db_protocol = _infer_db_protocol(columns)
    invariants = data.get("invariants", [])
    adjacency = _build_adjacency(data, db_protocol)

    checked_counts: Dict[str, int] = defaultdict(int)
    violations_by_type: Dict[str, List[dict]] = defaultdict(list)
    all_violations: List[dict] = []
    skipped: List[dict] = []
    correlation_violations: Dict[Tuple[str, str], dict] = {}

    for inv in invariants:
        inv_type = inv.get("type", "unknown")
        protocol = _infer_invariant_protocol(inv, db_protocol)
        if inv_type == "value_range":
            checked, violation, skip = _check_value_range(conn, inv, protocol, columns)
        elif inv_type in {"inter_register", "inter_signal"}:
            checked, violation, skip = _check_correlation(conn, inv, protocol, columns)
        elif inv_type == "state_transition":
            checked, violation, skip = _check_state_transition(conn, inv, protocol, columns)
        else:
            checked, violation, skip = False, None, _skip(inv, protocol, "unsupported invariant type")

        if checked:
            checked_counts[inv_type] += 1
        if skip is not None:
            skipped.append(skip)
        if violation is not None:
            all_violations.append(violation)
            violations_by_type[inv_type].append(violation)
            if inv_type in {"inter_register", "inter_signal"}:
                _store_correlation_violation(correlation_violations, violation)

    roots, orphans = _build_violation_forest(
        violations_by_type.get("value_range", []), adjacency, correlation_violations
    )
    conn.close()

    invariants_checked = {kind: checked_counts.get(kind, 0) for kind in KNOWN_INVARIANT_TYPES}
    invariants_checked["checked"] = sum(checked_counts.values())
    invariants_checked["skipped"] = len(skipped)
    invariants_checked["total"] = len(invariants)

    violations_detected = {
        kind: len(violations_by_type.get(kind, [])) for kind in KNOWN_INVARIANT_TYPES
    }
    violations_detected["total"] = len(all_violations)

    flat_violations = {kind: violations_by_type.get(kind, []) for kind in KNOWN_INVARIANT_TYPES}
    report = {
        "invariants_checked": invariants_checked,
        "violations_detected": violations_detected,
        "violations": _sort_violations(all_violations),
        "violation_trees": [_node_to_dict(root) for root in roots],
        "uncorrelated_violations": [_node_to_dict(orphan) for orphan in orphans],
        "flat_violations": flat_violations,
        "skipped_invariants": skipped,
    }

    if print_report:
        _print_report(report)
    return report


def validate_many(
    pairs: Iterable[Tuple[Path, Path]],
    *,
    print_report: bool = True,
) -> dict:
    """Validate multiple invariant/DB pairs and merge into one report."""
    input_reports = []
    checked_totals: Dict[str, int] = defaultdict(int)
    detected_totals: Dict[str, int] = defaultdict(int)
    flat_violations: Dict[str, List[dict]] = {kind: [] for kind in KNOWN_INVARIANT_TYPES}
    all_violations: List[dict] = []
    all_trees: List[dict] = []
    all_orphans: List[dict] = []
    all_skipped: List[dict] = []

    pair_list = list(pairs)
    if not pair_list:
        raise ValueError("At least one invariant/DB pair is required")

    for invariants_path, attack_db_path in pair_list:
        report = validate(invariants_path, attack_db_path, print_report=False)
        source = {
            "invariants_path": str(invariants_path),
            "attack_db_path": str(attack_db_path),
        }

        for key, value in report["invariants_checked"].items():
            checked_totals[key] += int(value)
        for key, value in report["violations_detected"].items():
            detected_totals[key] += int(value)

        for violation in report.get("violations", []):
            tagged = dict(violation)
            tagged["source"] = source
            all_violations.append(tagged)

        for kind in KNOWN_INVARIANT_TYPES:
            for violation in report.get("flat_violations", {}).get(kind, []):
                tagged = dict(violation)
                tagged["source"] = source
                flat_violations[kind].append(tagged)

        for tree in report.get("violation_trees", []):
            tagged = dict(tree)
            tagged["source"] = source
            all_trees.append(tagged)
        for orphan in report.get("uncorrelated_violations", []):
            tagged = dict(orphan)
            tagged["source"] = source
            all_orphans.append(tagged)
        for skipped in report.get("skipped_invariants", []):
            tagged = dict(skipped)
            tagged["source"] = source
            all_skipped.append(tagged)

        input_reports.append(
            {
                **source,
                "invariants_checked": report["invariants_checked"],
                "violations_detected": report["violations_detected"],
            }
        )

    merged = {
        "inputs": input_reports,
        "invariants_checked": dict(checked_totals),
        "violations_detected": dict(detected_totals),
        "violations": _sort_violations(all_violations),
        "violation_trees": all_trees,
        "uncorrelated_violations": all_orphans,
        "flat_violations": flat_violations,
        "skipped_invariants": all_skipped,
    }
    for kind in KNOWN_INVARIANT_TYPES:
        merged["invariants_checked"].setdefault(kind, 0)
        merged["violations_detected"].setdefault(kind, 0)
    merged["invariants_checked"].setdefault("checked", 0)
    merged["invariants_checked"].setdefault("skipped", 0)
    merged["invariants_checked"].setdefault("total", 0)
    merged["violations_detected"].setdefault("total", 0)

    if print_report:
        _print_report(merged, title="COMBINED INVARIANT VALIDATION REPORT")
    return merged


def _sort_violations(violations: Iterable[dict]) -> List[dict]:
    def key(v: dict) -> tuple:
        first_time = v.get("first_violation_time")
        missing_time = first_time is None
        return (
            missing_time,
            float(first_time) if first_time is not None else float("inf"),
            v.get("protocol") or "",
            v.get("type") or "",
            v.get("name") or "",
        )

    return sorted(violations, key=key)


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------


def _print_report(report: dict, *, title: str = "INVARIANT VALIDATION REPORT") -> None:
    checked = report["invariants_checked"]
    detected = report["violations_detected"]

    print(f"\n{'=' * 60}")
    print(title)
    print(f"{'=' * 60}")
    print(
        f"Checked: {checked.get('value_range', 0)} value-range, "
        f"{checked.get('inter_register', 0)} inter-register, "
        f"{checked.get('inter_signal', 0)} inter-signal, "
        f"{checked.get('state_transition', 0)} state-transition "
        f"(of {checked['total']} total; {checked.get('skipped', 0)} skipped)"
    )
    print(
        f"Violations: {detected.get('value_range', 0)} value-range, "
        f"{detected.get('inter_register', 0)} inter-register, "
        f"{detected.get('inter_signal', 0)} inter-signal, "
        f"{detected.get('state_transition', 0)} state-transition"
    )

    violations = report.get("violations") or []
    if violations:
        print(f"\n{'-' * 60}")
        print(f"VIOLATIONS ({len(violations)} total)")
        print(f"{'-' * 60}")
        for violation in violations:
            _print_violation(violation)

    trees = report["violation_trees"]
    orphans = report["uncorrelated_violations"]
    if trees:
        print(f"\n{'-' * 60}")
        print(f"VIOLATION TREES ({len(trees)} root cause(s) identified)")
        print(f"{'-' * 60}")
        for i, root in enumerate(trees):
            print(f"\nTree #{i + 1}:")
            _print_tree_node(root, indent=2)

    if orphans:
        print(f"\n{'-' * 60}")
        print(f"UNCORRELATED VALUE-RANGE VIOLATIONS ({len(orphans)} isolated)")
        print(f"{'-' * 60}")
        for orphan in orphans:
            _print_tree_node(orphan, indent=2)

    if not violations:
        print("\nNo violations detected; attack data is within checked invariant bounds.")


def _identity_label(violation: dict) -> str:
    identity = violation.get("identity") or {}
    if violation.get("protocol") == "modbus":
        reg = identity.get("register") or violation.get("register")
        unit_id = identity.get("unit_id") or violation.get("unit_id")
        return f"reg {reg}, unit {unit_id}"
    if violation.get("protocol") == "mqtt":
        return ".".join(
            part
            for part in [
                identity.get("topic") or violation.get("topic"),
                identity.get("field_name") or violation.get("field_name"),
            ]
            if part
        ) or str((violation.get("signal_ids") or ["unknown"])[0])
    if violation.get("protocol") == "opcua":
        return identity.get("node_id") or violation.get("node_id") or str(
            (violation.get("signal_ids") or ["unknown"])[0]
        )
    return str(identity or (violation.get("signal_ids") or ["unknown"])[0])


def _print_violation(violation: dict, indent: int = 2) -> None:
    pad = " " * indent
    first_time = violation.get("first_violation_time")
    time_text = f"t={first_time:.4f}" if first_time is not None else "t=n/a"
    print(
        f"{pad}- [{violation.get('protocol')}/{violation.get('type')}] "
        f"{violation.get('name')} ({_identity_label(violation)}) {time_text}"
    )
    for kind, desc in violation.get("violations", {}).items():
        print(f"{pad}  {kind}: {desc}")

    benign = violation.get("benign") or {}
    attack = violation.get("attack") or {}
    if violation.get("type") == "value_range":
        print(
            f"{pad}  benign range: [{benign.get('min')}, {benign.get('max')}], "
            f"attack range: [{attack.get('min')}, {attack.get('max')}], "
            f"obs={violation.get('observation_count')}"
        )
    elif violation.get("type") in {"inter_register", "inter_signal"}:
        print(
            f"{pad}  benign r: {benign.get('pearson_r')}, "
            f"attack r: {attack.get('pearson_r')}, "
            f"pairs={violation.get('observation_count')}"
        )


def _print_tree_node(node: dict, indent: int = 0) -> None:
    pad = " " * indent
    name = node.get("name", "signal")
    first_time = node.get("first_violation_time")
    time_text = f"t={first_time:.4f}" if first_time is not None else "t=n/a"
    evidence = node.get("evidence")
    if evidence:
        delay = evidence["delay_seconds"]
        corr = evidence["benign_correlation"]
        parent = evidence["parent_variable"]
        broke = " [correlation BROKEN]" if evidence["correlation_violated"] else ""
        print(f"{pad}- {name} {time_text} (+{delay:.4f}s from {parent}, r={corr}){broke}")
    else:
        print(f"{pad}- {name} {time_text} [ROOT CAUSE]")
    for kind, desc in node.get("violations", {}).items():
        print(f"{pad}  {kind}: {desc}")
    for child in node.get("downstream", []):
        _print_tree_node(child, indent + 4)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate benign invariants against attack signal DuckDBs. "
            "Use the legacy positional form for one pair, or repeat --pair "
            "to combine Modbus, MQTT, and OPC UA results into one report."
        )
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Legacy form: <invariants.json> <attack.duckdb> [output.json].",
    )
    parser.add_argument(
        "--pair",
        action="append",
        nargs=2,
        metavar=("INVARIANTS_JSON", "ATTACK_DUCKDB"),
        help="Invariant/DB pair. Repeat for Modbus, MQTT, OPC UA, etc.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write the structured report JSON to this path.",
    )
    args = parser.parse_args(argv)

    if args.pair:
        if args.paths:
            parser.error("Do not mix --pair with positional legacy arguments")
        return args

    if len(args.paths) not in {2, 3}:
        parser.error(
            "use either <invariants.json> <attack.duckdb> [output.json] "
            "or one or more --pair <invariants.json> <attack.duckdb>"
        )
    if args.output and len(args.paths) == 3:
        parser.error("provide output either as legacy third positional arg or --output, not both")
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    if args.pair:
        pairs = [(Path(invariants), Path(db)) for invariants, db in args.pair]
        report = validate_many(pairs)
        output = args.output
    else:
        invariants_path = Path(args.paths[0])
        attack_db_path = Path(args.paths[1])
        report = validate(invariants_path, attack_db_path)
        output = args.output or (Path(args.paths[2]) if len(args.paths) == 3 else None)

    if output is not None:
        output.write_text(json.dumps(report, indent=2))
        print(f"\nStructured report written to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
