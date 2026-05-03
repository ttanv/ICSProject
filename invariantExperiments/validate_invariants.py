"""Validate benign invariants against a (potentially attacked) signal database.

For each invariant, checks whether the attack data violates the benign-learned
bounds.  When violations are found, builds a **causal violation tree** using:

1. **Temporal evidence**: first-violation-time per register (earliest timestamp
   where a value exits its benign range).
2. **Correlation evidence**: the benign correlation graph tells us which
   registers are physically coupled.  Edges are directed from the
   earlier-violated register to the later one.
3. **Correlation-break evidence**: for each edge in the tree we also check
   whether the benign correlation still holds in the attack data.

The tree answers "what was the root-cause register, and what cascaded from it?"
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb


# ---------------------------------------------------------------------------
# Helpers — temporal violation detection
# ---------------------------------------------------------------------------

def _first_violation_time(
    conn: duckdb.Connection,
    guid: str,
    benign_min: float,
    benign_max: float,
) -> Optional[float]:
    """Return the earliest timestamp where a signal exits its benign [min, max]."""
    row = conn.execute(
        """
        SELECT MIN(timestamp)
        FROM signal_observations
        WHERE signal_container_guid = ?
          AND (value < ? OR value > ?)
        """,
        [guid, benign_min, benign_max],
    ).fetchone()
    return row[0] if row and row[0] is not None else None


def _first_violation_time_by_reg(
    conn: duckdb.Connection,
    register: int,
    unit_id: int,
    benign_min: float,
    benign_max: float,
) -> Optional[float]:
    """Fallback: find first violation by register address + unit_id."""
    row = conn.execute(
        """
        SELECT MIN(timestamp)
        FROM signal_observations
        WHERE register_address = ? AND unit_id = ?
          AND function_code NOT IN (1, 2, 5, 15)
          AND (value < ? OR value > ?)
        """,
        [register, unit_id, benign_min, benign_max],
    ).fetchone()
    return row[0] if row and row[0] is not None else None


# ---------------------------------------------------------------------------
# Helpers — aggregate violation checks (kept from original)
# ---------------------------------------------------------------------------

def _check_value_range(
    conn: duckdb.Connection,
    inv: dict,
) -> Optional[dict]:
    """Check a single value_range invariant.  Returns violation dict or None."""
    guid = inv["signal_container_guid"]
    params = inv["parameters"]
    if guid is None:
        return None

    row = conn.execute(
        """
        SELECT MIN(value), MAX(value), AVG(value), STDDEV_SAMP(value), COUNT(*)
        FROM signal_observations
        WHERE signal_container_guid = ?
        """,
        [guid],
    ).fetchone()

    if row is None or row[4] == 0:
        reg = inv["registers"][0]
        unit_id = inv["unit_id"]
        row = conn.execute(
            """
            SELECT MIN(value), MAX(value), AVG(value), STDDEV_SAMP(value), COUNT(*)
            FROM signal_observations
            WHERE register_address = ? AND unit_id = ?
              AND function_code NOT IN (1, 2, 5, 15)
            """,
            [reg, unit_id],
        ).fetchone()

    if row is None or row[4] == 0:
        return None

    atk_min, atk_max, atk_mean, atk_std, atk_count = row
    benign_min = params["min"]
    benign_max = params["max"]
    benign_mean = params["mean"]
    benign_std = params["stddev"] or 0

    v: dict[str, str] = {}
    if atk_min < benign_min:
        v["below_min"] = f"{atk_min} < {benign_min}"
    if atk_max > benign_max:
        v["above_max"] = f"{atk_max} > {benign_max}"
    if benign_std > 0:
        mean_shift = abs(atk_mean - benign_mean) / benign_std
        if mean_shift > 3.0:
            v["mean_shift"] = f"{mean_shift:.1f} sigma ({benign_mean:.1f} -> {atk_mean:.1f})"

    if not v:
        return None

    name = params.get("variable_name", f"reg_{inv['registers'][0]}")
    return {
        "type": "value_range",
        "name": name,
        "register": inv["registers"][0],
        "unit_id": inv["unit_id"],
        "signal_container_guid": guid,
        "violations": v,
        "benign_range": [benign_min, benign_max],
        "attack_range": [atk_min, atk_max],
        "attack_obs": atk_count,
    }


def _check_inter_register(
    conn: duckdb.Connection,
    inv: dict,
) -> Optional[dict]:
    """Check a single inter_register invariant.  Returns violation dict or None."""
    params = inv["parameters"]
    guid_a = params.get("signal_guid_a")
    guid_b = params.get("signal_guid_b")
    if not guid_a or not guid_b:
        return None

    benign_r = params["pearson_r"]
    benign_slope = params.get("slope")
    benign_intercept = params.get("intercept")

    result = conn.execute(
        """
        WITH a AS (
            SELECT timestamp AS ts, value AS val_a
            FROM signal_observations
            WHERE signal_container_guid = ?
            ORDER BY timestamp
        ),
        b AS (
            SELECT timestamp AS ts, value AS val_b
            FROM signal_observations
            WHERE signal_container_guid = ?
            ORDER BY timestamp
        ),
        paired AS (
            SELECT a.val_a, b.val_b
            FROM a ASOF JOIN b ON a.ts >= b.ts
            WHERE b.val_b IS NOT NULL
        )
        SELECT CORR(val_a, val_b),
               REGR_SLOPE(val_b, val_a),
               REGR_INTERCEPT(val_b, val_a),
               COUNT(*)
        FROM paired
        """,
        [guid_a, guid_b],
    ).fetchone()

    if result is None or result[3] < 10:
        return None

    atk_r, atk_slope, atk_intercept, pair_count = result
    if atk_r is None or math.isnan(atk_r):
        return None

    reg_a, reg_b = params["register_a"], params["register_b"]
    names = params.get("variable_names", {})
    name_a = names.get(str(reg_a), f"reg_{reg_a}")
    name_b = names.get(str(reg_b), f"reg_{reg_b}")

    v: dict[str, str] = {}
    r_drop = abs(benign_r) - abs(atk_r)
    if r_drop > 0.1:
        v["correlation_drop"] = f"|r| {abs(benign_r):.4f} -> {abs(atk_r):.4f} (drop={r_drop:.4f})"
    if benign_slope is not None and atk_slope is not None and benign_slope != 0:
        slope_change = abs(atk_slope - benign_slope) / abs(benign_slope)
        if slope_change > 0.2:
            v["slope_change"] = f"{benign_slope:.4f} -> {atk_slope:.4f} ({slope_change * 100:.1f}% change)"
    if benign_intercept is not None and atk_intercept is not None:
        int_change = abs(atk_intercept - benign_intercept)
        if int_change > 50:
            v["intercept_shift"] = f"{benign_intercept:.2f} -> {atk_intercept:.2f} (delta={int_change:.2f})"

    if not v:
        return None

    return {
        "type": "inter_register",
        "name": f"{name_a} ~ {name_b}",
        "registers": [reg_a, reg_b],
        "signal_guid_a": guid_a,
        "signal_guid_b": guid_b,
        "violations": v,
        "benign_r": benign_r,
        "attack_r": round(atk_r, 4),
        "attack_pairs": pair_count,
    }


# ---------------------------------------------------------------------------
# Correlation adjacency (from invariant list or pre-built graph)
# ---------------------------------------------------------------------------

def _build_adjacency(data: dict) -> Dict[str, List[dict]]:
    """Build guid -> [{peer, pearson_r, ...}] adjacency from invariants.

    Uses the correlation_graph section if present, otherwise falls back to
    scanning inter_register invariants directly.
    """
    adj: Dict[str, List[dict]] = {}

    graph = data.get("correlation_graph")
    if graph and graph.get("edges"):
        for edge in graph["edges"]:
            src, tgt = edge["source"], edge["target"]
            info = {
                "pearson_r": edge["pearson_r"],
                "relationship": edge.get("relationship"),
            }
            adj.setdefault(src, []).append({"peer": tgt, **info})
            adj.setdefault(tgt, []).append({"peer": src, **info})
        return adj

    # Fallback: build from flat invariant list
    for inv in data["invariants"]:
        if inv["type"] != "inter_register":
            continue
        p = inv["parameters"]
        ga, gb = p.get("signal_guid_a"), p.get("signal_guid_b")
        if not ga or not gb:
            continue
        info = {"pearson_r": p["pearson_r"], "relationship": p.get("relationship")}
        adj.setdefault(ga, []).append({"peer": gb, **info})
        adj.setdefault(gb, []).append({"peer": ga, **info})
    return adj


# ---------------------------------------------------------------------------
# Violation tree construction
# ---------------------------------------------------------------------------

def _build_violation_forest(
    violated_nodes: Dict[str, dict],
    adjacency: Dict[str, List[dict]],
    correlation_violations: Dict[Tuple[str, str], dict],
) -> Tuple[List[dict], List[dict]]:
    """Build a causal violation forest from violated nodes + correlation edges.

    For each violated register, its **parent** is the most-proximate
    (closest in time, but strictly earlier) correlated register that was also
    violated.  This maximises the chance that the parent is the direct cause
    rather than an indirect ancestor.

    Returns (roots, orphans) where orphans are violated nodes with no
    correlation edges to any other violated node.
    """
    if not violated_nodes:
        return [], []

    sorted_nodes = sorted(
        violated_nodes.values(), key=lambda n: n["first_violation_time"]
    )
    guid_lookup = {n["guid"]: n for n in sorted_nodes}

    for node in sorted_nodes:
        node["children"] = []
        node["evidence"] = None

    # For each node, find the most-proximate earlier-violated correlated peer
    for node in sorted_nodes:
        guid = node["guid"]
        neighbors = adjacency.get(guid, [])

        best_parent = None
        best_time = -float("inf")
        best_edge_info: dict = {}

        for nb in neighbors:
            peer_guid = nb["peer"]
            if peer_guid not in guid_lookup:
                continue
            peer = guid_lookup[peer_guid]
            if peer["first_violation_time"] < node["first_violation_time"]:
                # Pick the most proximate (latest time that is still earlier)
                if peer["first_violation_time"] > best_time:
                    best_time = peer["first_violation_time"]
                    best_parent = peer
                    best_edge_info = nb

        if best_parent is not None:
            delay = node["first_violation_time"] - best_parent["first_violation_time"]
            # Look up whether this correlation also broke in attack data
            edge_key = _edge_key(best_parent["guid"], node["guid"])
            corr_viol = correlation_violations.get(edge_key)

            node["evidence"] = {
                "parent_guid": best_parent["guid"],
                "parent_variable": best_parent["variable_name"],
                "benign_correlation": best_edge_info.get("pearson_r"),
                "relationship": best_edge_info.get("relationship"),
                "delay_seconds": round(delay, 6),
                "correlation_violated": corr_viol is not None,
                "correlation_violation_detail": corr_viol,
            }
            best_parent["children"].append(node)

    roots = [n for n in sorted_nodes if n["evidence"] is None]

    # Separate true roots (have children or have correlated violated peers)
    # from orphans (no correlation edge to any other violated node at all)
    violated_guids = set(guid_lookup)
    true_roots = []
    orphans = []
    for r in roots:
        has_violated_neighbor = any(
            nb["peer"] in violated_guids
            for nb in adjacency.get(r["guid"], [])
        )
        if r["children"] or has_violated_neighbor:
            true_roots.append(r)
        else:
            orphans.append(r)

    return true_roots, orphans


def _edge_key(guid_a: str, guid_b: str) -> Tuple[str, str]:
    """Canonical (sorted) edge key so lookup is direction-independent."""
    return (min(guid_a, guid_b), max(guid_a, guid_b))


def _node_to_dict(node: dict) -> dict:
    """Serialise a tree node recursively."""
    result: dict[str, Any] = {
        "signal_container_guid": node["guid"],
        "register": node["register"],
        "unit_id": node["unit_id"],
        "variable_name": node["variable_name"],
        "first_violation_time": node["first_violation_time"],
        "violations": node["violations"],
        "benign_range": node["benign_range"],
        "attack_range": node["attack_range"],
        "attack_observations": node["attack_obs"],
    }
    if node["evidence"] is not None:
        result["evidence"] = node["evidence"]
    if node["children"]:
        result["downstream"] = [_node_to_dict(c) for c in node["children"]]
    return result


# ---------------------------------------------------------------------------
# Main validation
# ---------------------------------------------------------------------------

def validate(invariants_path: Path, attack_db_path: Path) -> dict:
    """Validate invariants against attack data and return structured report."""
    with open(invariants_path) as f:
        data = json.load(f)

    conn = duckdb.connect(str(attack_db_path), read_only=True)

    invariants = data["invariants"]
    adjacency = _build_adjacency(data)

    # --- Pass 1: aggregate violation checks (value_range + inter_register) ---
    value_violations: list[dict] = []
    correlation_violations: Dict[Tuple[str, str], dict] = {}
    checked_vr = 0
    checked_ir = 0

    for inv in invariants:
        if inv["type"] == "value_range":
            result = _check_value_range(conn, inv)
            if result is not None:
                value_violations.append(result)
            if inv["signal_container_guid"]:
                checked_vr += 1

        elif inv["type"] == "inter_register":
            result = _check_inter_register(conn, inv)
            if result is not None:
                ga = inv["parameters"].get("signal_guid_a")
                gb = inv["parameters"].get("signal_guid_b")
                if ga and gb:
                    correlation_violations[_edge_key(ga, gb)] = result
            checked_ir += 1

    # --- Pass 2: temporal violation detection for value_range violations ---
    violated_nodes: Dict[str, dict] = {}
    for vv in value_violations:
        guid = vv["signal_container_guid"]
        # Find the benign bounds from the original invariant
        benign_min, benign_max = vv["benign_range"]

        t = _first_violation_time(conn, guid, benign_min, benign_max)
        if t is None:
            t = _first_violation_time_by_reg(
                conn, vv["register"], vv["unit_id"], benign_min, benign_max,
            )
        if t is None:
            continue

        violated_nodes[guid] = {
            "guid": guid,
            "register": vv["register"],
            "unit_id": vv["unit_id"],
            "variable_name": vv["name"],
            "first_violation_time": t,
            "violations": vv["violations"],
            "benign_range": vv["benign_range"],
            "attack_range": vv["attack_range"],
            "attack_obs": vv["attack_obs"],
        }

    # --- Pass 3: build causal violation tree ---
    roots, orphans = _build_violation_forest(
        violated_nodes, adjacency, correlation_violations,
    )

    conn.close()

    # --- Build report ---
    report = {
        "invariants_checked": {
            "value_range": checked_vr,
            "inter_register": checked_ir,
            "total": len(invariants),
        },
        "violations_detected": {
            "value_range": len(value_violations),
            "inter_register": len(correlation_violations),
        },
        "violation_trees": [_node_to_dict(r) for r in roots],
        "uncorrelated_violations": [_node_to_dict(o) for o in orphans],
        "flat_violations": {
            "value_range": value_violations,
            "inter_register": list(correlation_violations.values()),
        },
    }

    _print_report(report)
    return report


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------

def _print_report(report: dict) -> None:
    checked = report["invariants_checked"]
    detected = report["violations_detected"]

    print(f"\n{'=' * 60}")
    print("INVARIANT VALIDATION REPORT")
    print(f"{'=' * 60}")
    print(
        f"Checked: {checked['value_range']} value-range, "
        f"{checked['inter_register']} inter-register "
        f"(of {checked['total']} total invariants)"
    )
    print(
        f"Violations: {detected['value_range']} value-range, "
        f"{detected['inter_register']} inter-register"
    )

    trees = report["violation_trees"]
    orphans = report["uncorrelated_violations"]

    if trees:
        print(f"\n{'─' * 60}")
        print(f"VIOLATION TREES ({len(trees)} root cause(s) identified)")
        print(f"{'─' * 60}")
        for i, root in enumerate(trees):
            print(f"\nTree #{i + 1}:")
            _print_tree_node(root, indent=2)

    if orphans:
        print(f"\n{'─' * 60}")
        print(f"UNCORRELATED VIOLATIONS ({len(orphans)} isolated)")
        print(f"{'─' * 60}")
        for o in orphans:
            name = o.get("variable_name", f"reg_{o['register']}")
            print(f"  {name} (reg {o['register']}): first violated at t={o['first_violation_time']:.4f}")
            for k, desc in o["violations"].items():
                print(f"    - {k}: {desc}")

    if not trees and not orphans:
        flat_vr = report["flat_violations"]["value_range"]
        flat_ir = report["flat_violations"]["inter_register"]
        if flat_vr or flat_ir:
            print("\nViolations detected but no temporal tree could be built.")
            print("(Aggregate violations are in the flat_violations section.)")
        else:
            print("\nNo violations detected — attack data is within benign invariant bounds.")


def _print_tree_node(node: dict, indent: int = 0) -> None:
    pad = " " * indent
    name = node.get("variable_name", f"reg_{node['register']}")
    t = node["first_violation_time"]

    # Evidence line for non-root nodes
    ev = node.get("evidence")
    if ev:
        delay = ev["delay_seconds"]
        corr = ev["benign_correlation"]
        parent = ev["parent_variable"]
        broke = " [correlation BROKEN]" if ev["correlation_violated"] else ""
        print(
            f"{pad}└─ {name} (reg {node['register']})  "
            f"t={t:.4f}  (+{delay:.4f}s from {parent}, "
            f"r={corr}){broke}"
        )
    else:
        print(f"{pad}{name} (reg {node['register']})  t={t:.4f}  [ROOT CAUSE]")

    # Violation details
    for k, desc in node["violations"].items():
        print(f"{pad}   {k}: {desc}")
    print(
        f"{pad}   benign: {node['benign_range']}, "
        f"attack: {node['attack_range']} "
        f"({node['attack_observations']:,} obs)"
    )

    for child in node.get("downstream", []):
        _print_tree_node(child, indent + 4)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print(
            "Usage: python -m invariantExperiments.validate_invariants "
            "<invariants.json> <attack.duckdb> [output.json]"
        )
        sys.exit(1)

    report = validate(Path(sys.argv[1]), Path(sys.argv[2]))

    if len(sys.argv) == 4:
        out = Path(sys.argv[3])
        out.write_text(json.dumps(report, indent=2))
        print(f"\nStructured report written to {out}")
