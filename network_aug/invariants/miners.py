"""Mining algorithms for process invariants.

Three invariant types (matching SAIN categories):
- Value range: single-variable intra-state bounds
- Inter-register correlation: multi-variable intra-state relationships
- State transition: inter-state guards (derived from ST, not mined here)
"""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING, List

from .models import Invariant

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)


def mine_value_ranges(
    conn: duckdb.Connection,
    start_ts: float,
    end_ts: float,
    min_observations: int = 10,
) -> List[Invariant]:
    """Mine value range invariants via DuckDB aggregation.

    Groups by (register_address, unit_id) and computes MIN/MAX/AVG/STDDEV.
    Confidence = min(1.0, observation_count / 100).
    """
    rows = conn.execute(
        """
        SELECT
            signal_container_guid,
            ANY_VALUE(register_address) AS register_address,
            ANY_VALUE(unit_id) AS unit_id,
            MIN(value) AS min_val,
            MAX(value) AS max_val,
            AVG(value) AS mean_val,
            STDDEV_SAMP(value) AS stddev_val,
            COUNT(*) AS obs_count
        FROM signal_observations
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY signal_container_guid
        HAVING COUNT(*) >= ?
        ORDER BY signal_container_guid
        """,
        [start_ts, end_ts, min_observations],
    ).fetchall()

    invariants = []
    for row in rows:
        guid, reg_addr, unit_id, min_val, max_val, mean_val, stddev_val, obs_count = row
        invariants.append(
            Invariant(
                type="value_range",
                registers=[reg_addr],
                unit_id=unit_id,
                signal_container_guid=guid,
                confidence=min(1.0, obs_count / 100),
                observation_count=obs_count,
                parameters={
                    "min": min_val,
                    "max": max_val,
                    "mean": round(mean_val, 4) if mean_val is not None else None,
                    "stddev": round(stddev_val, 4) if stddev_val is not None else None,
                },
            )
        )

    logger.info("Mined %d value range invariants", len(invariants))
    return invariants


def mine_inter_register_correlations(
    conn: duckdb.Connection,
    start_ts: float,
    end_ts: float,
    min_observations: int = 10,
    correlation_threshold: float = 0.7,
) -> List[Invariant]:
    """Mine inter-register correlation invariants.

    Pre-filters to registers on the same unit_id with sufficient observations,
    caps at 50 registers per unit, uses ASOF JOIN for temporal pairing,
    then CORR() for Pearson correlation.
    """
    # Get eligible signals per (server_host, unit_id), cap at 50 per group
    eligible = conn.execute(
        """
        WITH signal_counts AS (
            SELECT
                signal_container_guid,
                ANY_VALUE(register_address) AS register_address,
                ANY_VALUE(unit_id) AS unit_id,
                ANY_VALUE(server_host) AS server_host,
                COUNT(*) AS cnt
            FROM signal_observations
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY signal_container_guid
            HAVING COUNT(*) >= ?
        ),
        ranked AS (
            SELECT *, ROW_NUMBER() OVER (
                PARTITION BY server_host, unit_id ORDER BY cnt DESC
            ) AS rn
            FROM signal_counts
        )
        SELECT signal_container_guid, register_address, unit_id, server_host
        FROM ranked
        WHERE rn <= 50
        ORDER BY server_host, unit_id, register_address
        """,
        [start_ts, end_ts, max(min_observations, 30)],
    ).fetchall()

    if len(eligible) < 2:
        logger.info("Fewer than 2 eligible signals, skipping correlation mining")
        return []

    # Group signals by (server_host, unit_id) — only correlate within same device
    device_signals: dict[tuple, list[tuple[str, int]]] = {}
    for guid, reg_addr, unit_id, server_host in eligible:
        key = (server_host, unit_id)
        device_signals.setdefault(key, []).append((guid, reg_addr))

    invariants = []
    for (server_host, unit_id), signals in device_signals.items():
        if len(signals) < 2:
            continue

        # Compute pairwise correlations using ASOF JOIN within each device
        for i in range(len(signals)):
            for j in range(i + 1, len(signals)):
                guid_a, reg_a = signals[i]
                guid_b, reg_b = signals[j]

                result = conn.execute(
                    """
                    WITH a AS (
                        SELECT timestamp AS ts, value AS val_a
                        FROM signal_observations
                        WHERE signal_container_guid = ?
                          AND timestamp >= ? AND timestamp <= ?
                        ORDER BY timestamp
                    ),
                    b AS (
                        SELECT timestamp AS ts, value AS val_b
                        FROM signal_observations
                        WHERE signal_container_guid = ?
                          AND timestamp >= ? AND timestamp <= ?
                        ORDER BY timestamp
                    ),
                    paired AS (
                        SELECT a.val_a, b.val_b
                        FROM a ASOF JOIN b ON a.ts >= b.ts
                        WHERE b.val_b IS NOT NULL
                    )
                    SELECT CORR(val_a, val_b) AS pearson_r, COUNT(*) AS pair_count
                    FROM paired
                    """,
                    [
                        guid_a, start_ts, end_ts,
                        guid_b, start_ts, end_ts,
                    ],
                ).fetchone()

                if result is None:
                    continue
                pearson_r, pair_count = result
                if (
                    pearson_r is None
                    or math.isnan(pearson_r)
                    or pair_count < min_observations
                ):
                    continue
                if abs(pearson_r) < correlation_threshold:
                    continue

                relationship = "positive" if pearson_r > 0 else "negative"
                invariants.append(
                    Invariant(
                        type="inter_register",
                        registers=[reg_a, reg_b],
                        unit_id=unit_id,
                        confidence=min(1.0, pair_count / 100),
                        observation_count=pair_count,
                        parameters={
                            "register_a": reg_a,
                            "register_b": reg_b,
                            "signal_guid_a": guid_a,
                            "signal_guid_b": guid_b,
                            "pearson_r": round(pearson_r, 4),
                            "relationship": relationship,
                        },
                    )
                )

    logger.info("Mined %d inter-register correlation invariants", len(invariants))
    return invariants


def mine_all(
    conn: duckdb.Connection,
    start_ts: float,
    end_ts: float,
    min_observations: int = 10,
    correlation_threshold: float = 0.7,
) -> List[Invariant]:
    """Run all state-agnostic miners and return combined invariants."""
    invariants = mine_value_ranges(conn, start_ts, end_ts, min_observations)
    invariants.extend(
        mine_inter_register_correlations(
            conn, start_ts, end_ts, min_observations, correlation_threshold
        )
    )
    return invariants
