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
            register_address,
            unit_id,
            MIN(value) AS min_val,
            MAX(value) AS max_val,
            AVG(value) AS mean_val,
            STDDEV_SAMP(value) AS stddev_val,
            COUNT(*) AS obs_count
        FROM signal_observations
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY register_address, unit_id
        HAVING COUNT(*) >= ?
        ORDER BY register_address, unit_id
        """,
        [start_ts, end_ts, min_observations],
    ).fetchall()

    invariants = []
    for row in rows:
        reg_addr, unit_id, min_val, max_val, mean_val, stddev_val, obs_count = row
        invariants.append(
            Invariant(
                type="value_range",
                registers=[reg_addr],
                unit_id=unit_id,
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
    # Get eligible registers per unit_id (cap at 50)
    eligible = conn.execute(
        """
        WITH reg_counts AS (
            SELECT register_address, unit_id, COUNT(*) AS cnt
            FROM signal_observations
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY register_address, unit_id
            HAVING COUNT(*) >= ?
        ),
        ranked AS (
            SELECT *, ROW_NUMBER() OVER (
                PARTITION BY unit_id ORDER BY cnt DESC
            ) AS rn
            FROM reg_counts
        )
        SELECT register_address, unit_id
        FROM ranked
        WHERE rn <= 50
        ORDER BY unit_id, register_address
        """,
        [start_ts, end_ts, max(min_observations, 30)],
    ).fetchall()

    if len(eligible) < 2:
        logger.info("Fewer than 2 eligible registers, skipping correlation mining")
        return []

    # Group registers by unit_id
    unit_registers: dict[int | None, list[int]] = {}
    for reg_addr, unit_id in eligible:
        unit_registers.setdefault(unit_id, []).append(reg_addr)

    invariants = []
    for unit_id, registers in unit_registers.items():
        if len(registers) < 2:
            continue

        # Compute pairwise correlations using ASOF JOIN within each unit
        for i in range(len(registers)):
            for j in range(i + 1, len(registers)):
                reg_a, reg_b = registers[i], registers[j]

                result = conn.execute(
                    """
                    WITH a AS (
                        SELECT timestamp AS ts, value AS val_a
                        FROM signal_observations
                        WHERE register_address = ?
                          AND (unit_id = ? OR (unit_id IS NULL AND ? IS NULL))
                          AND timestamp >= ? AND timestamp <= ?
                        ORDER BY timestamp
                    ),
                    b AS (
                        SELECT timestamp AS ts, value AS val_b
                        FROM signal_observations
                        WHERE register_address = ?
                          AND (unit_id = ? OR (unit_id IS NULL AND ? IS NULL))
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
                        reg_a, unit_id, unit_id, start_ts, end_ts,
                        reg_b, unit_id, unit_id, start_ts, end_ts,
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
