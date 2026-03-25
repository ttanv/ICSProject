"""Invariant extraction from baseline ICS signal data.

Mines process invariants (value ranges, inter-register correlations,
state transitions) from DuckDB signal observations, optionally enhanced
with IEC 61131-3 Structured Text program analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import Invariant, InvariantSet

logger = logging.getLogger(__name__)


@dataclass
class InvariantConfig:
    """Configuration for the invariant mining pipeline."""

    signal_db: Path
    """Path to the DuckDB signal database."""

    st_file: Optional[Path] = None
    """Optional path to an IEC 61131-3 Structured Text file."""

    output: Path = field(default_factory=lambda: Path("invariants.json"))
    """Output JSON file path."""

    baseline_hours: Optional[float] = None
    """Use first N hours as baseline (None = all data)."""

    register_offset: int = 0
    """Offset for AT address -> Modbus register mapping."""

    correlation_threshold: float = 0.7
    """Minimum |r| for inter-register correlations."""

    min_observations: int = 10
    """Minimum observations per register to include."""


def mine_invariants(config: InvariantConfig) -> InvariantSet:
    """Run the full invariant mining pipeline.

    1. Open DuckDB read-only
    2. Compute time window from baseline_hours
    3. Run state-agnostic miners
    4. If ST file provided: parse and enhance/partition
    5. Return InvariantSet
    """
    try:
        import duckdb
    except ImportError as e:
        raise ImportError(
            "DuckDB is required for invariant mining. "
            "Install it with: pip install duckdb"
        ) from e

    from .miners import mine_all
    from .state_partitioner import enhance_with_st
    from .st_parser import parse_st_file

    conn = duckdb.connect(str(config.signal_db), read_only=True)
    try:
        # Determine time window
        ts_range = conn.execute(
            "SELECT MIN(timestamp), MAX(timestamp), COUNT(*) FROM signal_observations"
        ).fetchone()
        if ts_range is None or ts_range[2] == 0:
            logger.warning("No observations in signal database")
            return InvariantSet(
                generated_at=datetime.now(timezone.utc).isoformat(),
                signal_db_path=str(config.signal_db),
            )

        start_ts, end_ts, total_obs = ts_range

        if config.baseline_hours is not None:
            end_ts = min(end_ts, start_ts + config.baseline_hours * 3600.0)

        logger.info(
            "Mining invariants from %.1f to %.1f (%d total observations)",
            start_ts, end_ts, total_obs,
        )

        # State-agnostic mining
        invariants = mine_all(
            conn, start_ts, end_ts,
            config.min_observations, config.correlation_threshold,
        )

        # State-aware enhancement
        st_file_path = None
        if config.st_file is not None:
            st_file_path = str(config.st_file)
            program = parse_st_file(config.st_file, config.register_offset)
            invariants = enhance_with_st(
                invariants, program, conn, start_ts, end_ts,
                config.min_observations, config.correlation_threshold,
            )

        return InvariantSet(
            generated_at=datetime.now(timezone.utc).isoformat(),
            signal_db_path=str(config.signal_db),
            st_file_path=st_file_path,
            baseline_hours=config.baseline_hours,
            total_observations_used=total_obs,
            invariants=invariants,
        )
    finally:
        conn.close()


__all__ = ["mine_invariants", "InvariantConfig", "Invariant", "InvariantSet"]
