"""State-aware invariant enhancement.

Path A (FSM detected): partition data by FSM state, re-mine per-state invariants,
extract state transition invariants from CASE structure.

Path B (continuous control, no FSM): annotate invariants with LIMIT bounds,
add variable names, pre-seed correlation pairs.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, List, Tuple

from .miners import mine_inter_register_correlations, mine_value_ranges
from .models import Invariant
from .st_parser import STProgramInfo

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)


def _build_register_name_map(program: STProgramInfo) -> Dict[int, str]:
    """Map resolved register addresses to ST variable names."""
    return {var.resolved_register: var.name for var in program.variables}


def _find_state_intervals(
    conn: duckdb.Connection,
    state_register: int,
    start_ts: float,
    end_ts: float,
) -> List[Tuple[int, float, float]]:
    """Find contiguous time intervals per state value using run-length grouping.

    Returns list of (state_value, interval_start, interval_end).
    """
    rows = conn.execute(
        """
        WITH ordered AS (
            SELECT
                timestamp,
                value,
                value - LAG(value) OVER (ORDER BY timestamp) AS val_diff,
                ROW_NUMBER() OVER (ORDER BY timestamp) AS rn
            FROM signal_observations
            WHERE register_address = ?
              AND timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp
        ),
        groups AS (
            SELECT
                timestamp,
                value,
                SUM(CASE WHEN val_diff IS NULL OR val_diff != 0 THEN 1 ELSE 0 END)
                    OVER (ORDER BY rn) AS grp
            FROM ordered
        )
        SELECT
            value AS state_value,
            MIN(timestamp) AS interval_start,
            MAX(timestamp) AS interval_end
        FROM groups
        GROUP BY grp, value
        HAVING COUNT(*) >= 2
        ORDER BY interval_start
        """,
        [state_register, start_ts, end_ts],
    ).fetchall()

    return [(int(r[0]), r[1], r[2]) for r in rows]


def _enhance_fsm(
    invariants: List[Invariant],
    program: STProgramInfo,
    conn: duckdb.Connection,
    start_ts: float,
    end_ts: float,
    min_observations: int = 10,
    correlation_threshold: float = 0.7,
) -> List[Invariant]:
    """Path A: FSM-based state partitioning and transition invariants."""
    fsm = program.fsm
    if fsm is None or fsm.state_register is None:
        return invariants

    name_map = _build_register_name_map(program)
    intervals = _find_state_intervals(conn, fsm.state_register, start_ts, end_ts)

    if not intervals:
        logger.warning("No state intervals found for register %d", fsm.state_register)
        return invariants

    # Group intervals by state value
    state_windows: Dict[int, List[Tuple[float, float]]] = {}
    for state_val, t_start, t_end in intervals:
        state_windows.setdefault(state_val, []).append((t_start, t_end))

    # Re-mine per-state invariants (tighter bounds)
    per_state_invariants: List[Invariant] = []
    for state_val, windows in state_windows.items():
        state_name = f"state_{state_val}"
        for win_start, win_end in windows:
            vr = mine_value_ranges(conn, win_start, win_end, min_observations)
            for inv in vr:
                inv.state_id = state_val
                inv.state_name = state_name
            per_state_invariants.extend(vr)

            cr = mine_inter_register_correlations(
                conn, win_start, win_end, min_observations, correlation_threshold
            )
            for inv in cr:
                inv.state_id = state_val
                inv.state_name = state_name
            per_state_invariants.extend(cr)

    # Extract state transition invariants from FSM structure
    transition_invariants: List[Invariant] = []
    for i in range(len(fsm.state_ids) - 1):
        from_state = fsm.state_ids[i]
        to_state = fsm.state_ids[i + 1]
        transition_invariants.append(
            Invariant(
                type="state_transition",
                registers=[fsm.state_register],
                unit_id=None,
                state_id=from_state,
                state_name=f"state_{from_state}",
                confidence=1.0,  # Derived from program structure
                observation_count=0,
                parameters={
                    "from_state": from_state,
                    "to_state": to_state,
                    "guard_registers": [fsm.state_register],
                    "guard_conditions": [
                        f"{fsm.state_variable} == {from_state}"
                    ],
                },
            )
        )

    # Add variable names to all invariants
    all_invariants = invariants + per_state_invariants + transition_invariants
    for inv in all_invariants:
        for reg in inv.registers:
            if reg in name_map and "variable_names" not in inv.parameters:
                inv.parameters.setdefault("variable_names", {})
            if reg in name_map:
                inv.parameters.setdefault("variable_names", {})[str(reg)] = name_map[reg]

    logger.info(
        "FSM enhancement: %d per-state, %d transition invariants added",
        len(per_state_invariants),
        len(transition_invariants),
    )
    return all_invariants


def _enhance_continuous(
    invariants: List[Invariant],
    program: STProgramInfo,
    conn: duckdb.Connection,
    start_ts: float,
    end_ts: float,
) -> List[Invariant]:
    """Path B: Continuous control enhancement with LIMIT bounds and variable names.

    Note: LIMIT bounds in ST are typically in engineering units (e.g., 0-100%
    for valve positions), not raw register values (0-65535 UINT). We attach
    LIMIT bounds as metadata for reference but do NOT compare them directly
    against raw register ranges — that requires understanding the scaling
    chain (scale_to_real / scale_to_uint), which we don't trace yet.
    """
    name_map = _build_register_name_map(program)

    for inv in invariants:
        if inv.type == "value_range":
            reg = inv.registers[0] if inv.registers else None
            if reg is not None and reg in name_map:
                inv.parameters["variable_name"] = name_map[reg]

        elif inv.type == "inter_register":
            names = {}
            for reg in inv.registers:
                if reg in name_map:
                    names[str(reg)] = name_map[reg]
            if names:
                inv.parameters["variable_names"] = names

    # Attach LIMIT bounds as top-level metadata (engineering-unit bounds,
    # not directly comparable to raw register values)
    if program.limit_bounds:
        limit_summary = []
        for lb in program.limit_bounds:
            if lb.low is not None or lb.high is not None:
                limit_summary.append({
                    "variable": lb.variable,
                    "expression": lb.expression,
                    "low": lb.low,
                    "high": lb.high,
                    "note": "engineering-unit bounds (pre-scale_to_uint)",
                })
        if limit_summary:
            # Annotate the first invariant as a carrier, or log it
            logger.info(
                "ST declares %d LIMIT bounds (engineering units): %s",
                len(limit_summary),
                ", ".join(
                    f"{lb['variable']}=[{lb['low']}..{lb['high']}]"
                    for lb in limit_summary
                ),
            )

    logger.info("Continuous control enhancement applied to %d invariants", len(invariants))
    return invariants


def enhance_with_st(
    invariants: List[Invariant],
    program: STProgramInfo,
    conn: duckdb.Connection,
    start_ts: float,
    end_ts: float,
    min_observations: int = 10,
    correlation_threshold: float = 0.7,
) -> List[Invariant]:
    """Enhance invariants using ST program information.

    Routes to FSM-based (Path A) or continuous control (Path B) enhancement.
    """
    if program.has_fsm:
        logger.info("FSM detected, using state-aware partitioning (Path A)")
        return _enhance_fsm(
            invariants, program, conn, start_ts, end_ts,
            min_observations, correlation_threshold,
        )
    else:
        logger.info("No FSM detected, using continuous control enhancement (Path B)")
        return _enhance_continuous(invariants, program, conn, start_ts, end_ts)
