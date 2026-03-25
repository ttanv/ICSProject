"""Invariant data models and JSON serialization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Invariant:
    """A single process invariant mined from baseline signal data.

    Three types following SAIN's invariant categories:
    - value_range: single-variable intra-state bounds
    - inter_register: multi-variable intra-state correlations
    - state_transition: inter-state transition guards (ST-derived only)
    """

    type: str
    """One of: 'value_range', 'inter_register', 'state_transition'."""

    registers: List[int]
    """Register addresses involved in this invariant."""

    unit_id: Optional[int]
    """Modbus unit ID, if applicable."""

    signal_container_guid: Optional[str] = None
    """Unique signal identifier encoding host|port|unitId|registerType|address."""

    state_id: Optional[int] = None
    """FSM state ID when state-aware, None for state-agnostic."""

    state_name: Optional[str] = None
    """Human-readable state name from ST file."""

    confidence: float = 0.0
    """Confidence score 0.0-1.0 based on observation count."""

    observation_count: int = 0
    """Number of observations used to derive this invariant."""

    parameters: Dict[str, Any] = field(default_factory=dict)
    """Type-specific parameters.

    value_range: min, max, mean, stddev, st_declared_min, st_declared_max
    inter_register: register_a, register_b, pearson_r, relationship
    state_transition: from_state, to_state, guard_registers, guard_conditions
    """

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvariantSet:
    """Collection of invariants with provenance metadata."""

    generated_at: str
    """ISO 8601 timestamp of generation."""

    signal_db_path: str
    """Path to the DuckDB signal database used."""

    st_file_path: Optional[str] = None
    """Path to the ST file used for state-aware mode."""

    baseline_hours: Optional[float] = None
    """Hours of baseline data used (None = all data)."""

    total_observations_used: int = 0
    """Total signal observations considered."""

    invariants: List[Invariant] = field(default_factory=list)
    """The mined invariants."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "signal_db_path": self.signal_db_path,
            "st_file_path": self.st_file_path,
            "baseline_hours": self.baseline_hours,
            "total_observations_used": self.total_observations_used,
            "invariants": [inv.to_dict() for inv in self.invariants],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
