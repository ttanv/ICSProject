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
    """Unique signal identifier encoding host|port|unitId|registerType|address.

    Note: in the current codebase this GUID is derived from the polling client
    host (see protocol_utils._generate_node_guid_for_signal_container), so it is
    shared across all RTUs that the same client polls at the same address. Use
    server_host to disambiguate per-physical-signal.
    """

    server_host: Optional[str] = None
    """Server hostname (the Modbus slave / RTU). Combined with
    signal_container_guid this uniquely identifies one physical signal."""

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

    def _build_correlation_graph(self) -> Dict[str, Any]:
        """Derive a correlation graph from value_range and inter_register invariants.

        Nodes come from value_range invariants (one per signal/register).
        Edges come from inter_register invariants (correlation between two signals).
        This restructures existing data into an explicit graph for downstream
        causal analysis (e.g. violation tree construction).

        Node keys are composite "guid@server_host" strings so that the same
        Modbus GUID polled across multiple RTUs produces distinct nodes. Edges
        carry explicit source/target guid + server_host fields in addition to
        the composite source/target node ids.
        """
        def node_key(guid: Optional[str], server_host: Optional[str]) -> Optional[str]:
            if not guid:
                return None
            if not server_host:
                return guid
            return f"{guid}@{server_host}"

        nodes: Dict[str, Any] = {}
        edges: List[Dict[str, Any]] = []

        for inv in self.invariants:
            if inv.type == "value_range" and inv.signal_container_guid:
                key = node_key(inv.signal_container_guid, inv.server_host)
                if key is None:
                    continue
                nodes[key] = {
                    "signal_container_guid": inv.signal_container_guid,
                    "server_host": inv.server_host,
                    "register": inv.registers[0],
                    "unit_id": inv.unit_id,
                    "variable_name": inv.parameters.get("variable_name"),
                }

        for inv in self.invariants:
            if inv.type != "inter_register":
                continue
            p = inv.parameters
            guid_a = p.get("signal_guid_a")
            guid_b = p.get("signal_guid_b")
            host_a = p.get("server_host_a") or inv.server_host
            host_b = p.get("server_host_b") or inv.server_host
            src_key = node_key(guid_a, host_a)
            tgt_key = node_key(guid_b, host_b)
            if not src_key or not tgt_key:
                continue
            edges.append({
                "source": src_key,
                "target": tgt_key,
                "source_guid": guid_a,
                "source_server_host": host_a,
                "target_guid": guid_b,
                "target_server_host": host_b,
                "pearson_r": p["pearson_r"],
                "slope": p.get("slope"),
                "intercept": p.get("intercept"),
                "relationship": p.get("relationship"),
            })

        return {"nodes": nodes, "edges": edges}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "signal_db_path": self.signal_db_path,
            "st_file_path": self.st_file_path,
            "baseline_hours": self.baseline_hours,
            "total_observations_used": self.total_observations_used,
            "correlation_graph": self._build_correlation_graph(),
            "invariants": [inv.to_dict() for inv in self.invariants],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
