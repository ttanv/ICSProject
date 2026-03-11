"""Shared context passed into protocol handlers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, TYPE_CHECKING

from ..correlation import TelemetryConnectionIndex
from ..models import IndexedConnection

if TYPE_CHECKING:
    from ..missing_augmentor import MissingTrafficAugmentor


@dataclass
class ProtocolBuildContext:
    """Mutable build state used by protocol handlers."""

    augmentor: "MissingTrafficAugmentor"
    connections: Sequence[IndexedConnection]
    base_connection_ids: Set[str]
    correlated_cids: Set[str]
    processed_cids: Set[str]
    show_progress: bool
    telemetry_index: Optional[TelemetryConnectionIndex]

    asset_statements: Dict[str, str]
    service_statements: Dict[str, str]
    host_statements: Dict[str, str]
    register_statements: Dict[str, str]
    process_statements: Dict[str, str]
    runs_statements: Dict[str, str]
    relationship_statements: List[str]
    process_register_statements: List[str]
