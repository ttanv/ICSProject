"""Core protocol plugin interfaces for augmentation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, Set

from .context import ProtocolBuildContext


@dataclass
class ProtocolBuildResult:
    """Result returned by protocol handlers after artifact generation."""

    relationship_count: int = 0
    consumed_cids: Set[str] = field(default_factory=set)


class ProtocolHandler(Protocol):
    """Interface for protocol-specific artifact handlers."""

    name: str

    def build_artifacts(self, context: ProtocolBuildContext) -> ProtocolBuildResult:
        """Generate protocol-specific artifacts and return summary counts."""
        ...
