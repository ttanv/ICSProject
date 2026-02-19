"""Registry for protocol plugin handlers."""

from __future__ import annotations

from typing import Dict, Iterable

from .base import ProtocolBuildResult, ProtocolHandler
from .context import ProtocolBuildContext


class ProtocolRegistry:
    """Maintains a named collection of protocol handlers."""

    def __init__(self) -> None:
        self._handlers: Dict[str, ProtocolHandler] = {}

    def register(self, handler: ProtocolHandler) -> None:
        """Register or replace a handler by its canonical name."""
        self._handlers[handler.name] = handler

    def run(self, handler_name: str, context: ProtocolBuildContext) -> ProtocolBuildResult:
        """Run a registered handler and return its build result."""
        handler = self._handlers.get(handler_name)
        if handler is None:
            return ProtocolBuildResult()
        return handler.build_artifacts(context)

    def names(self) -> Iterable[str]:
        """Return registered handler names."""
        return self._handlers.keys()
