"""Protocol plugin package."""

from __future__ import annotations

from .base import ProtocolBuildResult, ProtocolHandler
from .context import ProtocolBuildContext
from .modbus_handler import ModbusProtocolHandler
from .http_monitor_handler import HttpMonitorHandler
from .registry import ProtocolRegistry

__all__ = [
    "ProtocolBuildContext",
    "ProtocolBuildResult",
    "ProtocolHandler",
    "ProtocolRegistry",
    "build_default_registry",
]


def build_default_registry() -> ProtocolRegistry:
    """Return the baseline protocol registry used by augmentors."""
    registry = ProtocolRegistry()
    registry.register(ModbusProtocolHandler())
    registry.register(HttpMonitorHandler())
    return registry
