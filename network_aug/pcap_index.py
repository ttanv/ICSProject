"""Utilities for indexing PCAP files and exposing packet summaries per connection.

This module provides two implementations:
1. FastPCAPConnectionIndex (default): Uses dpkt for ~15-20x faster parsing
2. ScapyPCAPConnectionIndex (fallback): Uses Scapy for full protocol support

The fast implementation is used by default. Set USE_SCAPY_PARSER=1 environment
variable to force the Scapy implementation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from .models import ConnectionKey, IndexedConnection, PacketRecord

# Determine which parser backend to use
_USE_SCAPY = os.environ.get("USE_SCAPY_PARSER", "").lower() in ("1", "true", "yes")
_PARSER_BACKEND = "unknown"

if not _USE_SCAPY:
    try:
        import dpkt  # noqa: F401
        _HAS_DPKT = True
    except ImportError:
        _HAS_DPKT = False
        _USE_SCAPY = True
else:
    _HAS_DPKT = False

if _USE_SCAPY:
    # Use Scapy-based implementation
    from .pcap_index_scapy import ScapyPCAPConnectionIndex as PCAPConnectionIndex
    from .pcap_index_scapy import detect_high_level_protocol
    _PARSER_BACKEND = "scapy"
else:
    # Use fast dpkt-based implementation
    from .pcap_index_fast import FastPCAPConnectionIndex as PCAPConnectionIndex
    from .pcap_index_fast import _detect_protocol_fast as detect_high_level_protocol
    _PARSER_BACKEND = "dpkt"


def get_parser_backend() -> str:
    """Return the name of the PCAP parser backend being used."""
    return _PARSER_BACKEND


__all__ = [
    "PCAPConnectionIndex",
    "detect_high_level_protocol",
    "get_parser_backend",
]
