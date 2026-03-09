"""Utilities for indexing PCAP files and exposing packet summaries per connection.

This module provides two implementations:
1. FastPCAPConnectionIndex (default): Uses dpkt for ~15-20x faster parsing
2. ScapyPCAPConnectionIndex (fallback): Uses Scapy for full protocol support

The fast implementation is used by default. Set USE_SCAPY_PARSER=1 environment
variable to force the Scapy implementation.
"""

from __future__ import annotations

import os

# Determine which parser backend to use
_USE_SCAPY = os.environ.get("USE_SCAPY_PARSER", "").lower() in ("1", "true", "yes")

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
else:
    # Use fast dpkt-based implementation
    from .pcap_index_fast import FastPCAPConnectionIndex as PCAPConnectionIndex
    from .pcap_index_fast import _detect_protocol_fast as detect_high_level_protocol


__all__ = [
    "PCAPConnectionIndex",
    "detect_high_level_protocol",
]
