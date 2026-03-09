"""Filtering logic that decides which PCAP-only connections should be added."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Sequence, Set

from .models import ConnectionKey, PacketRecord


@dataclass
class AugmentationPolicy:
    """Configuration describing what qualifies as interesting missing traffic."""

    internal_prefixes: Sequence[str] = (
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",
    )
    exclude_outer_prefixes: Sequence[str] = ("172.16.",)
    interesting_ports: Set[int] = field(
        default_factory=lambda: {
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            135,
            139,
            143,
            161,
            162,
            443,
            445,
            502,
            1433,
            1883,
            8883,
            4840,
            3389,
            44818,
        }
    )
    ignored_ports: Set[int] = field(
        default_factory=lambda: {
            137,  # NetBIOS Name Service (broadcast heavy)
            138,  # NetBIOS Datagram Service
            1900,  # SSDP
            5353,  # mDNS
            5355,  # LLMNR (Link-Local Multicast Name Resolution)
        }
    )
    min_packet_threshold: int = 3
    ignore_ephemeral: bool = True
    ephemeral_port_ranges: Sequence[tuple[int, int]] = (
        (32768, 60999),  # Common Linux range
        (49152, 65535),  # IANA/Windows range
    )

    def is_internal(self, ip: str) -> bool:
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return obj.is_private or any(ip.startswith(prefix) for prefix in self.internal_prefixes)

    def is_outer(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self.exclude_outer_prefixes)

    def is_broadcast_or_multicast(self, ip: str) -> bool:
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if obj.version == 4 and str(obj).endswith(".255"):
            return True
        return obj.is_multicast or obj.is_unspecified

    def is_interesting(self, connection: ConnectionKey, packets: Sequence[PacketRecord]) -> bool:
        if not packets:
            return False

        # Filter out multicast/broadcast FIRST, before any other checks
        if self.is_broadcast_or_multicast(connection.src_ip) or self.is_broadcast_or_multicast(connection.dst_ip):
            return False

        if any(pkt.ip_layer_index >= 1 for pkt in packets):
            return True

        if self.is_outer(connection.src_ip) and self.is_outer(connection.dst_ip):
            return False

        if len(packets) < self.min_packet_threshold:
            return False

        if self.ignore_ephemeral and (
            self._is_ephemeral(connection.src_port) and self._is_ephemeral(connection.dst_port)
        ):
            return False

        if connection.src_port in self.ignored_ports or connection.dst_port in self.ignored_ports:
            return False

        if connection.src_port in self.interesting_ports or connection.dst_port in self.interesting_ports:
            return True

        if self.is_internal(connection.src_ip) or self.is_internal(connection.dst_ip):
            return True

        return False

    def _is_ephemeral(self, port: int) -> bool:
        for low, high in self.ephemeral_port_ranges:
            if low <= port <= high:
                return True
        return False
