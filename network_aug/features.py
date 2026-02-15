"""Feature extraction helpers for packets grouped by connection."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import ConnectionKey, PacketRecord


@dataclass
class PreSortedPackets:
    """Wrapper for pre-sorted packets to avoid redundant sorting."""

    packets: List[PacketRecord]
    _sorted: bool = True

    @classmethod
    def from_packets(cls, packets: Sequence[PacketRecord]) -> "PreSortedPackets":
        """Create a pre-sorted packet list."""
        sorted_packets = sorted(packets, key=lambda pkt: pkt.timestamp)
        return cls(packets=sorted_packets, _sorted=True)

    def __iter__(self):
        return iter(self.packets)

    def __len__(self):
        return len(self.packets)

    def __getitem__(self, idx):
        return self.packets[idx]


def total_bytes(packets: Iterable[PacketRecord]) -> int:
    return sum(pkt.size for pkt in packets)


def packet_count(packets: Iterable[PacketRecord]) -> int:
    return sum(1 for _ in packets)


def duration_seconds(packets: Sequence[PacketRecord]) -> float:
    if isinstance(packets, PreSortedPackets):
        ordered = packets.packets
    else:
        ordered = sorted(packets, key=lambda pkt: pkt.timestamp)
    if len(ordered) < 2:
        return 0.0
    return ordered[-1].timestamp - ordered[0].timestamp


def average_packet_size(packets: Iterable[PacketRecord]) -> float:
    packet_list = list(packets)
    if not packet_list:
        return 0.0
    return total_bytes(packet_list) / len(packet_list)


def dominant_protocol(packets: Sequence[PacketRecord]) -> str:
    if not packets:
        return "UNKNOWN"
    counts = Counter(pkt.high_level_protocol or "UNKNOWN" for pkt in packets)
    return counts.most_common(1)[0][0]


def directional_totals(
    connection: ConnectionKey,
    packets: Sequence[PacketRecord],
) -> Tuple[int, int, int, int]:
    bytes_out = bytes_in = 0
    packets_out = packets_in = 0
    for pkt in packets:
        if pkt.src_ip == connection.src_ip and pkt.dst_ip == connection.dst_ip:
            bytes_out += pkt.size
            packets_out += 1
        elif pkt.src_ip == connection.dst_ip and pkt.dst_ip == connection.src_ip:
            bytes_in += pkt.size
            packets_in += 1
    return bytes_out, bytes_in, packets_out, packets_in


def directionality_ratio(bytes_out: int, bytes_in: int) -> Optional[float]:
    if bytes_out == 0 and bytes_in == 0:
        return 0.0
    if bytes_in == 0:
        return None
    return bytes_out / bytes_in


def mean_interarrival_time(packets: Sequence[PacketRecord]) -> float:
    if len(packets) < 2:
        return 0.0
    if isinstance(packets, PreSortedPackets):
        ordered = packets.packets
    else:
        ordered = sorted(packets, key=lambda pkt: pkt.timestamp)
    deltas = [
        ordered[idx + 1].timestamp - ordered[idx].timestamp for idx in range(len(ordered) - 1)
    ]
    return sum(deltas) / len(deltas) if deltas else 0.0


def aggregate_tcp_flags(packets: Sequence[PacketRecord]) -> str:
    if isinstance(packets, PreSortedPackets):
        ordered = packets.packets
    else:
        ordered = sorted(packets, key=lambda pkt: pkt.timestamp)
    seen: list[str] = []
    for pkt in ordered:
        flags = (pkt.tcp_flags or "").strip()
        if not flags:
            continue
        if flags not in seen:
            seen.append(flags)
    return ",".join(seen)


def count_tcp_retransmits(packets: Sequence[PacketRecord]) -> int:
    retransmits = 0
    seen_sequences: Dict[Tuple[str, str], set[Tuple[int, int]]] = {}
    if isinstance(packets, PreSortedPackets):
        ordered = packets.packets
    else:
        ordered = sorted(packets, key=lambda pkt: pkt.timestamp)
    for pkt in ordered:
        if pkt.protocol.lower() != "tcp":
            continue
        if pkt.tcp_seq is None:
            continue
        payload_len = pkt.payload_len or 0
        if payload_len <= 0:
            continue
        direction = (pkt.src_ip, pkt.dst_ip)
        entries = seen_sequences.setdefault(direction, set())
        key = (pkt.tcp_seq, payload_len)
        if key in entries:
            retransmits += 1
        else:
            entries.add(key)
    return retransmits


def resolve_mac_addresses(connection: ConnectionKey, packets: Sequence[PacketRecord]) -> Tuple[str, str]:
    if isinstance(packets, PreSortedPackets):
        ordered = packets.packets
    else:
        ordered = sorted(packets, key=lambda pkt: pkt.timestamp)
    src_mac = ""
    dst_mac = ""
    for pkt in ordered:
        if (
            pkt.src_ip == connection.src_ip
            and pkt.dst_ip == connection.dst_ip
            and pkt.src_mac
            and pkt.dst_mac
        ):
            src_mac = pkt.src_mac
            dst_mac = pkt.dst_mac
            break
    if not src_mac or not dst_mac:
        for pkt in ordered:
            if not src_mac and pkt.src_mac:
                src_mac = pkt.src_mac
            if not dst_mac and pkt.dst_mac:
                dst_mac = pkt.dst_mac
            if src_mac and dst_mac:
                break
    return src_mac, dst_mac


def extract_http_features(packets: Sequence[PacketRecord]) -> Dict[str, Optional[object]]:
    if isinstance(packets, PreSortedPackets):
        ordered = packets.packets
    else:
        ordered = sorted(packets, key=lambda pkt: pkt.timestamp)
    method = next((pkt.http_method for pkt in ordered if pkt.http_method), None)
    status = next((pkt.http_status for pkt in ordered if pkt.http_status is not None), None)
    host = next((pkt.http_host for pkt in ordered if pkt.http_host), "")
    path = next((pkt.http_path for pkt in ordered if pkt.http_path), "")
    content_type = next((pkt.http_content_type for pkt in ordered if pkt.http_content_type), "")

    http_content = ""
    if host or path:
        http_content = f"{host}{path}"
    elif content_type:
        http_content = content_type

    return {
        "method": method,
        "status": status,
        "content": http_content or None,
    }


def extract_tls_sni(packets: Sequence[PacketRecord]) -> Optional[str]:
    for pkt in packets:
        if pkt.tls_sni:
            return pkt.tls_sni
    return None


def mean_rtt_ms(connection: ConnectionKey, packets: Sequence[PacketRecord]) -> float:
    """Estimate mean RTT in milliseconds using TCP seq/ack tracking.

    Optimized version using dict-based lookup instead of O(n) list search.
    """
    if isinstance(packets, PreSortedPackets):
        ordered = packets.packets
    else:
        ordered = sorted(packets, key=lambda pkt: pkt.timestamp)

    # Use dicts keyed by ack_target for O(1) lookup
    # Value is timestamp of the packet that expects this ack
    pending_src: Dict[int, float] = {}
    pending_dst: Dict[int, float] = {}
    rtts: list[float] = []

    for pkt in ordered:
        if pkt.protocol.lower() != "tcp":
            continue
        seq = pkt.tcp_seq
        ack = pkt.tcp_ack
        payload_len = pkt.payload_len or 0
        flags = pkt.tcp_flags or ""

        direction: Optional[str] = None
        if pkt.src_ip == connection.src_ip and pkt.dst_ip == connection.dst_ip:
            direction = "src"
        elif pkt.src_ip == connection.dst_ip and pkt.dst_ip == connection.src_ip:
            direction = "dst"

        if direction == "src" and seq is not None:
            ack_target = seq + max(payload_len, 0)
            if "S" in flags or "F" in flags:
                ack_target += 1
            if ack_target > seq:
                # Only store first occurrence (earliest timestamp)
                if ack_target not in pending_src:
                    pending_src[ack_target] = pkt.timestamp
        elif direction == "dst" and seq is not None:
            ack_target = seq + max(payload_len, 0)
            if "S" in flags or "F" in flags:
                ack_target += 1
            if ack_target > seq:
                if ack_target not in pending_dst:
                    pending_dst[ack_target] = pkt.timestamp

        # Check for exact ack match (O(1) lookup)
        if direction == "dst" and ack is not None and ack in pending_src:
            ts = pending_src.pop(ack)
            rtts.append((pkt.timestamp - ts) * 1000.0)
        elif direction == "src" and ack is not None and ack in pending_dst:
            ts = pending_dst.pop(ack)
            rtts.append((pkt.timestamp - ts) * 1000.0)

    if not rtts:
        return 0.0
    return sum(rtts) / len(rtts)
