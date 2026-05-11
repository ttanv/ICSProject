"""Feature extraction helpers for packets grouped by connection.

This module exposes two equivalent APIs:

* **List-based functions** (``directional_totals``, ``mean_rtt_ms``, etc.)
  take a materialized packet list and return their feature. Convenient for
  small/test workloads.
* **Streaming accumulator** (:class:`RelationshipFeatureAccumulator`)
  consumes packets one at a time and produces the full feature dict at
  the end. Used by ``_augment_existing_relationships`` to avoid loading
  millions of packets per base-graph edge into RAM. The peak there was
  the dominant memory term at 24h+ scale.

The accumulator assumes packets arrive in non-decreasing timestamp order
(callers should use ``heapq.merge`` over per-source sorted streams). The
list-based functions sort internally and therefore work on any ordering.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

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


def extract_mqtt_features(packets: Sequence[PacketRecord]) -> Dict[str, Optional[object]]:
    """Extract compact MQTT metadata from a packet sequence."""
    packet_types: List[str] = []
    topics: List[str] = []
    client_ids: List[str] = []
    qos_levels: set[int] = set()
    publish_count = 0
    subscribe_count = 0
    retain_seen = False

    for pkt in packets:
        pkt_type = (pkt.mqtt_packet_type or "").upper()
        if pkt_type:
            if pkt_type not in packet_types:
                packet_types.append(pkt_type)
            if pkt_type == "PUBLISH":
                publish_count += 1
            elif pkt_type in {"SUBSCRIBE", "UNSUBSCRIBE"}:
                subscribe_count += 1
        if pkt.mqtt_topic:
            topic = pkt.mqtt_topic[:120]
            if topic not in topics:
                topics.append(topic)
        if pkt.mqtt_client_id:
            cid = pkt.mqtt_client_id[:120]
            if cid not in client_ids:
                client_ids.append(cid)
        if pkt.mqtt_qos is not None and 0 <= pkt.mqtt_qos <= 2:
            qos_levels.add(pkt.mqtt_qos)
        if pkt.mqtt_retain is True:
            retain_seen = True

    return {
        "packetTypes": ",".join(packet_types[:8]) or None,
        "topics": ",".join(topics[:8]) or None,
        "clientIds": ",".join(client_ids[:4]) or None,
        "qosLevels": ",".join(str(q) for q in sorted(qos_levels)) or None,
        "publishCount": publish_count if publish_count > 0 else None,
        "subscribeCount": subscribe_count if subscribe_count > 0 else None,
        "retainSeen": retain_seen if packet_types else None,
    }


def extract_opcua_features(packets: Sequence[PacketRecord]) -> Dict[str, Optional[object]]:
    """Extract compact OPC UA metadata from a packet sequence."""
    message_types: List[str] = []
    chunk_types: List[str] = []
    endpoint_urls: List[str] = []
    security_policies: List[str] = []
    secure_channel_ids: set[int] = set()
    open_count = 0
    msg_count = 0
    close_count = 0

    for pkt in packets:
        message_type = (pkt.opcua_message_type or "").upper()
        if message_type:
            if message_type not in message_types:
                message_types.append(message_type)
            if message_type == "OPN":
                open_count += 1
            elif message_type == "MSG":
                msg_count += 1
            elif message_type == "CLO":
                close_count += 1

        chunk_type = (pkt.opcua_chunk_type or "").upper()
        if chunk_type and chunk_type in {"F", "C", "A"} and chunk_type not in chunk_types:
            chunk_types.append(chunk_type)

        if pkt.opcua_endpoint_url:
            endpoint = pkt.opcua_endpoint_url[:200]
            if endpoint not in endpoint_urls:
                endpoint_urls.append(endpoint)

        if pkt.opcua_security_policy_uri:
            policy = pkt.opcua_security_policy_uri[:200]
            if policy not in security_policies:
                security_policies.append(policy)

        if pkt.opcua_secure_channel_id is not None and pkt.opcua_secure_channel_id >= 0:
            secure_channel_ids.add(pkt.opcua_secure_channel_id)

    return {
        "messageTypes": ",".join(message_types[:8]) or None,
        "chunkTypes": ",".join(chunk_types[:3]) or None,
        "endpointUrls": ",".join(endpoint_urls[:4]) or None,
        "securityPolicies": ",".join(security_policies[:4]) or None,
        "secureChannelIds": ",".join(str(scid) for scid in sorted(secure_channel_ids)[:8]) or None,
        "openCount": open_count if open_count > 0 else None,
        "msgCount": msg_count if msg_count > 0 else None,
        "closeCount": close_count if close_count > 0 else None,
    }


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


# ---------------------------------------------------------------------------
# Streaming feature accumulator
# ---------------------------------------------------------------------------


@dataclass
class RelationshipFeatureAccumulator:
    """Single-pass packet feature accumulator for streaming relationship build.

    Mirrors the feature set computed by ``MissingTrafficAugmentor._relationship_properties``
    but never materializes the full packet list. Designed for use with
    ``heapq.merge`` over per-source sorted packet iterators, so memory is
    bounded by the small accumulator state regardless of how many packets
    are folded in.

    Assumes packets are fed in non-decreasing timestamp order. Mixing
    timestamps will degrade timing-sensitive features (inter-arrival,
    retransmits, RTT) but won't crash.
    """

    connection: ConnectionKey

    # Scalar / running stats
    packet_count: int = 0
    total_bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    _prev_ts: Optional[float] = None
    _inter_arrival_sum: float = 0.0
    _inter_arrival_count: int = 0

    # Directional
    bytes_out: int = 0
    bytes_in: int = 0
    packets_out: int = 0
    packets_in: int = 0
    src_mac: str = ""
    dst_mac: str = ""
    _src_mac_locked: bool = False
    _dst_mac_locked: bool = False

    # High-level protocol mix
    _protocol_counts: Counter = field(default_factory=Counter)

    # TCP retransmit detection — per-direction (seq, payload_len) sets
    _retransmits: int = 0
    _seen_seq_out: Set[Tuple[int, int]] = field(default_factory=set)
    _seen_seq_in: Set[Tuple[int, int]] = field(default_factory=set)

    # RTT — pending ack-target → timestamp, in each direction
    _pending_src: Dict[int, float] = field(default_factory=dict)
    _pending_dst: Dict[int, float] = field(default_factory=dict)
    _rtt_sum: float = 0.0
    _rtt_count: int = 0

    # First-non-null grabs
    _tls_sni: Optional[str] = None
    _http_method: Optional[str] = None
    _http_status: Optional[int] = None
    _http_host: str = ""
    _http_path: str = ""
    _http_content_type: str = ""

    # MQTT
    _mqtt_packet_types: List[str] = field(default_factory=list)
    _mqtt_topics: List[str] = field(default_factory=list)
    _mqtt_client_ids: List[str] = field(default_factory=list)
    _mqtt_qos_levels: Set[int] = field(default_factory=set)
    _mqtt_publish_count: int = 0
    _mqtt_subscribe_count: int = 0
    _mqtt_retain_seen: bool = False

    # OPC UA
    _opcua_message_types: List[str] = field(default_factory=list)
    _opcua_chunk_types: List[str] = field(default_factory=list)
    _opcua_endpoint_urls: List[str] = field(default_factory=list)
    _opcua_security_policies: List[str] = field(default_factory=list)
    _opcua_secure_channel_ids: Set[int] = field(default_factory=set)
    _opcua_open_count: int = 0
    _opcua_msg_count: int = 0
    _opcua_close_count: int = 0

    # --- per-packet update ---------------------------------------------------

    def update(self, pkt: PacketRecord) -> None:
        ts = pkt.timestamp

        # Basic counters
        self.packet_count += 1
        self.total_bytes += pkt.size
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts
        # Inter-arrival assumes monotonic feed; for an out-of-order packet we
        # still take a non-negative delta against prev_ts.
        if self._prev_ts is not None:
            delta = ts - self._prev_ts
            if delta >= 0:
                self._inter_arrival_sum += delta
                self._inter_arrival_count += 1
        self._prev_ts = ts

        # Directional + MACs
        direction: Optional[str] = None
        if pkt.src_ip == self.connection.src_ip and pkt.dst_ip == self.connection.dst_ip:
            direction = "out"
            self.bytes_out += pkt.size
            self.packets_out += 1
        elif pkt.src_ip == self.connection.dst_ip and pkt.dst_ip == self.connection.src_ip:
            direction = "in"
            self.bytes_in += pkt.size
            self.packets_in += 1

        if direction == "out" and pkt.src_mac and pkt.dst_mac and not self._src_mac_locked:
            self.src_mac = pkt.src_mac
            self.dst_mac = pkt.dst_mac
            self._src_mac_locked = True
            self._dst_mac_locked = True
        else:
            if not self.src_mac and pkt.src_mac:
                self.src_mac = pkt.src_mac
            if not self.dst_mac and pkt.dst_mac:
                self.dst_mac = pkt.dst_mac

        # High-level protocol counter
        proto = pkt.high_level_protocol or "UNKNOWN"
        self._protocol_counts[proto] += 1

        # TCP retransmits + RTT (only for TCP packets with payload / seq)
        protocol_lower = pkt.protocol.lower()
        if protocol_lower == "tcp":
            self._update_tcp(pkt, direction)

        # TLS SNI (first non-empty wins)
        if self._tls_sni is None and pkt.tls_sni:
            self._tls_sni = pkt.tls_sni

        # HTTP first-non-null
        if self._http_method is None and pkt.http_method:
            self._http_method = pkt.http_method
        if self._http_status is None and pkt.http_status is not None:
            self._http_status = pkt.http_status
        if not self._http_host and pkt.http_host:
            self._http_host = pkt.http_host
        if not self._http_path and pkt.http_path:
            self._http_path = pkt.http_path
        if not self._http_content_type and pkt.http_content_type:
            self._http_content_type = pkt.http_content_type

        # MQTT
        pkt_type = (pkt.mqtt_packet_type or "").upper()
        if pkt_type:
            if pkt_type not in self._mqtt_packet_types:
                self._mqtt_packet_types.append(pkt_type)
            if pkt_type == "PUBLISH":
                self._mqtt_publish_count += 1
            elif pkt_type in {"SUBSCRIBE", "UNSUBSCRIBE"}:
                self._mqtt_subscribe_count += 1
        if pkt.mqtt_topic:
            topic = pkt.mqtt_topic[:120]
            if topic not in self._mqtt_topics:
                self._mqtt_topics.append(topic)
        if pkt.mqtt_client_id:
            cid = pkt.mqtt_client_id[:120]
            if cid not in self._mqtt_client_ids:
                self._mqtt_client_ids.append(cid)
        if pkt.mqtt_qos is not None and 0 <= pkt.mqtt_qos <= 2:
            self._mqtt_qos_levels.add(pkt.mqtt_qos)
        if pkt.mqtt_retain is True:
            self._mqtt_retain_seen = True

        # OPC UA
        message_type = (pkt.opcua_message_type or "").upper()
        if message_type:
            if message_type not in self._opcua_message_types:
                self._opcua_message_types.append(message_type)
            if message_type == "OPN":
                self._opcua_open_count += 1
            elif message_type == "MSG":
                self._opcua_msg_count += 1
            elif message_type == "CLO":
                self._opcua_close_count += 1
        chunk_type = (pkt.opcua_chunk_type or "").upper()
        if chunk_type and chunk_type in {"F", "C", "A"} and chunk_type not in self._opcua_chunk_types:
            self._opcua_chunk_types.append(chunk_type)
        if pkt.opcua_endpoint_url:
            endpoint = pkt.opcua_endpoint_url[:200]
            if endpoint not in self._opcua_endpoint_urls:
                self._opcua_endpoint_urls.append(endpoint)
        if pkt.opcua_security_policy_uri:
            policy = pkt.opcua_security_policy_uri[:200]
            if policy not in self._opcua_security_policies:
                self._opcua_security_policies.append(policy)
        if pkt.opcua_secure_channel_id is not None and pkt.opcua_secure_channel_id >= 0:
            self._opcua_secure_channel_ids.add(pkt.opcua_secure_channel_id)

    def _update_tcp(self, pkt: PacketRecord, direction: Optional[str]) -> None:
        seq = pkt.tcp_seq
        ack = pkt.tcp_ack
        payload_len = pkt.payload_len or 0
        flags = pkt.tcp_flags or ""

        # Retransmit detection: same (seq, payload_len) seen again in same direction.
        if seq is not None and payload_len > 0 and direction is not None:
            key = (seq, payload_len)
            if direction == "out":
                if key in self._seen_seq_out:
                    self._retransmits += 1
                else:
                    self._seen_seq_out.add(key)
            else:
                if key in self._seen_seq_in:
                    self._retransmits += 1
                else:
                    self._seen_seq_in.add(key)

        # RTT estimation via ack-target tracking.
        if direction == "out" and seq is not None:
            ack_target = seq + max(payload_len, 0)
            if "S" in flags or "F" in flags:
                ack_target += 1
            if ack_target > seq and ack_target not in self._pending_src:
                self._pending_src[ack_target] = pkt.timestamp
        elif direction == "in" and seq is not None:
            ack_target = seq + max(payload_len, 0)
            if "S" in flags or "F" in flags:
                ack_target += 1
            if ack_target > seq and ack_target not in self._pending_dst:
                self._pending_dst[ack_target] = pkt.timestamp

        if direction == "in" and ack is not None and ack in self._pending_src:
            ts = self._pending_src.pop(ack)
            self._rtt_sum += (pkt.timestamp - ts) * 1000.0
            self._rtt_count += 1
        elif direction == "out" and ack is not None and ack in self._pending_dst:
            ts = self._pending_dst.pop(ack)
            self._rtt_sum += (pkt.timestamp - ts) * 1000.0
            self._rtt_count += 1

    # --- output --------------------------------------------------------------

    def feature_dict(self) -> Dict[str, Any]:
        """Return the same dict shape as MissingTrafficAugmentor._relationship_properties."""
        dir_index = directionality_ratio(self.bytes_out, self.bytes_in)
        if self.packet_count > 0:
            avg_pkt_size = self.total_bytes / self.packet_count
        else:
            avg_pkt_size = 0.0
        inter_arrival = (
            self._inter_arrival_sum / self._inter_arrival_count
            if self._inter_arrival_count > 0 else 0.0
        )
        duration = (
            self.last_seen - self.first_seen
            if self.first_seen is not None and self.last_seen is not None else 0.0
        )
        if self._protocol_counts:
            high_level = self._protocol_counts.most_common(1)[0][0]
        else:
            high_level = "UNKNOWN"
        rtt_ms = (self._rtt_sum / self._rtt_count) if self._rtt_count > 0 else 0.0

        http_content = ""
        if self._http_host or self._http_path:
            http_content = f"{self._http_host}{self._http_path}"
        elif self._http_content_type:
            http_content = self._http_content_type

        return {
            "SourceIp": self.connection.src_ip,
            "SourcePort": self.connection.src_port,
            "DestinationIp": self.connection.dst_ip,
            "DestinationPort": self.connection.dst_port,
            "Protocol": self.connection.protocol.lower(),
            "inferredFrom": "pcap",
            "pcapAugmented": True,
            "note": "Observed in PCAP but missing from host telemetry",
            "packetCount": self.packet_count,
            "durationSeconds": duration,
            "avgPacketSize": round(avg_pkt_size, 2),
            "highLevelProtocol": high_level,
            "firstSeen": self.first_seen,
            "lastSeen": self.last_seen,
            "srcMac": self.src_mac or None,
            "dstMac": self.dst_mac or None,
            "bytesOut": self.bytes_out,
            "bytesIn": self.bytes_in,
            "directionalityIndex": round(dir_index, 6) if dir_index is not None else None,
            "meanInterArrivalPacketTime": round(inter_arrival, 6),
            "retransmits": self._retransmits,
            "tlsSNI": self._tls_sni or None,
            "httpMethod": self._http_method,
            "httpStatus": self._http_status,
            "httpContent": http_content or None,
            "mqttPacketTypes": ",".join(self._mqtt_packet_types[:8]) or None,
            "mqttTopics": ",".join(self._mqtt_topics[:8]) or None,
            "mqttClientIds": ",".join(self._mqtt_client_ids[:4]) or None,
            "mqttQosLevels": ",".join(str(q) for q in sorted(self._mqtt_qos_levels)) or None,
            "mqttPublishCount": self._mqtt_publish_count if self._mqtt_publish_count > 0 else None,
            "mqttSubscribeCount": self._mqtt_subscribe_count if self._mqtt_subscribe_count > 0 else None,
            "mqttRetainSeen": self._mqtt_retain_seen if self._mqtt_packet_types else None,
            "opcuaMessageTypes": ",".join(self._opcua_message_types[:8]) or None,
            "opcuaChunkTypes": ",".join(self._opcua_chunk_types[:3]) or None,
            "opcuaEndpointUrls": ",".join(self._opcua_endpoint_urls[:4]) or None,
            "opcuaSecurityPolicies": ",".join(self._opcua_security_policies[:4]) or None,
            "opcuaSecureChannelIds": ",".join(
                str(scid) for scid in sorted(self._opcua_secure_channel_ids)[:8]
            ) or None,
            "opcuaOpenCount": self._opcua_open_count if self._opcua_open_count > 0 else None,
            "opcuaMsgCount": self._opcua_msg_count if self._opcua_msg_count > 0 else None,
            "opcuaCloseCount": self._opcua_close_count if self._opcua_close_count > 0 else None,
            "rttMs": round(rtt_ms, 3) if rtt_ms > 0.0 else None,
        }


def stream_relationship_features(
    connection: ConnectionKey,
    packets: Iterator[PacketRecord],
) -> Dict[str, Any]:
    """Build the relationship feature dict by streaming packets through an accumulator.

    Equivalent to materializing ``packets`` into a list and calling the
    legacy list-based extractors, but memory is bounded by accumulator
    state. Use this when the packet source is large (e.g. ``heapq.merge``
    over many spooled connections feeding a single base-graph edge).
    """
    acc = RelationshipFeatureAccumulator(connection=connection)
    for pkt in packets:
        acc.update(pkt)
    return acc.feature_dict()
