"""Standalone raw signal extraction helpers for MQTT and OPC UA."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Sequence, Tuple

from .models import PacketRecord
from .protocol_utils import generate_signal_guid

_MAX_PENDING_PACKETS = 256


def resolve_hostname(ip_address: str, ip_to_host: Dict[str, str]) -> str:
    """Resolve an IP to a hostname, falling back to the IP string."""
    return ip_to_host.get(ip_address, ip_address)


def extract_mqtt_signal_observations(
    *,
    packets: Sequence[PacketRecord],
    client_ip: str,
    server_ip: str,
    server_port: int,
    ip_to_host: Dict[str, str],
) -> List[Tuple[object, ...]]:
    """Extract raw numeric MQTT observations from a connection."""
    client_host = resolve_hostname(client_ip, ip_to_host)
    server_host = resolve_hostname(server_ip, ip_to_host)
    connection_client_id = _find_mqtt_client_id(packets, client_ip, server_ip, server_port)

    observations: List[Tuple[object, ...]] = []
    for packet in packets:
        if (packet.mqtt_packet_type or "").upper() != "PUBLISH":
            continue

        topic = (packet.mqtt_topic or "").strip()
        if not topic or not packet.mqtt_payload_values:
            continue

        access_type: Optional[str] = None
        if packet.dst_ip == server_ip and packet.dst_port == server_port:
            access_type = "write"
        elif packet.src_ip == server_ip and packet.src_port == server_port:
            access_type = "read"
        if access_type is None:
            continue

        for field_name, value in packet.mqtt_payload_values:
            clean_field = str(field_name or "value").strip() or "value"
            signal_name = f"{topic}.{clean_field}"
            signal_guid = generate_signal_guid(
                "mqtt", server_host, server_port, topic, clean_field
            )
            observations.append(
                (
                    packet.timestamp,
                    topic,
                    clean_field,
                    signal_name,
                    float(value),
                    access_type,
                    client_host,
                    server_host,
                    client_ip,
                    server_ip,
                    packet.mqtt_packet_id,
                    packet.mqtt_qos,
                    packet.mqtt_retain,
                    packet.mqtt_dup,
                    packet.mqtt_client_id or connection_client_id,
                    signal_guid,
                    packet.pcap_file,
                )
            )

    return observations


class MqttSignalStreamExtractor:
    """Streaming MQTT extractor that keeps only small per-connection state."""

    def __init__(self, *, ip_to_host: Dict[str, str]) -> None:
        self.ip_to_host = ip_to_host
        self.client_ip: Optional[str] = None
        self.server_ip: Optional[str] = None
        self.server_port: Optional[int] = None
        self.client_id: Optional[str] = None
        self._pending_packets: Deque[PacketRecord] = deque(maxlen=_MAX_PENDING_PACKETS)

    def consume(self, packet: PacketRecord) -> List[Tuple[object, ...]]:
        rows: List[Tuple[object, ...]] = []

        orientation = self._infer_orientation(packet)
        if orientation is not None:
            self.client_ip, self.server_ip, self.server_port = orientation

        if not self._is_oriented:
            self._pending_packets.append(packet)
            return rows

        if self._pending_packets:
            while self._pending_packets:
                rows.extend(self._process_packet(self._pending_packets.popleft()))

        rows.extend(self._process_packet(packet))
        return rows

    def finish(self) -> List[Tuple[object, ...]]:
        if not self._is_oriented or not self._pending_packets:
            self._pending_packets.clear()
            return []

        rows: List[Tuple[object, ...]] = []
        while self._pending_packets:
            rows.extend(self._process_packet(self._pending_packets.popleft()))
        return rows

    @property
    def _is_oriented(self) -> bool:
        return (
            self.client_ip is not None
            and self.server_ip is not None
            and self.server_port is not None
        )

    def _infer_orientation(self, packet: PacketRecord) -> Optional[Tuple[str, str, int]]:
        if self._is_oriented:
            return self.client_ip, self.server_ip, self.server_port

        if packet.dst_port in {1883, 8883} and packet.src_port not in {1883, 8883}:
            return packet.src_ip, packet.dst_ip, packet.dst_port
        if packet.src_port in {1883, 8883} and packet.dst_port not in {1883, 8883}:
            return packet.dst_ip, packet.src_ip, packet.src_port

        if (
            packet.mqtt_packet_type_code == 1
            and (packet.mqtt_packet_type or "").upper() == "CONNECT"
            and packet.dst_port > 0
        ):
            return packet.src_ip, packet.dst_ip, packet.dst_port

        return None

    def _process_packet(self, packet: PacketRecord) -> List[Tuple[object, ...]]:
        assert self.client_ip is not None
        assert self.server_ip is not None
        assert self.server_port is not None

        if (
            packet.src_ip == self.client_ip
            and packet.dst_ip == self.server_ip
            and packet.dst_port == self.server_port
            and (packet.mqtt_packet_type or "").upper() == "CONNECT"
            and packet.mqtt_client_id
        ):
            self.client_id = packet.mqtt_client_id

        if (packet.mqtt_packet_type or "").upper() != "PUBLISH":
            return []

        topic = (packet.mqtt_topic or "").strip()
        if not topic or not packet.mqtt_payload_values:
            return []

        access_type: Optional[str] = None
        if packet.dst_ip == self.server_ip and packet.dst_port == self.server_port:
            access_type = "write"
        elif packet.src_ip == self.server_ip and packet.src_port == self.server_port:
            access_type = "read"
        if access_type is None:
            return []

        client_host = resolve_hostname(self.client_ip, self.ip_to_host)
        server_host = resolve_hostname(self.server_ip, self.ip_to_host)

        rows: List[Tuple[object, ...]] = []
        for field_name, value in packet.mqtt_payload_values:
            clean_field = str(field_name or "value").strip() or "value"
            signal_name = f"{topic}.{clean_field}"
            signal_guid = generate_signal_guid(
                "mqtt", server_host, self.server_port, topic, clean_field
            )
            rows.append(
                (
                    packet.timestamp,
                    topic,
                    clean_field,
                    signal_name,
                    float(value),
                    access_type,
                    client_host,
                    server_host,
                    self.client_ip,
                    self.server_ip,
                    packet.mqtt_packet_id,
                    packet.mqtt_qos,
                    packet.mqtt_retain,
                    packet.mqtt_dup,
                    packet.mqtt_client_id or self.client_id,
                    signal_guid,
                    packet.pcap_file,
                )
            )

        return rows


@dataclass(frozen=True)
class _PendingOpcUaRequest:
    timestamp: float
    node_ids: Tuple[str, ...]
    operation: str


def extract_opcua_signal_observations(
    *,
    packets: Sequence[PacketRecord],
    client_ip: str,
    server_ip: str,
    server_port: int,
    ip_to_host: Dict[str, str],
) -> List[Tuple[object, ...]]:
    """Extract raw numeric OPC UA observations from a connection."""
    client_host = resolve_hostname(client_ip, ip_to_host)
    server_host = resolve_hostname(server_ip, ip_to_host)

    observations: List[Tuple[object, ...]] = []
    pending_requests: Dict[Tuple[str, int, int], _PendingOpcUaRequest] = {}

    for packet in packets:
        service_type = (packet.opcua_service_type or "").strip()
        operation = (packet.opcua_operation or "").strip().lower()
        message_type = (packet.opcua_message_type or "").upper()
        from_server = packet.src_ip == server_ip and packet.src_port == server_port
        to_server = packet.dst_ip == server_ip and packet.dst_port == server_port
        explicit_node_ids = _filter_explicit_node_ids(packet.opcua_node_ids)

        if to_server and explicit_node_ids and operation in {"read", "write"}:
            key = _opcua_request_key(
                client_ip=packet.src_ip,
                secure_channel_id=packet.opcua_secure_channel_id,
                request_id=packet.opcua_request_id,
            )
            if key is not None:
                pending_requests[key] = _PendingOpcUaRequest(
                    timestamp=packet.timestamp,
                    node_ids=explicit_node_ids,
                    operation=operation,
                )

            if operation == "write" and packet.opcua_values:
                observations.extend(
                    _build_opcua_value_rows(
                        packet=packet,
                        node_ids=explicit_node_ids,
                        values=packet.opcua_values,
                        access_type="write",
                        client_host=client_host,
                        server_host=server_host,
                        client_ip=client_ip,
                        server_ip=server_ip,
                        server_port=server_port,
                    )
                )
            continue

        if from_server and service_type in {"ReadResponse", "WriteResponse"}:
            key = _opcua_request_key(
                client_ip=packet.dst_ip,
                secure_channel_id=packet.opcua_secure_channel_id,
                request_id=packet.opcua_request_id,
            )
            pending = pending_requests.pop(key, None) if key is not None else None
            if pending is None:
                continue

            if service_type == "ReadResponse" and pending.operation == "read" and packet.opcua_values:
                observations.extend(
                    _build_opcua_value_rows(
                        packet=packet,
                        node_ids=pending.node_ids,
                        values=packet.opcua_values,
                        access_type="read",
                        client_host=client_host,
                        server_host=server_host,
                        client_ip=client_ip,
                        server_ip=server_ip,
                        server_port=server_port,
                    )
                )

    return observations


class OpcUaSignalStreamExtractor:
    """Streaming OPC UA extractor that preserves only request correlation state."""

    def __init__(self, *, ip_to_host: Dict[str, str]) -> None:
        self.ip_to_host = ip_to_host
        self.client_ip: Optional[str] = None
        self.server_ip: Optional[str] = None
        self.server_port: Optional[int] = None
        self.pending_requests: Dict[Tuple[str, int, int], _PendingOpcUaRequest] = {}
        self._pending_packets: Deque[PacketRecord] = deque(maxlen=_MAX_PENDING_PACKETS)

    def consume(self, packet: PacketRecord) -> List[Tuple[object, ...]]:
        rows: List[Tuple[object, ...]] = []

        orientation = self._infer_orientation(packet)
        if orientation is not None:
            self.client_ip, self.server_ip, self.server_port = orientation

        if not self._is_oriented:
            self._pending_packets.append(packet)
            return rows

        if self._pending_packets:
            while self._pending_packets:
                rows.extend(self._process_packet(self._pending_packets.popleft()))

        rows.extend(self._process_packet(packet))
        return rows

    def finish(self) -> List[Tuple[object, ...]]:
        if not self._is_oriented or not self._pending_packets:
            self._pending_packets.clear()
            self.pending_requests.clear()
            return []

        rows: List[Tuple[object, ...]] = []
        while self._pending_packets:
            rows.extend(self._process_packet(self._pending_packets.popleft()))
        self.pending_requests.clear()
        return rows

    @property
    def _is_oriented(self) -> bool:
        return (
            self.client_ip is not None
            and self.server_ip is not None
            and self.server_port is not None
        )

    def _infer_orientation(self, packet: PacketRecord) -> Optional[Tuple[str, str, int]]:
        if self._is_oriented:
            return self.client_ip, self.server_ip, self.server_port

        if packet.dst_port == 4840 and packet.src_port != 4840:
            return packet.src_ip, packet.dst_ip, packet.dst_port
        if packet.src_port == 4840 and packet.dst_port != 4840:
            return packet.dst_ip, packet.src_ip, packet.src_port

        message_type = (packet.opcua_message_type or "").upper()
        if message_type in {"HEL", "OPN"} and packet.dst_port > 0:
            return packet.src_ip, packet.dst_ip, packet.dst_port

        return None

    def _process_packet(self, packet: PacketRecord) -> List[Tuple[object, ...]]:
        assert self.client_ip is not None
        assert self.server_ip is not None
        assert self.server_port is not None

        client_host = resolve_hostname(self.client_ip, self.ip_to_host)
        server_host = resolve_hostname(self.server_ip, self.ip_to_host)

        rows: List[Tuple[object, ...]] = []
        service_type = (packet.opcua_service_type or "").strip()
        operation = (packet.opcua_operation or "").strip().lower()
        from_server = packet.src_ip == self.server_ip and packet.src_port == self.server_port
        to_server = packet.dst_ip == self.server_ip and packet.dst_port == self.server_port
        explicit_node_ids = _filter_explicit_node_ids(packet.opcua_node_ids)

        if to_server and explicit_node_ids and operation in {"read", "write"}:
            key = _opcua_request_key(
                client_ip=packet.src_ip,
                secure_channel_id=packet.opcua_secure_channel_id,
                request_id=packet.opcua_request_id,
            )
            if key is not None:
                self.pending_requests[key] = _PendingOpcUaRequest(
                    timestamp=packet.timestamp,
                    node_ids=explicit_node_ids,
                    operation=operation,
                )

            if operation == "write" and packet.opcua_values:
                rows.extend(
                    _build_opcua_value_rows(
                        packet=packet,
                        node_ids=explicit_node_ids,
                        values=packet.opcua_values,
                        access_type="write",
                        client_host=client_host,
                        server_host=server_host,
                        client_ip=self.client_ip,
                        server_ip=self.server_ip,
                        server_port=self.server_port,
                    )
                )
            return rows

        if from_server and service_type in {"ReadResponse", "WriteResponse"}:
            key = _opcua_request_key(
                client_ip=packet.dst_ip,
                secure_channel_id=packet.opcua_secure_channel_id,
                request_id=packet.opcua_request_id,
            )
            pending = self.pending_requests.pop(key, None) if key is not None else None
            if pending is None:
                return rows

            if service_type == "ReadResponse" and pending.operation == "read" and packet.opcua_values:
                rows.extend(
                    _build_opcua_value_rows(
                        packet=packet,
                        node_ids=pending.node_ids,
                        values=packet.opcua_values,
                        access_type="read",
                        client_host=client_host,
                        server_host=server_host,
                        client_ip=self.client_ip,
                        server_ip=self.server_ip,
                        server_port=self.server_port,
                    )
                )

        return rows


def _find_mqtt_client_id(
    packets: Sequence[PacketRecord],
    client_ip: str,
    server_ip: str,
    server_port: int,
) -> Optional[str]:
    for packet in packets:
        if (
            packet.src_ip == client_ip
            and packet.dst_ip == server_ip
            and packet.dst_port == server_port
            and (packet.mqtt_packet_type or "").upper() == "CONNECT"
            and packet.mqtt_client_id
        ):
            return packet.mqtt_client_id
    return None


def _filter_explicit_node_ids(node_ids: Sequence[str]) -> Tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            node_id
            for node_id in node_ids
            if node_id
            and not node_id.startswith("ns=0;")
            and not node_id.startswith("ns=1;")
        )
    )


def _opcua_request_key(
    *,
    client_ip: str,
    secure_channel_id: Optional[int],
    request_id: Optional[int],
) -> Optional[Tuple[str, int, int]]:
    if request_id is None:
        return None
    return (client_ip, secure_channel_id if secure_channel_id is not None else -1, request_id)


def _opcua_display_name(node_id: str) -> str:
    marker = ";s="
    if marker not in node_id:
        return node_id
    raw = node_id.split(marker, 1)[1] or node_id
    if '".' in raw or '."' in raw:
        raw = raw.replace('"."', ".").replace('."', ".").replace('"', "")
    return raw


def _build_opcua_value_rows(
    *,
    packet: PacketRecord,
    node_ids: Sequence[str],
    values: Sequence[Optional[float]],
    access_type: str,
    client_host: str,
    server_host: str,
    client_ip: str,
    server_ip: str,
    server_port: int,
) -> List[Tuple[object, ...]]:
    rows: List[Tuple[object, ...]] = []
    for index, node_id in enumerate(node_ids):
        value = values[index] if index < len(values) else None
        if value is None:
            continue
        rows.append(
            (
                packet.timestamp,
                node_id,
                _opcua_display_name(node_id),
                float(value),
                access_type,
                packet.opcua_message_type,
                packet.opcua_service_type,
                client_host,
                server_host,
                client_ip,
                server_ip,
                packet.opcua_request_id,
                packet.opcua_secure_channel_id,
                generate_signal_guid("opcua", server_host, server_port, node_id),
                packet.pcap_file,
            )
        )
    return rows
