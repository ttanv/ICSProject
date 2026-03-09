"""Core data models used by the network augmentation pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class SignalContainerData:
    """Lightweight signal reference for Neo4j export.

    Actual signal observations are stored in DuckDB.
    This class represents metadata about a signal at a specific observer endpoint.
    """

    address: int
    """Signal address (e.g., Modbus register address 40001)."""

    unit_id: Optional[int]
    """Protocol-specific unit identifier (e.g., Modbus unit ID)."""

    observer_host: str
    """Hostname of the device that observed this signal traffic."""

    port: int
    """Service port where signal was observed (e.g., 502 for Modbus)."""

    modbus_register_type: Optional[str] = None
    """Original Modbus register type if applicable: coil, discreteInput,
    holdingRegister, inputRegister."""

    # Aggregate metadata (computed during collection)
    total_observations: int = 0
    read_count: int = 0
    write_count: int = 0
    first_seen_at: Optional[float] = None
    last_seen_at: Optional[float] = None

    def to_properties(self) -> Dict[str, Any]:
        """Convert to Neo4j node properties dict.

        Returns:
            Dict containing lightweight reference properties.
        """
        props: Dict[str, Any] = {
            "address": self.address,
            "port": self.port,
            "observerHost": self.observer_host,
            "totalObservations": self.total_observations,
            "readCount": self.read_count,
            "writeCount": self.write_count,
            "pcapAugmented": True,
        }

        if self.unit_id is not None:
            props["unitId"] = self.unit_id

        if self.modbus_register_type:
            props["modbusRegisterType"] = self.modbus_register_type

        if self.first_seen_at is not None:
            props["firstSeenAt"] = self.first_seen_at
        if self.last_seen_at is not None:
            props["lastSeenAt"] = self.last_seen_at

        return props


@dataclass(frozen=True)
class ConnectionKey:
    """Normalized five-tuple key for a network conversation."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    def normalized_tuple(self) -> Tuple[str, int, str, int, str]:
        """Return a bidirectional canonical tuple for comparison."""
        left = (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)
        right = (self.dst_ip, self.dst_port, self.src_ip, self.src_port, self.protocol)
        return min(left, right)

    def bidirectional_id(self) -> str:
        """Return a stable identifier used across modules."""
        src = f"{self.src_ip}:{self.src_port}"
        dst = f"{self.dst_ip}:{self.dst_port}"
        fwd = f"{src}->{dst}:{self.protocol}"
        rev = f"{dst}->{src}:{self.protocol}"
        return min(fwd, rev)

    def to_dict(self) -> Dict[str, object]:
        """Serialize the key to a plain dictionary."""
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
        }

    @classmethod
    def from_dict(cls, props: Dict[str, str]) -> "ConnectionKey":
        """Build a key from a dictionary containing connection properties."""
        return cls(
            src_ip=str(props.get("SourceIp") or props.get("sourceIp") or ""),
            src_port=int(props.get("SourcePort") or props.get("sourcePort") or 0),
            dst_ip=str(
                props.get("DestinationIp")
                or props.get("destinationIp")
                or props.get("DestIp")
                or props.get("destIp")
                or ""
            ),
            dst_port=int(
                props.get("DestinationPort")
                or props.get("destinationPort")
                or props.get("DestPort")
                or props.get("destPort")
                or 0
            ),
            protocol=str(props.get("Protocol") or props.get("protocol") or "tcp").lower(),
        )


@dataclass
class PacketRecord:
    """Summary of a single packet extracted from PCAP."""

    pcap_file: str
    packet_index: int
    timestamp: float
    size: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    high_level_protocol: str
    ip_layer_index: int
    ip_layer_count: int
    src_mac: str = ""
    dst_mac: str = ""
    tcp_flags: str = ""
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    payload_len: int = 0
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    http_content_type: Optional[str] = None
    tls_sni: Optional[str] = None
    mqtt_packet_type: Optional[str] = None
    mqtt_packet_type_code: Optional[int] = None
    mqtt_topic: Optional[str] = None
    mqtt_qos: Optional[int] = None
    mqtt_retain: Optional[bool] = None
    mqtt_dup: Optional[bool] = None
    mqtt_client_id: Optional[str] = None
    mqtt_keepalive: Optional[int] = None
    mqtt_packet_id: Optional[int] = None
    mqtt_payload_size: Optional[int] = None
    opcua_message_type: Optional[str] = None
    opcua_chunk_type: Optional[str] = None
    opcua_message_size: Optional[int] = None
    opcua_secure_channel_id: Optional[int] = None
    opcua_endpoint_url: Optional[str] = None
    opcua_security_policy_uri: Optional[str] = None
    opcua_service_type: Optional[str] = None
    opcua_operation: Optional[str] = None
    opcua_request_id: Optional[int] = None
    opcua_node_ids: Tuple[str, ...] = field(default_factory=tuple)
    modbus_function: Optional[int] = None
    modbus_unit_id: Optional[int] = None
    modbus_registers: Tuple[int, ...] = field(default_factory=tuple)
    modbus_read_registers: Tuple[int, ...] = field(default_factory=tuple)
    modbus_write_registers: Tuple[int, ...] = field(default_factory=tuple)
    modbus_register_values: Tuple[int, ...] = field(default_factory=tuple)
    modbus_transaction_id: Optional[int] = None
    opcua_values: Tuple[Optional[float], ...] = field(default_factory=tuple)
    mqtt_payload_values: Tuple[Tuple[str, float], ...] = field(default_factory=tuple)

    def connection_key(self) -> ConnectionKey:
        """Return the five-tuple key represented by this packet."""
        return ConnectionKey(
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            protocol=self.protocol,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "PacketRecord":
        """Create a PacketRecord from a plain dictionary."""
        def _optional_int(value: object) -> Optional[int]:
            if value in (None, "", "None"):
                return None
            try:
                return int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                try:
                    return int(float(value))  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    return None

        def _optional_bool(value: object) -> Optional[bool]:
            if value in (None, "", "None"):
                return None
            if isinstance(value, bool):
                return value
            text = str(value).strip().lower()
            if text in ("1", "true", "yes", "y"):
                return True
            if text in ("0", "false", "no", "n"):
                return False
            return None

        return cls(
            pcap_file=str(data.get("pcap_file", "")),
            packet_index=int(data.get("packet_index", 0)),
            timestamp=float(data.get("timestamp", 0.0)),
            size=int(data.get("size", 0)),
            src_ip=str(data.get("src_ip", "")),
            dst_ip=str(data.get("dst_ip", "")),
            src_port=int(data.get("src_port", 0)),
            dst_port=int(data.get("dst_port", 0)),
            protocol=str(data.get("protocol", "tcp")),
            high_level_protocol=str(data.get("high_level_protocol", "UNKNOWN")),
            ip_layer_index=int(data.get("ip_layer_index", 0)),
            ip_layer_count=int(data.get("ip_layer_count", 1)),
            src_mac=str(data.get("src_mac") or ""),
            dst_mac=str(data.get("dst_mac") or ""),
            tcp_flags=str(data.get("tcp_flags") or ""),
            tcp_seq=_optional_int(data.get("tcp_seq")),
            tcp_ack=_optional_int(data.get("tcp_ack")),
            payload_len=_optional_int(data.get("payload_len")) or 0,
            http_method=str(data.get("http_method") or "") or None,
            http_host=str(data.get("http_host") or "") or None,
            http_path=str(data.get("http_path") or "") or None,
            http_status=_optional_int(data.get("http_status")),
            http_content_type=str(data.get("http_content_type") or "") or None,
            tls_sni=str(data.get("tls_sni") or "") or None,
            mqtt_packet_type=str(data.get("mqtt_packet_type") or "") or None,
            mqtt_packet_type_code=_optional_int(data.get("mqtt_packet_type_code")),
            mqtt_topic=str(data.get("mqtt_topic") or "") or None,
            mqtt_qos=_optional_int(data.get("mqtt_qos")),
            mqtt_retain=_optional_bool(data.get("mqtt_retain")),
            mqtt_dup=_optional_bool(data.get("mqtt_dup")),
            mqtt_client_id=str(data.get("mqtt_client_id") or "") or None,
            mqtt_keepalive=_optional_int(data.get("mqtt_keepalive")),
            mqtt_packet_id=_optional_int(data.get("mqtt_packet_id")),
            mqtt_payload_size=_optional_int(data.get("mqtt_payload_size")),
            opcua_message_type=str(data.get("opcua_message_type") or "") or None,
            opcua_chunk_type=str(data.get("opcua_chunk_type") or "") or None,
            opcua_message_size=_optional_int(data.get("opcua_message_size")),
            opcua_secure_channel_id=_optional_int(data.get("opcua_secure_channel_id")),
            opcua_endpoint_url=str(data.get("opcua_endpoint_url") or "") or None,
            opcua_security_policy_uri=str(data.get("opcua_security_policy_uri") or "") or None,
            opcua_service_type=str(data.get("opcua_service_type") or "") or None,
            opcua_operation=str(data.get("opcua_operation") or "") or None,
            opcua_request_id=_optional_int(data.get("opcua_request_id")),
            opcua_node_ids=tuple(str(node) for node in data.get("opcua_node_ids") or []),
            modbus_function=_optional_int(data.get("modbus_function")),
            modbus_unit_id=_optional_int(data.get("modbus_unit_id")),
            modbus_registers=tuple(int(reg) for reg in data.get("modbus_registers") or []),
            modbus_read_registers=tuple(int(reg) for reg in data.get("modbus_read_registers") or []),
            modbus_write_registers=tuple(int(reg) for reg in data.get("modbus_write_registers") or []),
            modbus_register_values=tuple(int(val) for val in data.get("modbus_register_values") or []),
            modbus_transaction_id=_optional_int(data.get("modbus_transaction_id")),
            opcua_values=tuple(
                None if v is None else float(v)
                for v in (data.get("opcua_values") or [])
            ),
            mqtt_payload_values=tuple(
                (str(pair[0]), float(pair[1]))
                for pair in (data.get("mqtt_payload_values") or [])
            ),
        )


def iter_connection_ids(records: Iterable[PacketRecord]) -> Iterable[str]:
    """Yield bidirectional identifiers for a sequence of packet records."""
    for record in records:
        yield record.connection_key().bidirectional_id()


@dataclass
class IndexedConnection:
    """Aggregated view of packets grouped by canonical connection ID.

    `origin` is the first-observed packet direction for the canonical flow. It is
    not guaranteed to be the semantic client->server orientation; callers that
    need client/server semantics must explicitly orient the flow from packets.
    """

    canonical_id: str
    origin: ConnectionKey
    records: List[PacketRecord]
    origin_timestamp: float
