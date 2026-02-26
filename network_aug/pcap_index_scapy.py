"""Utilities for indexing PCAP files and exposing packet summaries per connection."""

from __future__ import annotations

import gc
import pickle
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Iterator, List, MutableMapping, NamedTuple, Optional, Tuple

import scapy.all as scapy
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBTSession
from scapy.layers.smb import SMB_Header

from dataclasses import asdict

from tqdm import tqdm

from .mqtt_helpers import MQTTDetails, parse_mqtt_details
from .opcua_helpers import OPCUADetails, OPCUA_PORTS, parse_opcua_details
from .models import ConnectionKey, IndexedConnection, PacketRecord


class _ModbusDetails(NamedTuple):
    function_code: Optional[int]
    unit_id: Optional[int]
    registers: Tuple[int, ...]
    read_registers: Tuple[int, ...]
    write_registers: Tuple[int, ...]
    register_values: Tuple[int, ...]
    transaction_id: Optional[int]


class ScapyPCAPConnectionIndex:
    """Streaming PCAP index that groups packets by normalized connection key."""

    _IGNORED_IPS: frozenset[str] = frozenset({"172.16.142.250"})

    def __init__(
        self,
        pcap_directory: Path,
        cache_path: Optional[Path] = None,
        prefer_innermost: bool = True,
        packet_limit: Optional[int] = None,
    ) -> None:
        self.pcap_directory = Path(pcap_directory)
        self.cache_path = Path(cache_path) if cache_path else Path("pcap_connection_index.pkl")
        self._index: MutableMapping[str, IndexedConnection] = {}
        self.prefer_innermost = prefer_innermost
        self.packet_limit = packet_limit

    def build(self, force_rebuild: bool = False) -> None:
        """Populate the connection index from PCAP files or cache."""
        if not force_rebuild and self.cache_path.exists():
            with self.cache_path.open("rb") as fh:
                cached = pickle.load(fh)
            self._index = {}
            for key, payload in cached.items():
                if isinstance(payload, list):
                    # Backwards compatibility with older cache format
                    records = [PacketRecord.from_dict(pkt) for pkt in payload]
                    origin = records[0].connection_key() if records else ConnectionKey("", 0, "", 0, "tcp")
                    origin_ts = records[0].timestamp if records else 0.0
                else:
                    origin_dict = payload.get("origin", {})
                    origin = ConnectionKey(
                        src_ip=origin_dict.get("src_ip", ""),
                        src_port=int(origin_dict.get("src_port", 0)),
                        dst_ip=origin_dict.get("dst_ip", ""),
                        dst_port=int(origin_dict.get("dst_port", 0)),
                        protocol=str(origin_dict.get("protocol", "tcp")).lower(),
                    )
                    records = [PacketRecord.from_dict(pkt) for pkt in payload.get("records", [])]
                    origin_ts = float(payload.get("origin_timestamp", records[0].timestamp if records else 0.0))
                if self._should_ignore_connection(origin):
                    continue
                self._index[key] = IndexedConnection(
                    canonical_id=key,
                    origin=origin,
                    records=records,
                    origin_timestamp=origin_ts,
                )
            return

        if not self.pcap_directory.exists():
            raise FileNotFoundError(f"PCAP directory not found: {self.pcap_directory}")

        pcap_files = sorted(f for f in self.pcap_directory.iterdir() if f.suffix in {".pcap", ".pcapng"})
        processed_packets = 0
        for pcap_file in pcap_files:
            with scapy.PcapReader(str(pcap_file)) as reader:
                packet_iter = enumerate(reader)
                packet_bar = tqdm(
                    packet_iter,
                    desc=f"Packets ({pcap_file.name})",
                    unit="pkt",
                    total=self.packet_limit if self.packet_limit is not None else None,
                    leave=False,
                )
                for packet_index, packet in packet_bar:
                    if self.packet_limit is not None and processed_packets >= self.packet_limit:
                        break
                    processed_packets += 1
                    ip_layers = _extract_ip_layers(packet)
                    if self.prefer_innermost and len(ip_layers) > 1:
                        layer_iterable = [(len(ip_layers) - 1, ip_layers[-1])]
                    else:
                        layer_iterable = list(enumerate(ip_layers))

                    for layer_index, layer_info in layer_iterable:
                        conn_id, origin_key = _make_connection_keys(layer_info)
                        if not conn_id:
                            continue
                        if self._should_ignore_layer(layer_info):
                            continue

                        src_mac, dst_mac = _extract_mac_addresses(packet)
                        tcp_flags, tcp_seq, tcp_ack = _extract_tcp_metadata(packet)
                        transport_payload = _extract_transport_payload(packet, layer_info.protocol)
                        payload_len = _infer_payload_length(packet, layer_info.protocol)
                        http_meta = _extract_http_metadata(packet)
                        tls_sni = _extract_tls_sni(packet)
                        mqtt_details = (
                            parse_mqtt_details(
                                transport_payload,
                                layer_info.src_port,
                                layer_info.dst_port,
                            )
                            if layer_info.protocol == "tcp"
                            else MQTTDetails()
                        )
                        opcua_details = (
                            parse_opcua_details(
                                transport_payload,
                                layer_info.src_port,
                                layer_info.dst_port,
                            )
                            if layer_info.protocol == "tcp"
                            else OPCUADetails()
                        )

                        modbus_details = _extract_modbus_details(packet, layer_info)

                        record = PacketRecord(
                            pcap_file=pcap_file.name,
                            packet_index=packet_index,
                            timestamp=float(packet.time),
                            size=len(packet),
                            src_ip=layer_info.src_ip,
                            dst_ip=layer_info.dst_ip,
                            src_port=layer_info.src_port,
                            dst_port=layer_info.dst_port,
                            protocol=layer_info.protocol,
                            high_level_protocol=detect_high_level_protocol(
                                packet,
                                layer_info.src_port,
                                layer_info.dst_port,
                                layer_info.protocol,
                            ),
                            ip_layer_index=layer_index,
                            ip_layer_count=layer_info.layer_count,
                            src_mac=src_mac,
                            dst_mac=dst_mac,
                            tcp_flags=tcp_flags,
                            tcp_seq=tcp_seq,
                            tcp_ack=tcp_ack,
                            payload_len=payload_len,
                            http_method=http_meta.get("method"),
                            http_host=http_meta.get("host"),
                            http_path=http_meta.get("path"),
                            http_status=http_meta.get("status"),
                            http_content_type=http_meta.get("content_type"),
                            tls_sni=tls_sni,
                            mqtt_packet_type=mqtt_details.packet_type,
                            mqtt_packet_type_code=mqtt_details.packet_type_code,
                            mqtt_topic=mqtt_details.topic,
                            mqtt_qos=mqtt_details.qos,
                            mqtt_retain=mqtt_details.retain,
                            mqtt_dup=mqtt_details.dup,
                            mqtt_client_id=mqtt_details.client_id,
                            mqtt_keepalive=mqtt_details.keepalive,
                            mqtt_packet_id=mqtt_details.packet_id,
                            mqtt_payload_size=mqtt_details.payload_size,
                            opcua_message_type=opcua_details.message_type,
                            opcua_chunk_type=opcua_details.chunk_type,
                            opcua_message_size=opcua_details.message_size,
                            opcua_secure_channel_id=opcua_details.secure_channel_id,
                            opcua_endpoint_url=opcua_details.endpoint_url,
                            opcua_security_policy_uri=opcua_details.security_policy_uri,
                            opcua_service_type=opcua_details.service_type,
                            opcua_operation=opcua_details.operation,
                            opcua_request_id=opcua_details.request_id,
                            opcua_node_ids=opcua_details.node_ids,
                            opcua_values=opcua_details.values,
                            mqtt_payload_values=mqtt_details.payload_values,
                            modbus_function=modbus_details.function_code,
                            modbus_unit_id=modbus_details.unit_id,
                            modbus_registers=modbus_details.registers,
                            modbus_read_registers=modbus_details.read_registers,
                            modbus_write_registers=modbus_details.write_registers,
                            modbus_register_values=modbus_details.register_values,
                            modbus_transaction_id=modbus_details.transaction_id,
                        )
                        if conn_id not in self._index:
                            self._index[conn_id] = IndexedConnection(
                                canonical_id=conn_id,
                                origin=origin_key,
                                records=[record],
                                origin_timestamp=record.timestamp,
                            )
                        else:
                            connection = self._index[conn_id]
                            # Prefer the earliest packet orientation if timestamps indicate earlier origin
                            if record.timestamp < connection.origin_timestamp:
                                connection.origin = origin_key
                                connection.origin_timestamp = record.timestamp
                            connection.records.append(record)
                packet_bar.close()
            gc.collect()
            if self.packet_limit is not None and processed_packets >= self.packet_limit:
                break

        # Persist cache in a lightweight format
        serialized = {
            key: {
                "origin": connection.origin.to_dict(),
                "records": [asdict(record) for record in connection.records],
                "origin_timestamp": connection.origin_timestamp,
            }
            for key, connection in self._index.items()
        }
        with self.cache_path.open("wb") as fh:
            pickle.dump(serialized, fh)

    def iter_connections(self) -> Iterator[IndexedConnection]:
        """Yield aggregated connection views."""
        yield from self._index.values()

    def get_packets(self, key: ConnectionKey | str) -> List[PacketRecord]:
        """Return packet records for a given normalized connection identifier."""
        conn_id = key.bidirectional_id() if isinstance(key, ConnectionKey) else key
        connection = self._index.get(conn_id)
        if not connection:
            return []
        return list(connection.records)

    def keys(self) -> Iterable[str]:
        """Return an iterable of all connection identifiers in the index."""
        return self._index.keys()

    def _should_ignore_connection(self, connection: ConnectionKey) -> bool:
        return connection.src_ip in self._IGNORED_IPS or connection.dst_ip in self._IGNORED_IPS

    def _should_ignore_layer(self, layer: "_LayerInfo") -> bool:
        return layer.src_ip in self._IGNORED_IPS or layer.dst_ip in self._IGNORED_IPS


def detect_high_level_protocol(packet, src_port: int, dst_port: int, protocol: str) -> str:
    """Heuristic protocol classifier that inspects packet structure and ports."""
    if DNS in packet:
        return "DNS"
    if HTTPRequest in packet or HTTPResponse in packet:
        return "HTTP"
    if SMB_Header in packet:
        return "SMB"
    if NBTSession in packet:
        return "NetBIOS"

    well_known = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        135: "RPC",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-TRAP",
        443: "HTTPS",
        445: "SMB",
        502: "Modbus",
        4840: "OPCUA",
        1883: "MQTT",
        8883: "MQTT",
        8080: "HTTP",
        8443: "HTTPS",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        44818: "EtherNet/IP",
    }

    for port in (src_port, dst_port):
        if port in well_known:
            detected = well_known[port]
            if detected == "HTTP" and _is_tls(packet):
                return "HTTPS"
            return detected

    proto = protocol.lower()
    if proto == "tcp":
        payload = bytes(packet[TCP].payload) if TCP in packet and packet[TCP].payload else b""
        mqtt_details = parse_mqtt_details(
            payload,
            src_port,
            dst_port,
        )
        mqtt_on_known_port = src_port in {1883, 8883} or dst_port in {1883, 8883}
        mqtt_on_nonstandard_port = mqtt_details.packet_type_code == 1
        if mqtt_details.packet_type_code is not None and (mqtt_on_known_port or mqtt_on_nonstandard_port):
            return "MQTT"
        opcua_details = parse_opcua_details(payload, src_port, dst_port)
        opcua_on_known_port = src_port in OPCUA_PORTS or dst_port in OPCUA_PORTS
        opcua_on_nonstandard_port = opcua_details.strong_match
        if opcua_details.message_type is not None and (opcua_on_known_port or opcua_on_nonstandard_port):
            return "OPCUA"
        if _is_http_like(packet):
            return "HTTP"
        if _is_tls(packet):
            return "TLS"
    elif proto == "udp":
        if _is_dhcp_like(packet):
            return "DHCP"
        if _is_modbus_like(packet):
            return "Modbus"
    return protocol.upper() if protocol else "UNKNOWN"


def _is_http_like(packet) -> bool:
    payload = bytes(packet[TCP].payload) if TCP in packet and packet[TCP].payload else b""
    if not payload:
        return False
    prefixes = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ")
    responses = (b"HTTP/1.", b"HTTP/2.")
    head = payload[:32]
    return any(head.startswith(prefix) for prefix in prefixes) or any(resp in head for resp in responses)


def _is_tls(packet) -> bool:
    if TCP not in packet or not packet[TCP].payload:
        return False
    payload = bytes(packet[TCP].payload)
    return len(payload) > 5 and payload[0] in (20, 21, 22, 23) and payload[1:3] in {b"\x03\x00", b"\x03\x01", b"\x03\x02", b"\x03\x03"}


def _is_dhcp_like(packet) -> bool:
    if UDP not in packet:
        return False
    sport, dport = packet[UDP].sport, packet[UDP].dport
    return {sport, dport}.issubset({67, 68})


def _is_modbus_like(packet) -> bool:
    if UDP in packet and packet[UDP].dport == 502:
        return True
    if TCP in packet and packet[TCP].dport == 502:
        return True
    return False


class _LayerInfo:
    """Internal helper structure describing a single IP layer."""

    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "layer_count")

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, layer_count: int) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.layer_count = layer_count


def _extract_ip_layers(packet) -> List[_LayerInfo]:
    """Return all IP layers within a packet to handle encapsulation."""
    layers: List[_LayerInfo] = []
    ip_layers = []
    current = packet
    while current:
        if IP in current:
            ip_layers.append(current[IP])
            current = current.payload
        elif IPv6 in current:
            ip_layers.append(current[IPv6])
            current = current.payload
        else:
            break

    total = len(ip_layers)
    for layer in ip_layers:
        protocol = "other"
        src_port = 0
        dst_port = 0
        if TCP in layer:
            protocol = "tcp"
            src_port = layer[TCP].sport
            dst_port = layer[TCP].dport
        elif UDP in layer:
            protocol = "udp"
            src_port = layer[UDP].sport
            dst_port = layer[UDP].dport
        info = _LayerInfo(layer.src, layer.dst, src_port, dst_port, protocol, total)
        layers.append(info)
    return layers


def _make_connection_keys(layer: _LayerInfo) -> Tuple[str, ConnectionKey]:
    original = ConnectionKey(
        src_ip=layer.src_ip,
        src_port=layer.src_port,
        dst_ip=layer.dst_ip,
        dst_port=layer.dst_port,
        protocol=layer.protocol or "other",
    )
    return original.bidirectional_id(), original


def _extract_mac_addresses(packet) -> Tuple[str, str]:
    if Ether in packet:
        eth = packet[Ether]
        src = getattr(eth, "src", "") or ""
        dst = getattr(eth, "dst", "") or ""
        return str(src), str(dst)
    return "", ""


def _extract_tcp_metadata(packet) -> Tuple[str, Optional[int], Optional[int]]:
    if TCP in packet:
        tcp_layer = packet[TCP]
        flags = str(getattr(tcp_layer, "flags", "") or "")
        seq = getattr(tcp_layer, "seq", None)
        ack = getattr(tcp_layer, "ack", None)
        try:
            seq_val = int(seq) if seq is not None else None
        except (TypeError, ValueError):
            seq_val = None
        try:
            ack_val = int(ack) if ack is not None else None
        except (TypeError, ValueError):
            ack_val = None
        return flags, seq_val, ack_val
    return "", None, None


def _infer_payload_length(packet, protocol: str) -> int:
    proto = (protocol or "").lower()
    try:
        if proto == "tcp" and TCP in packet:
            payload = packet[TCP].payload
        elif proto == "udp" and UDP in packet:
            payload = packet[UDP].payload
        else:
            return 0
        raw = bytes(payload) if payload else b""
        return len(raw)
    except Exception:
        return 0


def _extract_transport_payload(packet, protocol: str) -> bytes:
    """Return transport payload bytes for TCP/UDP packets."""
    proto = (protocol or "").lower()
    try:
        if proto == "tcp" and TCP in packet:
            return bytes(packet[TCP].payload or b"")
        if proto == "udp" and UDP in packet:
            return bytes(packet[UDP].payload or b"")
    except Exception:
        return b""
    return b""


def _extract_http_metadata(packet) -> dict[str, Optional[object]]:
    metadata: dict[str, Optional[object]] = {
        "method": None,
        "host": None,
        "path": None,
        "status": None,
        "content_type": None,
    }
    try:
        if HTTPRequest in packet:
            request = packet[HTTPRequest]
            metadata["method"] = _safe_decode(getattr(request, "Method", b""))
            metadata["host"] = _safe_decode(getattr(request, "Host", b""))
            metadata["path"] = _safe_decode(getattr(request, "Path", b""))
        if HTTPResponse in packet:
            response = packet[HTTPResponse]
            metadata["status"] = _parse_int(getattr(response, "Status_Code", None))
            content_type = _safe_decode(getattr(response, "Content_Type", b""))
            if not content_type:
                content_type = _safe_decode(getattr(response, "Headers", b""))
            metadata["content_type"] = content_type or None
    except Exception:
        pass
    # Normalise empty strings to None
    for key in ("method", "host", "path", "content_type"):
        if isinstance(metadata[key], str) and not metadata[key]:
            metadata[key] = None
    return metadata


def _extract_tls_sni(packet) -> Optional[str]:
    if TCP not in packet:
        return None
    payload = bytes(packet[TCP].payload or b"")
    if len(payload) < 5 or payload[0] != 0x16:
        return None
    # TLS record header: type(1) + version(2) + length(2)
    handshake_start = 5
    if len(payload) <= handshake_start:
        return None
    handshake_type = payload[handshake_start]
    if handshake_type != 0x01:
        return None  # Not a ClientHello
    idx = handshake_start + 1
    if len(payload) < idx + 3:
        return None
    # Skip handshake length (3 bytes)
    idx += 3
    if len(payload) < idx + 2:
        return None
    # Skip version
    idx += 2
    # Skip random
    if len(payload) < idx + 32:
        return None
    idx += 32
    if len(payload) <= idx:
        return None
    session_id_len = payload[idx]
    idx += 1 + session_id_len
    if len(payload) < idx + 2:
        return None
    cipher_suites_len = int.from_bytes(payload[idx : idx + 2], "big")
    idx += 2 + cipher_suites_len
    if len(payload) <= idx:
        return None
    compression_methods_len = payload[idx]
    idx += 1 + compression_methods_len
    if len(payload) < idx + 2:
        return None
    extensions_len = int.from_bytes(payload[idx : idx + 2], "big")
    idx += 2
    end = idx + extensions_len
    if end > len(payload):
        end = len(payload)
    while idx + 4 <= end:
        ext_type = int.from_bytes(payload[idx : idx + 2], "big")
        ext_len = int.from_bytes(payload[idx + 2 : idx + 4], "big")
        idx += 4
        if idx + ext_len > end:
            break
        if ext_type == 0x00 and ext_len >= 5:
            list_len = int.from_bytes(payload[idx : idx + 2], "big")
            idx += 2
            list_end = idx + list_len
            while idx + 3 <= list_end <= len(payload):
                name_type = payload[idx]
                name_len = int.from_bytes(payload[idx + 1 : idx + 3], "big")
                idx += 3
                if name_type == 0 and idx + name_len <= len(payload):
                    server_name = payload[idx : idx + name_len].decode("utf-8", errors="ignore")
                    return server_name or None
                idx += name_len
            return None
        idx += ext_len
    return None


def _safe_decode(value: object) -> str:
    if value in (None, b"", ""):
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _parse_int(value: object) -> Optional[int]:
    if value in (None, "", b""):
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii", errors="ignore")
        except Exception:
            return None
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _extract_modbus_details(packet, layer: _LayerInfo) -> _ModbusDetails:
    """Return parsed Modbus metadata for the given transport layer."""
    if layer.protocol not in ("tcp", "udp"):
        return _ModbusDetails(None, None, (), (), (), (), None)
    if 502 not in (layer.src_port, layer.dst_port):
        return _ModbusDetails(None, None, (), (), (), (), None)

    transport = None
    if layer.protocol == "tcp" and TCP in packet:
        transport = packet[TCP]
    elif layer.protocol == "udp" and UDP in packet:
        transport = packet[UDP]
    if transport is None:
        return _ModbusDetails(None, None, (), (), (), (), None)

    raw_payload = getattr(transport, "payload", None)
    if raw_payload in (None, b"", ""):
        return _ModbusDetails(None, None, (), (), (), (), None)
    try:
        payload_bytes = bytes(raw_payload)
    except Exception:
        return _ModbusDetails(None, None, (), (), (), (), None)
    if len(payload_bytes) < 8:
        return _ModbusDetails(None, None, (), (), (), (), None)

    transaction_id = int.from_bytes(payload_bytes[0:2], "big")
    unit_id = payload_bytes[6]
    function_code = payload_bytes[7]
    pdu = payload_bytes[7:]

    if layer.dst_port == 502:
        read_registers, write_registers, values = _parse_modbus_request(function_code, pdu)
    else:
        read_registers, write_registers, values = _parse_modbus_response(function_code, pdu)

    registers = tuple(dict.fromkeys((*read_registers, *write_registers))) if (read_registers or write_registers) else ()
    return _ModbusDetails(function_code, unit_id, registers, read_registers, write_registers, values, transaction_id)


def _parse_modbus_request(function_code: int, pdu: bytes) -> Tuple[Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]:
    """Return (read_registers, write_registers, write_values) for a Modbus request PDU."""
    if not pdu:
        return (), (), ()

    # First byte of PDU is function code; remainder contains parameters
    params = pdu[1:]

    if function_code in {1, 2, 3, 4}:
        if len(params) < 4:
            return (), (), ()
        start = int.from_bytes(params[0:2], "big")
        quantity = int.from_bytes(params[2:4], "big")
        read_registers = _expand_modbus_range(start, quantity)
        return read_registers, (), ()

    if function_code == 5:
        if len(params) < 4:
            return (), (), ()
        address = int.from_bytes(params[0:2], "big")
        value = int.from_bytes(params[2:4], "big")
        return (), (address,), (1 if value == 0xFF00 else 0,)

    if function_code == 6:
        if len(params) < 4:
            return (), (), ()
        address = int.from_bytes(params[0:2], "big")
        value = int.from_bytes(params[2:4], "big")
        return (), (address,), (value,)

    if function_code in {15, 16}:
        if len(params) < 5:
            return (), (), ()
        start = int.from_bytes(params[0:2], "big")
        quantity = int.from_bytes(params[2:4], "big")
        byte_count = params[4]
        data = params[5 : 5 + byte_count]
        write_registers = _expand_modbus_range(start, quantity)
        if function_code == 15:
            values = tuple(_iter_coil_bits(data, quantity))
        else:
            values = _parse_register_values(data, quantity)
        return (), write_registers, values

    if function_code == 23:  # Read/Write Multiple Registers
        if len(params) < 9:
            return (), (), ()
        read_start = int.from_bytes(params[0:2], "big")
        read_quantity = int.from_bytes(params[2:4], "big")
        write_start = int.from_bytes(params[4:6], "big")
        write_quantity = int.from_bytes(params[6:8], "big")
        byte_count = params[8]
        data = params[9 : 9 + byte_count]
        read_registers = _expand_modbus_range(read_start, read_quantity)
        write_registers = _expand_modbus_range(write_start, write_quantity)
        values = _parse_register_values(data, write_quantity)
        return read_registers, write_registers, values

    return (), (), ()


def _parse_modbus_response(function_code: int, pdu: bytes) -> Tuple[Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]:
    """Return (read_registers, write_registers, values) for a Modbus response PDU."""
    if not pdu:
        return (), (), ()

    params = pdu[1:]

    if function_code in {1, 2, 3, 4, 23}:
        if len(params) < 1:
            return (), (), ()
        byte_count = params[0]
        data = params[1 : 1 + byte_count]
        if function_code in {1, 2}:
            values = tuple(_iter_coil_bits(data, byte_count * 8))
        else:
            quantity = byte_count // 2
            values = _parse_register_values(data, quantity)
        return (), (), values

    if function_code == 5:
        if len(params) < 4:
            return (), (), ()
        address = int.from_bytes(params[0:2], "big")
        value = int.from_bytes(params[2:4], "big")
        coil_state = 1 if value == 0xFF00 else 0
        return (), (address,), (coil_state,)

    if function_code == 6:
        if len(params) < 4:
            return (), (), ()
        address = int.from_bytes(params[0:2], "big")
        value = int.from_bytes(params[2:4], "big")
        return (), (address,), (value,)

    if function_code in {15, 16}:
        if len(params) < 4:
            return (), (), ()
        start = int.from_bytes(params[0:2], "big")
        quantity = int.from_bytes(params[2:4], "big")
        write_registers = _expand_modbus_range(start, quantity)
        return (), write_registers, ()

    return (), (), ()


def _parse_register_values(data: bytes, quantity: int) -> Tuple[int, ...]:
    """Interpret a sequence of Modbus register bytes into integers."""
    if quantity <= 0:
        return ()
    values: List[int] = []
    expected_len = quantity * 2
    data = data[:expected_len]
    for i in range(0, len(data), 2):
        if i + 2 > len(data):
            break
        values.append(int.from_bytes(data[i : i + 2], "big"))
    return tuple(values[:quantity])


def _iter_coil_bits(data: bytes, quantity: int) -> Iterable[int]:
    """Yield coil states from packed Modbus coil bytes."""
    limit = max(quantity, 0)
    if limit <= 0:
        return
    count = 0
    for byte in data:
        for bit in range(8):
            if count >= limit:
                return
            yield (byte >> bit) & 0x01
            count += 1


def _expand_modbus_range(start: int, quantity: int, max_span: int = 512) -> Tuple[int, ...]:
    """Expand a Modbus range into individual register addresses."""
    if quantity <= 0:
        quantity = 1
    quantity = min(quantity, max_span)
    end = start + quantity
    return tuple(range(start, end))
