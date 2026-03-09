"""Fast PCAP parsing using dpkt instead of Scapy for 10-20x speedup."""

from __future__ import annotations

import gc
import os
import pickle
import socket
import struct
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
)

from tqdm import tqdm

from .mqtt_helpers import MQTTDetails, MQTT_PORTS, parse_mqtt_details
from .opcua_helpers import OPCUADetails, OPCUA_PORTS, parse_opcua_details
from .models import ConnectionKey, IndexedConnection, PacketRecord


# TCP flag constants
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

# Well-known ports for protocol detection
WELL_KNOWN_PROTOCOLS: Dict[int, str] = {
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
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP",
    8443: "HTTPS",
    44818: "EtherNet/IP",
}


def _tcp_flags_to_str(flags: int) -> str:
    """Convert TCP flags integer to string representation."""
    parts = []
    if flags & TCP_FIN:
        parts.append("F")
    if flags & TCP_SYN:
        parts.append("S")
    if flags & TCP_RST:
        parts.append("R")
    if flags & TCP_PSH:
        parts.append("P")
    if flags & TCP_ACK:
        parts.append("A")
    if flags & TCP_URG:
        parts.append("U")
    if flags & TCP_ECE:
        parts.append("E")
    if flags & TCP_CWR:
        parts.append("C")
    return "".join(parts)


def _detect_protocol_fast(
    src_port: int,
    dst_port: int,
    protocol: str,
    payload: bytes,
) -> str:
    """Fast protocol detection using port mapping and payload heuristics."""
    # Check well-known ports first
    for port in (dst_port, src_port):
        if port in WELL_KNOWN_PROTOCOLS:
            detected = WELL_KNOWN_PROTOCOLS[port]
            # Check if it's actually TLS on an HTTP port
            if detected == "HTTP" and payload and _is_tls_payload(payload):
                return "HTTPS"
            return detected

    # Payload-based detection for TCP
    if protocol == "tcp" and payload:
        mqtt_details = parse_mqtt_details(payload, src_port, dst_port)
        mqtt_on_known_port = src_port in MQTT_PORTS or dst_port in MQTT_PORTS
        mqtt_on_nonstandard_port = mqtt_details.packet_type_code == 1
        if mqtt_details.packet_type_code is not None and (mqtt_on_known_port or mqtt_on_nonstandard_port):
            return "MQTT"
        opcua_details = parse_opcua_details(payload, src_port, dst_port)
        opcua_on_known_port = src_port in OPCUA_PORTS or dst_port in OPCUA_PORTS
        opcua_on_nonstandard_port = opcua_details.strong_match
        if opcua_details.message_type is not None and (opcua_on_known_port or opcua_on_nonstandard_port):
            return "OPCUA"
        if _is_http_payload(payload):
            return "HTTP"
        if _is_tls_payload(payload):
            return "TLS"

    return protocol.upper() if protocol else "UNKNOWN"


def _is_http_payload(payload: bytes) -> bool:
    """Check if payload looks like HTTP."""
    if len(payload) < 4:
        return False
    prefixes = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/")
    head = payload[:16]
    return any(head.startswith(p) for p in prefixes)


def _is_tls_payload(payload: bytes) -> bool:
    """Check if payload looks like TLS."""
    if len(payload) < 5:
        return False
    # TLS record: content type (20-23), version (0x0300-0x0303)
    return payload[0] in (20, 21, 22, 23) and payload[1:3] in {
        b"\x03\x00",
        b"\x03\x01",
        b"\x03\x02",
        b"\x03\x03",
    }


def _extract_tls_sni_fast(payload: bytes) -> Optional[str]:
    """Extract TLS SNI from ClientHello - optimized version."""
    if len(payload) < 43 or payload[0] != 0x16:
        return None

    # TLS record header: type(1) + version(2) + length(2)
    handshake_start = 5
    if len(payload) <= handshake_start or payload[handshake_start] != 0x01:
        return None  # Not ClientHello

    try:
        idx = handshake_start + 1 + 3 + 2 + 32  # Skip header, length, version, random
        if idx >= len(payload):
            return None

        session_id_len = payload[idx]
        idx += 1 + session_id_len
        if idx + 2 > len(payload):
            return None

        cipher_suites_len = int.from_bytes(payload[idx : idx + 2], "big")
        idx += 2 + cipher_suites_len
        if idx >= len(payload):
            return None

        compression_len = payload[idx]
        idx += 1 + compression_len
        if idx + 2 > len(payload):
            return None

        extensions_len = int.from_bytes(payload[idx : idx + 2], "big")
        idx += 2
        end = min(idx + extensions_len, len(payload))

        while idx + 4 <= end:
            ext_type = int.from_bytes(payload[idx : idx + 2], "big")
            ext_len = int.from_bytes(payload[idx + 2 : idx + 4], "big")
            idx += 4

            if ext_type == 0x00 and ext_len >= 5:  # SNI extension
                # Skip list length (2 bytes)
                name_idx = idx + 2
                if name_idx + 3 > end:
                    break
                name_type = payload[name_idx]
                name_len = int.from_bytes(payload[name_idx + 1 : name_idx + 3], "big")
                name_idx += 3
                if name_type == 0 and name_idx + name_len <= len(payload):
                    return payload[name_idx : name_idx + name_len].decode(
                        "utf-8", errors="ignore"
                    )
                return None

            idx += ext_len

    except (IndexError, ValueError):
        pass

    return None


def _extract_http_metadata_fast(payload: bytes) -> Dict[str, Optional[str]]:
    """Fast HTTP metadata extraction from raw payload."""
    result: Dict[str, Optional[str]] = {
        "method": None,
        "host": None,
        "path": None,
        "status": None,
        "content_type": None,
    }

    if not payload or len(payload) < 10:
        return result

    try:
        # Find end of first line
        first_line_end = payload.find(b"\r\n")
        if first_line_end == -1:
            first_line_end = payload.find(b"\n")
        if first_line_end == -1:
            first_line_end = min(len(payload), 256)

        first_line = payload[:first_line_end].decode("utf-8", errors="ignore")

        # Check for request
        methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
        for method in methods:
            if first_line.startswith(method + " "):
                result["method"] = method
                parts = first_line.split(" ", 2)
                if len(parts) >= 2:
                    result["path"] = parts[1]
                break

        # Check for response
        if first_line.startswith("HTTP/"):
            parts = first_line.split(" ", 2)
            if len(parts) >= 2:
                try:
                    result["status"] = parts[1]
                except ValueError:
                    pass

        # Extract Host header
        headers_start = first_line_end + 2
        headers_section = payload[headers_start : headers_start + 1024]
        headers_text = headers_section.decode("utf-8", errors="ignore").lower()

        for line in headers_text.split("\r\n"):
            if line.startswith("host:"):
                result["host"] = line[5:].strip()
            elif line.startswith("content-type:"):
                result["content_type"] = line[13:].strip()

    except Exception:
        pass

    return result


def _parse_modbus_fast(
    payload: bytes, dst_port: int, src_port: int
) -> Tuple[
    Optional[int],  # function_code
    Optional[int],  # unit_id
    Tuple[int, ...],  # registers
    Tuple[int, ...],  # read_registers
    Tuple[int, ...],  # write_registers
    Tuple[int, ...],  # register_values
    Optional[int],  # transaction_id
]:
    """Fast Modbus/TCP parsing."""
    empty = (None, None, (), (), (), (), None)

    if len(payload) < 8:
        return empty

    transaction_id = int.from_bytes(payload[0:2], "big")
    unit_id = payload[6]
    function_code = payload[7]
    pdu = payload[7:]

    is_request = dst_port == 502

    if is_request:
        read_regs, write_regs, values = _parse_modbus_request_fast(function_code, pdu)
    else:
        read_regs, write_regs, values = _parse_modbus_response_fast(function_code, pdu)

    registers = tuple(dict.fromkeys((*read_regs, *write_regs))) if (read_regs or write_regs) else ()

    return (function_code, unit_id, registers, read_regs, write_regs, values, transaction_id)


def _parse_modbus_request_fast(
    function_code: int, pdu: bytes
) -> Tuple[Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]:
    """Parse Modbus request PDU."""
    if not pdu or len(pdu) < 2:
        return (), (), ()

    params = pdu[1:]

    # Read functions (1, 2, 3, 4)
    if function_code in {1, 2, 3, 4}:
        if len(params) < 4:
            return (), (), ()
        start = int.from_bytes(params[0:2], "big")
        quantity = int.from_bytes(params[2:4], "big")
        quantity = min(quantity, 512)
        return tuple(range(start, start + quantity)), (), ()

    # Write single coil (5)
    if function_code == 5:
        if len(params) < 4:
            return (), (), ()
        address = int.from_bytes(params[0:2], "big")
        value = int.from_bytes(params[2:4], "big")
        return (), (address,), (1 if value == 0xFF00 else 0,)

    # Write single register (6)
    if function_code == 6:
        if len(params) < 4:
            return (), (), ()
        address = int.from_bytes(params[0:2], "big")
        value = int.from_bytes(params[2:4], "big")
        return (), (address,), (value,)

    # Write multiple coils/registers (15, 16)
    if function_code in {15, 16}:
        if len(params) < 5:
            return (), (), ()
        start = int.from_bytes(params[0:2], "big")
        quantity = int.from_bytes(params[2:4], "big")
        quantity = min(quantity, 512)
        byte_count = params[4]
        data = params[5 : 5 + byte_count]
        write_regs = tuple(range(start, start + quantity))

        if function_code == 15:
            values = tuple(_iter_coil_bits(data, quantity))
        else:
            values = _parse_register_values_fast(data, quantity)
        return (), write_regs, values

    # Read/Write Multiple Registers (23)
    if function_code == 23:
        if len(params) < 9:
            return (), (), ()
        read_start = int.from_bytes(params[0:2], "big")
        read_qty = min(int.from_bytes(params[2:4], "big"), 512)
        write_start = int.from_bytes(params[4:6], "big")
        write_qty = min(int.from_bytes(params[6:8], "big"), 512)
        byte_count = params[8]
        data = params[9 : 9 + byte_count]
        read_regs = tuple(range(read_start, read_start + read_qty))
        write_regs = tuple(range(write_start, write_start + write_qty))
        values = _parse_register_values_fast(data, write_qty)
        return read_regs, write_regs, values

    return (), (), ()


def _parse_modbus_response_fast(
    function_code: int, pdu: bytes
) -> Tuple[Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]:
    """Parse Modbus response PDU."""
    if not pdu or len(pdu) < 2:
        return (), (), ()

    params = pdu[1:]

    # Read responses (1, 2, 3, 4, 23)
    if function_code in {1, 2, 3, 4, 23}:
        if len(params) < 1:
            return (), (), ()
        byte_count = params[0]
        data = params[1 : 1 + byte_count]
        if function_code in {1, 2}:
            values = tuple(_iter_coil_bits(data, byte_count * 8))
        else:
            quantity = byte_count // 2
            values = _parse_register_values_fast(data, quantity)
        return (), (), values

    # Write single coil/register echo (5, 6)
    if function_code in {5, 6}:
        if len(params) < 4:
            return (), (), ()
        address = int.from_bytes(params[0:2], "big")
        value = int.from_bytes(params[2:4], "big")
        if function_code == 5:
            value = 1 if value == 0xFF00 else 0
        return (), (address,), (value,)

    # Write multiple echo (15, 16)
    if function_code in {15, 16}:
        if len(params) < 4:
            return (), (), ()
        start = int.from_bytes(params[0:2], "big")
        quantity = min(int.from_bytes(params[2:4], "big"), 512)
        return (), tuple(range(start, start + quantity)), ()

    return (), (), ()


def _parse_register_values_fast(data: bytes, quantity: int) -> Tuple[int, ...]:
    """Parse Modbus register values."""
    if quantity <= 0:
        return ()
    values = []
    for i in range(0, min(len(data), quantity * 2), 2):
        if i + 2 > len(data):
            break
        values.append(int.from_bytes(data[i : i + 2], "big"))
    return tuple(values[:quantity])


def _iter_coil_bits(data: bytes, quantity: int) -> Iterable[int]:
    """Yield coil states from packed bytes."""
    count = 0
    for byte in data:
        for bit in range(8):
            if count >= quantity:
                return
            yield (byte >> bit) & 0x01
            count += 1


class FastPCAPConnectionIndex:
    """High-performance PCAP index using dpkt for parsing."""

    _IGNORED_IPS: frozenset = frozenset({"172.16.142.250"})

    def __init__(
        self,
        pcap_directory: Path,
        cache_path: Optional[Path] = None,
        prefer_innermost: bool = True,
        packet_limit: Optional[int] = None,
        workers: Optional[int] = None,
    ) -> None:
        self.pcap_directory = Path(pcap_directory)
        self.cache_path = Path(cache_path) if cache_path else Path("pcap_connection_index.pkl")
        self._index: MutableMapping[str, IndexedConnection] = {}
        self.prefer_innermost = prefer_innermost
        self.packet_limit = packet_limit
        self.workers = workers

    def build(self, force_rebuild: bool = False) -> None:
        """Populate the connection index from PCAP files or cache."""
        if not force_rebuild and self.cache_path.exists():
            self._load_from_cache()
            return

        if not self.pcap_directory.exists():
            raise FileNotFoundError(f"PCAP directory not found: {self.pcap_directory}")

        pcap_files = sorted(
            f for f in self.pcap_directory.iterdir() if f.suffix in {".pcap", ".pcapng"}
        )

        if not pcap_files:
            return

        # Use multiprocessing for multiple files
        num_workers = self.workers or min(len(pcap_files), max(1, os.cpu_count() or 1))

        if num_workers > 1 and len(pcap_files) > 1:
            self._build_parallel(pcap_files, num_workers)
        else:
            self._build_sequential(pcap_files)

        self._save_to_cache()

    def _build_parallel(self, pcap_files: List[Path], num_workers: int) -> None:
        """Process PCAP files in parallel."""
        print(f"Processing {len(pcap_files)} PCAP files with {num_workers} workers...")

        # Prepare arguments for worker processes
        args_list = [
            (
                str(pcap_file),
                self.prefer_innermost,
                self.packet_limit,
                set(self._IGNORED_IPS),
            )
            for pcap_file in pcap_files
        ]

        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            results = list(
                tqdm(
                    executor.map(_process_pcap_file, args_list),
                    total=len(pcap_files),
                    desc="Processing PCAP files",
                    unit="file",
                )
            )

        # Merge results
        for partial_index in results:
            for conn_id, conn_data in partial_index.items():
                if conn_id not in self._index:
                    self._index[conn_id] = conn_data
                else:
                    existing = self._index[conn_id]
                    existing.records.extend(conn_data.records)
                    if conn_data.origin_timestamp < existing.origin_timestamp:
                        existing.origin = conn_data.origin
                        existing.origin_timestamp = conn_data.origin_timestamp

    def _build_sequential(self, pcap_files: List[Path]) -> None:
        """Process PCAP files sequentially."""
        processed_packets = 0

        for pcap_file in pcap_files:
            partial_index = _process_pcap_file(
                (
                    str(pcap_file),
                    self.prefer_innermost,
                    self.packet_limit,
                    set(self._IGNORED_IPS),
                )
            )

            for conn_id, conn_data in partial_index.items():
                if conn_id not in self._index:
                    self._index[conn_id] = conn_data
                else:
                    existing = self._index[conn_id]
                    existing.records.extend(conn_data.records)
                    if conn_data.origin_timestamp < existing.origin_timestamp:
                        existing.origin = conn_data.origin
                        existing.origin_timestamp = conn_data.origin_timestamp

            processed_packets += sum(len(c.records) for c in partial_index.values())
            gc.collect()

            if self.packet_limit and processed_packets >= self.packet_limit:
                break

    def _load_from_cache(self) -> None:
        """Load index from pickle cache."""
        with self.cache_path.open("rb") as fh:
            cached = pickle.load(fh)

        self._index = {}
        for key, payload in cached.items():
            if isinstance(payload, list):
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

            if origin.src_ip in self._IGNORED_IPS or origin.dst_ip in self._IGNORED_IPS:
                continue

            self._index[key] = IndexedConnection(
                canonical_id=key,
                origin=origin,
                records=records,
                origin_timestamp=origin_ts,
            )

    def _save_to_cache(self) -> None:
        """Save index to pickle cache."""
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


def _process_pcap_file(
    args: Tuple[str, bool, Optional[int], set],
) -> Dict[str, IndexedConnection]:
    """Process a single PCAP file - designed to run in a worker process."""
    pcap_path, prefer_innermost, packet_limit, ignored_ips = args

    # Import dpkt here to avoid import overhead in main process
    try:
        import dpkt
    except ImportError:
        raise ImportError(
            "dpkt is required for fast PCAP parsing. Install with: pip install dpkt"
        )

    index: Dict[str, IndexedConnection] = {}
    pcap_name = Path(pcap_path).name

    try:
        with open(pcap_path, "rb") as f:
            # Try pcapng first, fall back to pcap
            try:
                pcap_reader = dpkt.pcapng.Reader(f)
            except ValueError:
                f.seek(0)
                pcap_reader = dpkt.pcap.Reader(f)

            packet_iter = enumerate(pcap_reader)
            packet_bar = tqdm(
                packet_iter,
                desc=f"Packets ({pcap_name})",
                unit="pkt",
                total=packet_limit,
                leave=False,
            )

            for packet_index, (ts, buf) in packet_bar:
                if packet_limit is not None and packet_index >= packet_limit:
                    break

                record = _parse_packet_fast(
                    buf, ts, pcap_name, packet_index, ignored_ips
                )
                if record is None:
                    continue

                conn_key = record.connection_key()
                conn_id = conn_key.bidirectional_id()

                if conn_id not in index:
                    index[conn_id] = IndexedConnection(
                        canonical_id=conn_id,
                        origin=conn_key,
                        records=[record],
                        origin_timestamp=record.timestamp,
                    )
                else:
                    connection = index[conn_id]
                    if record.timestamp < connection.origin_timestamp:
                        connection.origin = conn_key
                        connection.origin_timestamp = record.timestamp
                    connection.records.append(record)

            packet_bar.close()

    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")

    return index


def _parse_packet_fast(
    buf: bytes,
    timestamp: float,
    pcap_file: str,
    packet_index: int,
    ignored_ips: set,
) -> Optional[PacketRecord]:
    """Parse a single packet using manual byte parsing for speed."""
    if len(buf) < 14:
        return None

    # Parse Ethernet header
    eth_type = struct.unpack("!H", buf[12:14])[0]
    src_mac = ":".join(f"{b:02x}" for b in buf[0:6])
    dst_mac = ":".join(f"{b:02x}" for b in buf[6:12])

    ip_start = 14

    # Handle VLAN tags
    if eth_type == 0x8100:  # 802.1Q
        if len(buf) < 18:
            return None
        eth_type = struct.unpack("!H", buf[16:18])[0]
        ip_start = 18

    # Only handle IPv4 for now (0x0800)
    if eth_type != 0x0800:
        return None

    if len(buf) < ip_start + 20:
        return None

    # Parse IP header (may need to unwrap GRE/encapsulation)
    ip_header = buf[ip_start:]
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4

    if version != 4 or ihl < 20:
        return None

    protocol = ip_header[9]

    # Track IP layer depth for encapsulation detection
    ip_layer_index = 0
    ip_layer_count = 1

    # Handle GRE encapsulation (protocol 47) - unwrap to inner IP
    if protocol == 47:
        # Mark this as encapsulated traffic
        ip_layer_index = 1
        ip_layer_count = 2
        gre_start = ip_start + ihl
        if len(buf) < gre_start + 4:
            return None
        # GRE header: flags(2) + protocol(2), optionally more
        gre_flags = struct.unpack("!H", buf[gre_start:gre_start + 2])[0]
        gre_proto = struct.unpack("!H", buf[gre_start + 2:gre_start + 4])[0]

        # Calculate GRE header length based on flags
        gre_hdr_len = 4
        if gre_flags & 0x8000:  # Checksum present
            gre_hdr_len += 4
        if gre_flags & 0x2000:  # Key present
            gre_hdr_len += 4
        if gre_flags & 0x1000:  # Sequence present
            gre_hdr_len += 4

        inner_start = gre_start + gre_hdr_len

        # Handle Transparent Ethernet Bridging (0x6558) - inner Ethernet frame
        if gre_proto == 0x6558:
            # Skip inner Ethernet header (14 bytes)
            if len(buf) < inner_start + 14:
                return None
            inner_eth_type = struct.unpack("!H", buf[inner_start + 12:inner_start + 14])[0]
            if inner_eth_type != 0x0800:  # Must be IPv4
                return None
            inner_start += 14
        elif gre_proto != 0x0800:
            # Only handle IPv4 or bridged Ethernet
            return None

        if len(buf) < inner_start + 20:
            return None

        # Parse inner IP header
        ip_start = inner_start
        ip_header = buf[ip_start:]
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        if version != 4 or ihl < 20:
            return None
        protocol = ip_header[9]

    total_length = struct.unpack("!H", ip_header[2:4])[0]
    src_ip = socket.inet_ntoa(ip_header[12:16])
    dst_ip = socket.inet_ntoa(ip_header[16:20])

    if src_ip in ignored_ips or dst_ip in ignored_ips:
        return None

    transport_start = ip_start + ihl
    payload = b""
    src_port = 0
    dst_port = 0
    proto_str = "other"
    tcp_flags = ""
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    payload_len = 0

    # TCP (protocol 6)
    if protocol == 6:
        proto_str = "tcp"
        if len(buf) < transport_start + 20:
            return None

        tcp_header = buf[transport_start:]
        src_port = struct.unpack("!H", tcp_header[0:2])[0]
        dst_port = struct.unpack("!H", tcp_header[2:4])[0]
        tcp_seq = struct.unpack("!I", tcp_header[4:8])[0]
        tcp_ack = struct.unpack("!I", tcp_header[8:12])[0]
        data_offset = (tcp_header[12] >> 4) * 4
        flags_byte = tcp_header[13]
        tcp_flags = _tcp_flags_to_str(flags_byte)

        payload_start = transport_start + data_offset
        if payload_start < len(buf):
            payload = buf[payload_start:]
            payload_len = len(payload)

    # UDP (protocol 17)
    elif protocol == 17:
        proto_str = "udp"
        if len(buf) < transport_start + 8:
            return None

        udp_header = buf[transport_start:]
        src_port = struct.unpack("!H", udp_header[0:2])[0]
        dst_port = struct.unpack("!H", udp_header[2:4])[0]

        payload_start = transport_start + 8
        if payload_start < len(buf):
            payload = buf[payload_start:]
            payload_len = len(payload)
    else:
        return None

    # Protocol detection
    high_level_protocol = _detect_protocol_fast(src_port, dst_port, proto_str, payload)

    # Extract protocol-specific metadata only for interesting ports
    http_meta: Dict[str, Optional[str]] = {}
    tls_sni: Optional[str] = None
    mqtt_details = parse_mqtt_details(payload, src_port, dst_port) if proto_str == "tcp" else MQTTDetails()
    opcua_details = parse_opcua_details(payload, src_port, dst_port) if proto_str == "tcp" else OPCUADetails()
    modbus_data = (None, None, (), (), (), (), None)

    if 502 in (src_port, dst_port):
        modbus_data = _parse_modbus_fast(payload, dst_port, src_port)
    elif mqtt_details.packet_type_code is not None or src_port in MQTT_PORTS or dst_port in MQTT_PORTS:
        # Metadata already parsed via parse_mqtt_details() above.
        pass
    elif opcua_details.message_type is not None or src_port in OPCUA_PORTS or dst_port in OPCUA_PORTS:
        # Metadata already parsed via parse_opcua_details() above.
        pass
    elif _is_http_payload(payload):
        http_meta = _extract_http_metadata_fast(payload)
    elif dst_port in {443, 8443} or src_port in {443, 8443}:
        tls_sni = _extract_tls_sni_fast(payload)

    return PacketRecord(
        pcap_file=pcap_file,
        packet_index=packet_index,
        timestamp=timestamp,
        size=len(buf),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto_str,
        high_level_protocol=high_level_protocol,
        ip_layer_index=ip_layer_index,
        ip_layer_count=ip_layer_count,
        src_mac=src_mac,
        dst_mac=dst_mac,
        tcp_flags=tcp_flags,
        tcp_seq=tcp_seq,
        tcp_ack=tcp_ack,
        payload_len=payload_len,
        http_method=http_meta.get("method"),
        http_host=http_meta.get("host"),
        http_path=http_meta.get("path"),
        http_status=int(http_meta["status"]) if http_meta.get("status") else None,
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
        modbus_function=modbus_data[0],
        modbus_unit_id=modbus_data[1],
        modbus_registers=modbus_data[2],
        modbus_read_registers=modbus_data[3],
        modbus_write_registers=modbus_data[4],
        modbus_register_values=modbus_data[5],
        modbus_transaction_id=modbus_data[6],
    )


# Alias for drop-in replacement
PCAPConnectionIndex = FastPCAPConnectionIndex
