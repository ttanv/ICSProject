"""Streaming PCAP processor for memory-efficient processing of large captures.

This module processes PCAP files one at a time, computing aggregate statistics
incrementally and discarding packet-level data after each file. This allows
processing of multi-GB PCAP datasets without running out of memory.
"""

from __future__ import annotations

import gc
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Dict,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from tqdm import tqdm

from .enhancer import _PendingModbusRequest, _RegisterAccumulator
from .modbus_helpers import modbus_transaction_key, register_type_from_function
from .models import ConnectionKey, IndexedConnection, PacketRecord


@dataclass
class ConnectionStats:
    """Lightweight connection statistics accumulated across PCAP files.

    Unlike IndexedConnection which stores all PacketRecord objects,
    this class only stores computed aggregate statistics, using much less memory.
    """

    canonical_id: str
    origin: ConnectionKey
    origin_timestamp: float

    # Packet counts and sizes
    packet_count: int = 0
    total_bytes: int = 0

    # Directional stats (based on origin direction)
    forward_packets: int = 0
    forward_bytes: int = 0
    reverse_packets: int = 0
    reverse_bytes: int = 0

    # Timing
    first_seen: float = float('inf')
    last_seen: float = 0.0

    # Protocol detection
    protocols_seen: Set[str] = field(default_factory=set)
    high_level_protocol: str = "UNKNOWN"

    # TCP flags (for TCP connections)
    has_syn: bool = False
    has_fin: bool = False
    has_rst: bool = False
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    # Payload tracking
    packets_with_payload: int = 0
    total_payload_bytes: int = 0

    # Modbus-specific tracking (addresses only, not values)
    modbus_function_codes: Set[int] = field(default_factory=set)
    modbus_unit_ids: Set[int] = field(default_factory=set)
    modbus_registers_seen: Set[int] = field(default_factory=set)
    modbus_transaction_count: int = 0
    modbus_register_stats: Dict[Tuple[int, Optional[int], str], _RegisterAccumulator] = field(
        default_factory=dict,
        repr=False,
    )
    _modbus_pending: Dict[Tuple[str, int, str, Optional[int], int], _PendingModbusRequest] = field(
        default_factory=dict,
        repr=False,
    )

    # HTTP tracking
    http_methods_seen: Set[str] = field(default_factory=set)
    http_hosts_seen: Set[str] = field(default_factory=set)
    http_paths_seen: Set[str] = field(default_factory=set)

    # TLS tracking
    tls_snis_seen: Set[str] = field(default_factory=set)

    # Source ports seen (for session tracking with telemetry)
    client_ports_seen: Set[int] = field(default_factory=set)

    # PCAP files this connection appears in
    pcap_files: Set[str] = field(default_factory=set)

    # Sample packets for detailed analysis (limited to save memory)
    _sample_packets: List[PacketRecord] = field(default_factory=list)
    _max_samples: int = 100  # Keep at most 100 sample packets per connection

    @staticmethod
    def _infer_service_port(packet: PacketRecord) -> Optional[int]:
        if packet.dst_port == 502 or packet.src_port == 502:
            return 502
        if packet.dst_port < 1024:
            return packet.dst_port
        if packet.src_port < 1024:
            return packet.src_port
        return None

    @staticmethod
    def _normalize_register_type(register_type: Optional[str]) -> str:
        return register_type or "unknown"

    def _get_register_acc(
        self,
        address: int,
        unit_id: Optional[int],
        register_type: str,
    ) -> _RegisterAccumulator:
        key = (address, unit_id, register_type)
        if key not in self.modbus_register_stats:
            self.modbus_register_stats[key] = _RegisterAccumulator(
                address=address,
                unit_id=unit_id,
                register_type=register_type,
            )
        return self.modbus_register_stats[key]

    def _ensure_register_hints(
        self,
        addresses: Sequence[int],
        unit_id: Optional[int],
        timestamp: float,
        function_code: Optional[int],
        register_type: Optional[str],
    ) -> None:
        normalized_type = self._normalize_register_type(register_type)
        for address in addresses:
            if address is None or address < 0:
                continue
            acc = self._get_register_acc(address, unit_id, normalized_type)
            acc.apply_type_hint(register_type)
            acc.mark_seen(timestamp, function_code)

    def _accumulate_modbus_registers(self, packet: PacketRecord) -> None:
        function_code = packet.modbus_function
        if function_code is None:
            return

        service_port = self._infer_service_port(packet)
        if service_port is None:
            return

        register_type = register_type_from_function(function_code)
        normalized_type = self._normalize_register_type(register_type)
        unit_id = packet.modbus_unit_id
        read_registers = packet.modbus_read_registers or ()
        write_registers = packet.modbus_write_registers or ()
        if not read_registers and not write_registers and packet.modbus_registers:
            read_registers = packet.modbus_registers

        if packet.dst_port == service_port:
            key = modbus_transaction_key(packet, service_port)
            if key is not None:
                self._modbus_pending[key] = _PendingModbusRequest(
                    timestamp=packet.timestamp,
                    unit_id=unit_id,
                    function_code=function_code,
                    read_registers=read_registers,
                    write_registers=write_registers,
                )
            self._ensure_register_hints(read_registers, unit_id, packet.timestamp, function_code, register_type)
            self._ensure_register_hints(write_registers, unit_id, packet.timestamp, function_code, register_type)

            if write_registers and packet.modbus_register_values:
                for address, value in zip(write_registers, packet.modbus_register_values):
                    if address is None or address < 0:
                        continue
                    acc = self._get_register_acc(address, unit_id, normalized_type)
                    acc.observe(
                        value=value,
                        timestamp=packet.timestamp,
                        function_code=function_code,
                        role="write",
                        register_type=register_type,
                    )
            return

        if packet.src_port != service_port:
            return

        key = modbus_transaction_key(packet, service_port)
        request = self._modbus_pending.pop(key, None)
        response_values = tuple(packet.modbus_register_values or ())

        if request:
            req_type = register_type_from_function(request.function_code)
            normalized_req_type = self._normalize_register_type(req_type)
            read_addresses = request.read_registers
            if read_addresses and response_values:
                trimmed_values = response_values[: len(read_addresses)]
                for address, value in zip(read_addresses, trimmed_values):
                    if address is None or address < 0:
                        continue
                    acc = self._get_register_acc(address, request.unit_id, normalized_req_type)
                    acc.observe(
                        value=value,
                        timestamp=packet.timestamp,
                        function_code=request.function_code,
                        role="read",
                        register_type=req_type,
                    )
            elif read_addresses:
                self._ensure_register_hints(
                    read_addresses,
                    request.unit_id,
                    packet.timestamp,
                    request.function_code,
                    req_type,
                )

            if request.write_registers and response_values:
                trimmed_values = response_values[: len(request.write_registers)]
                for address, value in zip(request.write_registers, trimmed_values):
                    if address is None or address < 0:
                        continue
                    acc = self._get_register_acc(address, request.unit_id, normalized_req_type)
                    acc.observe(
                        value=value,
                        timestamp=packet.timestamp,
                        function_code=request.function_code,
                        role="write",
                        register_type=req_type,
                    )
            elif request.write_registers:
                self._ensure_register_hints(
                    request.write_registers,
                    request.unit_id,
                    packet.timestamp,
                    request.function_code,
                    req_type,
                )
            return

        fallback_registers = packet.modbus_write_registers or packet.modbus_registers or ()
        if fallback_registers and response_values:
            fallback_type = register_type_from_function(function_code)
            normalized_fallback_type = self._normalize_register_type(fallback_type)
            trimmed_values = response_values[: len(fallback_registers)]
            for address, value in zip(fallback_registers, trimmed_values):
                if address is None or address < 0:
                    continue
                acc = self._get_register_acc(address, unit_id, normalized_fallback_type)
                acc.observe(
                    value=value,
                    timestamp=packet.timestamp,
                    function_code=function_code,
                    role="write",
                    register_type=fallback_type,
                )
        elif fallback_registers:
            self._ensure_register_hints(
                fallback_registers,
                unit_id,
                packet.timestamp,
                function_code,
                register_type,
            )

    def add_packet(self, packet: PacketRecord) -> None:
        """Update statistics with a new packet."""
        self.packet_count += 1
        self.total_bytes += packet.size

        # Track timing
        if packet.timestamp < self.first_seen:
            self.first_seen = packet.timestamp
        if packet.timestamp > self.last_seen:
            self.last_seen = packet.timestamp

        # Track direction (forward = matches origin direction)
        is_forward = (packet.src_ip == self.origin.src_ip and
                      packet.src_port == self.origin.src_port)
        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += packet.size
        else:
            self.reverse_packets += 1
            self.reverse_bytes += packet.size

        # Track protocol
        if packet.high_level_protocol:
            self.protocols_seen.add(packet.high_level_protocol)
            # Update dominant protocol (prefer specific over generic)
            if self.high_level_protocol == "UNKNOWN":
                self.high_level_protocol = packet.high_level_protocol
            elif packet.high_level_protocol not in ("TCP", "UDP", "UNKNOWN"):
                self.high_level_protocol = packet.high_level_protocol

        # Track TCP flags
        if packet.tcp_flags:
            if 'S' in packet.tcp_flags and 'A' not in packet.tcp_flags:
                self.has_syn = True
                self.syn_count += 1
            if 'F' in packet.tcp_flags:
                self.has_fin = True
                self.fin_count += 1
            if 'R' in packet.tcp_flags:
                self.has_rst = True
                self.rst_count += 1

        # Track payload
        if packet.payload_len > 0:
            self.packets_with_payload += 1
            self.total_payload_bytes += packet.payload_len

        # Track Modbus
        if packet.modbus_function is not None:
            self.modbus_function_codes.add(packet.modbus_function)
        if packet.modbus_unit_id is not None:
            self.modbus_unit_ids.add(packet.modbus_unit_id)
        if packet.modbus_registers:
            self.modbus_registers_seen.update(packet.modbus_registers)
        if packet.modbus_read_registers:
            self.modbus_registers_seen.update(packet.modbus_read_registers)
        if packet.modbus_write_registers:
            self.modbus_registers_seen.update(packet.modbus_write_registers)
        if packet.modbus_transaction_id is not None:
            self.modbus_transaction_count += 1
        self._accumulate_modbus_registers(packet)

        # Track HTTP
        if packet.http_method:
            self.http_methods_seen.add(packet.http_method)
        if packet.http_host:
            self.http_hosts_seen.add(packet.http_host)
        if packet.http_path:
            # Only keep first 100 chars to save memory
            self.http_paths_seen.add(packet.http_path[:100])

        # Track TLS
        if packet.tls_sni:
            self.tls_snis_seen.add(packet.tls_sni)

        # Track client ports (ephemeral side for telemetry correlation)
        service_port = 502 if 502 in (packet.src_port, packet.dst_port) else \
                       80 if 80 in (packet.src_port, packet.dst_port) else \
                       443 if 443 in (packet.src_port, packet.dst_port) else \
                       8080 if 8080 in (packet.src_port, packet.dst_port) else None
        if service_port:
            client_port = packet.src_port if packet.dst_port == service_port else packet.dst_port
            if client_port > 1024:  # Likely ephemeral
                self.client_ports_seen.add(client_port)

        # Track PCAP file
        if packet.pcap_file:
            self.pcap_files.add(packet.pcap_file)

        # Keep sample packets (spaced throughout the connection)
        if len(self._sample_packets) < self._max_samples:
            self._sample_packets.append(packet)
        elif self.packet_count % (self.packet_count // self._max_samples + 1) == 0:
            # Periodically replace old samples to get better coverage
            idx = len(self._sample_packets) % self._max_samples
            self._sample_packets[idx] = packet

    def to_indexed_connection(self) -> IndexedConnection:
        """Convert to IndexedConnection for compatibility with existing code."""
        return IndexedConnection(
            canonical_id=self.canonical_id,
            origin=self.origin,
            records=self._sample_packets,  # Only sample packets, not all
            origin_timestamp=self.origin_timestamp,
        )

    def get_register_summaries(self) -> Dict[Tuple[int, Optional[int], str], Dict[str, object]]:
        """Return finalized per-register summaries for this connection."""
        return {key: acc.to_properties() for key, acc in self.modbus_register_stats.items()}

    def duration_seconds(self) -> float:
        """Return connection duration in seconds."""
        if self.first_seen == float('inf') or self.last_seen == 0.0:
            return 0.0
        return self.last_seen - self.first_seen

    def to_properties(self) -> Dict[str, object]:
        """Generate relationship properties from accumulated stats."""
        props: Dict[str, object] = {
            "pcapAugmented": True,
            "packetCount": self.packet_count,
            "totalBytes": self.total_bytes,
        }

        if self.duration_seconds() > 0:
            props["durationSeconds"] = round(self.duration_seconds(), 3)

        if self.forward_packets > 0 or self.reverse_packets > 0:
            total = self.forward_packets + self.reverse_packets
            props["forwardPackets"] = self.forward_packets
            props["reversePackets"] = self.reverse_packets
            if total > 0:
                props["directionalityRatio"] = round(self.forward_packets / total, 3)

        if self.high_level_protocol != "UNKNOWN":
            props["dominantProtocol"] = self.high_level_protocol

        if self.protocols_seen:
            props["protocolsSeen"] = ",".join(sorted(self.protocols_seen))

        # TCP flag stats
        if self.syn_count > 0:
            props["synPackets"] = self.syn_count
        if self.fin_count > 0:
            props["finPackets"] = self.fin_count
        if self.rst_count > 0:
            props["rstPackets"] = self.rst_count

        # Payload stats
        if self.packets_with_payload > 0:
            props["packetsWithPayload"] = self.packets_with_payload
            props["totalPayloadBytes"] = self.total_payload_bytes
            props["avgPayloadSize"] = round(self.total_payload_bytes / self.packets_with_payload, 1)

        # Modbus stats
        if self.modbus_function_codes:
            props["modbusFunctionCodes"] = ",".join(str(fc) for fc in sorted(self.modbus_function_codes))
        if self.modbus_unit_ids:
            props["modbusUnitIds"] = ",".join(str(uid) for uid in sorted(self.modbus_unit_ids))
        if self.modbus_registers_seen:
            props["modbusRegisterCount"] = len(self.modbus_registers_seen)
            # Store sample of registers if not too many
            if len(self.modbus_registers_seen) <= 50:
                props["modbusRegisters"] = ",".join(str(r) for r in sorted(self.modbus_registers_seen))
        if self.modbus_transaction_count > 0:
            props["modbusTransactions"] = self.modbus_transaction_count

        # HTTP stats
        if self.http_methods_seen:
            props["httpMethods"] = ",".join(sorted(self.http_methods_seen))
        if self.http_hosts_seen:
            # Limit to first 5 hosts
            hosts = sorted(self.http_hosts_seen)[:5]
            props["httpHosts"] = ",".join(hosts)

        # TLS stats
        if self.tls_snis_seen:
            snis = sorted(self.tls_snis_seen)[:5]
            props["tlsSNIs"] = ",".join(snis)

        # Client ports for correlation
        if self.client_ports_seen:
            props["clientPortCount"] = len(self.client_ports_seen)

        # PCAP source tracking
        if self.pcap_files:
            props["pcapFileCount"] = len(self.pcap_files)

        # Timestamps
        if self.first_seen != float('inf'):
            props["firstPacketTime"] = round(self.first_seen, 3)
        if self.last_seen > 0:
            props["lastPacketTime"] = round(self.last_seen, 3)

        return props


class StreamingPCAPIndex:
    """Memory-efficient PCAP index that processes files one at a time.

    Unlike PCAPConnectionIndex which loads all packets into memory,
    this class processes packets incrementally and only keeps aggregate
    statistics in memory.
    """

    _IGNORED_IPS: frozenset = frozenset({"172.16.142.250"})

    def __init__(
        self,
        pcap_directory: Path,
        packet_limit_per_file: Optional[int] = None,
    ) -> None:
        self.pcap_directory = Path(pcap_directory)
        self.packet_limit_per_file = packet_limit_per_file
        self._stats: Dict[str, ConnectionStats] = {}
        self._processed_files: List[str] = []
        self._total_packets: int = 0

    def build(self) -> None:
        """Process all PCAP files, accumulating statistics incrementally."""
        if not self.pcap_directory.exists():
            raise FileNotFoundError(f"PCAP directory not found: {self.pcap_directory}")

        pcap_files = sorted(
            f for f in self.pcap_directory.iterdir()
            if f.suffix in {".pcap", ".pcapng"}
        )

        if not pcap_files:
            print("No PCAP files found")
            return

        print(f"Processing {len(pcap_files)} PCAP files in streaming mode...")

        for pcap_file in tqdm(pcap_files, desc="PCAP files", unit="file"):
            self._process_single_file(pcap_file)
            gc.collect()  # Force garbage collection between files

        print(f"Processed {self._total_packets:,} packets across {len(pcap_files)} files")
        print(f"Found {len(self._stats):,} unique connections")

    def _process_single_file(self, pcap_path: Path) -> None:
        """Process a single PCAP file, updating statistics."""
        try:
            import dpkt
        except ImportError:
            raise ImportError("dpkt is required: pip install dpkt")

        pcap_name = pcap_path.name
        packets_in_file = 0

        try:
            with open(pcap_path, "rb") as f:
                try:
                    pcap_reader = dpkt.pcapng.Reader(f)
                except ValueError:
                    f.seek(0)
                    pcap_reader = dpkt.pcap.Reader(f)

                for packet_index, (ts, buf) in enumerate(pcap_reader):
                    if self.packet_limit_per_file and packet_index >= self.packet_limit_per_file:
                        break

                    record = self._parse_packet(buf, ts, pcap_name, packet_index)
                    if record is None:
                        continue

                    conn_key = record.connection_key()
                    conn_id = conn_key.bidirectional_id()

                    if conn_id not in self._stats:
                        self._stats[conn_id] = ConnectionStats(
                            canonical_id=conn_id,
                            origin=conn_key,
                            origin_timestamp=record.timestamp,
                        )

                    stats = self._stats[conn_id]
                    stats.add_packet(record)

                    # Update origin if this packet is earlier
                    if record.timestamp < stats.origin_timestamp:
                        stats.origin = conn_key
                        stats.origin_timestamp = record.timestamp

                    packets_in_file += 1
                    self._total_packets += 1

        except Exception as e:
            print(f"Error processing {pcap_path}: {e}")

        self._processed_files.append(pcap_name)

    def _parse_packet(
        self,
        buf: bytes,
        timestamp: float,
        pcap_file: str,
        packet_index: int,
    ) -> Optional[PacketRecord]:
        """Parse a single packet - imported from pcap_index_fast logic."""
        # Import the fast parser function
        from .pcap_index_fast import _parse_packet_fast
        return _parse_packet_fast(buf, timestamp, pcap_file, packet_index, set(self._IGNORED_IPS))

    def iter_stats(self) -> Iterator[ConnectionStats]:
        """Yield ConnectionStats objects for streaming processing."""
        yield from self._stats.values()
