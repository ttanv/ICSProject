"""Streaming PCAP processor for memory-efficient processing of large captures.

This module processes PCAP files one at a time, computing aggregate statistics
incrementally and discarding packet-level data after each file. This allows
processing of multi-GB PCAP datasets without running out of memory.
"""

from __future__ import annotations

import gc
import importlib.util
import multiprocessing
import os
import pickle
import signal
import tempfile
import traceback
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

_PARSER_DPKT = "dpkt"
_PARSER_SCAPY = "scapy"
_TRUE_VALUES = ("1", "true", "yes")


def _env_prefers_scapy_parser() -> bool:
    return os.environ.get("USE_SCAPY_PARSER", "").strip().lower() in _TRUE_VALUES


def _parser_backend_available(backend: str) -> bool:
    module_name = {
        _PARSER_DPKT: "dpkt",
        _PARSER_SCAPY: "scapy.all",
    }.get(backend)
    if not module_name:
        return False
    return importlib.util.find_spec(module_name) is not None


def resolve_streaming_parser_backend() -> str:
    """Return the preferred streaming parser backend for this environment."""
    if _env_prefers_scapy_parser():
        if not _parser_backend_available(_PARSER_SCAPY):
            raise ImportError("USE_SCAPY_PARSER=1 was set, but scapy is not installed.")
        return _PARSER_SCAPY
    if _parser_backend_available(_PARSER_DPKT):
        return _PARSER_DPKT
    if _parser_backend_available(_PARSER_SCAPY):
        return _PARSER_SCAPY
    raise ImportError("No streaming parser backend is available. Install dpkt or scapy.")


def _parser_backend_candidates(preferred: str) -> List[str]:
    if preferred == _PARSER_SCAPY:
        return [_PARSER_SCAPY]
    candidates = [_PARSER_DPKT]
    if _parser_backend_available(_PARSER_SCAPY):
        candidates.append(_PARSER_SCAPY)
    return candidates


def _signal_name_for_exitcode(exitcode: int) -> Optional[str]:
    if exitcode >= 0:
        return None
    try:
        return signal.Signals(-exitcode).name
    except ValueError:
        return None


def describe_streaming_worker_failure(
    *,
    pcap_path: Path,
    backend: str,
    phase: str,
    exitcode: int,
    error_message: Optional[str] = None,
) -> str:
    """Build a readable failure message for isolated parser workers."""
    base = f"{phase} failed for {pcap_path.name} using parser backend '{backend}'"
    if error_message:
        return f"{base}: {error_message.strip()}"
    if exitcode < 0:
        signal_name = _signal_name_for_exitcode(exitcode)
        if signal_name:
            return f"{base}: worker crashed with signal {-exitcode} ({signal_name})"
        return f"{base}: worker crashed with signal {-exitcode}"
    return f"{base}: worker exited with status {exitcode}"


def _iter_packet_records_for_backend(
    pcap_path: Path,
    *,
    packet_limit: Optional[int],
    backend: str,
    ignored_ips: Sequence[str],
) -> Iterator[PacketRecord]:
    if backend == _PARSER_DPKT:
        import dpkt

        from .pcap_index_fast import _parse_packet_fast

        with pcap_path.open("rb") as handle:
            try:
                reader = dpkt.pcapng.Reader(handle)
            except ValueError:
                handle.seek(0)
                reader = dpkt.pcap.Reader(handle)

            for packet_index, (timestamp, buf) in enumerate(reader):
                if packet_limit is not None and packet_index >= packet_limit:
                    break
                record = _parse_packet_fast(
                    buf,
                    timestamp,
                    pcap_path.name,
                    packet_index,
                    set(ignored_ips),
                )
                if record is not None:
                    yield record
        return

    if backend == _PARSER_SCAPY:
        import scapy.all as scapy

        from .pcap_index_scapy import iter_packet_records_scapy

        with scapy.PcapReader(str(pcap_path)) as reader:
            for packet_index, packet in enumerate(reader):
                if packet_limit is not None and packet_index >= packet_limit:
                    break
                yield from iter_packet_records_scapy(
                    packet,
                    pcap_file=pcap_path.name,
                    packet_index=packet_index,
                    prefer_innermost=True,
                    ignored_ips=ignored_ips,
                )
        return

    raise ValueError(f"Unsupported parser backend: {backend}")


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

    # Directional stats (based on origin direction)
    forward_bytes: int = 0
    reverse_bytes: int = 0

    # Timing
    first_seen: float = float('inf')
    last_seen: float = 0.0

    # Protocol detection
    protocols_seen: Set[str] = field(default_factory=set)
    high_level_protocol: str = "UNKNOWN"

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

    # MQTT tracking
    mqtt_packet_type_codes_seen: Set[int] = field(default_factory=set)
    mqtt_topics_seen: Set[str] = field(default_factory=set)

    # OPC UA tracking
    opcua_message_types_seen: Set[str] = field(default_factory=set)
    opcua_has_hel_with_endpoint: bool = False

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

    _WELL_KNOWN_SERVICE_PORTS = frozenset({502, 1883, 8883, 4840})

    @staticmethod
    def _infer_service_port(packet: PacketRecord) -> Optional[int]:
        for port in (packet.dst_port, packet.src_port):
            if port in ConnectionStats._WELL_KNOWN_SERVICE_PORTS:
                return port
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

    def _finalize_modbus_registers(self) -> None:
        """Flush deferred per-register observation buffers populated via buffer_observe()."""
        for acc in self.modbus_register_stats.values():
            acc.flush_buffer()

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
                    acc.buffer_observe(
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
                    acc.buffer_observe(
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
                    acc.buffer_observe(
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
                acc.buffer_observe(
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

        # Track timing
        if packet.timestamp < self.first_seen:
            self.first_seen = packet.timestamp
        if packet.timestamp > self.last_seen:
            self.last_seen = packet.timestamp

        # Track direction (forward = matches origin direction)
        is_forward = (packet.src_ip == self.origin.src_ip and
                      packet.src_port == self.origin.src_port)
        if is_forward:
            self.forward_bytes += packet.size
        else:
            self.reverse_bytes += packet.size

        # Track protocol
        if packet.high_level_protocol:
            self.protocols_seen.add(packet.high_level_protocol)
            # Update dominant protocol (prefer specific over generic)
            if self.high_level_protocol == "UNKNOWN":
                self.high_level_protocol = packet.high_level_protocol
            elif packet.high_level_protocol not in ("TCP", "UDP", "UNKNOWN"):
                self.high_level_protocol = packet.high_level_protocol

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

        # Track MQTT
        if packet.mqtt_packet_type_code is not None and packet.mqtt_packet_type_code > 0:
            self.mqtt_packet_type_codes_seen.add(packet.mqtt_packet_type_code)
        if packet.mqtt_topic:
            topic = packet.mqtt_topic.strip()
            if topic and len(self.mqtt_topics_seen) < 50:
                self.mqtt_topics_seen.add(topic)

        # Track OPC UA
        msg_type = (packet.opcua_message_type or "").upper()
        if msg_type:
            self.opcua_message_types_seen.add(msg_type)
            if msg_type == "HEL" and packet.opcua_endpoint_url:
                self.opcua_has_hel_with_endpoint = True

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
        service_port = self._infer_service_port(packet)
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
        self._finalize_modbus_registers()
        return {key: acc.to_properties() for key, acc in self.modbus_register_stats.items()}

    def duration_seconds(self) -> float:
        """Return connection duration in seconds."""
        if self.first_seen == float('inf') or self.last_seen == 0.0:
            return 0.0
        return self.last_seen - self.first_seen

    def directional_bytes(self, oriented_origin: ConnectionKey) -> Tuple[int, int]:
        """Return bytes as (out, in) for an oriented flow."""
        same_direction = (
            oriented_origin.src_ip == self.origin.src_ip
            and oriented_origin.src_port == self.origin.src_port
            and oriented_origin.dst_ip == self.origin.dst_ip
            and oriented_origin.dst_port == self.origin.dst_port
            and oriented_origin.protocol.lower() == self.origin.protocol.lower()
        )
        if same_direction:
            return self.forward_bytes, self.reverse_bytes
        return self.reverse_bytes, self.forward_bytes

    @staticmethod
    def _is_more_specific_protocol(candidate: str, current: str) -> bool:
        generic = {"TCP", "UDP", "UNKNOWN", ""}
        return candidate not in generic and current in generic

    def _merge_register_accumulator(self, other: _RegisterAccumulator) -> None:
        other.flush_buffer()
        key = (other.address, other.unit_id, self._normalize_register_type(other.register_type))
        if key not in self.modbus_register_stats:
            self.modbus_register_stats[key] = other
            return

        current = self.modbus_register_stats[key]
        current.flush_buffer()
        current.apply_type_hint(other.register_type)
        current.read_count += other.read_count
        current.write_count += other.write_count
        current.state_changes += other.state_changes
        current.observed_functions.update(other.observed_functions)
        current.last_function_code = other.last_function_code or current.last_function_code

        if other.last_seen_at is not None and (
            current.last_seen_at is None or other.last_seen_at > current.last_seen_at
        ):
            current.last_seen_at = other.last_seen_at
            current.last_value = other.last_value
        if other.last_write_at is not None and (
            current.last_write_at is None or other.last_write_at > current.last_write_at
        ):
            current.last_write_at = other.last_write_at
        if other.min_value is not None:
            current.min_value = other.min_value if current.min_value is None else min(current.min_value, other.min_value)
        if other.max_value is not None:
            current.max_value = other.max_value if current.max_value is None else max(current.max_value, other.max_value)

        total_samples = current.sample_count + other.sample_count
        if total_samples > 0:
            current.mean_value = (
                (current.mean_value * current.sample_count) + (other.mean_value * other.sample_count)
            ) / total_samples
            current.sample_count = total_samples

        current._seen_values_hll |= other._seen_values_hll
        current.distinct_values = max(current.distinct_values, other.distinct_values)
        for value, count in other.value_frequencies.items():
            if value in current.value_frequencies or len(current.value_frequencies) < current._MAX_TRACKED_VALUES:
                current.value_frequencies[value] = current.value_frequencies.get(value, 0) + count

    def merge(self, other: "ConnectionStats") -> None:
        """Merge another per-file stats object into this aggregate view."""
        if other.canonical_id != self.canonical_id:
            raise ValueError("Cannot merge different connections")

        final_origin = self.origin
        final_origin_ts = self.origin_timestamp
        if other.origin_timestamp < self.origin_timestamp:
            final_origin = other.origin
            final_origin_ts = other.origin_timestamp

        self_out, self_in = self.directional_bytes(final_origin)
        other_out, other_in = other.directional_bytes(final_origin)

        self.origin = final_origin
        self.origin_timestamp = final_origin_ts
        self.forward_bytes = self_out + other_out
        self.reverse_bytes = self_in + other_in
        self.packet_count += other.packet_count
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        self.packets_with_payload += other.packets_with_payload
        self.total_payload_bytes += other.total_payload_bytes

        self.protocols_seen.update(other.protocols_seen)
        if self.high_level_protocol == "UNKNOWN" or self._is_more_specific_protocol(
            other.high_level_protocol,
            self.high_level_protocol,
        ):
            self.high_level_protocol = other.high_level_protocol or self.high_level_protocol

        self.modbus_function_codes.update(other.modbus_function_codes)
        self.modbus_unit_ids.update(other.modbus_unit_ids)
        self.modbus_registers_seen.update(other.modbus_registers_seen)
        self.modbus_transaction_count += other.modbus_transaction_count
        for acc in other.modbus_register_stats.values():
            self._merge_register_accumulator(acc)

        self.mqtt_packet_type_codes_seen.update(other.mqtt_packet_type_codes_seen)
        self.mqtt_topics_seen.update(other.mqtt_topics_seen)
        self.opcua_message_types_seen.update(other.opcua_message_types_seen)
        self.opcua_has_hel_with_endpoint = self.opcua_has_hel_with_endpoint or other.opcua_has_hel_with_endpoint
        self.http_methods_seen.update(other.http_methods_seen)
        self.http_hosts_seen.update(other.http_hosts_seen)
        self.http_paths_seen.update(other.http_paths_seen)
        self.tls_snis_seen.update(other.tls_snis_seen)
        self.client_ports_seen.update(other.client_ports_seen)
        self.pcap_files.update(other.pcap_files)

        merged_samples = sorted(
            self._sample_packets + other._sample_packets,
            key=lambda packet: packet.timestamp,
        )
        if len(merged_samples) > self._max_samples:
            step = len(merged_samples) / self._max_samples
            merged_samples = [
                merged_samples[min(int(index * step), len(merged_samples) - 1)]
                for index in range(self._max_samples)
            ]
        self._sample_packets = merged_samples

    def to_properties(self, oriented_origin: ConnectionKey) -> Dict[str, object]:
        """Generate relationship properties from accumulated stats."""
        bytes_out, bytes_in = self.directional_bytes(oriented_origin)
        total_observed_bytes = bytes_out + bytes_in
        props: Dict[str, object] = {
            "pcapAugmented": True,
            "packetCount": self.packet_count,
            "bytesOut": bytes_out,
            "bytesIn": bytes_in,
        }

        if self.duration_seconds() > 0:
            props["durationSeconds"] = round(self.duration_seconds(), 3)

        if self.packet_count > 0 and total_observed_bytes > 0:
            props["avgPacketSize"] = round(total_observed_bytes / self.packet_count, 2)

        if self.high_level_protocol != "UNKNOWN":
            props["dominantProtocol"] = self.high_level_protocol

        if self.protocols_seen:
            props["protocolsSeen"] = ",".join(sorted(self.protocols_seen))

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
        parser_backend: Optional[str] = None,
    ) -> None:
        self.pcap_directory = Path(pcap_directory)
        self.packet_limit_per_file = packet_limit_per_file
        self.parser_backend = parser_backend or resolve_streaming_parser_backend()
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
            self._process_single_file_isolated(pcap_file)
            gc.collect()  # Force garbage collection between files

        print(f"Processed {self._total_packets:,} packets across {len(pcap_files)} files")
        print(f"Found {len(self._stats):,} unique connections")

    def _process_single_file_isolated(self, pcap_path: Path) -> None:
        """Process one file in an isolated worker so parser crashes are recoverable."""
        backends = _parser_backend_candidates(self.parser_backend)
        last_failure: Optional[str] = None

        for index, backend in enumerate(backends):
            try:
                partial_stats, processed_packets = self._run_stats_worker(pcap_path, backend)
            except RuntimeError as exc:
                last_failure = str(exc)
                if index + 1 < len(backends):
                    print(last_failure)
                    print(f"Retrying {pcap_path.name} with parser backend '{backends[index + 1]}'...")
                    continue
                raise

            if backend != self.parser_backend:
                print(
                    f"Recovered {pcap_path.name} with parser backend '{backend}' "
                    f"after primary backend '{self.parser_backend}' failed."
                )

            self._merge_file_stats(partial_stats, processed_packets)
            self._processed_files.append(pcap_path.name)
            return

        raise RuntimeError(last_failure or f"Failed to process {pcap_path.name}")

    def _merge_file_stats(
        self,
        partial_stats: Dict[str, ConnectionStats],
        processed_packets: int,
    ) -> None:
        for conn_id, partial in partial_stats.items():
            if conn_id not in self._stats:
                self._stats[conn_id] = partial
            else:
                self._stats[conn_id].merge(partial)
        self._total_packets += processed_packets

    def _run_stats_worker(
        self,
        pcap_path: Path,
        backend: str,
    ) -> Tuple[Dict[str, ConnectionStats], int]:
        with tempfile.NamedTemporaryFile(prefix="stream_stats_", suffix=".pkl", delete=False) as handle:
            result_path = Path(handle.name)

        ctx = multiprocessing.get_context("spawn")
        process = ctx.Process(
            target=_stream_file_stats_worker,
            args=(
                str(pcap_path),
                self.packet_limit_per_file,
                backend,
                tuple(self._IGNORED_IPS),
                str(result_path),
            ),
        )
        process.start()
        process.join()

        payload = self._read_worker_payload(result_path)
        try:
            if process.exitcode == 0:
                if not payload or not payload.get("ok"):
                    error_message = (payload or {}).get("error")
                    raise RuntimeError(
                        describe_streaming_worker_failure(
                            pcap_path=pcap_path,
                            backend=backend,
                            phase="Streaming parse",
                            exitcode=process.exitcode,
                            error_message=error_message or "worker completed without a result payload",
                        )
                    )
                return payload["stats"], int(payload["processed_packets"])

            error_message = payload.get("error") if payload else None
            raise RuntimeError(
                describe_streaming_worker_failure(
                    pcap_path=pcap_path,
                    backend=backend,
                    phase="Streaming parse",
                    exitcode=process.exitcode or 1,
                    error_message=error_message,
                )
            )
        finally:
            result_path.unlink(missing_ok=True)

    @staticmethod
    def _read_worker_payload(result_path: Path) -> Dict[str, object]:
        if not result_path.exists() or result_path.stat().st_size == 0:
            return {}
        with result_path.open("rb") as handle:
            payload = pickle.load(handle)
        if not isinstance(payload, dict):
            return {}
        return payload

    def iter_stats(self) -> Iterator[ConnectionStats]:
        """Yield ConnectionStats objects for streaming processing."""
        yield from self._stats.values()


def _stream_file_stats_worker(
    pcap_path_str: str,
    packet_limit_per_file: Optional[int],
    backend: str,
    ignored_ips: Tuple[str, ...],
    result_path_str: str,
) -> None:
    """Worker that parses one PCAP file and serializes per-file streaming stats."""
    result_path = Path(result_path_str)
    try:
        pcap_path = Path(pcap_path_str)
        partial_stats: Dict[str, ConnectionStats] = {}
        processed_packets = 0

        for record in _iter_packet_records_for_backend(
            pcap_path,
            packet_limit=packet_limit_per_file,
            backend=backend,
            ignored_ips=ignored_ips,
        ):
            conn_key = record.connection_key()
            conn_id = conn_key.bidirectional_id()
            if conn_id not in partial_stats:
                partial_stats[conn_id] = ConnectionStats(
                    canonical_id=conn_id,
                    origin=conn_key,
                    origin_timestamp=record.timestamp,
                )

            stats = partial_stats[conn_id]
            stats.add_packet(record)
            if record.timestamp < stats.origin_timestamp:
                stats.origin = conn_key
                stats.origin_timestamp = record.timestamp
            processed_packets += 1

        with result_path.open("wb") as handle:
            pickle.dump(
                {
                    "ok": True,
                    "stats": partial_stats,
                    "processed_packets": processed_packets,
                },
                handle,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
    except Exception:
        with result_path.open("wb") as handle:
            pickle.dump(
                {
                    "ok": False,
                    "error": traceback.format_exc(),
                },
                handle,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        raise
