"""High-level orchestration for adding PCAP-only connections to the base graph."""

from __future__ import annotations


import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Set, Tuple

from . import cypher_emit
from .correlation import (
    CorrelatedConnection,
    CorrelationConfig,
    CorrelationEngine,
    TelemetryConnectionIndex,
    TemporalProcessEntry,
    TemporalProcessIndex,
)
from .cypher_reader import (
    CypherConnectionExtractor,
    ExistingConnection,
    _consume_brace_block,
    _parse_property_block,
)
from .features import (
    PreSortedPackets,
    aggregate_tcp_flags,
    average_packet_size,
    count_tcp_retransmits,
    dominant_protocol,
    duration_seconds,
    directional_totals,
    directionality_ratio,
    extract_http_features,
    extract_tls_sni,
    mean_interarrival_time,
    mean_rtt_ms,
    packet_count,
    resolve_mac_addresses,
    total_bytes,
)
from .filters import AugmentationPolicy
from tqdm import tqdm

from .grouping import (
    CollapsedConnectionGroup,
    HTTPMonitorGroup,
    ModbusGroup,
    group_collapsed_connections,
    group_http_monitor_connections,
    group_modbus_connections,
    _is_service_port,
)
from .models import ConnectionKey, IndexedConnection, PacketRecord

logger = logging.getLogger(__name__)

if TYPE_CHECKING:  # pragma: no cover - import for typing only
    from .pcap_index import PCAPConnectionIndex


@dataclass
class AugmentationConfig:
    """Runtime configuration for the missing traffic augmentation step."""

    base_cypher: Path
    output_cypher: Path
    pcap_directory: Path
    asset_file: Optional[Path] = None
    cache_path: Path = Path("pcap_connection_index.pkl")
    ip_hostname_map: Dict[str, str] = field(
        default_factory=lambda: {
            "192.168.42.12": "EWS-WIN-01",
            "192.168.42.21": "HMI-01",
            "192.168.42.20": "SCADA-01",
            "192.168.43.9": "PLC-01",
            "192.168.43.10": "PLC-02",
            "192.168.43.11": "PLC-03",
            "192.168.44.11": "PLC-03",  # Secondary network interface
        }
    )
    service_map: Dict[int, str] = field(
        default_factory=lambda: {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP Trap",
            443: "HTTPS",
            445: "SMB",
            502: "Modbus",
            1433: "SQL",
            1883: "MQTT",
            8883: "MQTT TLS",
            4840: "OPC UA",
            3389: "RDP",
            44818: "EtherNet/IP",
        }
    )
    policy: AugmentationPolicy = field(default_factory=AugmentationPolicy)
    relationship_name: str = "ESTABLISH_CONNECTION"
    force_rebuild_index: bool = False
    packet_limit: Optional[int] = None
    min_aggregation_threshold: int = 2

    # Correlation configuration
    min_correlation_confidence: float = 0.5
    temporal_tolerance_seconds: float = 60.0
    require_temporal_overlap: bool = False
    enable_process_attribution: bool = True
    telemetry_attribution_only: bool = False  # Only attribute when telemetry evidence exists (no temporal fallback)
    pcap_time_offset_seconds: float = 0.0  # Offset to apply to PCAP timestamps (e.g., -10800 for UTC+3 -> UTC)

    # Signal database configuration
    signal_db_path: Optional[Path] = None  # Path to DuckDB file for raw signal observations


@dataclass
class AggregationMetrics:
    """Summary statistics describing how much aggregation compressed the graph."""

    total_connections: int
    raw_relationships: int
    raw_asset_nodes: int
    raw_service_nodes: int
    aggregated_relationships: int
    aggregated_asset_nodes: int
    aggregated_service_nodes: int
    aggregated_register_nodes: int
    modbus_relationships: int
    http_monitor_relationships: int
    collapsed_relationships: int
    individual_relationships: int
    existing_relationship_updates: int

    # Correlation statistics
    correlation_attempts: int = 0
    successful_correlations: int = 0
    temporal_matches: int = 0
    process_attributed_registers: int = 0  # READ/WRITE register attribution
    process_attributed_signals: int = 0  # SignalContainer-based attribution (optional)

    @property
    def raw_node_count(self) -> int:
        return self.raw_asset_nodes + self.raw_service_nodes

    @property
    def aggregated_node_count(self) -> int:
        return self.aggregated_asset_nodes + self.aggregated_service_nodes + self.aggregated_register_nodes

    @property
    def final_relationship_count(self) -> int:
        return self.aggregated_relationships + self.existing_relationship_updates

    @property
    def relationships_saved(self) -> int:
        return self.raw_relationships - self.aggregated_relationships

    @property
    def service_nodes_saved(self) -> int:
        return self.raw_service_nodes - self.aggregated_service_nodes


@dataclass
class AugmentationArtifacts:
    """Intermediate Cypher statements produced during aggregation."""

    asset_statements: Dict[str, str]
    service_statements: Dict[str, str]
    host_statements: Dict[str, str]  # External/unknown Host nodes
    register_statements: Dict[str, str]  # Modbus Register nodes
    signal_statements: Dict[str, str]  # Optional SignalContainer evidence nodes
    process_statements: Dict[str, str]  # Virtual Process nodes for PLCs/RTUs
    runs_statements: Dict[str, str]  # Asset-[:RUNS]->Process relationships
    relationship_statements: List[str]
    existing_relationship_updates: List[str]
    process_register_statements: List[str]  # READ/WRITE register edges
    process_signal_statements: List[str]  # ACCESSED_SIGNAL edges (optional)
    modbus_relationships: int
    http_monitor_relationships: int
    collapsed_relationships: int
    individual_relationships: int
    internal_relationships: int  # ESTABLISH_INTERNAL_CONNECTION count
    external_relationships: int  # ESTABLISH_EXTERNAL_CONNECTION count

    # Correlation statistics
    correlation_attempts: int = 0
    successful_correlations: int = 0
    temporal_matches: int = 0
    process_attributed_registers: int = 0  # READ/WRITE register attribution
    process_attributed_signals: int = 0  # SignalContainer attribution (optional)


@dataclass
class AssetMetadata:
    """Extended asset info from assets.yaml for PLC/RTU detection."""

    hostname: str
    ip_addresses: List[str]
    role: str
    has_logs: bool

    @property
    def is_plc_or_rtu(self) -> bool:
        """Return True if this asset is a PLC or RTU without logs."""
        role_lower = self.role.lower()
        return not self.has_logs and role_lower in ("plc", "rtu", "controller")


@dataclass
class _SDTCompressor:
    """Swinging Door Trending compressor for register value timelines."""

    tolerance: float = 1.0
    max_points: int = 100

    # Compressed points: list of (timestamp, value)
    points: List[Tuple[float, float]] = field(default_factory=list)

    # SDT state
    _last_stored_ts: Optional[float] = None
    _last_stored_val: Optional[float] = None
    _upper_slope: float = float("inf")
    _lower_slope: float = float("-inf")
    _pending: Optional[Tuple[float, float]] = None

    # Adaptive tracking
    recompression_count: int = 0

    def add(self, timestamp: float, value: float) -> None:
        """Add a sample using SDT compression."""
        if self._last_stored_ts is None:
            # First point - always store
            self._store(timestamp, value)
            return

        dt = timestamp - self._last_stored_ts
        if dt <= 0:
            return

        # Check if point is outside the aperture
        upper_limit = self._last_stored_val + self._upper_slope * dt + self.tolerance
        lower_limit = self._last_stored_val + self._lower_slope * dt - self.tolerance

        if value > upper_limit or value < lower_limit:
            # Store pending point first (closes the door)
            if self._pending:
                self._store(*self._pending)
            self._store(timestamp, value)
        else:
            # Update slopes and keep as pending
            upper_slope_to_point = (value + self.tolerance - self._last_stored_val) / dt
            lower_slope_to_point = (value - self.tolerance - self._last_stored_val) / dt
            self._upper_slope = min(self._upper_slope, upper_slope_to_point)
            self._lower_slope = max(self._lower_slope, lower_slope_to_point)
            self._pending = (timestamp, value)

        # Adaptive: recompress if too many points
        if len(self.points) > self.max_points:
            self._recompress()

    def _store(self, timestamp: float, value: float) -> None:
        self.points.append((timestamp, value))
        self._last_stored_ts = timestamp
        self._last_stored_val = value
        self._upper_slope = float("inf")
        self._lower_slope = float("-inf")
        self._pending = None

    def _recompress(self) -> None:
        """Double tolerance and recompress existing points."""
        self.tolerance *= 2
        self.recompression_count += 1
        old_points = self.points

        # Reset state
        self.points = []
        self._last_stored_ts = None
        self._last_stored_val = None
        self._upper_slope = float("inf")
        self._lower_slope = float("-inf")
        self._pending = None

        # Replay through SDT with new tolerance
        for ts, val in old_points:
            self.add(ts, val)

    def finalize(self) -> None:
        """Flush any pending point."""
        if self._pending:
            self._store(*self._pending)

    @staticmethod
    def _format_value(value: float) -> str:
        """Format a value for timeline encoding, preserving precision."""
        if value == int(value):
            return str(int(value))
        return f"{value:.3f}"

    def encode_timeline(self) -> Optional[str]:
        """Encode compressed points as a compact string."""
        if not self.points:
            return None

        self.finalize()

        if len(self.points) == 1:
            ts, val = self.points[0]
            return f"@{ts:.3f}|0:{self._format_value(val)}"

        base_ts = self.points[0][0]
        parts = []
        for ts, val in self.points:
            dt = ts - base_ts
            parts.append(f"{dt:.2f}:{self._format_value(val)}")

        return f"@{base_ts:.3f}|" + ",".join(parts)


@dataclass(slots=True)
class _PendingModbusRequest:
    timestamp: float
    unit_id: Optional[int]
    function_code: Optional[int]
    read_registers: Tuple[int, ...] = ()
    write_registers: Tuple[int, ...] = ()


@dataclass
class _RegisterAccumulator:
    address: int
    unit_id: Optional[int]
    register_type: Optional[str] = None
    read_count: int = 0
    write_count: int = 0
    last_value: Optional[int] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    mean_value: float = 0.0
    sample_count: int = 0
    state_changes: int = 0
    last_seen_at: Optional[float] = None
    last_write_at: Optional[float] = None
    last_function_code: Optional[int] = None
    observed_functions: Set[int] = field(default_factory=set)
    distinct_values: int = 0
    value_frequencies: Dict[int, int] = field(default_factory=dict)
    _seen_values_hll: int = 0  # HyperLogLog-style approximate distinct count

    # SDT compressor for value timeline
    _sdt: Optional[_SDTCompressor] = field(default=None, repr=False)
    _rle: List[Tuple[int, int]] = field(default_factory=list, repr=False)
    _rle_truncated: bool = field(default=False, repr=False)

    _TYPE_PRIORITY: Dict[str, int] = field(
        init=False,
        default_factory=lambda: {"coil": 0, "discreteInput": 0, "holdingRegister": 1, "inputRegister": 1},
    )
    _MAX_TRACKED_VALUES: int = 4
    _RLE_MAX_RUNS: int = 200

    def apply_type_hint(self, register_type: Optional[str]) -> None:
        if not register_type:
            return
        if not self.register_type:
            self.register_type = register_type
            return
        current_priority = self._TYPE_PRIORITY.get(self.register_type, 99)
        incoming_priority = self._TYPE_PRIORITY.get(register_type, 99)
        if incoming_priority < current_priority:
            self.register_type = register_type

    def mark_seen(self, timestamp: float, function_code: Optional[int]) -> None:
        if self.last_seen_at is None or timestamp > self.last_seen_at:
            self.last_seen_at = timestamp
        if function_code is not None:
            self.last_function_code = function_code
            self.observed_functions.add(function_code)

    def observe(
        self,
        value: Optional[int],
        timestamp: float,
        function_code: Optional[int],
        role: str,
        register_type: Optional[str],
    ) -> None:
        self.mark_seen(timestamp, function_code)
        self.apply_type_hint(register_type)

        if role == "read":
            self.read_count += 1
        elif role == "write":
            self.write_count += 1
            self.last_write_at = timestamp

        if value is None:
            return

        previous_value = self.last_value
        self.last_value = value
        if previous_value is not None and register_type in {"coil", "discreteInput"} and previous_value != value:
            self.state_changes += 1

        if self.min_value is None or value < self.min_value:
            self.min_value = value
        if self.max_value is None or value > self.max_value:
            self.max_value = value

        self.sample_count += 1
        delta = float(value) - self.mean_value
        self.mean_value += delta / self.sample_count

        # Track distinct values using bitmask (memory-efficient for 16-bit values)
        # Use a 64-bit mask to track which hash buckets have been seen
        bucket = hash(value) & 63  # 64 buckets
        bucket_mask = 1 << bucket
        if not (self._seen_values_hll & bucket_mask):
            self._seen_values_hll |= bucket_mask
            self.distinct_values += 1

        # Track top values (capped at 4)
        if value in self.value_frequencies:
            self.value_frequencies[value] += 1
        elif len(self.value_frequencies) < self._MAX_TRACKED_VALUES:
            self.value_frequencies[value] = 1

        # Update run-length encoding (RLE) of observed values
        if not self._rle:
            self._rle.append((value, 1))
        else:
            last_val, last_count = self._rle[-1]
            if value == last_val:
                self._rle[-1] = (last_val, last_count + 1)
            else:
                self._rle.append((value, 1))
                if len(self._rle) > self._RLE_MAX_RUNS:
                    self._rle.pop(0)
                    self._rle_truncated = True

        # Feed value to SDT compressor
        if self._sdt is None:
            self._sdt = _SDTCompressor(tolerance=1.0, max_points=100)
        self._sdt.add(timestamp, value)

    def to_properties(self) -> Dict[str, object]:
        props: Dict[str, object] = {}
        if self.register_type:
            props["registerType"] = self.register_type
        if self.read_count:
            props["readCount"] = self.read_count
        if self.write_count:
            props["writeCount"] = self.write_count
        if self.sample_count:
            props["valueSamples"] = self.sample_count
            props["meanValue"] = round(self.mean_value, 3)
        if self.last_value is not None:
            props["lastValue"] = self.last_value
        if self.min_value is not None:
            props["minValue"] = self.min_value
        if self.max_value is not None:
            props["maxValue"] = self.max_value
        if self.distinct_values:
            props["distinctValues"] = self.distinct_values
        if self.state_changes:
            props["stateChanges"] = self.state_changes
        if self.last_seen_at is not None:
            props["lastSeenAt"] = round(self.last_seen_at, 3)
        if self.last_write_at is not None:
            props["lastWriteAt"] = round(self.last_write_at, 3)
        if self.last_function_code is not None:
            props["lastFunctionCode"] = self.last_function_code
        if self.observed_functions:
            props["observedFunctions"] = ",".join(str(code) for code in sorted(self.observed_functions))
        if self.value_frequencies:
            ordered = sorted(self.value_frequencies.items(), key=lambda item: (-item[1], item[0]))
            props["topValues"] = ",".join(f"{value}:{count}" for value, count in ordered)

        # RLE compressed timeline (value:run_length, comma-separated)
        if self._rle:
            props["valueRLE"] = ",".join(f"{value}:{count}" for value, count in self._rle)
            props["rleRuns"] = len(self._rle)
            if self.sample_count > 0:
                props["rleCompressionRatio"] = round(self.sample_count / len(self._rle), 2)
            if self._rle_truncated:
                props["rleTruncated"] = True

        # SDT compressed timeline
        if self._sdt is not None:
            timeline = self._sdt.encode_timeline()
            if timeline:
                props["valueTimeline"] = timeline
                props["timelinePoints"] = len(self._sdt.points)
                if self.sample_count > 0:
                    props["compressionRatio"] = round(self.sample_count / len(self._sdt.points), 2)
                props["sdtTolerance"] = self._sdt.tolerance
                if self._sdt.recompression_count > 0:
                    props["sdtRecompressions"] = self._sdt.recompression_count

        return props


@dataclass
class _SignalAccumulator:
    """Protocol-agnostic accumulator for SDT/RLE/statistics on OPC UA or MQTT signals."""

    signal_id: str
    protocol: str  # "opcua" or "mqtt"

    read_count: int = 0
    write_count: int = 0
    last_value: Optional[float] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    mean_value: float = 0.0
    sample_count: int = 0
    last_seen_at: Optional[float] = None
    last_write_at: Optional[float] = None
    distinct_values: int = 0
    value_frequencies: Dict[int, int] = field(default_factory=dict)
    _seen_values_hll: int = 0

    _sdt: Optional[_SDTCompressor] = field(default=None, repr=False)
    _rle: List[Tuple[int, int]] = field(default_factory=list, repr=False)
    _rle_truncated: bool = field(default=False, repr=False)

    _MAX_TRACKED_VALUES: int = 4
    _RLE_MAX_RUNS: int = 200

    def observe(self, value: Optional[float], timestamp: float, role: str) -> None:
        if self.last_seen_at is None or timestamp > self.last_seen_at:
            self.last_seen_at = timestamp

        if role == "read":
            self.read_count += 1
        elif role == "write":
            self.write_count += 1
            self.last_write_at = timestamp

        if value is None:
            return

        self.last_value = value

        if self.min_value is None or value < self.min_value:
            self.min_value = value
        if self.max_value is None or value > self.max_value:
            self.max_value = value

        self.sample_count += 1
        delta = value - self.mean_value
        self.mean_value += delta / self.sample_count

        # Quantize to int for RLE and frequency tracking
        quantized = int(round(value))

        bucket = hash(quantized) & 63
        bucket_mask = 1 << bucket
        if not (self._seen_values_hll & bucket_mask):
            self._seen_values_hll |= bucket_mask
            self.distinct_values += 1

        if quantized in self.value_frequencies:
            self.value_frequencies[quantized] += 1
        elif len(self.value_frequencies) < self._MAX_TRACKED_VALUES:
            self.value_frequencies[quantized] = 1

        if not self._rle:
            self._rle.append((quantized, 1))
        else:
            last_val, last_count = self._rle[-1]
            if quantized == last_val:
                self._rle[-1] = (last_val, last_count + 1)
            else:
                self._rle.append((quantized, 1))
                if len(self._rle) > self._RLE_MAX_RUNS:
                    self._rle.pop(0)
                    self._rle_truncated = True

        if self._sdt is None:
            self._sdt = _SDTCompressor(tolerance=1.0, max_points=100)
        self._sdt.add(timestamp, value)

    def to_properties(self) -> Dict[str, object]:
        props: Dict[str, object] = {}
        if self.sample_count:
            props["valueSamples"] = self.sample_count
            props["meanValue"] = round(self.mean_value, 3)
        if self.last_value is not None:
            props["lastValue"] = round(self.last_value, 3) if self.last_value != int(self.last_value) else int(self.last_value)
        if self.min_value is not None:
            props["minValue"] = round(self.min_value, 3) if self.min_value != int(self.min_value) else int(self.min_value)
        if self.max_value is not None:
            props["maxValue"] = round(self.max_value, 3) if self.max_value != int(self.max_value) else int(self.max_value)
        if self.distinct_values:
            props["distinctValues"] = self.distinct_values
        if self.value_frequencies:
            ordered = sorted(self.value_frequencies.items(), key=lambda item: (-item[1], item[0]))
            props["topValues"] = ",".join(f"{value}:{count}" for value, count in ordered)

        if self._rle:
            props["valueRLE"] = ",".join(f"{value}:{count}" for value, count in self._rle)
            props["rleRuns"] = len(self._rle)
            if self.sample_count > 0:
                props["rleCompressionRatio"] = round(self.sample_count / len(self._rle), 2)
            if self._rle_truncated:
                props["rleTruncated"] = True

        if self._sdt is not None:
            timeline = self._sdt.encode_timeline()
            if timeline:
                props["valueTimeline"] = timeline
                props["timelinePoints"] = len(self._sdt.points)
                if self.sample_count > 0:
                    props["compressionRatio"] = round(self.sample_count / len(self._sdt.points), 2)
                props["sdtTolerance"] = self._sdt.tolerance
                if self._sdt.recompression_count > 0:
                    props["sdtRecompressions"] = self._sdt.recompression_count

        return props




# ---------------------------------------------------------------------------
# Signal Storage
# ---------------------------------------------------------------------------
