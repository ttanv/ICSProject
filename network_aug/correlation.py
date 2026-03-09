"""Deterministic correlation between telemetry connections and PCAP flows."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .cypher_reader import ExistingConnection
from .models import ConnectionKey, IndexedConnection, PacketRecord
from .orientation import oriented_connection_key

logger = logging.getLogger(__name__)


def _parse_timestamp(value: object) -> Optional[float]:
    """Parse a timestamp from telemetry into epoch seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Already numeric - could be epoch seconds or milliseconds
        val = float(value)
        # If it looks like milliseconds (> year 2001 in seconds), convert
        if val > 1_000_000_000_000:
            return val / 1000.0
        return val
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        # Handle Neo4j datetime('...') wrapper format
        if value.startswith("datetime('") and value.endswith("')"):
            value = value[10:-2]  # Extract the inner timestamp string
        # Try common timestamp formats
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ):
            try:
                dt = datetime.strptime(value, fmt)
                return dt.timestamp()
            except ValueError:
                continue
        # Try parsing as numeric string
        try:
            val = float(value)
            if val > 1_000_000_000_000:
                return val / 1000.0
            return val
        except ValueError:
            pass
    return None


@dataclass(frozen=True)
class ProcessContext:
    """Process attribution carried through from telemetry.

    This captures the process-level context from Sysmon/ETW logs that
    can be associated with PCAP-derived network features.
    """
    process_guid: str
    process_image: str
    process_id: int
    user: str
    computer: str

    @classmethod
    def from_properties(cls, props: Dict[str, object]) -> "ProcessContext":
        """Extract process context from telemetry connection properties."""
        return cls(
            process_guid=str(props.get("ProcessGuid") or props.get("processGuid") or ""),
            process_image=str(props.get("Image") or props.get("image") or ""),
            process_id=int(props.get("ProcessId") or props.get("processId") or 0),
            user=str(props.get("User") or props.get("user") or ""),
            computer=str(props.get("Computer") or props.get("computer") or ""),
        )

    @classmethod
    def from_connection(cls, conn: "ExistingConnection") -> "ProcessContext":
        """Extract process context from an ExistingConnection.

        If the source node is a Process, use its GUID as the process_guid.
        Also extract other process properties from the relationship properties.
        """
        props = conn.properties

        # If source is a Process node, the src_guid IS the process guid
        if conn.src_label and conn.src_label.lower() == "process":
            process_guid = conn.src_guid
        else:
            process_guid = str(props.get("ProcessGuid") or props.get("processGuid") or "")

        return cls(
            process_guid=process_guid,
            process_image=str(props.get("Image") or props.get("image") or ""),
            process_id=_safe_int(props.get("ProcessId") or props.get("processId")),
            user=str(props.get("User") or props.get("user") or ""),
            computer=str(props.get("Computer") or props.get("computer") or props.get("host") or ""),
        )

    def is_valid(self) -> bool:
        """Return True if this context has meaningful process information."""
        return bool(self.process_guid or self.process_image)



def _safe_int(value: object) -> int:
    """Safely convert a value to int, returning 0 on failure."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return 0


@dataclass
class TelemetryAnchor:
    """A telemetry connection that can anchor PCAP flows.

    This represents a network connection observed in host telemetry (Sysmon/ETW)
    with its time window and process context. PCAP flows are correlated to
    these anchors to inherit process attribution.
    """
    connection_key: ConnectionKey
    time_window: Tuple[Optional[float], Optional[float]]  # (firstSeen, lastSeen) as epoch
    process_context: ProcessContext
    src_guid: str
    dst_guid: str
    src_label: str
    dst_label: str
    rel_properties: Dict[str, object]
    rel_type: str  # Relationship type (ESTABLISH_INTERNAL_CONNECTION or ESTABLISH_EXTERNAL_CONNECTION)

    # Session metadata for deterministic PCAP correlation
    # Parallel arrays: sessionPorts[i] was active at sessionTimestamps[i]
    session_ports: List[int] = field(default_factory=list)
    session_timestamps: List[float] = field(default_factory=list)

    @classmethod
    def from_existing_connection(cls, conn: ExistingConnection) -> "TelemetryAnchor":
        """Create a TelemetryAnchor from an ExistingConnection."""
        props = conn.properties

        # Extract time window
        first_seen = _parse_timestamp(
            props.get("firstSeen") or props.get("FirstSeen") or props.get("timestamp")
        )
        last_seen = _parse_timestamp(
            props.get("lastSeen") or props.get("LastSeen") or props.get("timestamp")
        )

        # If only one timestamp, use it for both
        if first_seen is not None and last_seen is None:
            last_seen = first_seen
        elif last_seen is not None and first_seen is None:
            first_seen = last_seen

        # Build process context - use src_guid as process_guid if source is a Process node
        process_context = ProcessContext.from_connection(conn)

        # Extract session metadata for deterministic correlation
        session_ports: List[int] = []
        session_timestamps: List[float] = []
        raw_ports = props.get("sessionPorts", [])
        raw_timestamps = props.get("sessionTimestamps", [])

        if isinstance(raw_ports, list) and isinstance(raw_timestamps, list):
            for port, ts in zip(raw_ports, raw_timestamps):
                try:
                    session_ports.append(int(port))
                    session_timestamps.append(float(ts))
                except (ValueError, TypeError):
                    pass

        return cls(
            connection_key=conn.key,
            time_window=(first_seen, last_seen),
            process_context=process_context,
            src_guid=conn.src_guid,
            dst_guid=conn.dst_guid,
            src_label=conn.src_label,
            dst_label=conn.dst_label,
            rel_properties=dict(props),
            rel_type=conn.rel_type,
            session_ports=session_ports,
            session_timestamps=session_timestamps,
        )

    def has_time_window(self) -> bool:
        """Return True if this anchor has valid timestamp information."""
        return self.time_window[0] is not None or self.time_window[1] is not None

    def has_session_metadata(self) -> bool:
        """Return True if this anchor has session port metadata for deterministic correlation."""
        return len(self.session_ports) > 0 and len(self.session_ports) == len(self.session_timestamps)

    def find_session_by_port(self, port: int, timestamp: float, tolerance: float = 60.0) -> Optional[int]:
        """Find the index of a session matching the given port and timestamp.

        Returns the index into session_ports/session_timestamps if found, None otherwise.
        Uses tolerance (in seconds) to allow for clock skew between telemetry and PCAP.
        """
        if not self.has_session_metadata():
            return None

        for i, (sess_port, sess_ts) in enumerate(zip(self.session_ports, self.session_timestamps)):
            if sess_port == port:
                # Port matches - check if timestamp is within tolerance
                if abs(timestamp - sess_ts) <= tolerance:
                    return i
        return None

    def find_session_by_port_only(self, port: int) -> Optional[int]:
        """Find the index of a session matching the given port (ignoring timestamp).

        Returns the first index where port matches, None if not found.
        Useful when temporal correlation is done separately.
        """
        if not self.has_session_metadata():
            return None

        for i, sess_port in enumerate(self.session_ports):
            if sess_port == port:
                return i
        return None


@dataclass
class CorrelatedConnection:
    """A PCAP connection correlated to a telemetry anchor.

    This represents the result of successfully correlating a PCAP flow
    to a telemetry connection, enabling process attribution.
    """
    telemetry_anchor: TelemetryAnchor
    pcap_connection: IndexedConnection
    confidence: float  # 0.0 - 1.0
    correlation_method: str  # e.g., "temporal_5tuple", "5tuple_only"

    # Packets from the correlated PCAP connection
    packets: List[PacketRecord] = field(default_factory=list)

    @property
    def process_context(self) -> ProcessContext:
        """Return the process context inherited from the telemetry anchor."""
        return self.telemetry_anchor.process_context

    @property
    def has_process_attribution(self) -> bool:
        """Return True if this correlation has valid process attribution."""
        return self.process_context.is_valid()


class TelemetryConnectionIndex:
    """Index telemetry connections for efficient PCAP correlation.

    This builds hash-based indexes over telemetry connections to enable
    O(1) lookup of candidate anchors for each PCAP connection, avoiding
    O(N*M) comparisons.
    """

    def __init__(
        self,
        existing_connections: Sequence[ExistingConnection],
        ip_to_hostname: Optional[Dict[str, str]] = None,
    ) -> None:
        self._anchors: List[TelemetryAnchor] = []
        self._ip_to_hostname = ip_to_hostname or {}

        # Index by forward service endpoint (client_ip, server_ip, server_port, protocol)
        self._by_service_endpoint: Dict[
            Tuple[str, str, int, str], List[TelemetryAnchor]
        ] = defaultdict(list)

        # Index by normalized forward endpoint for multi-IP matching.
        self._by_normalized_endpoint: Dict[
            Tuple[str, str, int, str], List[TelemetryAnchor]
        ] = defaultdict(list)

        # Index by exact 5-tuple for precise matches
        self._by_exact_key: Dict[
            Tuple[str, int, str, int, str], List[TelemetryAnchor]
        ] = defaultdict(list)

        # Index by process GUID for direct process-context lookups
        self._by_process: Dict[str, List[TelemetryAnchor]] = defaultdict(list)

        # Track anchors with session metadata for deterministic correlation
        self._anchors_with_sessions = 0
        self._total_session_ports = 0

        # Build indexes
        self._build_indexes(existing_connections)

        logger.info(
            "Built TelemetryConnectionIndex with %d anchors, %d service endpoints, "
            "%d anchors with session metadata (%d total session ports)",
            len(self._anchors),
            len(self._by_service_endpoint),
            self._anchors_with_sessions,
            self._total_session_ports,
        )

    def _normalize_ip(self, ip: str) -> str:
        """Normalize an IP address to hostname if mapping is available."""
        return self._ip_to_hostname.get(ip, ip)

    def _build_indexes(self, connections: Sequence[ExistingConnection]) -> None:
        """Build all lookup indexes from existing connections."""
        for conn in connections:
            anchor = TelemetryAnchor.from_existing_connection(conn)
            self._anchors.append(anchor)

            # Track session metadata coverage
            if anchor.has_session_metadata():
                self._anchors_with_sessions += 1
                self._total_session_ports += len(anchor.session_ports)

            key = anchor.connection_key

            # Forward service endpoint index (client_ip, server_ip, server_port, protocol).
            service_key = (key.src_ip, key.dst_ip, key.dst_port, key.protocol.lower())
            self._by_service_endpoint[service_key].append(anchor)

            # Normalized endpoint index (hostname-based for multi-IP matching)
            src_host = self._normalize_ip(key.src_ip)
            dst_host = self._normalize_ip(key.dst_ip)
            normalized_key = (src_host, dst_host, key.dst_port, key.protocol.lower())
            self._by_normalized_endpoint[normalized_key].append(anchor)

            # Exact key index
            exact_key = (key.src_ip, key.src_port, key.dst_ip, key.dst_port, key.protocol.lower())
            self._by_exact_key[exact_key].append(anchor)

            # Process index
            proc_guid = anchor.process_context.process_guid
            if proc_guid:
                self._by_process[proc_guid].append(anchor)

    def find_candidates(
        self,
        connection_key: ConnectionKey,
    ) -> List[Tuple[TelemetryAnchor, float]]:
        """Find telemetry anchors that could correlate with this oriented PCAP flow.

        Returns list of (anchor, base_score) tuples where base_score reflects
        how well the 5-tuple matched (exact match scores higher than service-only).
        """
        candidates: List[Tuple[TelemetryAnchor, float]] = []
        seen_anchors: Set[int] = set()  # Track by id() to avoid duplicates

        proto = connection_key.protocol.lower()

        # Try exact 5-tuple match first (highest base score)
        exact_key = (
            connection_key.src_ip,
            connection_key.src_port,
            connection_key.dst_ip,
            connection_key.dst_port,
            proto,
        )
        for anchor in self._by_exact_key.get(exact_key, []):
            if id(anchor) not in seen_anchors:
                seen_anchors.add(id(anchor))
                candidates.append((anchor, 0.5))  # Base score for exact match

        # Try service endpoint match (lower base score)
        service_key = (
            connection_key.src_ip,
            connection_key.dst_ip,
            connection_key.dst_port,
            proto,
        )
        for anchor in self._by_service_endpoint.get(service_key, []):
            if id(anchor) not in seen_anchors:
                seen_anchors.add(id(anchor))
                candidates.append((anchor, 0.3))  # Lower base for service-only match

        src_host = self._normalize_ip(connection_key.src_ip)
        dst_host = self._normalize_ip(connection_key.dst_ip)
        normalized_key = (src_host, dst_host, connection_key.dst_port, proto)
        for anchor in self._by_normalized_endpoint.get(normalized_key, []):
            if id(anchor) not in seen_anchors:
                seen_anchors.add(id(anchor))
                candidates.append((anchor, 0.25))

        return candidates

    def get_anchors_for_process(self, process_guid: str) -> List[TelemetryAnchor]:
        """Return all anchors associated with a specific process."""
        return self._by_process.get(process_guid, [])

    @staticmethod
    def _anchor_matches_src_port(anchor: TelemetryAnchor, src_port: int) -> bool:
        """Return True when anchor evidence deterministically matches a client source port."""
        if src_port <= 0:
            return False
        if anchor.find_session_by_port_only(src_port) is not None:
            return True
        if anchor.connection_key.src_port == src_port:
            return True
        rel_src_port = _safe_int(
            anchor.rel_properties.get("SourcePort") or anchor.rel_properties.get("sourcePort")
        )
        return rel_src_port == src_port

    def _select_process_context(
        self,
        anchors: Sequence[TelemetryAnchor],
        *,
        src_port: Optional[int] = None,
        require_src_port_match: bool = False,
    ) -> Optional[ProcessContext]:
        """Pick the best process context from candidate anchors."""
        valid_anchors = [anchor for anchor in anchors if anchor.process_context.is_valid()]
        if not valid_anchors:
            return None

        if src_port is not None and src_port > 0:
            for anchor in valid_anchors:
                if self._anchor_matches_src_port(anchor, src_port):
                    return anchor.process_context
            if require_src_port_match:
                return None

        return valid_anchors[0].process_context

    def find_process_for_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str = "tcp",
        src_port: Optional[int] = None,
        require_src_port_match: bool = False,
    ) -> Optional[ProcessContext]:
        """Find the process context for a connection based on telemetry.

        This is used to attribute PCAP traffic to the correct process when
        telemetry already shows which process made a connection to this endpoint.

        Performs lookup in two stages:
        1. Direct IP match against telemetry connection IPs
        2. Normalized hostname match (for multi-IP hosts where PCAP uses different
           IP than telemetry, e.g., inner vs outer network interfaces)

        Args:
            src_ip: Source IP address (client)
            dst_ip: Destination IP address (server)
            dst_port: Destination port
            protocol: Protocol (tcp/udp)
            src_port: Source port (optional, enables deterministic source-port matching)
            require_src_port_match: When True and src_port is provided, only return
                contexts with exact source-port evidence (session port or exact key).

        Returns:
            ProcessContext if a matching telemetry connection is found, None otherwise.
        """
        proto = protocol.lower()

        # PHASE 1: Try direct IP match
        # Try forward service endpoint match (ignores ephemeral source port)
        service_key = (src_ip, dst_ip, dst_port, proto)
        anchors = self._by_service_endpoint.get(service_key, [])

        proc_ctx = self._select_process_context(
            anchors,
            src_port=src_port,
            require_src_port_match=require_src_port_match,
        )
        if proc_ctx is not None:
            return proc_ctx

        # PHASE 2: Try normalized hostname lookup
        # This handles multi-IP hosts (e.g., PCAP uses 192.168.44.x inner layer,
        # telemetry uses 192.168.42.x/43.x outer layer for the same host)
        src_host = self._normalize_ip(src_ip)
        dst_host = self._normalize_ip(dst_ip)

        # Only proceed if at least one IP was normalized to a hostname
        if src_host != src_ip or dst_host != dst_ip:
            normalized_key = (src_host, dst_host, dst_port, proto)
            normalized_anchors = self._by_normalized_endpoint.get(normalized_key, [])

            proc_ctx = self._select_process_context(
                normalized_anchors,
                src_port=src_port,
                require_src_port_match=require_src_port_match,
            )
            if proc_ctx is not None:
                return proc_ctx

        return None

    @property
    def anchor_count(self) -> int:
        """Return the total number of telemetry anchors."""
        return len(self._anchors)

    @property
    def anchors_with_session_metadata(self) -> int:
        """Return the number of anchors with session port metadata."""
        return self._anchors_with_sessions

    @property
    def total_session_ports(self) -> int:
        """Return the total number of session ports across all anchors."""
        return self._total_session_ports

    @property
    def session_metadata_coverage(self) -> float:
        """Return the fraction of anchors that have session metadata (0.0-1.0)."""
        if len(self._anchors) == 0:
            return 0.0
        return self._anchors_with_sessions / len(self._anchors)


@dataclass
class CorrelationConfig:
    """Configuration for the correlation engine."""

    # Minimum confidence score to accept a correlation (0.0 - 1.0)
    min_confidence: float = 0.5

    # Temporal tolerance in seconds for session port temporal proximity check
    temporal_tolerance_seconds: float = 60.0

    # Time offset to apply to PCAP timestamps (in seconds)
    # Use negative values to shift PCAP times earlier (e.g., -10800 for UTC+3 -> UTC)
    pcap_time_offset_seconds: float = 0.0


class CorrelationEngine:
    """Correlates PCAP flows to telemetry connections via deterministic session-port matching.

    Matches PCAP src_port against sessionPorts[] on telemetry CONNECT_TO edges.
    No heuristic/temporal fallback is used.
    """

    def __init__(
        self,
        config: Optional[CorrelationConfig] = None,
        ip_hostname_map: Optional[Dict[str, str]] = None,
    ) -> None:
        self.config = config or CorrelationConfig()
        self._ip_hostname_map = ip_hostname_map or {}

        # Statistics for reporting
        self._stats = {
            "total_attempts": 0,
            "successful_correlations": 0,
            "session_port_matches": 0,  # Deterministic matches via sessionPorts
            "below_threshold": 0,
            "no_candidates": 0,
            "unoriented_connections": 0,
        }

    def correlate(
        self,
        pcap_conn: IndexedConnection,
        telemetry_index: TelemetryConnectionIndex,
    ) -> Optional[CorrelatedConnection]:
        """Correlate a PCAP connection to a telemetry anchor via session-port matching.

        Uses deterministic session-based matching (sessionPorts metadata) only.
        No temporal/heuristic fallback.

        Returns a CorrelatedConnection if a session-port match is found,
        otherwise None.
        """
        self._stats["total_attempts"] += 1

        pcap_key = oriented_connection_key(pcap_conn.origin, pcap_conn.records)
        if pcap_key is None:
            self._stats["unoriented_connections"] += 1
            return None

        # Find candidate anchors using the forward-oriented client->server flow.
        candidates = telemetry_index.find_candidates(pcap_key)

        if not candidates:
            self._stats["no_candidates"] += 1
            return None

        time_offset = self.config.pcap_time_offset_seconds

        for anchor, _base_score in candidates:
            if anchor.has_session_metadata():
                session_idx = anchor.find_session_by_port_only(pcap_key.src_port)
                if session_idx is not None:
                    # Found deterministic match via session port!
                    # Verify temporal proximity for extra confidence
                    session_ts = anchor.session_timestamps[session_idx]
                    pcap_timestamps = [p.timestamp + time_offset for p in pcap_conn.records]
                    pcap_first = min(pcap_timestamps) if pcap_timestamps else 0

                    # Check temporal proximity (session timestamp should be close to PCAP start)
                    temporal_diff = abs(pcap_first - session_ts)
                    if temporal_diff <= self.config.temporal_tolerance_seconds:
                        # Perfect match: port + temporal proximity
                        confidence = 1.0
                        if confidence < self.config.min_confidence:
                            self._stats["below_threshold"] += 1
                            return None
                        self._stats["session_port_matches"] += 1
                        self._stats["successful_correlations"] += 1
                        return CorrelatedConnection(
                            telemetry_anchor=anchor,
                            pcap_connection=pcap_conn,
                            confidence=confidence,
                            correlation_method="session_port_exact",
                            packets=list(pcap_conn.records),
                        )
                    else:
                        # Port matches but temporal is off - still a good match
                        # Could be clock skew or longer-lived connection
                        confidence = 0.9
                        if confidence < self.config.min_confidence:
                            self._stats["below_threshold"] += 1
                            return None
                        self._stats["session_port_matches"] += 1
                        self._stats["successful_correlations"] += 1
                        return CorrelatedConnection(
                            telemetry_anchor=anchor,
                            pcap_connection=pcap_conn,
                            confidence=confidence,
                            correlation_method="session_port_match",
                            packets=list(pcap_conn.records),
                        )

        # No session-port match found
        return None

    def correlate_batch(
        self,
        pcap_connections: Sequence[IndexedConnection],
        telemetry_index: TelemetryConnectionIndex,
    ) -> Dict[str, CorrelatedConnection]:
        """Correlate multiple PCAP connections, returning a map by canonical_id.

        This is more efficient than calling correlate() repeatedly as it
        can potentially optimize batch lookups.
        """
        results: Dict[str, CorrelatedConnection] = {}

        for pcap_conn in pcap_connections:
            correlated = self.correlate(pcap_conn, telemetry_index)
            if correlated:
                results[pcap_conn.canonical_id] = correlated

        return results

    def get_statistics(self) -> Dict[str, int]:
        """Return correlation statistics for reporting."""
        return dict(self._stats)

    def reset_statistics(self) -> None:
        """Reset correlation statistics."""
        for key in self._stats:
            self._stats[key] = 0


def build_correlation_index(
    existing_connections: Sequence[ExistingConnection],
) -> TelemetryConnectionIndex:
    """Convenience function to build a TelemetryConnectionIndex."""
    return TelemetryConnectionIndex(existing_connections)


def correlate_pcap_to_telemetry(
    pcap_connections: Sequence[IndexedConnection],
    existing_connections: Sequence[ExistingConnection],
    config: Optional[CorrelationConfig] = None,
    ip_hostname_map: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, CorrelatedConnection], Dict[str, int]]:
    """High-level function to correlate PCAP connections to telemetry.

    Returns:
        Tuple of (correlations_by_canonical_id, statistics)
    """
    index = TelemetryConnectionIndex(existing_connections)
    engine = CorrelationEngine(config=config, ip_hostname_map=ip_hostname_map)

    correlations = engine.correlate_batch(pcap_connections, index)
    stats = engine.get_statistics()

    return correlations, stats
