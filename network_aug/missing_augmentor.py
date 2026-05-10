"""
Add missing traffic connections, augments existing connections with traffic metadata, 
"""
from dataclasses import dataclass, field
import hashlib
import logging
from pathlib import Path
import re
from typing import Tuple, Optional, Dict, Set, List, Sequence
from tqdm import tqdm
import uuid
from .models import SignalContainerData, ConnectionKey, IndexedConnection, PacketRecord
from .enhancer import AugmentationConfig, AggregationMetrics, AugmentationArtifacts, AssetMetadata, _PendingModbusRequest, _RegisterAccumulator, _SignalAccumulator, _SDTCompressor

from . import cypher_emit
from .correlation import (
    CorrelatedConnection,
    CorrelationConfig,
    CorrelationEngine,
    ProcessContext,
    TelemetryConnectionIndex,
)
from .cypher_reader import (
    CypherConnectionExtractor,
    ExistingConnection,
    _consume_brace_block,
    _parse_property_block,
)
from .features import (
    PreSortedPackets,
    average_packet_size,
    count_tcp_retransmits,
    dominant_protocol,
    duration_seconds,
    directional_totals,
    directionality_ratio,
    extract_http_features,
    extract_mqtt_features,
    extract_opcua_features,
    extract_tls_sni,
    mean_interarrival_time,
    mean_rtt_ms,
    resolve_mac_addresses,
)
from .modbus_helpers import modbus_transaction_key, register_type_from_function
from .mqtt_helpers import MQTT_PORTS
from .opcua_helpers import OPCUA_PORTS
from .protocols import ProtocolBuildContext, build_default_registry

from .grouping import (
    CollapsedConnectionGroup,
    HTTPMonitorGroup,
    ModbusGroup,
    group_collapsed_connections,
    group_http_monitor_connections,
    group_modbus_connections,
)
from .orientation import orient_connection
from . import protocol_utils
from .streaming import ConnectionStats

logger = logging.getLogger(__name__)

_SESSION_METADATA_KEYS = {"sessionPorts", "sessionTimestamps"}
_CORRELATED_EDGE_NOTE = "Augmented with PCAP-derived metrics via correlation"

def _modbus_transaction_key(packet: PacketRecord, service_port: int) -> Optional[Tuple[str, int, str, Optional[int], int]]:
    return modbus_transaction_key(packet, service_port)

def _generate_node_guid(node_type: str, hostname: str, *identifiers: object) -> str:
    """Replicate the GUID scheme used by the base provenance notebook."""
    components = [node_type, hostname] + [str(value) for value in identifiers if value not in (None, "")]
    combined = "|".join(components).lower()
    guid_hash = hashlib.md5(combined.encode("utf-8")).digest()
    guid = uuid.UUID(bytes=guid_hash)
    return f"{{{guid}}}"


def _normalize_transport_protocol(protocol: object) -> str:
    """Normalize transport protocol values used for service identity."""
    normalized = str(protocol or "").strip().lower()
    return normalized or "tcp"


def _generate_network_service_guid(hostname: str, port: int, protocol: object) -> str:
    """Generate a NetworkService GUID matching the base graph: (type, host, port) only."""
    normalized_port = port if port and port >= 0 else 0
    return _generate_node_guid("NetworkService", hostname, normalized_port)


def _generate_signal_guid(protocol: str, host: str, port: int, *identifiers: object) -> str:
    """Generate deterministic ICSSignal GUID (case-preserving identifiers)."""
    return protocol_utils.generate_signal_guid(protocol, host, port, *identifiers)


def _generate_signal_key(protocol: str, host: str, port: int, *identifiers: object) -> str:
    """Generate canonical ICSSignal identity key."""
    return protocol_utils.generate_signal_key(protocol, host, port, *identifiers)

def _register_type_from_function(function_code: Optional[int]) -> Optional[str]:
    return register_type_from_function(function_code)


@dataclass
class _ModbusGroupPayload:
    """Fork-safe computation result for a Modbus group.

    Produced by _compute_modbus_group_payload() with no shared-state mutation.
    Intentionally omits the group itself so result-pickle cost stays small when
    workers send payloads back to the main process; the group is re-associated
    by the caller in _apply_modbus_group_payload().
    """

    connection_key: "ConnectionKey"
    source_ports: Set[int]
    protocol_counts: Dict[str, int]
    total_packets: int
    bytes_out: int
    bytes_in: int
    first_seen: float
    last_seen: float
    all_function_codes: Set[int]
    all_unit_ids: Set[int]
    all_registers: Set[int]
    total_transactions: int
    src_mac: str
    dst_mac: str
    register_summaries: Dict[Tuple[int, Optional[int], str], Dict[str, object]]


@dataclass
class _StagedConnectEdge:
    """Internal staging container used to merge duplicate CONNECT_TO emissions."""

    source_guid: str
    dest_guid: str
    relationship_name: str
    source_label: str
    dest_label: str
    properties: Dict[str, object]
    statement_index: int
    source_ports: Set[int] = field(default_factory=set)
    protocol_values: Set[str] = field(default_factory=set)

class MissingTrafficAugmentor:
    """Coordinates loading graph outputs, indexing PCAP, and writing augmented Cypher."""

    def __init__(self, config: AugmentationConfig) -> None:
        self.config = config
        self._protocol_registry = build_default_registry()
        self._asset_ip_map = self._load_asset_lookup()
        self._asset_metadata: Dict[str, AssetMetadata] = {}  # hostname -> metadata
        self._ip_to_hostname: Dict[str, str] = {}  # IP -> hostname (multi-IP support)
        self._placeholder_processes: Dict[str, str] = {}  # hostname -> process_guid cache
        self._staged_connect_edges: Dict[Tuple[str, str, str], _StagedConnectEdge] = {}
        self._load_asset_metadata()

        # Build set of all known hostnames for placeholder-process gating
        self._known_hostnames: Set[str] = (
            set(self._asset_metadata.keys())
            | set(self._asset_ip_map.values())
            | set(self.config.ip_hostname_map.values())
        )

        # Initialize DuckDB connection for signal storage
        self._signal_db = None
        if config.signal_db_path:
            from .signal_db import SignalDatabase
            self._signal_db = SignalDatabase(config.signal_db_path)
            logger.info("Initialized signal database at %s", config.signal_db_path)

    def _build_artifacts(
        self,
        connections: Sequence[IndexedConnection],
        base_connection_ids: Set[str],
        existing_connections: Sequence[ExistingConnection],
        show_progress: bool = True,
    ) -> AugmentationArtifacts:
        asset_statements: Dict[str, str] = {}
        service_statements: Dict[str, str] = {}
        host_statements: Dict[str, str] = {}  # External/unknown NetworkEndpoint nodes
        register_statements: Dict[str, str] = {}  # Modbus Register nodes
        signal_statements: Dict[str, str] = {}  # Optional SignalContainer evidence nodes
        process_statements: Dict[str, str] = {}  # Virtual Process nodes for PLCs/RTUs
        runs_statements: Dict[str, str] = {}  # Process ownership relationships (RUN_ON/BINDS)
        relationship_statements: List[str] = []
        self._staged_connect_edges = {}
        process_register_stmts: List[str] = []  # READ_SIGNAL / WRITE_SIGNAL edges
        processed_cids: Set[str] = set()

        modbus_relationships = 0
        http_relationships = 0
        collapsed_relationships = 0
        individual_relationships = 0
        internal_relationships = 0
        external_relationships = 0
        
        """
        1- Augments existing relationships
        2- Build Temporal Process (if applicable)
        3- Group Modbus and HTTP connections then iterate over them
        4- Group Ephemeral Stuff and Process
        5- Process rest of connections?
        """

        existing_rel_update_entries, proc_register_stmts, correlated_cids, corr_stats, telemetry_index = self._augment_existing_relationships(
            existing_connections, connections,
            asset_statements=asset_statements,
            service_statements=service_statements,
            register_statements=register_statements,
            process_statements=process_statements,
            runs_statements=runs_statements,
        )
        # Exclude correlated PCAP connections from further processing - they link to existing telemetry
        processed_cids.update(correlated_cids)
        logger.info(
            "Excluding %d correlated PCAP connections from new node creation",
            len(correlated_cids),
        )

        modbus_result = self._protocol_registry.run(
            "modbus",
            ProtocolBuildContext(
                augmentor=self,
                connections=connections,
                base_connection_ids=base_connection_ids,
                correlated_cids=correlated_cids,
                processed_cids=processed_cids,
                show_progress=show_progress,
                telemetry_index=telemetry_index,
                asset_statements=asset_statements,
                service_statements=service_statements,
                host_statements=host_statements,
                register_statements=register_statements,
                process_statements=process_statements,
                runs_statements=runs_statements,
                relationship_statements=relationship_statements,
                process_register_statements=process_register_stmts,
            ),
        )
        modbus_relationships += modbus_result.relationship_count
        
        http_result = self._protocol_registry.run(
            "http_monitor",
            ProtocolBuildContext(
                augmentor=self,
                connections=connections,
                base_connection_ids=base_connection_ids,
                correlated_cids=correlated_cids,
                processed_cids=processed_cids,
                show_progress=show_progress,
                telemetry_index=telemetry_index,
                asset_statements=asset_statements,
                service_statements=service_statements,
                host_statements=host_statements,
                register_statements=register_statements,
                process_statements=process_statements,
                runs_statements=runs_statements,
                relationship_statements=relationship_statements,
                process_register_statements=process_register_stmts,
            ),
        )
        http_relationships += http_result.relationship_count

        mqtt_result = self._protocol_registry.run(
            "mqtt",
            ProtocolBuildContext(
                augmentor=self,
                connections=connections,
                base_connection_ids=base_connection_ids,
                correlated_cids=correlated_cids,
                processed_cids=processed_cids,
                show_progress=show_progress,
                telemetry_index=telemetry_index,
                asset_statements=asset_statements,
                service_statements=service_statements,
                host_statements=host_statements,
                register_statements=register_statements,
                process_statements=process_statements,
                runs_statements=runs_statements,
                relationship_statements=relationship_statements,
                process_register_statements=process_register_stmts,
            ),
        )
        # MQTT phase aggregates protocol flows before staging CONNECT_TO edges.
        individual_relationships += mqtt_result.relationship_count

        opcua_result = self._protocol_registry.run(
            "opcua",
            ProtocolBuildContext(
                augmentor=self,
                connections=connections,
                base_connection_ids=base_connection_ids,
                correlated_cids=correlated_cids,
                processed_cids=processed_cids,
                show_progress=show_progress,
                telemetry_index=telemetry_index,
                asset_statements=asset_statements,
                service_statements=service_statements,
                host_statements=host_statements,
                register_statements=register_statements,
                process_statements=process_statements,
                runs_statements=runs_statements,
                relationship_statements=relationship_statements,
                process_register_statements=process_register_stmts,
            ),
        )
        # OPC UA phase aggregates protocol flows before staging CONNECT_TO edges.
        individual_relationships += opcua_result.relationship_count

        collapse_groups, collapse_consumed = group_collapsed_connections(
            connections,
            exclude_ids=processed_cids,
            min_unique_ports=self.config.min_aggregation_threshold,
        )
        collapse_iterable = (
            tqdm(collapse_groups, desc="Processing aggregated port groups", unit="group")
            if show_progress
            else collapse_groups
        )
        for group in collapse_iterable:
            # Skip if all connections are either in base telemetry OR already correlated
            if all(cid in base_connection_ids or cid in correlated_cids for cid in group.canonical_ids()):
                continue
            # Asset-IP scope filter
            if self._asset_ips and group.client_ip not in self._asset_ips and group.server_ip not in self._asset_ips:
                continue
            packets = group.packets()
            if not packets:
                continue

            connection_key = ConnectionKey(
                src_ip=group.client_ip,
                src_port=0,
                dst_ip=group.server_ip,
                dst_port=group.service_port,
                protocol=group.protocol,
            )

            if not self.config.policy.is_interesting(connection_key, packets):
                continue

            before_count = len(relationship_statements)
            rel_type = self._add_collapsed_group(
                group,
                connection_key,
                packets,
                asset_statements,
                service_statements,
                host_statements,
                process_statements,
                runs_statements,
                relationship_statements,
                telemetry_index=telemetry_index,
            )
            added = len(relationship_statements) - before_count
            collapsed_relationships += max(added, 0)
            processed_cids.update(group.canonical_ids())

        processed_cids.update(collapse_consumed)

        connection_iterable = (
            tqdm(connections, desc="Processing individual connections", unit="connection")
            if show_progress
            else connections
        )
        for indexed in connection_iterable:
            if indexed.canonical_id in base_connection_ids:
                continue
            if indexed.canonical_id in processed_cids:
                continue
            # Asset-IP scope filter: skip connections where neither IP is a known asset
            if self._asset_ips and indexed.origin.src_ip not in self._asset_ips and indexed.origin.dst_ip not in self._asset_ips:
                continue

            packets = indexed.records
            if not packets:
                continue

            connection_key = indexed.origin
            if not self.config.policy.is_interesting(connection_key, packets):
                continue

            # Orient the connection so CONNECT_TO always points from client process to server service.
            orientation = orient_connection(connection_key, packets)
            if orientation is not None:
                client_ip, _, server_ip, server_port, proto = orientation
                client_port = 0
                oriented_key = ConnectionKey(
                    src_ip=client_ip,
                    src_port=0,
                    dst_ip=server_ip,
                    dst_port=server_port,
                    protocol=proto,
                )
            else:
                client_ip = connection_key.src_ip
                client_port = connection_key.src_port
                oriented_key = connection_key

            hostname, ip_address = self._resolve_host(client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            src_node_id = self._ensure_placeholder_process(
                hostname, asset_guid, process_statements, runs_statements
            )
            src_is_process = True

            # Classify destination
            rel_type, dst_label = self._classify_destination(oriented_key.dst_ip)
            dst_node_id = self._ensure_network_service_node(
                ip=oriented_key.dst_ip,
                port=oriented_key.dst_port,
                protocol=oriented_key.protocol,
                asset_statements=asset_statements,
                service_statements=service_statements,
                process_statements=process_statements,
                runs_statements=runs_statements,
            )

            if not src_node_id or not dst_node_id:
                continue

            # Build relationship properties
            rel_props = self._relationship_properties(oriented_key, packets)

            source_label = "Process"
            added = self._stage_connect_relationship(
                relationship_statements=relationship_statements,
                source_guid=src_node_id,
                dest_guid=dst_node_id,
                properties=rel_props,
                relationship_name=rel_type,
                source_label=source_label,
                dest_label=dst_label,
                source_ports=[client_port] if client_port > 0 else None,
            )
            if added:
                individual_relationships += 1

        staged_keys = set(self._staged_connect_edges.keys())
        existing_rel_updates = [
            statement
            for edge_key, statement in existing_rel_update_entries
            if edge_key not in staged_keys
        ]
        dropped_existing_duplicates = len(existing_rel_update_entries) - len(existing_rel_updates)
        if dropped_existing_duplicates > 0:
            logger.info(
                "Dropped %d duplicate CONNECT_TO update statements already covered by staged relationships",
                dropped_existing_duplicates,
            )

        return AugmentationArtifacts(
            asset_statements=asset_statements,
            service_statements=service_statements,
            host_statements=host_statements,
            register_statements=register_statements,
            signal_statements=signal_statements,
            process_statements=process_statements,
            runs_statements=runs_statements,
            relationship_statements=relationship_statements,
            existing_relationship_updates=existing_rel_updates,
            process_register_statements=proc_register_stmts + process_register_stmts,
            process_signal_statements=[],
            modbus_relationships=modbus_relationships,
            http_monitor_relationships=http_relationships,
            collapsed_relationships=collapsed_relationships,
            individual_relationships=individual_relationships,
            internal_relationships=internal_relationships,
            external_relationships=external_relationships,
            correlation_attempts=corr_stats.get("total_attempts", 0),
            successful_correlations=corr_stats.get("successful_correlations", 0),
            temporal_matches=0,
            process_attributed_registers=corr_stats.get("process_attributed_registers", 0),
            process_attributed_signals=0,
        )

    def run(self) -> Tuple[int, int]:
        """Execute the augmentation workflow and return (node_count, relationship_count)."""
        base_connection_ids, existing_connections = self._load_existing_connections()
        from .pcap_index import PCAPConnectionIndex  # Local import to avoid scapy dependency at module import time
        connection_index = PCAPConnectionIndex(
            self.config.pcap_directory,
            cache_path=self.config.cache_path,
            packet_limit=self.config.packet_limit,
        )
        connection_index.build(force_rebuild=self.config.force_rebuild_index)

        connections = list(connection_index.iter_connections())
        artifacts = self._build_artifacts(
            connections,
            base_connection_ids=base_connection_ids,
            existing_connections=existing_connections,
            show_progress=True,
        )

        ordered_assets = [artifacts.asset_statements[key] for key in sorted(artifacts.asset_statements)]
        ordered_services = [artifacts.service_statements[key] for key in sorted(artifacts.service_statements)]
        ordered_hosts = [artifacts.host_statements[key] for key in sorted(artifacts.host_statements)]
        ordered_registers = [artifacts.register_statements[key] for key in sorted(artifacts.register_statements)]
        ordered_signals = [artifacts.signal_statements[key] for key in sorted(artifacts.signal_statements)]
        ordered_processes = [artifacts.process_statements[key] for key in sorted(artifacts.process_statements)]
        ordered_runs = [artifacts.runs_statements[key] for key in sorted(artifacts.runs_statements)]
        all_relationships = (
            artifacts.existing_relationship_updates +
            artifacts.relationship_statements +
            artifacts.process_register_statements +
            artifacts.process_signal_statements
        )
        self._write_output(
            ordered_assets, ordered_services, ordered_hosts, ordered_registers,
            ordered_signals, ordered_processes, ordered_runs, all_relationships
        )

        # Log correlation statistics
        if artifacts.correlation_attempts > 0:
            logger.info(
                "Correlation stats: %d attempts, %d successful (%.1f%%), %d temporal matches, %d process-attributed registers",
                artifacts.correlation_attempts,
                artifacts.successful_correlations,
                100.0 * artifacts.successful_correlations / artifacts.correlation_attempts,
                artifacts.temporal_matches,
                artifacts.process_attributed_registers,
            )


        node_count = (
            len(artifacts.asset_statements)
            + len(artifacts.service_statements)
            + len(artifacts.host_statements)
            + len(artifacts.register_statements)
            + len(artifacts.signal_statements)
            + len(artifacts.process_statements)
        )
        relationship_count = len(all_relationships) + len(artifacts.runs_statements)

        # Log signal database stats and close connection
        if self._signal_db:
            stats = self._signal_db.get_statistics()
            logger.info(
                "Signal database stats: %d observations (%d reads, %d writes), %d unique registers, %d signal containers",
                stats.get("total", 0),
                stats.get("access_read", 0),
                stats.get("access_write", 0),
                stats.get("unique_registers", 0),
                stats.get("unique_signals", 0),
            )
            self._signal_db.close()

        return node_count, relationship_count

    def summarize_aggregation(self, show_progress: bool = False, fast: bool = False) -> AggregationMetrics:
        """Compute before/after node and relationship counts without writing output."""
        base_connection_ids, existing_connections = self._load_existing_connections()
        from .pcap_index import PCAPConnectionIndex  # Local import to avoid scapy dependency at module import time
        connection_index = PCAPConnectionIndex(
            self.config.pcap_directory,
            cache_path=self.config.cache_path,
            packet_limit=self.config.packet_limit,
        )
        connection_index.build(force_rebuild=self.config.force_rebuild_index)

        connections = list(connection_index.iter_connections())
        original_asset_map = self._asset_ip_map.copy()
        try:
            # Skip expensive raw graph measurement in fast mode (10-20x speedup)
            # Raw counts are only used for "before vs after" comparison metrics
            if fast:
                raw_asset_nodes = 0
                raw_service_nodes = 0
                raw_relationships = 0
            else:
                raw_asset_statements: Dict[str, str] = {}
                raw_service_statements: Dict[str, str] = {}
                raw_relationships = 0

                raw_iterable = (
                    tqdm(connections, desc="Measuring raw graph size", unit="connection")
                    if show_progress
                    else connections
                )
                for indexed in raw_iterable:
                    if indexed.canonical_id in base_connection_ids:
                        continue

                    packets = indexed.records
                    if not packets:
                        continue

                    connection_key = indexed.origin
                    if not self.config.policy.is_interesting(connection_key, packets):
                        continue

                    src_node_id = self._ensure_network_service_node(
                        ip=connection_key.src_ip,
                        port=connection_key.src_port,
                        protocol=connection_key.protocol,
                        asset_statements=raw_asset_statements,
                        service_statements=raw_service_statements,
                    )
                    dst_node_id = self._ensure_network_service_node(
                        ip=connection_key.dst_ip,
                        port=connection_key.dst_port,
                        protocol=connection_key.protocol,
                        asset_statements=raw_asset_statements,
                        service_statements=raw_service_statements,
                    )
                    if not src_node_id or not dst_node_id:
                        continue

                    raw_relationships += 1

                raw_asset_nodes = len(raw_asset_statements)
                raw_service_nodes = len(raw_service_statements)

            self._asset_ip_map = original_asset_map.copy()
            if fast:
                metrics = self._summarize_fast(
                    connections=connections,
                    base_connection_ids=base_connection_ids,
                    existing_connections=existing_connections,
                    raw_asset_nodes=raw_asset_nodes,
                    raw_service_nodes=raw_service_nodes,
                    raw_relationships=raw_relationships,
                    show_progress=show_progress,
                )
            else:
                artifacts = self._build_artifacts(
                    connections,
                    base_connection_ids=base_connection_ids,
                    existing_connections=existing_connections,
                    show_progress=show_progress,
                )

                metrics = AggregationMetrics(
                    total_connections=len(connections),
                    raw_relationships=raw_relationships,
                    raw_asset_nodes=raw_asset_nodes,
                    raw_service_nodes=raw_service_nodes,
                    aggregated_relationships=len(artifacts.relationship_statements),
                    aggregated_asset_nodes=len(artifacts.asset_statements),
                    aggregated_service_nodes=len(artifacts.service_statements),
                    aggregated_register_nodes=len(artifacts.register_statements),
                    modbus_relationships=artifacts.modbus_relationships,
                    http_monitor_relationships=artifacts.http_monitor_relationships,
                    collapsed_relationships=artifacts.collapsed_relationships,
                    individual_relationships=artifacts.individual_relationships,
                    existing_relationship_updates=len(artifacts.existing_relationship_updates),
                    correlation_attempts=artifacts.correlation_attempts,
                    successful_correlations=artifacts.successful_correlations,
                    temporal_matches=artifacts.temporal_matches,
                    process_attributed_registers=artifacts.process_attributed_registers,
                    process_attributed_signals=0,
                )
            return metrics
        finally:
            self._asset_ip_map = original_asset_map

    def _count_existing_relationship_updates(
        self,
        existing_connections: Sequence[ExistingConnection],
        indexed_connections: Sequence[IndexedConnection],
    ) -> Tuple[int, Dict[str, int]]:
        """Return how many existing relationships would receive PCAP-derived updates.

        Uses the correlation engine to count matches, returning both the count
        and correlation statistics.
        """
        empty_stats: Dict[str, int] = {
            "total_attempts": 0,
            "successful_correlations": 0,
            "temporal_matches": 0,
        }

        if not existing_connections:
            return 0, empty_stats

        # Build correlation engine with config
        correlation_config = CorrelationConfig(
            min_confidence=self.config.min_correlation_confidence,
            temporal_tolerance_seconds=self.config.temporal_tolerance_seconds,
            pcap_time_offset_seconds=self.config.pcap_time_offset_seconds,
        )
        correlation_engine = CorrelationEngine(config=correlation_config)

        # Build telemetry index with IP-to-hostname map for multi-IP host normalization
        telemetry_index = TelemetryConnectionIndex(
            existing_connections,
            ip_to_hostname=self._ip_to_hostname,
        )

        # Count unique edges that would be updated
        seen_edges: Set[Tuple[str, str]] = set()

        for pcap_conn in indexed_connections:
            correlated = correlation_engine.correlate(pcap_conn, telemetry_index)
            if correlated:
                anchor = correlated.telemetry_anchor
                edge_key = (anchor.src_guid, anchor.dst_guid)
                seen_edges.add(edge_key)

        return len(seen_edges), correlation_engine.get_statistics()

    def _summarize_fast(
        self,
        connections: Sequence[IndexedConnection],
        base_connection_ids: Set[str],
        existing_connections: Sequence[ExistingConnection],
        raw_asset_nodes: int,
        raw_service_nodes: int,
        raw_relationships: int,
        show_progress: bool = False,
    ) -> AggregationMetrics:
        """Lightweight summary that skips Cypher materialization for speed."""
        asset_guids: Set[str] = set()
        service_guids: Set[str] = set()
        register_guids: Set[str] = set()
        processed_cids: Set[str] = set()

        existing_update_count, corr_stats = self._count_existing_relationship_updates(existing_connections, connections)

        def _record_service(ip: str, port: int, protocol: str = "tcp") -> Tuple[str, str, int]:
            hostname, ip_address = self._resolve_host(ip)
            if ip_address and ip_address not in self._asset_ip_map:
                self._asset_ip_map[ip_address] = hostname
            asset_guids.add(_generate_node_guid("NetworkEndpoint", hostname))
            normalized_port = port if port and port >= 0 else 0
            service_guids.add(_generate_network_service_guid(hostname, normalized_port, protocol))
            return hostname, ip_address, normalized_port

        # Aggregate Modbus groups
        modbus_groups, modbus_consumed = group_modbus_connections(connections)
        modbus_iterable = (
            tqdm(modbus_groups, desc="Processing Modbus groups", unit="group") if show_progress else modbus_groups
        )
        modbus_relationships = 0
        for group in modbus_iterable:
            if all(cid in base_connection_ids for cid in group.canonical_ids()):
                continue
            packets = group.packets()
            if not packets:
                continue

            connection_key = ConnectionKey(
                src_ip=group.client_ip,
                src_port=0,
                dst_ip=group.server_ip,
                dst_port=group.service_port,
                protocol=group.protocol,
            )

            if not self.config.policy.is_interesting(connection_key, packets):
                continue

            _record_service(group.client_ip, group.service_port, group.protocol)
            server_hostname, server_ip, _ = _record_service(group.server_ip, group.service_port, group.protocol)

            register_summaries = self._collect_modbus_registers(packets, server_ip, group.service_port)
            for (register_address, unit_id, register_type) in register_summaries.keys():
                register_guids.add(
                    _generate_signal_guid(
                        "modbus",
                        server_hostname,
                        group.service_port,
                        unit_id,
                        register_type,
                        register_address,
                    )
                )

            processed_cids.update(group.canonical_ids())
            modbus_relationships += 1

        processed_cids.update(modbus_consumed)

        # Aggregate HTTP monitor groups
        monitor_groups, monitor_consumed = group_http_monitor_connections(connections)
        monitor_iterable = (
            tqdm(monitor_groups, desc="Processing HTTP monitor groups", unit="group") if show_progress else monitor_groups
        )
        http_relationships = 0
        for group in monitor_iterable:
            if all(cid in base_connection_ids for cid in group.canonical_ids()):
                continue

            packets = group.packets()
            if not packets:
                continue

            connection_key = ConnectionKey(
                src_ip=group.client_ip,
                src_port=0,
                dst_ip=group.server_ip,
                dst_port=group.service_port,
                protocol=group.protocol,
            )

            if not self.config.policy.is_interesting(connection_key, packets):
                continue

            _record_service(group.client_ip, group.service_port, group.protocol)
            _record_service(group.server_ip, group.service_port, group.protocol)

            processed_cids.update(group.canonical_ids())
            http_relationships += 1

        processed_cids.update(monitor_consumed)

        # MQTT connections (metadata-first) are processed as individual links.
        mqtt_relationships = 0
        mqtt_iterable = (
            tqdm(connections, desc="Processing MQTT connections", unit="connection")
            if show_progress
            else connections
        )
        for indexed in mqtt_iterable:
            if indexed.canonical_id in base_connection_ids:
                continue
            if indexed.canonical_id in processed_cids:
                continue
            if not indexed.records:
                continue
            if not self._is_mqtt_indexed_connection(indexed):
                continue

            orientation = self._orient_mqtt_connection(indexed)
            if orientation is None:
                continue
            client_ip, server_ip, service_port, protocol = orientation
            connection_key = ConnectionKey(
                src_ip=client_ip,
                src_port=0,
                dst_ip=server_ip,
                dst_port=service_port,
                protocol=protocol,
            )
            if not self.config.policy.is_interesting(connection_key, indexed.records):
                continue

            _record_service(client_ip, 0, protocol)
            server_hostname, _, _ = _record_service(server_ip, service_port, protocol)
            mqtt_signal_summaries = self._collect_mqtt_signals(
                packets=indexed.records,
                server_ip=server_ip,
                server_port=service_port,
            )
            for topic in mqtt_signal_summaries.keys():
                register_guids.add(
                    _generate_signal_guid("mqtt", server_hostname, service_port, topic)
                )
            processed_cids.add(indexed.canonical_id)
            mqtt_relationships += 1

        # OPC UA connections (metadata-first) are processed as individual links.
        opcua_relationships = 0
        opcua_iterable = (
            tqdm(connections, desc="Processing OPC UA connections", unit="connection")
            if show_progress
            else connections
        )
        for indexed in opcua_iterable:
            if indexed.canonical_id in base_connection_ids:
                continue
            if indexed.canonical_id in processed_cids:
                continue
            if not indexed.records:
                continue
            if not self._is_opcua_indexed_connection(indexed):
                continue

            orientation = self._orient_opcua_connection(indexed)
            if orientation is None:
                continue
            client_ip, server_ip, service_port, protocol = orientation
            connection_key = ConnectionKey(
                src_ip=client_ip,
                src_port=0,
                dst_ip=server_ip,
                dst_port=service_port,
                protocol=protocol,
            )
            if not self.config.policy.is_interesting(connection_key, indexed.records):
                continue

            _record_service(client_ip, 0, protocol)
            server_hostname, _, _ = _record_service(server_ip, service_port, protocol)
            opcua_signal_summaries = self._collect_opcua_signals(
                packets=indexed.records,
                server_ip=server_ip,
                server_port=service_port,
            )
            for signal_name in opcua_signal_summaries.keys():
                register_guids.add(
                    _generate_signal_guid("opcua", server_hostname, service_port, signal_name)
                )
            processed_cids.add(indexed.canonical_id)
            opcua_relationships += 1

        # Aggregate collapsed port groups
        collapse_groups, collapse_consumed = group_collapsed_connections(
            connections,
            exclude_ids=processed_cids,
            min_unique_ports=self.config.min_aggregation_threshold,
        )
        collapse_iterable = (
            tqdm(collapse_groups, desc="Processing aggregated port groups", unit="group")
            if show_progress
            else collapse_groups
        )
        collapsed_relationships = 0
        for group in collapse_iterable:
            if all(cid in base_connection_ids for cid in group.canonical_ids()):
                continue
            packets = group.packets()
            if not packets:
                continue

            connection_key = ConnectionKey(
                src_ip=group.client_ip,
                src_port=0,
                dst_ip=group.server_ip,
                dst_port=group.service_port,
                protocol=group.protocol,
            )

            if not self.config.policy.is_interesting(connection_key, packets):
                continue

            _record_service(group.client_ip, 0, group.protocol)
            _record_service(group.server_ip, group.service_port, group.protocol)

            processed_cids.update(group.canonical_ids())
            collapsed_relationships += 1

        processed_cids.update(collapse_consumed)

        # Individual connections
        connection_iterable = (
            tqdm(connections, desc="Processing individual connections", unit="connection")
            if show_progress
            else connections
        )
        individual_relationships = mqtt_relationships + opcua_relationships
        for indexed in connection_iterable:
            if indexed.canonical_id in base_connection_ids:
                continue
            if indexed.canonical_id in processed_cids:
                continue
            # Asset-IP scope filter: skip connections where neither IP is a known asset
            if self._asset_ips and indexed.origin.src_ip not in self._asset_ips and indexed.origin.dst_ip not in self._asset_ips:
                continue

            packets = indexed.records
            if not packets:
                continue

            connection_key = indexed.origin
            if not self.config.policy.is_interesting(connection_key, packets):
                continue

            _record_service(connection_key.src_ip, connection_key.src_port, connection_key.protocol)
            _record_service(connection_key.dst_ip, connection_key.dst_port, connection_key.protocol)
            individual_relationships += 1

        aggregated_relationships = (
            modbus_relationships + http_relationships + collapsed_relationships + individual_relationships
        )

        return AggregationMetrics(
            total_connections=len(connections),
            raw_relationships=raw_relationships,
            raw_asset_nodes=raw_asset_nodes,
            raw_service_nodes=raw_service_nodes,
            aggregated_relationships=aggregated_relationships,
            aggregated_asset_nodes=len(asset_guids),
            aggregated_service_nodes=len(service_guids),
            aggregated_register_nodes=len(register_guids),
            modbus_relationships=modbus_relationships,
            http_monitor_relationships=http_relationships,
            collapsed_relationships=collapsed_relationships,
            individual_relationships=individual_relationships,
            existing_relationship_updates=existing_update_count,
            correlation_attempts=corr_stats.get("total_attempts", 0),
            successful_correlations=corr_stats.get("successful_correlations", 0),
            temporal_matches=corr_stats.get("temporal_matches", 0),
        )

    def _load_existing_connections(self) -> Tuple[Set[str], List[ExistingConnection]]:
        asset_file = self.config.asset_file
        if asset_file and not asset_file.is_absolute():
            # First try relative to CWD, then fall back to relative to cypher dir
            cwd_candidate = Path.cwd() / asset_file
            if cwd_candidate.exists():
                asset_file = cwd_candidate.resolve()
            else:
                asset_file = (self.config.base_cypher.parent / asset_file).resolve()
        if asset_file is None:
            # Auto-discover: try CWD first, then cypher directory
            cwd_candidate = Path.cwd() / "assets.yaml"
            cypher_candidate = self.config.base_cypher.parent / "assets.yaml"
            if cwd_candidate.exists():
                asset_file = cwd_candidate
            elif cypher_candidate.exists():
                asset_file = cypher_candidate

        if asset_file:
            logger.info("Using asset file for hostname/IP resolution: %s", asset_file)
        else:
            logger.warning("No assets.yaml found - hostname-to-IP resolution may be incomplete")

        relationship_types = ["CONNECT_TO"]
        extractor = CypherConnectionExtractor(
            self.config.base_cypher,
            relationship_types=relationship_types,
            asset_file=asset_file,
        )
        connections = extractor.load_connections()

        # Store the IP-to-hostname map for multi-IP host normalization
        # This enables matching PCAP traffic (inner layer IPs) to telemetry (outer layer IPs)
        self._ip_to_hostname = extractor.ip_to_hostname_map
        logger.debug(
            "Loaded IP-to-hostname map with %d entries for multi-IP host normalization",
            len(self._ip_to_hostname),
        )

        # Build asset-IP set for scope filtering
        self._asset_ips: Set[str] = set(self._asset_ip_map.keys()) | set(self.config.ip_hostname_map.keys())

        target_rels = {self.config.relationship_name.upper()}
        filtered = [conn for conn in connections if conn.rel_type in target_rels]
        return {conn.key.bidirectional_id() for conn in filtered}, filtered

    def _load_asset_lookup(self) -> Dict[str, str]:
        """Parse the base Cypher export to map IP addresses to hostnames."""
        lookup: Dict[str, str] = {}
        path = Path(self.config.base_cypher)
        if not path.exists():
            return lookup

        text = path.read_text(encoding="utf-8")
        cursor = 0
        token = ":NetworkEndpoint"
        while True:
            idx = text.find(token, cursor)
            if idx == -1:
                break
            brace_start = text.find("{", idx)
            if brace_start == -1:
                break
            block, brace_end = _consume_brace_block(text, brace_start)
            if brace_end == -1:
                break
            properties = _parse_property_block(block)
            hostname = str(properties.get("hostname") or "")
            ip_addresses = properties.get("ipAddresses") or properties.get("ip_addresses")
            if isinstance(ip_addresses, list):
                for ip in ip_addresses:
                    ip_address = str(ip or "").strip()
                    if hostname and ip_address:
                        lookup[ip_address] = hostname
            else:
                ip_address = str(properties.get("ipAddress") or "")
                if hostname and ip_address:
                    lookup[ip_address] = hostname
            cursor = brace_end + 1
        return lookup

    def _load_asset_metadata(self) -> None:
        """Load extended asset metadata from assets.yaml for PLC/RTU detection."""
        import yaml

        # Find assets.yaml file (always attempt to load)
        asset_file = self.config.asset_file
        candidates = []
        if asset_file:
            candidates.append(Path(asset_file))
        candidates.append(Path(self.config.base_cypher).parent / "assets.yaml")
        candidates.append(Path.cwd() / "assets.yaml")

        asset_path = next((p for p in candidates if p.exists()), None)
        if not asset_path:
            return

        try:
            with asset_path.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception as exc:
            logger.debug("Failed to load asset metadata from %s: %s", asset_path, exc)
            return

        hosts = data.get("hosts", {}) if isinstance(data, dict) else {}
        for hostname, details in hosts.items():
            if not isinstance(details, dict):
                continue

            # Collect all IP addresses for this host
            ip_addresses: List[str] = []
            ip_list = details.get("ip_addresses")
            if isinstance(ip_list, list):
                for ip in ip_list:
                    ip_str = str(ip or "").strip()
                    if ip_str:
                        ip_addresses.append(ip_str)
            else:
                # Fallback to single ip_address
                ip = details.get("ip_address") or details.get("ip")
                ip_str = str(ip or "").strip()
                if ip_str:
                    ip_addresses.append(ip_str)

            role = str(details.get("role") or "")
            is_managed = bool(details.get("is_managed", details.get("has_logs", True)))

            metadata = AssetMetadata(
                hostname=hostname,
                ip_addresses=ip_addresses,
                role=role,
                has_logs=is_managed,
            )
            self._asset_metadata[hostname] = metadata

            # Map all IPs to this hostname
            for ip in ip_addresses:
                self._ip_to_hostname[ip] = hostname

        logger.debug(
            "Loaded asset metadata for %d hosts (%d IPs mapped)",
            len(self._asset_metadata),
            len(self._ip_to_hostname),
        )

    def _is_plc_or_rtu(self, ip: str) -> bool:
        """Check if IP belongs to a PLC/RTU without logs."""
        hostname = self._ip_to_hostname.get(ip) or self._resolve_host(ip)[0]
        metadata = self._asset_metadata.get(hostname)
        return metadata.is_plc_or_rtu if metadata else False

    def _ensure_placeholder_process(
        self,
        hostname: str,
        asset_guid: str,
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
    ) -> Optional[str]:
        """Create/return placeholder Process node for PLC/RTU.

        Creates a single Virtual Process node per device (not per protocol).
        Also creates the RUN_ON relationship from Process to NetworkEndpoint.
        """
        if hostname not in self._known_hostnames:
            return None
        # Skip runtime for managed hosts that have Sysmon/log telemetry
        metadata = self._asset_metadata.get(hostname)
        if metadata and metadata.has_logs:
            return None
        if hostname in self._placeholder_processes:
            return self._placeholder_processes[hostname]

        process_guid = f"runtime://{hostname}"

        if process_guid not in process_statements:
            props = {
                "guid": process_guid,
                "image": f"{hostname} Runtime",
                "processName": f"{hostname} Runtime",
                "type": "Virtual Process",
                "computer": hostname,
                "host": hostname,
                "source": "pcap",
                "note": f"Placeholder process for {hostname} (no host telemetry available)",
            }
            process_statements[process_guid] = cypher_emit.create_virtual_process_statement(
                process_guid, props
            )

            # Create RUN_ON relationship
            runs_key = f"{asset_guid}|{process_guid}"
            if runs_key not in runs_statements:
                runs_statements[runs_key] = cypher_emit.create_runs_relationship_statement(
                    asset_guid, process_guid
                )

        self._placeholder_processes[hostname] = process_guid
        return process_guid

    def _augment_existing_relationships(
        self,
        existing_connections: Sequence[ExistingConnection],
        indexed_connections: Sequence[IndexedConnection],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        register_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
    ) -> Tuple[List[Tuple[Tuple[str, str, str], str]], List[str], Set[str], Dict[str, int], Optional["TelemetryConnectionIndex"]]:
        """Build Cypher statements that enrich existing CONNECT_TO edges.

        Uses the CorrelationEngine for deterministic session-port correlation.
        Returns:
            - relationship_updates: keyed SET statements for existing edges
            - process_register_statements: READ/WRITE register edges for process attribution
            - correlated_canonical_ids: set of PCAP canonical IDs that were successfully correlated
            - correlation_stats: statistics about the correlation process
            - telemetry_index: TelemetryConnectionIndex for process lookup (reusable)
        """
        empty_stats: Dict[str, int] = {
            "total_attempts": 0,
            "successful_correlations": 0,
            "process_attributed_registers": 0,
        }

        if not existing_connections:
            return [], [], set(), empty_stats, None

        # Build correlation engine with config
        correlation_config = CorrelationConfig(
            min_confidence=self.config.min_correlation_confidence,
            temporal_tolerance_seconds=self.config.temporal_tolerance_seconds,
            pcap_time_offset_seconds=self.config.pcap_time_offset_seconds,
        )
        correlation_engine = CorrelationEngine(config=correlation_config)

        # Build telemetry index with IP-to-hostname map for multi-IP host normalization
        telemetry_index = TelemetryConnectionIndex(
            existing_connections,
            ip_to_hostname=self._ip_to_hostname,
        )
        logger.info(
            "Built telemetry index with %d anchors for correlation (IP-to-hostname: %d entries)",
            telemetry_index.anchor_count,
            len(self._ip_to_hostname),
        )

        # Log session metadata coverage for diagnostics
        has_session_ports = sum(
            1 for ec in existing_connections
            if ec.properties.get("sessionPorts")
        )
        has_network_meta = sum(
            1 for ec in existing_connections
            if ec.properties.get("SourceIp") or ec.properties.get("DestinationIp")
        )
        logger.info(
            "Session metadata coverage: %d/%d connections have sessionPorts, "
            "%d/%d have network IPs",
            has_session_ports, len(existing_connections),
            has_network_meta, len(existing_connections),
        )

        # Correlate PCAP connections to telemetry anchors
        correlations: Dict[str, CorrelatedConnection] = {}
        for pcap_conn in indexed_connections:
            # Asset-IP scope filter: skip connections where neither IP is a known asset
            if self._asset_ips and pcap_conn.origin.src_ip not in self._asset_ips and pcap_conn.origin.dst_ip not in self._asset_ips:
                continue
            correlated = correlation_engine.correlate(pcap_conn, telemetry_index)
            if correlated:
                correlations[pcap_conn.canonical_id] = correlated

        correlation_stats = correlation_engine.get_statistics()
        logger.info(
            "Correlation complete: %d/%d PCAP connections matched to telemetry (%.1f%%)",
            correlation_stats["successful_correlations"],
            correlation_stats["total_attempts"],
            100.0 * correlation_stats["successful_correlations"] / max(1, correlation_stats["total_attempts"]),
        )

        # Generate relationship update statements
        statement_entries: List[Tuple[Tuple[str, str, str], str]] = []
        process_register_statements: List[str] = []
        seen_edges: Set[Tuple[str, str, str]] = set()
        process_attributed_registers = 0

        # Group correlations by telemetry anchor (edge)
        anchor_correlations: Dict[Tuple[str, str, str], List[CorrelatedConnection]] = {}
        for correlated in correlations.values():
            anchor = correlated.telemetry_anchor
            rel_type = (anchor.rel_type or self.config.relationship_name).upper()
            edge_key = (anchor.src_guid, anchor.dst_guid, rel_type)
            if edge_key not in anchor_correlations:
                anchor_correlations[edge_key] = []
            anchor_correlations[edge_key].append(correlated)

        # Process each unique telemetry edge
        for edge_key, edge_correlations in anchor_correlations.items():
            src_guid, dst_guid, anchor_rel_type = edge_key
            if not src_guid or not dst_guid:
                continue
            if edge_key in seen_edges:
                continue

            # Combine all packets from correlated PCAP connections
            all_packets: List[PacketRecord] = []
            best_confidence = 0.0
            representative_anchor: Optional[CorrelatedConnection] = None

            for corr in edge_correlations:
                all_packets.extend(corr.packets)
                if corr.confidence > best_confidence:
                    best_confidence = corr.confidence
                    representative_anchor = corr

            if not all_packets or representative_anchor is None:
                continue

            anchor = representative_anchor.telemetry_anchor
            base_key = anchor.connection_key
            proto = base_key.protocol.lower()

            # Determine source port from PCAP if telemetry doesn't have it
            if base_key.src_port > 0:
                src_port = base_key.src_port
            elif all_packets:
                # Use most common source port from PCAP
                port_counts: Dict[int, int] = {}
                for pkt in all_packets:
                    if pkt.src_ip == base_key.src_ip:
                        port_counts[pkt.src_port] = port_counts.get(pkt.src_port, 0) + 1
                    elif pkt.dst_ip == base_key.src_ip:
                        port_counts[pkt.dst_port] = port_counts.get(pkt.dst_port, 0) + 1
                src_port = max(port_counts, key=port_counts.get) if port_counts else 0
            else:
                src_port = 0

            connection_view = ConnectionKey(
                src_ip=base_key.src_ip,
                src_port=src_port,
                dst_ip=base_key.dst_ip,
                dst_port=base_key.dst_port,
                protocol=proto,
            )

            feature_props = self._relationship_properties(connection_view, all_packets)

            feature_props["correlatedPcapConnections"] = len(edge_correlations)

            proc_ctx = representative_anchor.process_context

            # Fill in missing network properties from telemetry
            if not anchor.rel_properties.get("SourceIp"):
                feature_props["SourceIp"] = base_key.src_ip
            if base_key.src_port > 0 and not anchor.rel_properties.get("SourcePort"):
                feature_props["SourcePort"] = base_key.src_port
            if not anchor.rel_properties.get("DestinationIp"):
                feature_props["DestinationIp"] = base_key.dst_ip
            if not anchor.rel_properties.get("DestinationPort"):
                feature_props["DestinationPort"] = base_key.dst_port
            if not anchor.rel_properties.get("Protocol"):
                feature_props["Protocol"] = proto

            feature_props["pcapAugmented"] = True
            feature_props["inferredFrom"] = "pcap"
            feature_props["note"] = _CORRELATED_EDGE_NOTE

            cypher_props = cypher_emit.format_properties(feature_props)
            src_label = anchor.src_label or "Process"
            dst_label = anchor.dst_label or "NetworkService"
            src_guid_escaped = cypher_emit.escape_cypher_string(src_guid)
            dst_guid_escaped = cypher_emit.escape_cypher_string(dst_guid)
            statement = (
                f"MATCH (src:{src_label} {{guid: '{src_guid_escaped}'}})\n"
                f"MATCH (dst:{dst_label} {{guid: '{dst_guid_escaped}'}})\n"
                f"MATCH (src)-[rel:{anchor_rel_type}]->(dst)\n"
                f"SET rel += {cypher_props}\n"
                f"SET rel.pcapAugmented = true"
            )

            statement_entries.append((edge_key, statement))
            seen_edges.add(edge_key)

            # Generate process-to-register attribution if enabled and Modbus traffic
            if (
                self.config.enable_process_attribution
                and proc_ctx.is_valid()
                and base_key.dst_port == 502  # Modbus port
            ):
                # Optional: persist raw observations to DuckDB without graph nodes
                if self._signal_db:
                    self._collect_modbus_signals(
                        packets=all_packets,
                        client_ip=base_key.src_ip,
                        server_ip=base_key.dst_ip,
                        server_port=base_key.dst_port,
                    )

                server_hostname, _ = self._resolve_host(base_key.dst_ip)
                server_asset_guid = self._ensure_asset_node(server_hostname, base_key.dst_ip, asset_statements)
                server_service_guid = self._ensure_network_service_node(
                    ip=base_key.dst_ip,
                    port=base_key.dst_port,
                    protocol=proto,
                    asset_statements=asset_statements,
                    service_statements=service_statements,
                    process_statements=process_statements,
                    runs_statements=runs_statements,
                    service_name="Modbus Server",
                    aggregation="modbus",
                )

                register_summaries = self._collect_modbus_registers(
                    packets=all_packets,
                    server_ip=base_key.dst_ip,
                    server_port=base_key.dst_port,
                )

                for (address, unit_id, register_type), summary in register_summaries.items():
                    self._ensure_register_node(
                        host=server_hostname,
                        port=base_key.dst_port,
                        asset_guid=server_asset_guid,
                        register_address=address,
                        unit_id=unit_id,
                        register_type=register_type,
                        register_statements=register_statements,
                        register_summary=summary,
                    )

                if register_summaries:
                    register_stmts, register_count = self._generate_process_register_access(
                        process_context=proc_ctx,
                        register_summaries=register_summaries,
                        server_hostname=server_hostname,
                        server_port=base_key.dst_port,
                        correlation_confidence=best_confidence,
                    )
                    process_register_statements.extend(register_stmts)
                    process_attributed_registers += register_count

            # Generate process-to-signal attribution for telemetry-correlated MQTT traffic
            if (
                self.config.enable_process_attribution
                and proc_ctx.is_valid()
                and base_key.dst_port in MQTT_PORTS
            ):
                server_hostname, _ = self._resolve_host(base_key.dst_ip)
                server_asset_guid = self._ensure_asset_node(server_hostname, base_key.dst_ip, asset_statements)
                mqtt_signal_summaries = self._collect_mqtt_signals(
                    packets=all_packets,
                    server_ip=base_key.dst_ip,
                    server_port=base_key.dst_port,
                )
                for topic, summary in mqtt_signal_summaries.items():
                    signal_guid = self._ensure_ics_signal_node(
                        protocol="mqtt",
                        host=server_hostname,
                        port=base_key.dst_port,
                        asset_guid=server_asset_guid,
                        signal_name=topic,
                        register_statements=register_statements,
                        signal_properties={
                            "signalKind": "topic",
                            "mqttTopic": topic,
                            "registerType": "topic",
                            **summary,
                        },
                    )
                    process_register_statements.extend(
                        self._build_process_signal_statements(
                            process_guid=proc_ctx.process_guid,
                            signal_guid=signal_guid,
                            summary=summary,
                            correlation_confidence=best_confidence,
                            process_image=proc_ctx.process_image,
                            process_id=proc_ctx.process_id,
                        )
                    )

            # Generate process-to-signal attribution for telemetry-correlated OPC UA traffic
            if (
                self.config.enable_process_attribution
                and proc_ctx.is_valid()
                and base_key.dst_port in OPCUA_PORTS
            ):
                server_hostname, _ = self._resolve_host(base_key.dst_ip)
                server_asset_guid = self._ensure_asset_node(server_hostname, base_key.dst_ip, asset_statements)
                opcua_signal_summaries = self._collect_opcua_signals(
                    packets=all_packets,
                    server_ip=base_key.dst_ip,
                    server_port=base_key.dst_port,
                )
                for signal_name, summary in opcua_signal_summaries.items():
                    identity_kind = str(summary.get("opcuaIdentityKind") or "nodeid")
                    signal_props: Dict[str, object] = {
                        "signalKind": "tag" if identity_kind == "nodeid" else "channel",
                        **summary,
                    }
                    signal_props.setdefault("opcuaTag", signal_name)
                    signal_props["name"] = signal_props["opcuaTag"]
                    if identity_kind != "nodeid":
                        signal_props["opcuaPseudoTag"] = True
                    signal_guid = self._ensure_ics_signal_node(
                        protocol="opcua",
                        host=server_hostname,
                        port=base_key.dst_port,
                        asset_guid=server_asset_guid,
                        signal_name=signal_name,
                        register_statements=register_statements,
                        signal_properties=signal_props,
                    )
                    process_register_statements.extend(
                        self._build_process_signal_statements(
                            process_guid=proc_ctx.process_guid,
                            signal_guid=signal_guid,
                            summary=summary,
                            correlation_confidence=best_confidence,
                            process_image=proc_ctx.process_image,
                            process_id=proc_ctx.process_id,
                        )
                    )

        correlation_stats["process_attributed_registers"] = process_attributed_registers
        # Return the set of canonical IDs that were successfully correlated
        correlated_cids = set(correlations.keys())
        return statement_entries, process_register_statements, correlated_cids, correlation_stats, telemetry_index

    def _generate_process_register_access(
        self,
        process_context: "ProcessContext",
        register_summaries: Dict[Tuple[int, Optional[int], str], Dict[str, object]],
        server_hostname: str,
        server_port: int,
        correlation_confidence: float,
    ) -> Tuple[List[str], int]:
        """Generate READ/WRITE signal relationship statements for process attribution."""
        from .correlation import ProcessContext  # Import for type hint

        statements: List[str] = []
        edge_count = 0
        if not register_summaries:
            return [], 0
        proc_guid_escaped = cypher_emit.escape_cypher_string(process_context.process_guid)

        for (register_address, unit_id, register_type), summary in register_summaries.items():
            register_guid = _generate_signal_guid(
                "modbus", server_hostname, server_port, unit_id, register_type, register_address
            )
            register_guid_escaped = cypher_emit.escape_cypher_string(register_guid)

            read_count = int(summary.get("readCount") or 0)
            write_count = int(summary.get("writeCount") or 0)

            common_props = {
                "correlationConfidence": round(correlation_confidence, 4),
                "inferredFrom": "pcap",
                "pcapAugmented": True,
                "processImage": process_context.process_image,
                "processId": process_context.process_id,
            }

            if read_count > 0:
                read_props = {
                    **common_props,
                    "readCount": read_count,
                }
                if "lastSeenAt" in summary:
                    read_props["lastSeenAt"] = summary["lastSeenAt"]
                cypher_props = cypher_emit.format_properties(read_props)
                statements.append(
                    f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
                    f"MATCH (reg:ICSSignal {{guid: '{register_guid_escaped}'}})\n"
                    f"MERGE (proc)-[acc:READ_SIGNAL]->(reg)\n"
                    f"SET acc += {cypher_props}\n"
                    f"SET acc.pcapAugmented = true"
                )
                edge_count += 1

            if write_count > 0:
                write_props = {
                    **common_props,
                    "writeCount": write_count,
                }
                if "lastWriteAt" in summary:
                    write_props["lastWriteAt"] = summary["lastWriteAt"]
                cypher_props = cypher_emit.format_properties(write_props)
                statements.append(
                    f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
                    f"MATCH (reg:ICSSignal {{guid: '{register_guid_escaped}'}})\n"
                    f"MERGE (proc)-[acc:WRITE_SIGNAL]->(reg)\n"
                    f"SET acc += {cypher_props}\n"
                    f"SET acc.pcapAugmented = true"
                )
                edge_count += 1

        return statements, edge_count

    def _generate_process_signal_access(
        self,
        process_context: "ProcessContext",
        signal_data_map: Dict[Tuple[int, Optional[int]], SignalContainerData],
        signal_guids: Dict[Tuple[int, Optional[int]], str],
        correlation_confidence: float,
    ) -> Tuple[List[str], int]:
        """Generate ACCESSED_SIGNAL relationship statements for process attribution.

        Links the process that initiated the connection to the SignalContainer nodes
        it accessed, enabling queries like "which process wrote to signal address 40001?".

        Args:
            process_context: Process information from telemetry correlation.
            signal_data_map: Map of (address, unit_id) -> SignalContainerData for client signals.
            signal_guids: Map of (address, unit_id) -> signal GUID for client signals.
            correlation_confidence: Confidence score from telemetry correlation.

        Returns:
            Tuple of (list of Cypher statements, count of signals attributed).
        """
        from .correlation import ProcessContext  # Import for type hint

        statements: List[str] = []
        signal_count = 0

        if not signal_data_map or not signal_guids:
            return [], 0

        for key, signal_data in signal_data_map.items():
            signal_guid = signal_guids.get(key)
            if not signal_guid:
                continue

            # Compute access type from signal observations
            # For now, we assume all Modbus traffic from client is read-oriented
            # unless we detect write operations
            total_samples = signal_data.total_observations

            access_props = {
                "accessType": "read",  # Default; could be enhanced with write detection
                "sampleCount": total_samples,
                "correlationConfidence": round(correlation_confidence, 4),
                "pcapAugmented": True,
                "processImage": process_context.process_image,
                "processId": process_context.process_id,
            }

            # Add read/write counts if available
            if signal_data.read_count > 0:
                access_props["readCount"] = signal_data.read_count
            if signal_data.write_count > 0:
                access_props["writeCount"] = signal_data.write_count

            statement = cypher_emit.create_accessed_signal_statement(
                process_guid=process_context.process_guid,
                signal_guid=signal_guid,
                properties=access_props,
            )

            statements.append(statement)
            signal_count += 1

        return statements, signal_count

    def _resolve_host(self, ip: str) -> Tuple[str, str]:
        """Return (hostname, ip_address) using config overrides."""
        hostname = self._asset_ip_map.get(ip)
        if hostname:
            return hostname, ip
        hostname = self.config.ip_hostname_map.get(ip)
        if hostname:
            return hostname, ip
        return ip, ip

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname, or return IP if unknown."""
        return self._asset_ip_map.get(ip, self.config.ip_hostname_map.get(ip, ip))

    def _is_known_host(self, ip: str) -> bool:
        """Return True if the IP is a known asset in the inventory."""
        return ip in self._asset_ip_map or ip in self.config.ip_hostname_map

    def _classify_destination(self, dst_ip: str) -> Tuple[str, str]:
        """Classify a destination and return (relationship_type, destination_node_label).

        For unified CONNECT_TO, always use NetworkService:
        """
        return (self.config.relationship_name, "NetworkService")

    def _ensure_host_node(
        self,
        ip: str,
        host_statements: Dict[str, str],
    ) -> str:
        """Ensure an external NetworkEndpoint MERGE statement exists."""
        guid = _generate_node_guid("NetworkEndpoint", ip)
        if guid not in host_statements:
            props = {
                "guid": guid,
                "hostname": ip,
                "ipAddress": ip,
                "source": "pcap",
                "isExternal": True,
                "isManaged": False,
                "zone": "Internet",
            }
            host_statements[guid] = cypher_emit.create_host_statement(guid, props)
        return guid

    def _ensure_asset_node(
        self,
        hostname: str,
        ip_address: str,
        asset_statements: Dict[str, str],
    ) -> str:
        """Ensure a NetworkEndpoint MERGE statement exists for the given host."""
        guid = _generate_node_guid("NetworkEndpoint", hostname)
        known = self._is_known_host(ip_address)
        if ip_address and ip_address not in self._asset_ip_map:
            self._asset_ip_map[ip_address] = hostname
        if guid not in asset_statements:
            props = {
                "guid": guid,
                "hostname": hostname,
                "ipAddress": ip_address,
                "ipAddresses": [ip_address] if ip_address else [],
                "isExternal": not known,
                "isManaged": known,
                "source": "pcap",
            }
            asset_statements[guid] = cypher_emit.create_asset_statement(guid, props)
        return guid

    def _ensure_network_service_node(
        self,
        ip: str,
        port: int,
        protocol: str,
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        process_statements: Optional[Dict[str, str]] = None,
        runs_statements: Optional[Dict[str, str]] = None,
        service_name: Optional[str] = None,
        aggregation: Optional[str] = None,
        note: Optional[str] = None,
    ) -> str:
        """Ensure a NetworkService MERGE statement exists and return its guid."""
        hostname, ip_address = self._resolve_host(ip)
        asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
        normalized_port = port if port and port >= 0 else 0
        normalized_protocol = _normalize_transport_protocol(protocol)
        service_guid = _generate_network_service_guid(hostname, normalized_port, normalized_protocol)

        if service_guid not in service_statements:
            props: Dict[str, object] = {
                "guid": service_guid,
                "host": hostname,
                "port": normalized_port,
                "protocol": normalized_protocol.upper(),
                "serviceName": service_name or self._service_name_for_port(normalized_port),
                "ipAddress": ip_address,
                "source": "pcap",
            }
            if aggregation:
                props["aggregation"] = aggregation
            if note:
                props["note"] = note

            service_statements[service_guid] = cypher_emit.create_network_service_statement(
                service_guid,
                props,
                asset_guid,
            )

        # For inferred services, ensure placeholder process ownership is present.
        if process_statements is not None and runs_statements is not None:
            owner_process_guid = self._ensure_placeholder_process(
                hostname,
                asset_guid,
                process_statements,
                runs_statements,
            )
            if owner_process_guid is not None:
                binds_key = f"{owner_process_guid}|{service_guid}|BINDS"
                if binds_key not in runs_statements:
                    runs_statements[binds_key] = cypher_emit.create_binds_relationship_statement(
                        owner_process_guid,
                        service_guid,
                    )

        return service_guid

    def _service_name_for_port(self, port: int) -> str:
        if port <= 0:
            return "Ephemeral Service"
        return self.config.service_map.get(port, f"Port {port}")

    def _relationship_properties(
        self,
        connection: ConnectionKey,
        packets: Sequence[PacketRecord],
    ) -> Dict[str, object]:
        # Pre-sort once to avoid redundant sorting in each feature function
        sorted_packets = PreSortedPackets.from_packets(packets)
        timestamps = [pkt.timestamp for pkt in sorted_packets]
        bytes_out, bytes_in, _, _ = directional_totals(connection, sorted_packets)
        dir_index = directionality_ratio(bytes_out, bytes_in)
        inter_arrival = mean_interarrival_time(sorted_packets)
        retransmits = count_tcp_retransmits(sorted_packets)
        src_mac, dst_mac = resolve_mac_addresses(connection, sorted_packets)
        http_features = extract_http_features(sorted_packets)
        mqtt_features = extract_mqtt_features(sorted_packets)
        opcua_features = extract_opcua_features(sorted_packets)
        tls_sni = extract_tls_sni(sorted_packets)
        rtt_ms = mean_rtt_ms(connection, sorted_packets)
        return {
            "SourceIp": connection.src_ip,
            "SourcePort": connection.src_port,
            "DestinationIp": connection.dst_ip,
            "DestinationPort": connection.dst_port,
            "Protocol": connection.protocol.lower(),
            "inferredFrom": "pcap",
            "pcapAugmented": True,
            "note": "Observed in PCAP but missing from host telemetry",
            "packetCount": len(sorted_packets),
            "durationSeconds": duration_seconds(sorted_packets),
            "avgPacketSize": round(average_packet_size(sorted_packets), 2),
            "highLevelProtocol": dominant_protocol(sorted_packets),
            "firstSeen": min(timestamps) if timestamps else None,
            "lastSeen": max(timestamps) if timestamps else None,
            "srcMac": src_mac or None,
            "dstMac": dst_mac or None,
            "bytesOut": bytes_out,
            "bytesIn": bytes_in,
            "directionalityIndex": round(dir_index, 6) if dir_index is not None else None,
            "meanInterArrivalPacketTime": round(inter_arrival, 6),
            "retransmits": retransmits,
            "tlsSNI": tls_sni or None,
            "httpMethod": http_features.get("method"),
            "httpStatus": http_features.get("status"),
            "httpContent": http_features.get("content"),
            "mqttPacketTypes": mqtt_features.get("packetTypes"),
            "mqttTopics": mqtt_features.get("topics"),
            "mqttClientIds": mqtt_features.get("clientIds"),
            "mqttQosLevels": mqtt_features.get("qosLevels"),
            "mqttPublishCount": mqtt_features.get("publishCount"),
            "mqttSubscribeCount": mqtt_features.get("subscribeCount"),
            "mqttRetainSeen": mqtt_features.get("retainSeen"),
            "opcuaMessageTypes": opcua_features.get("messageTypes"),
            "opcuaChunkTypes": opcua_features.get("chunkTypes"),
            "opcuaEndpointUrls": opcua_features.get("endpointUrls"),
            "opcuaSecurityPolicies": opcua_features.get("securityPolicies"),
            "opcuaSecureChannelIds": opcua_features.get("secureChannelIds"),
            "opcuaOpenCount": opcua_features.get("openCount"),
            "opcuaMsgCount": opcua_features.get("msgCount"),
            "opcuaCloseCount": opcua_features.get("closeCount"),
            "rttMs": round(rtt_ms, 3) if rtt_ms > 0.0 else None,
        }

    @staticmethod
    def _as_number(value: object) -> Optional[float]:
        """Convert scalar numeric-like values to float."""
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            return None

    def _combined_bytes(self, properties: Dict[str, object]) -> Optional[int]:
        """Return total observed bytes from directional counters when present."""
        total = 0
        seen = False
        for key in ("bytesOut", "bytesIn"):
            value = self._as_number(properties.get(key))
            if value is None:
                continue
            total += int(value)
            seen = True
        return total if seen else None

    def _extract_source_ports_from_properties(self, properties: Dict[str, object]) -> Set[int]:
        """Extract observed source ports from relationship properties."""
        ports: Set[int] = set()

        source_port = properties.get("SourcePort")
        source_port_num = self._as_number(source_port)
        if source_port_num is not None and int(source_port_num) > 0:
            ports.add(int(source_port_num))

        source_port_set = properties.get("sourcePortSet")
        if isinstance(source_port_set, str):
            for candidate in source_port_set.split(","):
                candidate = candidate.strip()
                if not candidate:
                    continue
                num = self._as_number(candidate)
                if num is not None and int(num) > 0:
                    ports.add(int(num))

        return ports

    def _extract_protocol_values(self, properties: Dict[str, object]) -> Set[str]:
        """Extract normalized transport protocols from relationship properties."""
        protocols: Set[str] = set()
        protocol = str(properties.get("Protocol") or "").strip().lower()
        if protocol and protocol != "mixed":
            protocols.add(protocol)

        protocol_set = properties.get("protocolSet")
        if isinstance(protocol_set, str):
            for candidate in protocol_set.split(","):
                normalized = candidate.strip().lower()
                if normalized and normalized != "mixed":
                    protocols.add(normalized)

        return protocols

    def _merge_connect_properties(
        self,
        existing: Dict[str, object],
        incoming: Dict[str, object],
    ) -> Dict[str, object]:
        """Merge duplicate CONNECT_TO payloads deterministically."""
        merged = dict(existing)
        sum_fields = {
            "packetCount",
            "bytesIn",
            "bytesOut",
            "canonicalCount",
        }
        min_fields = {"firstSeen"}
        max_fields = {"lastSeen"}
        or_boolean_fields = {"telemetryCorrelated", "correlatedFromTelemetry"}

        for key, value in incoming.items():
            if value is None:
                continue

            if key in sum_fields:
                old_num = self._as_number(merged.get(key))
                new_num = self._as_number(value)
                if old_num is None and new_num is None:
                    continue
                if old_num is None:
                    merged[key] = int(new_num) if new_num is not None else value
                elif new_num is None:
                    continue
                else:
                    merged[key] = int(old_num + new_num)
                continue

            if key in min_fields:
                old_num = self._as_number(merged.get(key))
                new_num = self._as_number(value)
                if old_num is None:
                    merged[key] = value
                elif new_num is None:
                    continue
                else:
                    merged[key] = min(old_num, new_num)
                continue

            if key in max_fields:
                old_num = self._as_number(merged.get(key))
                new_num = self._as_number(value)
                if old_num is None:
                    merged[key] = value
                elif new_num is None:
                    continue
                else:
                    merged[key] = max(old_num, new_num)
                continue

            if key in or_boolean_fields:
                merged[key] = bool(merged.get(key)) or bool(value)
                continue

            merged[key] = value

        return merged

    def _normalize_staged_connect_edge(self, edge: _StagedConnectEdge) -> None:
        """Normalize merged edge properties into a coherent aggregate payload."""
        props = edge.properties

        if edge.source_ports:
            sorted_ports = sorted(edge.source_ports)
            props["uniqueSourcePorts"] = len(sorted_ports)
            props["sourcePortMin"] = sorted_ports[0]
            props["sourcePortMax"] = sorted_ports[-1]
            if len(sorted_ports) == 1:
                props["SourcePort"] = sorted_ports[0]
                props.pop("sourcePortSet", None)
            else:
                props["SourcePort"] = "aggregated"
                if len(sorted_ports) <= 8:
                    props["sourcePortSet"] = ",".join(str(port) for port in sorted_ports)
                else:
                    props.pop("sourcePortSet", None)

        if edge.protocol_values:
            protocols = sorted(edge.protocol_values)
            if len(protocols) == 1:
                props["Protocol"] = protocols[0]
                props.pop("protocolSet", None)
            else:
                props["Protocol"] = "mixed"
                props["protocolSet"] = ",".join(protocols)

        first_seen = self._as_number(props.get("firstSeen"))
        last_seen = self._as_number(props.get("lastSeen"))
        if first_seen is not None and last_seen is not None and last_seen >= first_seen:
            props["durationSeconds"] = last_seen - first_seen

        total_bytes_value = self._combined_bytes(props)
        packet_count_value = self._as_number(props.get("packetCount"))
        if (
            total_bytes_value is not None
            and packet_count_value is not None
            and packet_count_value > 0
        ):
            props["avgPacketSize"] = round(total_bytes_value / packet_count_value, 2)

        canonical_count = self._as_number(props.get("canonicalCount"))
        if (
            total_bytes_value is not None
            and canonical_count is not None
            and canonical_count > 0
        ):
            props["meanBytesPerConnection"] = round(total_bytes_value / canonical_count, 2)

        bytes_out_value = self._as_number(props.get("bytesOut"))
        bytes_in_value = self._as_number(props.get("bytesIn"))
        if bytes_out_value is not None and bytes_in_value is not None:
            ratio = directionality_ratio(int(bytes_out_value), int(bytes_in_value))
            props["directionalityIndex"] = round(ratio, 6) if ratio is not None else None

        props["pcapAugmented"] = True

    def _stage_connect_relationship(
        self,
        *,
        relationship_statements: List[str],
        source_guid: str,
        dest_guid: str,
        properties: Dict[str, object],
        relationship_name: str = "CONNECT_TO",
        source_label: str = "Process",
        dest_label: str = "NetworkService",
        source_ports: Optional[Sequence[int]] = None,
    ) -> bool:
        """Stage and merge CONNECT_TO statements so each process/service pair is emitted once."""
        key = (source_guid, dest_guid, relationship_name)
        incoming_properties = {name: value for name, value in properties.items() if value is not None}

        observed_ports: Set[int] = set()
        if source_ports:
            for port in source_ports:
                numeric = self._as_number(port)
                if numeric is not None and int(numeric) > 0:
                    observed_ports.add(int(numeric))
        if not observed_ports:
            observed_ports.update(self._extract_source_ports_from_properties(incoming_properties))

        observed_protocols = self._extract_protocol_values(incoming_properties)

        staged = self._staged_connect_edges.get(key)
        if staged is None:
            staged = _StagedConnectEdge(
                source_guid=source_guid,
                dest_guid=dest_guid,
                relationship_name=relationship_name,
                source_label=source_label,
                dest_label=dest_label,
                properties=incoming_properties,
                statement_index=len(relationship_statements),
            )
            staged.source_ports.update(observed_ports)
            staged.protocol_values.update(observed_protocols)
            self._normalize_staged_connect_edge(staged)
            relationship_statements.append(
                cypher_emit.create_connection_statement(
                    staged.source_guid,
                    staged.dest_guid,
                    staged.properties,
                    relationship_name=staged.relationship_name,
                    source_label=staged.source_label,
                    dest_label=staged.dest_label,
                )
            )
            self._staged_connect_edges[key] = staged
            return True

        staged.source_ports.update(observed_ports)
        staged.protocol_values.update(observed_protocols)
        staged.properties = self._merge_connect_properties(staged.properties, incoming_properties)
        self._normalize_staged_connect_edge(staged)
        relationship_statements[staged.statement_index] = cypher_emit.create_connection_statement(
            staged.source_guid,
            staged.dest_guid,
            staged.properties,
            relationship_name=staged.relationship_name,
            source_label=staged.source_label,
            dest_label=staged.dest_label,
        )
        return False

    def _is_mqtt_indexed_connection(self, connection: IndexedConnection) -> bool:
        """Return True if this connection appears to carry MQTT traffic."""
        return protocol_utils.is_mqtt_connection(connection.origin, connection.records)

    def _orient_mqtt_connection(
        self,
        connection: IndexedConnection,
    ) -> Optional[Tuple[str, str, int, str]]:
        """Orient MQTT traffic as (client_ip, server_ip, service_port, protocol)."""
        return protocol_utils.orient_mqtt_connection(connection.origin, connection.records)

    def _add_mqtt_connection(
        self,
        *,
        client_ip: str,
        server_ip: str,
        service_port: int,
        protocol: str,
        packets: Sequence[PacketRecord],
        canonical_count: int,
        group_source_ports: Sequence[int],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        host_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
        register_statements: Dict[str, str],
        relationship_statements: List[str],
        process_register_statements: List[str],
        telemetry_index: Optional[TelemetryConnectionIndex] = None,
    ) -> str:
        """Add MQTT connection artifacts and return the relationship type."""
        service_name = self.config.service_map.get(service_port, "MQTT")

        client_node_id: Optional[str] = None
        client_is_process = False
        correlation_confidence = 0.5
        process_image: Optional[str] = None
        process_id: Optional[int] = None

        source_ports = sorted({int(port) for port in group_source_ports if int(port) > 0})

        if telemetry_index is not None:
            process_context = self._find_telemetry_process_context(
                telemetry_index=telemetry_index,
                client_ip=client_ip,
                server_ip=server_ip,
                service_port=service_port,
                protocol=protocol,
                source_ports=source_ports,
            )
            if process_context and process_context.is_valid():
                client_node_id = process_context.process_guid
                client_is_process = True
                correlation_confidence = 1.0
                process_image = process_context.process_image
                process_id = process_context.process_id

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname,
                asset_guid,
                process_statements,
                runs_statements,
            )
            client_is_process = True

        if client_node_id is None:
            return self.config.relationship_name

        rel_type, dst_label = self._classify_destination(server_ip)
        server_node_id = self._ensure_network_service_node(
            ip=server_ip,
            port=service_port,
            protocol=protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            process_statements=process_statements,
            runs_statements=runs_statements,
            service_name=service_name,
            aggregation="mqtt",
            note="MQTT server inferred from PCAP traffic",
        )

        server_hostname, server_ip_address = self._resolve_host(server_ip)
        server_asset_guid = self._ensure_asset_node(
            server_hostname,
            server_ip_address,
            asset_statements,
        )
        mqtt_signal_summaries = self._collect_mqtt_signals(
            packets=packets,
            server_ip=server_ip,
            server_port=service_port,
        )
        for topic, summary in mqtt_signal_summaries.items():
            signal_guid = self._ensure_ics_signal_node(
                protocol="mqtt",
                host=server_hostname,
                port=service_port,
                asset_guid=server_asset_guid,
                signal_name=topic,
                register_statements=register_statements,
                signal_properties={
                    "signalKind": "topic",
                    "mqttTopic": topic,
                    "registerType": "topic",
                    **summary,
                },
            )
            if client_is_process and client_node_id:
                process_register_statements.extend(
                    self._build_process_signal_statements(
                        process_guid=client_node_id,
                        signal_guid=signal_guid,
                        summary=summary,
                        correlation_confidence=correlation_confidence,
                        process_image=process_image,
                        process_id=process_id,
                    )
                )

        connection_key = ConnectionKey(
            src_ip=client_ip,
            src_port=0,
            dst_ip=server_ip,
            dst_port=service_port,
            protocol=protocol,
        )
        relationship_properties = self._relationship_properties(connection_key, packets)
        relationship_properties.update(
            {
                "aggregated": "mqtt",
                "canonicalCount": max(1, int(canonical_count)),
            }
        )
        if source_ports:
            relationship_properties["uniqueSourcePorts"] = len(source_ports)
            relationship_properties["sourcePortMin"] = source_ports[0]
            relationship_properties["sourcePortMax"] = source_ports[-1]
            if len(source_ports) == 1:
                relationship_properties["SourcePort"] = source_ports[0]
            else:
                relationship_properties["SourcePort"] = "aggregated"
                if len(source_ports) <= 8:
                    relationship_properties["sourcePortSet"] = ",".join(str(port) for port in source_ports)
        else:
            relationship_properties["SourcePort"] = "aggregated"

        if client_is_process and process_image:
            if correlation_confidence >= 1.0:
                relationship_properties["telemetryCorrelated"] = True
                relationship_properties["note"] = (
                    f"MQTT traffic correlated to process {process_image} "
                    f"(PID {process_id}) via Sysmon telemetry"
                )

        source_label = "Process"
        self._stage_connect_relationship(
            relationship_statements=relationship_statements,
            source_guid=client_node_id,
            dest_guid=server_node_id,
            properties=relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
            source_ports=source_ports,
        )
        return rel_type

    def _is_opcua_indexed_connection(self, connection: IndexedConnection) -> bool:
        """Return True if this connection appears to carry OPC UA traffic."""
        return protocol_utils.is_opcua_connection(connection.origin, connection.records)

    def _orient_opcua_connection(
        self,
        connection: IndexedConnection,
    ) -> Optional[Tuple[str, str, int, str]]:
        """Orient OPC UA traffic as (client_ip, server_ip, service_port, protocol)."""
        return protocol_utils.orient_opcua_connection(connection.origin, connection.records)

    def _add_opcua_connection(
        self,
        *,
        client_ip: str,
        server_ip: str,
        service_port: int,
        protocol: str,
        packets: Sequence[PacketRecord],
        canonical_count: int,
        group_source_ports: Sequence[int],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        host_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
        register_statements: Dict[str, str],
        relationship_statements: List[str],
        process_register_statements: List[str],
        telemetry_index: Optional[TelemetryConnectionIndex] = None,
    ) -> str:
        """Add OPC UA connection artifacts and return the relationship type."""
        service_name = self.config.service_map.get(service_port, "OPC UA")

        client_node_id: Optional[str] = None
        client_is_process = False
        correlation_confidence = 0.5
        process_image: Optional[str] = None
        process_id: Optional[int] = None

        source_ports = sorted({int(port) for port in group_source_ports if int(port) > 0})

        if telemetry_index is not None:
            process_context = self._find_telemetry_process_context(
                telemetry_index=telemetry_index,
                client_ip=client_ip,
                server_ip=server_ip,
                service_port=service_port,
                protocol=protocol,
                source_ports=source_ports,
            )
            if process_context and process_context.is_valid():
                client_node_id = process_context.process_guid
                client_is_process = True
                correlation_confidence = 1.0
                process_image = process_context.process_image
                process_id = process_context.process_id

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname,
                asset_guid,
                process_statements,
                runs_statements,
            )
            client_is_process = True

        if client_node_id is None:
            return self.config.relationship_name

        rel_type, dst_label = self._classify_destination(server_ip)
        server_node_id = self._ensure_network_service_node(
            ip=server_ip,
            port=service_port,
            protocol=protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            process_statements=process_statements,
            runs_statements=runs_statements,
            service_name=service_name,
            aggregation="opcua",
            note="OPC UA server inferred from PCAP traffic",
        )

        server_hostname, server_ip_address = self._resolve_host(server_ip)
        server_asset_guid = self._ensure_asset_node(
            server_hostname,
            server_ip_address,
            asset_statements,
        )
        opcua_signal_summaries = self._collect_opcua_signals(
            packets=packets,
            server_ip=server_ip,
            server_port=service_port,
        )
        for signal_name, summary in opcua_signal_summaries.items():
            identity_kind = str(summary.get("opcuaIdentityKind") or "nodeid")
            signal_props: Dict[str, object] = {
                "signalKind": "tag" if identity_kind == "nodeid" else "channel",
                **summary,
            }
            signal_props.setdefault("opcuaTag", signal_name)
            signal_props["name"] = signal_props["opcuaTag"]
            if identity_kind != "nodeid":
                signal_props["opcuaPseudoTag"] = True
            signal_guid = self._ensure_ics_signal_node(
                protocol="opcua",
                host=server_hostname,
                port=service_port,
                asset_guid=server_asset_guid,
                signal_name=signal_name,
                register_statements=register_statements,
                signal_properties=signal_props,
            )
            if client_is_process and client_node_id:
                process_register_statements.extend(
                    self._build_process_signal_statements(
                        process_guid=client_node_id,
                        signal_guid=signal_guid,
                        summary=summary,
                        correlation_confidence=correlation_confidence,
                        process_image=process_image,
                        process_id=process_id,
                    )
                )

        connection_key = ConnectionKey(
            src_ip=client_ip,
            src_port=0,
            dst_ip=server_ip,
            dst_port=service_port,
            protocol=protocol,
        )
        relationship_properties = self._relationship_properties(connection_key, packets)
        relationship_properties.update(
            {
                "aggregated": "opcua",
                "canonicalCount": max(1, int(canonical_count)),
            }
        )
        if source_ports:
            relationship_properties["uniqueSourcePorts"] = len(source_ports)
            relationship_properties["sourcePortMin"] = source_ports[0]
            relationship_properties["sourcePortMax"] = source_ports[-1]
            if len(source_ports) == 1:
                relationship_properties["SourcePort"] = source_ports[0]
            else:
                relationship_properties["SourcePort"] = "aggregated"
                if len(source_ports) <= 8:
                    relationship_properties["sourcePortSet"] = ",".join(str(port) for port in source_ports)
        else:
            relationship_properties["SourcePort"] = "aggregated"

        if client_is_process and process_image:
            if correlation_confidence >= 1.0:
                relationship_properties["telemetryCorrelated"] = True
                relationship_properties["note"] = (
                    f"OPC UA traffic correlated to process {process_image} "
                    f"(PID {process_id}) via Sysmon telemetry"
                )

        source_label = "Process"
        self._stage_connect_relationship(
            relationship_statements=relationship_statements,
            source_guid=client_node_id,
            dest_guid=server_node_id,
            properties=relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
            source_ports=source_ports,
        )
        return rel_type

    def _collect_modbus_registers(
        self,
        packets: Sequence[PacketRecord],
        server_ip: str,
        server_port: int,
    ) -> Dict[Tuple[int, Optional[int], str], Dict[str, object]]:
        """Return per-register summaries derived from Modbus traffic."""
        register_stats: Dict[Tuple[int, Optional[int], str], _RegisterAccumulator] = {}
        pending: Dict[Tuple[str, int, str, Optional[int], int], _PendingModbusRequest] = {}

        def _normalize_register_type(register_type: Optional[str]) -> str:
            return register_type or "unknown"

        def _get_acc(address: int, unit_id: Optional[int], register_type: str) -> _RegisterAccumulator:
            key = (address, unit_id, register_type)
            if key not in register_stats:
                register_stats[key] = _RegisterAccumulator(
                    address=address,
                    unit_id=unit_id,
                    register_type=register_type,
                )
            return register_stats[key]

        def _ensure_register_hints(
            addresses: Sequence[int],
            unit_id: Optional[int],
            timestamp: float,
            function_code: Optional[int],
            register_type: Optional[str],
        ) -> None:
            normalized_type = _normalize_register_type(register_type)
            for address in addresses:
                if address is None or address < 0:
                    continue
                acc = _get_acc(address, unit_id, normalized_type)
                acc.apply_type_hint(register_type)
                acc.mark_seen(timestamp, function_code)

        for packet in packets:
            if packet.modbus_function is None:
                continue
            if packet.dst_ip != server_ip and packet.src_ip != server_ip:
                continue
            function_code = packet.modbus_function
            register_type = _register_type_from_function(function_code)
            normalized_type = _normalize_register_type(register_type)
            unit_id = packet.modbus_unit_id
            read_registers = packet.modbus_read_registers or ()
            write_registers = packet.modbus_write_registers or ()
            if not read_registers and not write_registers and packet.modbus_registers:
                read_registers = packet.modbus_registers

            if packet.dst_port == server_port:
                key = _modbus_transaction_key(packet, server_port)
                if key is not None:
                    pending[key] = _PendingModbusRequest(
                        timestamp=packet.timestamp,
                        unit_id=unit_id,
                        function_code=function_code,
                        read_registers=read_registers,
                        write_registers=write_registers,
                    )
                _ensure_register_hints(read_registers, unit_id, packet.timestamp, function_code, register_type)
                _ensure_register_hints(write_registers, unit_id, packet.timestamp, function_code, register_type)
                if write_registers and packet.modbus_register_values:
                    for address, value in zip(write_registers, packet.modbus_register_values):
                        if address is None or address < 0:
                            continue
                        acc = _get_acc(address, unit_id, normalized_type)
                        acc.buffer_observe(
                            value=value,
                            timestamp=packet.timestamp,
                            function_code=function_code,
                            role="write",
                            register_type=register_type,
                        )
                continue

            if packet.src_port != server_port:
                continue

            key = _modbus_transaction_key(packet, server_port)
            request = pending.pop(key, None)
            response_values = tuple(packet.modbus_register_values or ())

            if request:
                req_type = _register_type_from_function(request.function_code)
                normalized_req_type = _normalize_register_type(req_type)
                read_addresses = request.read_registers
                if read_addresses and response_values:
                    trimmed_values = response_values[: len(read_addresses)]
                    for address, value in zip(read_addresses, trimmed_values):
                        if address is None or address < 0:
                            continue
                        acc = _get_acc(address, request.unit_id, normalized_req_type)
                        acc.buffer_observe(
                            value=value,
                            timestamp=packet.timestamp,
                            function_code=request.function_code,
                            role="read",
                            register_type=req_type,
                        )
                elif read_addresses:
                    _ensure_register_hints(read_addresses, request.unit_id, packet.timestamp, request.function_code, req_type)

                if request.write_registers and response_values:
                    trimmed_values = response_values[: len(request.write_registers)]
                    for address, value in zip(request.write_registers, trimmed_values):
                        if address is None or address < 0:
                            continue
                        acc = _get_acc(address, request.unit_id, normalized_req_type)
                        acc.buffer_observe(
                            value=value,
                            timestamp=packet.timestamp,
                            function_code=request.function_code,
                            role="write",
                            register_type=req_type,
                        )
                elif request.write_registers:
                    _ensure_register_hints(request.write_registers, request.unit_id, packet.timestamp, request.function_code, req_type)
                continue

            fallback_registers = packet.modbus_write_registers or packet.modbus_registers or ()
            if fallback_registers and response_values:
                fallback_type = _register_type_from_function(function_code)
                normalized_fallback_type = _normalize_register_type(fallback_type)
                trimmed_values = response_values[: len(fallback_registers)]
                for address, value in zip(fallback_registers, trimmed_values):
                    if address is None or address < 0:
                        continue
                    acc = _get_acc(address, unit_id, normalized_fallback_type)
                    acc.buffer_observe(
                        value=value,
                        timestamp=packet.timestamp,
                        function_code=function_code,
                        role="write",
                        register_type=fallback_type,
                    )
            elif fallback_registers:
                _ensure_register_hints(fallback_registers, unit_id, packet.timestamp, function_code, register_type)

        return {key: acc.to_properties() for key, acc in register_stats.items()}

    def _collect_modbus_signals(
        self,
        packets: Sequence[PacketRecord],
        client_ip: str,
        server_ip: str,
        server_port: int,
    ) -> Dict[str, Dict[Tuple[int, Optional[int]], SignalContainerData]]:
        """Collect signal observations for BOTH endpoints, storing raw data in DuckDB.

        For reads: Only store when request+response are matched (need both for address→value).
        For writes: Store immediately from request, update write_acknowledged when response arrives.

        Args:
            packets: Sequence of packet records from the connection.
            client_ip: IP address of the Modbus client.
            server_ip: IP address of the Modbus server.
            server_port: Modbus service port (typically 502).

        Returns:
            Dict mapping observer role ('client' or 'server') to a dict of
            (address, unit_id) -> SignalContainerData (lightweight metadata).
        """
        # Resolve hostnames for observers
        client_hostname, _ = self._resolve_host(client_ip)
        server_hostname, _ = self._resolve_host(server_ip)

        # Track signal metadata for reference nodes (lightweight)
        client_signals: Dict[Tuple[int, Optional[int]], SignalContainerData] = {}
        server_signals: Dict[Tuple[int, Optional[int]], SignalContainerData] = {}

        # Pending requests for transaction matching
        pending: Dict[Tuple[str, int, str, Optional[int], int], _PendingModbusRequest] = {}

        # Pending write transaction IDs that need acknowledgment updates
        pending_write_txids: Dict[int, float] = {}  # transaction_id -> request_timestamp

        # Collect observations for batch insert - use incremental batching for memory efficiency
        observations_to_insert: List[tuple] = []
        total_observations_inserted = 0
        BATCH_SIZE = 100_000  # Flush every 100K observations

        def _flush_observations() -> int:
            """Flush accumulated observations to DuckDB."""
            nonlocal observations_to_insert, total_observations_inserted
            if not observations_to_insert:
                return 0
            count = len(observations_to_insert)
            self._signal_db.insert_tuples_fast(observations_to_insert)
            total_observations_inserted += count
            observations_to_insert = []
            return count

        # Get pcap file name from first packet
        pcap_file = packets[0].pcap_file if packets else "unknown"

        def _get_or_create_signal_data(
            address: int,
            unit_id: Optional[int],
            observer: str,
            register_type: Optional[str],
        ) -> SignalContainerData:
            """Get or create lightweight signal metadata."""
            key = (address, unit_id)
            hostname = client_hostname if observer == "client" else server_hostname
            target_dict = client_signals if observer == "client" else server_signals

            if key not in target_dict:
                target_dict[key] = SignalContainerData(
                    address=address,
                    unit_id=unit_id,
                    observer_host=hostname,
                    port=server_port,
                    modbus_register_type=register_type,
                )
            elif register_type and not target_dict[key].modbus_register_type:
                target_dict[key].modbus_register_type = register_type
            return target_dict[key]

        def _record_observation(
            address: int,
            unit_id: Optional[int],
            value: int,
            timestamp: float,
            access_type: str,
            function_code: int,
            transaction_id: Optional[int],
            request_timestamp: Optional[float],
            response_timestamp: Optional[float],
            write_acknowledged: Optional[bool],
            register_type: Optional[str],
        ) -> None:
            """Record observation and update metadata."""
            # Update metadata for both endpoints
            for observer in ["client", "server"]:
                signal_data = _get_or_create_signal_data(address, unit_id, observer, register_type)
                signal_data.total_observations += 1
                if access_type == "read":
                    signal_data.read_count += 1
                else:
                    signal_data.write_count += 1
                if signal_data.first_seen_at is None or timestamp < signal_data.first_seen_at:
                    signal_data.first_seen_at = timestamp
                if signal_data.last_seen_at is None or timestamp > signal_data.last_seen_at:
                    signal_data.last_seen_at = timestamp

            # Generate ICSSignal GUID matching the graph builder's recipe
            # (see _ensure_modbus_ics_signal_node — same module). Falls back to
            # the SignalContainer GUID when keys are missing so downstream code
            # that joins on the column still has *some* identifier.
            reg_type_for_guid = _register_type_from_function(function_code)
            if server_hostname and unit_id is not None and reg_type_for_guid:
                signal_guid = _generate_signal_guid(
                    "modbus", server_hostname, server_port,
                    unit_id, reg_type_for_guid, address,
                )
            else:
                signal_guid = _generate_node_guid(
                    "SignalContainer", client_hostname, address, unit_id
                )

            # Create observation tuple for DuckDB (if signal_db is enabled)
            # Order must match OBSERVATION_COLUMNS in signal_db.py
            if self._signal_db:
                observations_to_insert.append((
                    timestamp,           # timestamp
                    address,             # register_address
                    value,               # value
                    access_type,         # access_type
                    function_code,       # function_code
                    unit_id,             # unit_id
                    client_hostname,     # client_host
                    server_hostname,     # server_host
                    client_ip,           # client_ip
                    server_ip,           # server_ip
                    transaction_id,      # transaction_id
                    request_timestamp,   # request_timestamp
                    response_timestamp,  # response_timestamp
                    write_acknowledged,  # write_acknowledged
                    signal_guid,         # signal_container_guid
                    pcap_file,           # pcap_file
                ))
                # Incremental flush to avoid memory buildup
                if len(observations_to_insert) >= BATCH_SIZE:
                    _flush_observations()

        for packet in packets:
            if packet.modbus_function is None:
                continue
            if packet.dst_ip != server_ip and packet.src_ip != server_ip:
                continue

            function_code = packet.modbus_function
            register_type = _register_type_from_function(function_code)
            unit_id = packet.modbus_unit_id
            read_registers = packet.modbus_read_registers or ()
            write_registers = packet.modbus_write_registers or ()
            if not read_registers and not write_registers and packet.modbus_registers:
                read_registers = packet.modbus_registers

            transaction_id = packet.modbus_transaction_id

            # Request packet (client -> server)
            if packet.dst_port == server_port:
                key = _modbus_transaction_key(packet, server_port)
                if key is not None:
                    pending[key] = _PendingModbusRequest(
                        timestamp=packet.timestamp,
                        unit_id=unit_id,
                        function_code=function_code,
                        read_registers=read_registers,
                        write_registers=write_registers,
                    )

                # For WRITES: Store immediately from request (don't wait for response)
                if write_registers and packet.modbus_register_values:
                    for address, value in zip(write_registers, packet.modbus_register_values):
                        if address is None or address < 0:
                            continue
                        _record_observation(
                            address=address,
                            unit_id=unit_id,
                            value=value,
                            timestamp=packet.timestamp,
                            access_type="write",
                            function_code=function_code,
                            transaction_id=transaction_id,
                            request_timestamp=packet.timestamp,
                            response_timestamp=None,  # Not yet acknowledged
                            write_acknowledged=None,  # Pending
                            register_type=register_type,
                        )
                    # Track for acknowledgment update
                    if transaction_id is not None:
                        pending_write_txids[transaction_id] = packet.timestamp
                continue

            # Response packet (server -> client)
            if packet.src_port != server_port:
                continue

            key = _modbus_transaction_key(packet, server_port)
            request = pending.pop(key, None)
            response_values = tuple(packet.modbus_register_values or ())

            if request:
                req_type = _register_type_from_function(request.function_code)

                # READ response: Now we have both addresses and values - store observation
                if request.read_registers and response_values:
                    trimmed_values = response_values[:len(request.read_registers)]
                    for address, value in zip(request.read_registers, trimmed_values):
                        if address is None or address < 0:
                            continue
                        _record_observation(
                            address=address,
                            unit_id=request.unit_id,
                            value=value,
                            timestamp=packet.timestamp,
                            access_type="read",
                            function_code=request.function_code,
                            transaction_id=transaction_id,
                            request_timestamp=request.timestamp,
                            response_timestamp=packet.timestamp,
                            write_acknowledged=None,  # N/A for reads
                            register_type=req_type,
                        )

                # WRITE response: Update acknowledgment status
                # (We already stored the write from the request, now mark as acknowledged)
                if request.write_registers and transaction_id is not None:
                    if transaction_id in pending_write_txids:
                        del pending_write_txids[transaction_id]
                        # Update in DuckDB if enabled
                        if self._signal_db:
                            self._signal_db.update_write_acknowledgment(
                                client_ip=client_ip,
                                server_ip=server_ip,
                                transaction_id=transaction_id,
                                response_timestamp=packet.timestamp,
                                acknowledged=True,
                            )
                continue

            # Fallback for unmatched responses (orphans)
            # For reads without matched request, we don't know register addresses - skip
            # For writes, values were already stored from request

        # Flush any remaining observations to DuckDB
        if self._signal_db:
            _flush_observations()
            if total_observations_inserted > 0:
                logger.debug(
                    "Fast-inserted %d total signal observations to DuckDB for %s -> %s",
                    total_observations_inserted, client_hostname, server_hostname,
                )

        # Return lightweight metadata for Neo4j reference nodes
        return {
            "client": client_signals,
            "server": server_signals,
        }

    def _ensure_signal_container_node(
        self,
        observer_host: str,
        port: int,
        service_guid: str,
        signal_data: SignalContainerData,
        signal_statements: Dict[str, str],
    ) -> str:
        """Ensure a SignalContainer node exists in the output.

        Args:
            observer_host: Hostname of the observing device.
            port: Service port where signal was observed.
            service_guid: GUID of the NetworkService that observed the signal.
            signal_data: Lightweight signal metadata (actual data in DuckDB).
            signal_statements: Dict to store generated Cypher statements.

        Returns:
            The generated signal GUID.
        """
        signal_guid = _generate_node_guid(
            "SignalContainer",
            observer_host,
            signal_data.address,
            signal_data.unit_id,
        )

        if signal_guid in signal_statements:
            return signal_guid

        props = signal_data.to_properties()
        props["guid"] = signal_guid
        props["source"] = "pcap"

        # Add reference to DuckDB if signal database is configured
        if self.config.signal_db_path:
            props["signalDbPath"] = str(self.config.signal_db_path)

        signal_statements[signal_guid] = cypher_emit.create_signal_container_statement(
            signal_guid=signal_guid,
            properties=props,
            service_guid=service_guid,
        )

        return signal_guid

    def _ensure_ics_signal_node(
        self,
        *,
        protocol: str,
        host: str,
        port: int,
        asset_guid: str,
        signal_name: str,
        register_statements: Dict[str, str],
        signal_properties: Optional[Dict[str, object]] = None,
    ) -> str:
        """Ensure an ICSSignal node and ownership edge exist in output."""
        return protocol_utils.ensure_ics_signal_node(
            protocol=protocol,
            host=host,
            port=port,
            asset_guid=asset_guid,
            signal_name=signal_name,
            register_statements=register_statements,
            signal_properties=signal_properties,
        )

    def _build_process_signal_statements(
        self,
        *,
        process_guid: str,
        signal_guid: str,
        summary: Dict[str, object],
        correlation_confidence: float,
        process_image: Optional[str] = None,
        process_id: Optional[int] = None,
    ) -> List[str]:
        """Build READ_SIGNAL / WRITE_SIGNAL statements for one process+signal pair."""
        return protocol_utils.build_process_signal_statements(
            process_guid=process_guid,
            signal_guid=signal_guid,
            summary=summary,
            correlation_confidence=correlation_confidence,
            process_image=process_image,
            process_id=process_id,
        )

    def _collect_mqtt_signals(
        self,
        *,
        packets: Sequence[PacketRecord],
        server_ip: str,
        server_port: int,
    ) -> Dict[str, Dict[str, object]]:
        """Collect per-field MQTT summaries suitable for ICSSignal properties."""
        return protocol_utils.collect_mqtt_signals(
            packets=packets, server_ip=server_ip, server_port=server_port,
        )

    def _collect_opcua_signals(
        self,
        *,
        packets: Sequence[PacketRecord],
        server_ip: str,
        server_port: int,
    ) -> Dict[str, Dict[str, object]]:
        """Collect per-signal OPC UA summaries for ICSSignal nodes."""
        return protocol_utils.collect_opcua_signals(
            packets=packets, server_ip=server_ip, server_port=server_port,
        )

    def _ensure_register_node(
        self,
        host: str,
        port: int,
        asset_guid: str,
        register_address: int,
        unit_id: Optional[int],
        register_type: str,
        register_statements: Dict[str, str],
        register_summary: Optional[Dict[str, object]] = None,
    ) -> None:
        """Ensure a Modbus ICSSignal node and ownership edges exist in output."""
        if not asset_guid:
            return
        signal_key = _generate_signal_key(
            "modbus",
            host,
            port,
            unit_id if unit_id is not None else "none",
            register_type,
            register_address,
        )
        register_guid = _generate_signal_guid(
            "modbus",
            host,
            port,
            unit_id,
            register_type,
            register_address,
        )
        if register_guid in register_statements:
            return
        props: Dict[str, object] = {
            "guid": register_guid,
            "signalKey": signal_key,
            "protocol": "modbus",
            "host": host,
            "address": register_address,
            "port": port,
            "source": "pcap",
            "signalKind": "register",
        }
        if unit_id is not None:
            props["unitId"] = unit_id
        props["registerType"] = register_type
        props["modbusAddress"] = register_address
        props["modbusRegisterType"] = register_type
        if unit_id is not None:
            props["modbusUnitId"] = unit_id
        if register_summary:
            props.update(register_summary)
        statement = cypher_emit.create_ics_signal_statement(
            signal_guid=register_guid,
            properties=props,
            endpoint_guid=asset_guid,
        )
        register_statements[register_guid] = statement

    def _extract_client_source_ports(
        self,
        *,
        packets: Sequence[PacketRecord],
        client_ip: str,
        server_ip: str,
        service_port: int,
    ) -> List[int]:
        """Extract client ephemeral source ports observed for a client->server flow."""
        return protocol_utils.extract_client_source_ports(
            packets=packets, client_ip=client_ip, server_ip=server_ip, service_port=service_port,
        )

    def _build_connection_stats(self, connection: IndexedConnection) -> Optional[ConnectionStats]:
        """Build lightweight per-connection stats without retaining full packet lists."""
        stats = ConnectionStats(
            canonical_id=connection.canonical_id,
            origin=connection.origin,
            origin_timestamp=connection.origin_timestamp,
        )
        for packet in connection.records:
            stats.add_packet(packet)
            if packet.timestamp < stats.origin_timestamp:
                stats.origin = packet.connection_key()
                stats.origin_timestamp = packet.timestamp
        if stats.packet_count <= 0:
            return None
        return stats

    def _merge_register_summaries(
        self,
        summary_maps: Sequence[Dict[Tuple[int, Optional[int], str], Dict[str, object]]],
    ) -> Dict[Tuple[int, Optional[int], str], Dict[str, object]]:
        """Merge per-connection register summaries into one aggregated map."""
        merged: Dict[Tuple[int, Optional[int], str], Dict[str, object]] = {}
        timeline_source_score: Dict[Tuple[int, Optional[int], str], Tuple[int, int, int, int]] = {}
        timeline_points_by_key: Dict[Tuple[int, Optional[int], str], List[Tuple[float, int]]] = {}
        timeline_tolerance_by_key: Dict[Tuple[int, Optional[int], str], List[float]] = {}

        def _to_int(props: Dict[str, object], key: str) -> int:
            value = props.get(key)
            if value in (None, ""):
                return 0
            try:
                return int(value)
            except (TypeError, ValueError):
                try:
                    return int(float(str(value)))
                except (TypeError, ValueError):
                    return 0

        def _to_float(props: Dict[str, object], key: str) -> Optional[float]:
            value = props.get(key)
            if value in (None, ""):
                return None
            try:
                return float(value)
            except (TypeError, ValueError):
                return None

        def _parse_top_values(encoded: object) -> Dict[int, int]:
            if not encoded:
                return {}
            result: Dict[int, int] = {}
            for token in str(encoded).split(","):
                if ":" not in token:
                    continue
                value_raw, count_raw = token.split(":", 1)
                try:
                    value = int(value_raw)
                    result[value] = result.get(value, 0) + int(count_raw)
                except (TypeError, ValueError):
                    continue
            return result

        def _parse_function_codes(encoded: object) -> Set[int]:
            if not encoded:
                return set()
            parsed: Set[int] = set()
            for token in str(encoded).split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    parsed.add(int(token))
                except ValueError:
                    continue
            return parsed

        def _summary_score(props: Dict[str, object]) -> Tuple[int, int, int, int]:
            return (
                _to_int(props, "timelinePoints"),
                _to_int(props, "distinctValues"),
                _to_int(props, "rleRuns"),
                _to_int(props, "valueSamples"),
            )

        def _parse_timeline(encoded: object) -> List[Tuple[float, int]]:
            if not encoded:
                return []
            text = str(encoded).strip()
            if not text.startswith("@") or "|" not in text:
                return []

            try:
                base_raw, points_raw = text[1:].split("|", 1)
                base_ts = float(base_raw)
            except (TypeError, ValueError):
                return []

            parsed: List[Tuple[float, int]] = []
            for token in points_raw.split(","):
                if ":" not in token:
                    continue
                dt_raw, value_raw = token.split(":", 1)
                try:
                    ts = base_ts + float(dt_raw)
                    value = int(float(value_raw))
                except (TypeError, ValueError):
                    continue
                parsed.append((ts, value))
            return parsed

        for summary_map in summary_maps:
            for key, incoming in summary_map.items():
                incoming_dict = dict(incoming)
                incoming_samples = _to_int(incoming_dict, "valueSamples")
                incoming_last_seen = _to_float(incoming_dict, "lastSeenAt")
                incoming_last_write = _to_float(incoming_dict, "lastWriteAt")
                incoming_tolerance = _to_float(incoming_dict, "sdtTolerance")
                parsed_timeline = _parse_timeline(incoming_dict.get("valueTimeline"))
                if parsed_timeline:
                    timeline_points_by_key.setdefault(key, []).extend(parsed_timeline)
                if incoming_tolerance is not None and incoming_tolerance > 0:
                    timeline_tolerance_by_key.setdefault(key, []).append(incoming_tolerance)

                if key not in merged:
                    merged[key] = incoming_dict
                    timeline_source_score[key] = _summary_score(incoming_dict)
                    continue

                current = merged[key]
                current_samples = _to_int(current, "valueSamples")
                current_mean = _to_float(current, "meanValue") or 0.0
                incoming_mean = _to_float(incoming_dict, "meanValue") or 0.0
                combined_samples = current_samples + incoming_samples

                for field in ("readCount", "writeCount", "valueSamples", "stateChanges"):
                    total = _to_int(current, field) + _to_int(incoming_dict, field)
                    if total > 0:
                        current[field] = total

                if combined_samples > 0:
                    weighted_mean = (
                        (current_mean * current_samples) + (incoming_mean * incoming_samples)
                    ) / combined_samples
                    current["meanValue"] = round(weighted_mean, 3)

                current_min = _to_float(current, "minValue")
                incoming_min = _to_float(incoming_dict, "minValue")
                if incoming_min is not None and (current_min is None or incoming_min < current_min):
                    current["minValue"] = int(incoming_min)

                current_max = _to_float(current, "maxValue")
                incoming_max = _to_float(incoming_dict, "maxValue")
                if incoming_max is not None and (current_max is None or incoming_max > current_max):
                    current["maxValue"] = int(incoming_max)

                current["distinctValues"] = max(
                    _to_int(current, "distinctValues"),
                    _to_int(incoming_dict, "distinctValues"),
                )

                current_last_seen = _to_float(current, "lastSeenAt")
                if incoming_last_seen is not None and (
                    current_last_seen is None or incoming_last_seen > current_last_seen
                ):
                    current["lastSeenAt"] = round(incoming_last_seen, 3)
                    if "lastValue" in incoming_dict:
                        current["lastValue"] = incoming_dict["lastValue"]
                    if "lastFunctionCode" in incoming_dict:
                        current["lastFunctionCode"] = incoming_dict["lastFunctionCode"]

                current_last_write = _to_float(current, "lastWriteAt")
                if incoming_last_write is not None and (
                    current_last_write is None or incoming_last_write > current_last_write
                ):
                    current["lastWriteAt"] = round(incoming_last_write, 3)

                current_funcs = _parse_function_codes(current.get("observedFunctions"))
                incoming_funcs = _parse_function_codes(incoming_dict.get("observedFunctions"))
                all_funcs = sorted(current_funcs | incoming_funcs)
                if all_funcs:
                    current["observedFunctions"] = ",".join(str(code) for code in all_funcs)

                top_values = _parse_top_values(current.get("topValues"))
                for value, count in _parse_top_values(incoming_dict.get("topValues")).items():
                    top_values[value] = top_values.get(value, 0) + count
                if top_values:
                    ordered = sorted(top_values.items(), key=lambda item: (-item[1], item[0]))[:4]
                    current["topValues"] = ",".join(f"{value}:{count}" for value, count in ordered)

                if current.get("rleTruncated") or incoming_dict.get("rleTruncated"):
                    current["rleTruncated"] = True

                incoming_score = _summary_score(incoming_dict)
                if incoming_score > timeline_source_score.get(key, (0, 0, 0, 0)):
                    for field in (
                        "valueRLE",
                        "rleRuns",
                        "rleCompressionRatio",
                        "rleTruncated",
                        "valueTimeline",
                        "timelinePoints",
                        "compressionRatio",
                        "sdtTolerance",
                        "sdtRecompressions",
                    ):
                        if field in incoming_dict:
                            current[field] = incoming_dict[field]
                    timeline_source_score[key] = incoming_score

        for key, summary in merged.items():
            points = timeline_points_by_key.get(key) or []
            if not points:
                continue

            points.sort(key=lambda item: item[0])
            deduped: List[Tuple[float, int]] = []
            for ts, val in points:
                if not deduped or deduped[-1] != (ts, val):
                    deduped.append((ts, val))

            tolerances = timeline_tolerance_by_key.get(key) or []
            seed_tolerance = min(tolerances) if tolerances else 1.0
            sdt = _SDTCompressor(tolerance=seed_tolerance, max_points=100)
            for ts, val in deduped:
                sdt.add(ts, val)
            timeline = sdt.encode_timeline()
            if timeline:
                summary["valueTimeline"] = timeline
                summary["timelinePoints"] = len(sdt.points)
                summary["sdtTolerance"] = sdt.tolerance
                if sdt.recompression_count > 0:
                    summary["sdtRecompressions"] = sdt.recompression_count
                elif "sdtRecompressions" in summary:
                    del summary["sdtRecompressions"]

        for summary in merged.values():
            samples = _to_int(summary, "valueSamples")
            rle_runs = _to_int(summary, "rleRuns")
            timeline_points = _to_int(summary, "timelinePoints")

            if samples > 0 and rle_runs > 0:
                summary["rleCompressionRatio"] = round(samples / rle_runs, 2)
            if samples > 0 and timeline_points > 0:
                summary["compressionRatio"] = round(samples / timeline_points, 2)

        return merged

    def _compute_modbus_group_payload(
        self,
        group: ModbusGroup,
        connection_key: ConnectionKey,
    ) -> Optional[_ModbusGroupPayload]:
        """Heavy per-group compute (packet walk + register aggregation).

        Thread-safe: only touches local data and pure self.*() helpers that do
        not mutate shared state.
        """
        policy = self.config.policy
        if (
            policy.is_broadcast_or_multicast(group.client_ip)
            or policy.is_broadcast_or_multicast(group.server_ip)
        ):
            return None
        if policy.is_outer(group.client_ip) and policy.is_outer(group.server_ip):
            return None

        group_stats: List[ConnectionStats] = []
        source_ports: Set[int] = set()
        protocol_counts: Dict[str, int] = {}
        total_packets = 0
        bytes_out = 0
        bytes_in = 0
        first_seen = float("inf")
        last_seen = 0.0
        all_function_codes: Set[int] = set()
        all_unit_ids: Set[int] = set()
        all_registers: Set[int] = set()
        total_transactions = 0
        src_mac = ""
        dst_mac = ""

        for connection in group.connections:
            stats = self._build_connection_stats(connection)
            if stats is None:
                continue
            group_stats.append(stats)
            total_packets += stats.packet_count
            if stats.first_seen < first_seen:
                first_seen = stats.first_seen
            if stats.last_seen > last_seen:
                last_seen = stats.last_seen
            all_function_codes.update(stats.modbus_function_codes)
            all_unit_ids.update(stats.modbus_unit_ids)
            all_registers.update(stats.modbus_registers_seen)
            total_transactions += stats.modbus_transaction_count

            for packet in connection.records:
                protocol_name = packet.high_level_protocol or "UNKNOWN"
                protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1
                if (
                    packet.src_ip == group.client_ip
                    and packet.dst_ip == group.server_ip
                    and packet.dst_port == group.service_port
                ):
                    bytes_out += packet.size
                    if packet.src_port > 0:
                        source_ports.add(packet.src_port)
                    if not src_mac and packet.src_mac:
                        src_mac = packet.src_mac
                    if not dst_mac and packet.dst_mac:
                        dst_mac = packet.dst_mac
                elif (
                    packet.src_ip == group.server_ip
                    and packet.dst_ip == group.client_ip
                    and packet.src_port == group.service_port
                ):
                    bytes_in += packet.size
                    if packet.dst_port > 0:
                        source_ports.add(packet.dst_port)
                    if not src_mac and packet.dst_mac:
                        src_mac = packet.dst_mac
                    if not dst_mac and packet.src_mac:
                        dst_mac = packet.src_mac

        if not group_stats or total_packets < policy.min_packet_threshold:
            return None

        register_summaries = self._merge_register_summaries(
            [stats.get_register_summaries() for stats in group_stats]
        )

        return _ModbusGroupPayload(
            connection_key=connection_key,
            source_ports=source_ports,
            protocol_counts=protocol_counts,
            total_packets=total_packets,
            bytes_out=bytes_out,
            bytes_in=bytes_in,
            first_seen=first_seen,
            last_seen=last_seen,
            all_function_codes=all_function_codes,
            all_unit_ids=all_unit_ids,
            all_registers=all_registers,
            total_transactions=total_transactions,
            src_mac=src_mac,
            dst_mac=dst_mac,
            register_summaries=register_summaries,
        )

    def _apply_modbus_group_payload(
        self,
        payload: _ModbusGroupPayload,
        group: ModbusGroup,
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        host_statements: Dict[str, str],
        register_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
        relationship_statements: List[str],
        process_register_statements: List[str],
        telemetry_index: Optional["TelemetryConnectionIndex"] = None,
    ) -> Optional[str]:
        """Stage Cypher for an already-computed Modbus group payload. Not thread-safe."""
        connection_key = payload.connection_key
        service_name = self.config.service_map.get(group.service_port, "Modbus")

        source_ports = payload.source_ports
        protocol_counts = payload.protocol_counts
        total_packets = payload.total_packets
        bytes_out = payload.bytes_out
        bytes_in = payload.bytes_in
        first_seen = payload.first_seen
        last_seen = payload.last_seen
        all_function_codes = payload.all_function_codes
        all_unit_ids = payload.all_unit_ids
        all_registers = payload.all_registers
        total_transactions = payload.total_transactions
        src_mac = payload.src_mac
        dst_mac = payload.dst_mac
        register_summaries = payload.register_summaries

        client_node_id: Optional[str] = None
        client_is_process = False
        process_context: Optional[ProcessContext] = None
        correlation_source = "pcap_only"
        correlation_confidence = 0.5
        sorted_source_ports = sorted(source_ports)

        if telemetry_index is not None:
            process_context = self._find_telemetry_process_context(
                telemetry_index=telemetry_index,
                client_ip=group.client_ip,
                server_ip=group.server_ip,
                service_port=group.service_port,
                protocol=connection_key.protocol,
                source_ports=sorted_source_ports,
            )
            if process_context and process_context.is_valid():
                client_node_id = process_context.process_guid
                client_is_process = True
                correlation_source = "telemetry"
                correlation_confidence = 1.0

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(group.client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname, asset_guid, process_statements, runs_statements
            )
            if client_node_id is None:
                return None
            client_is_process = True
            if process_context is None:
                process_context = ProcessContext(
                    process_guid=client_node_id,
                    process_image=f"{hostname} Runtime",
                    process_id=0,
                    user="",
                    computer=hostname,
                )

        rel_type, dst_label = self._classify_destination(group.server_ip)
        server_hostname, server_ip = self._resolve_host(group.server_ip)
        server_asset_guid = self._ensure_asset_node(server_hostname, server_ip, asset_statements)
        server_node_id = self._ensure_network_service_node(
            ip=group.server_ip,
            port=group.service_port,
            protocol=connection_key.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            process_statements=process_statements,
            runs_statements=runs_statements,
            service_name=service_name,
            aggregation="modbus",
            note="Aggregated Modbus server inferred from PCAP-only traffic",
        )

        if self._signal_db:
            for connection in group.connections:
                self._collect_modbus_signals(
                    packets=connection.records,
                    client_ip=group.client_ip,
                    server_ip=group.server_ip,
                    server_port=group.service_port,
                )

        for (address, unit_id, register_type), summary in register_summaries.items():
            self._ensure_register_node(
                host=server_hostname,
                port=group.service_port,
                asset_guid=server_asset_guid,
                register_address=address,
                unit_id=unit_id,
                register_type=register_type,
                register_statements=register_statements,
                register_summary=summary,
            )

        if (
            self.config.enable_process_attribution
            and client_is_process
            and process_context
            and register_summaries
        ):
            register_stmts, _ = self._generate_process_register_access(
                process_context=process_context,
                register_summaries=register_summaries,
                server_hostname=server_hostname,
                server_port=group.service_port,
                correlation_confidence=correlation_confidence,
            )
            process_register_statements.extend(register_stmts)

        dominant_protocol_name = (
            max(protocol_counts.keys(), key=lambda name: protocol_counts[name])
            if protocol_counts else "UNKNOWN"
        )
        relationship_properties: Dict[str, object] = {
            "SourceIp": group.client_ip,
            "SourcePort": "aggregated",
            "DestinationIp": group.server_ip,
            "DestinationPort": group.service_port,
            "Protocol": connection_key.protocol.lower(),
            "inferredFrom": "pcap",
            "pcapAugmented": True,
            "note": "Observed in PCAP but missing from host telemetry",
            "packetCount": total_packets,
            "bytesOut": bytes_out,
            "bytesIn": bytes_in,
            "aggregated": "modbus",
            "canonicalCount": len(group.connections),
            "uniqueSourcePorts": len(sorted_source_ports),
        }

        if first_seen != float("inf") and last_seen > 0:
            relationship_properties["firstSeen"] = first_seen
            relationship_properties["lastSeen"] = last_seen
            relationship_properties["durationSeconds"] = round(last_seen - first_seen, 6)

        total_bytes = bytes_out + bytes_in
        if total_packets > 0 and total_bytes > 0:
            relationship_properties["avgPacketSize"] = round(total_bytes / total_packets, 2)
        if total_packets > 0 and len(group.connections) > 0 and total_bytes > 0:
            relationship_properties["meanBytesPerConnection"] = round(total_bytes / len(group.connections), 2)

        dir_index = directionality_ratio(bytes_out, bytes_in)
        relationship_properties["directionalityIndex"] = round(dir_index, 6) if dir_index is not None else None

        if dominant_protocol_name != "UNKNOWN":
            relationship_properties["highLevelProtocol"] = dominant_protocol_name
        if src_mac:
            relationship_properties["srcMac"] = src_mac
        if dst_mac:
            relationship_properties["dstMac"] = dst_mac
        if all_function_codes:
            relationship_properties["modbusFunctionCodes"] = ",".join(str(fc) for fc in sorted(all_function_codes))
        if all_unit_ids:
            relationship_properties["modbusUnitIds"] = ",".join(str(uid) for uid in sorted(all_unit_ids))
        if all_registers:
            relationship_properties["modbusRegisterCount"] = len(all_registers)
        if total_transactions > 0:
            relationship_properties["modbusTransactions"] = total_transactions

        if client_is_process and process_context and correlation_source == "telemetry":
            relationship_properties["correlatedFromTelemetry"] = True
            relationship_properties["note"] = (
                f"Modbus traffic correlated to process {process_context.process_image} "
                f"(PID {process_context.process_id}) from telemetry connection"
            )

        source_label = "Process"
        self._stage_connect_relationship(
            relationship_statements=relationship_statements,
            source_guid=client_node_id,
            dest_guid=server_node_id,
            properties=relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
            source_ports=sorted_source_ports,
        )
        return rel_type

    def _find_telemetry_process_context(
        self,
        *,
        telemetry_index: Optional["TelemetryConnectionIndex"],
        client_ip: str,
        server_ip: str,
        service_port: int,
        protocol: str,
        source_ports: Sequence[int],
    ) -> Optional["ProcessContext"]:
        """Resolve process context from telemetry with deterministic source-port matching."""
        return protocol_utils.find_telemetry_process_context(
            telemetry_index=telemetry_index,
            client_ip=client_ip,
            server_ip=server_ip,
            service_port=service_port,
            protocol=protocol,
            source_ports=source_ports,
        )

    def _add_modbus_group(
        self,
        group: ModbusGroup,
        connection_key: ConnectionKey,
        packets: Sequence[PacketRecord],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        host_statements: Dict[str, str],
        register_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
        relationship_statements: List[str],
        process_register_statements: List[str],
        telemetry_index: Optional["TelemetryConnectionIndex"] = None,
    ) -> str:
        """Add a Modbus group and return the relationship type used."""
        service_name = self.config.service_map.get(group.service_port, "Modbus")

        # Try to find a Process node that matches this traffic via telemetry
        client_node_id: Optional[str] = None
        client_is_process = False
        process_context: Optional[ProcessContext] = None
        correlation_source = "pcap_only"
        correlation_confidence = 0.5
        source_ports = self._extract_client_source_ports(
            packets=packets,
            client_ip=group.client_ip,
            server_ip=group.server_ip,
            service_port=group.service_port,
        )

        # First, check if telemetry already tells us which process made this connection
        if telemetry_index is not None:
            process_context = self._find_telemetry_process_context(
                telemetry_index=telemetry_index,
                client_ip=group.client_ip,
                server_ip=group.server_ip,
                service_port=group.service_port,
                protocol=connection_key.protocol,
                source_ports=source_ports,
            )
            if process_context and process_context.is_valid():
                client_node_id = process_context.process_guid
                client_is_process = True
                correlation_source = "telemetry"
                correlation_confidence = 1.0
                logger.debug(
                    "Attributed Modbus group to Process %s (%s) from telemetry",
                    process_context.process_guid,
                    process_context.process_image,
                )

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(group.client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname, asset_guid, process_statements, runs_statements
            )
            if client_node_id is None:
                return None
            client_is_process = True
            if process_context is None:
                process_context = ProcessContext(
                    process_guid=client_node_id,
                    process_image=f"{hostname} Runtime",
                    process_id=0,
                    user="",
                    computer=hostname,
                )

        # Classify destination
        rel_type, dst_label = self._classify_destination(group.server_ip)
        server_hostname, server_ip = self._resolve_host(group.server_ip)
        server_asset_guid = self._ensure_asset_node(server_hostname, server_ip, asset_statements)
        server_node_id = self._ensure_network_service_node(
            ip=group.server_ip,
            port=group.service_port,
            protocol=connection_key.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            process_statements=process_statements,
            runs_statements=runs_statements,
            service_name=service_name,
            aggregation="modbus",
            note="Aggregated Modbus server inferred from PCAP-only traffic",
        )

        # Optional: persist raw observations to DuckDB without graph nodes
        if self._signal_db:
            self._collect_modbus_signals(
                packets=packets,
                client_ip=group.client_ip,
                server_ip=group.server_ip,
                server_port=group.service_port,
            )

        # Create Register nodes for observed Modbus addresses on the server
        register_summaries = self._collect_modbus_registers(
            packets=packets,
            server_ip=group.server_ip,
            server_port=group.service_port,
        )
        for (address, unit_id, register_type), summary in register_summaries.items():
            self._ensure_register_node(
                host=server_hostname,
                port=group.service_port,
                asset_guid=server_asset_guid,
                register_address=address,
                unit_id=unit_id,
                register_type=register_type,
                register_statements=register_statements,
                register_summary=summary,
            )

        # Generate READ/WRITE register relationships if process attribution is enabled
        if (
            self.config.enable_process_attribution
            and client_is_process
            and process_context
            and register_summaries
        ):
            register_stmts, _ = self._generate_process_register_access(
                process_context=process_context,
                register_summaries=register_summaries,
                server_hostname=server_hostname,
                server_port=group.service_port,
                correlation_confidence=correlation_confidence,
            )
            process_register_statements.extend(register_stmts)

        relationship_properties = self._relationship_properties(connection_key, packets)
        relationship_properties.update(
            {
                "SourcePort": "aggregated",
                "aggregated": "modbus",
                "canonicalCount": len(group.connections),
                "uniqueSourcePorts": len({pkt.src_port for pkt in packets}),
            }
        )
        combined_bytes = self._combined_bytes(relationship_properties)
        if group.connections and combined_bytes is not None:
            relationship_properties["meanBytesPerConnection"] = round(
                combined_bytes / len(group.connections), 2
            )

        # Add process correlation metadata
        if client_is_process and process_context:
            if correlation_source == "telemetry":
                relationship_properties["correlatedFromTelemetry"] = True
                relationship_properties["note"] = (
                    f"Modbus traffic correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) from telemetry connection"
                )

        # Use Process label if we found a matching process, otherwise NetworkService
        source_label = "Process"
        self._stage_connect_relationship(
            relationship_statements=relationship_statements,
            source_guid=client_node_id,
            dest_guid=server_node_id,
            properties=relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
            source_ports=source_ports,
        )
        return rel_type

    def _add_http_monitor_group(
        self,
        group: HTTPMonitorGroup,
        connection_key: ConnectionKey,
        packets: Sequence[PacketRecord],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        host_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
        relationship_statements: List[str],
        telemetry_index: Optional["TelemetryConnectionIndex"] = None,
    ) -> str:
        """Add an HTTP monitor group and return the relationship type used."""
        service_name = "Modbus Monitor"

        # Try to find a Process node that matches this traffic via telemetry.
        client_node_id: Optional[str] = None
        client_is_process = False
        process_context: Optional[ProcessContext] = None
        correlation_source = "pcap_only"
        source_ports = self._extract_client_source_ports(
            packets=packets,
            client_ip=group.client_ip,
            server_ip=group.server_ip,
            service_port=group.service_port,
        )

        if telemetry_index is not None:
            process_context = self._find_telemetry_process_context(
                telemetry_index=telemetry_index,
                client_ip=group.client_ip,
                server_ip=group.server_ip,
                service_port=group.service_port,
                protocol=connection_key.protocol,
                source_ports=source_ports,
            )
            if process_context and process_context.is_valid():
                client_node_id = process_context.process_guid
                client_is_process = True
                correlation_source = "telemetry"
                logger.debug(
                    "Attributed HTTP monitor group to Process %s (%s) from telemetry",
                    process_context.process_guid,
                    process_context.process_image,
                )

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(group.client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname, asset_guid, process_statements, runs_statements
            )
            if client_node_id is None:
                return None
            client_is_process = True
            if process_context is None:
                process_context = ProcessContext(
                    process_guid=client_node_id,
                    process_image=f"{hostname} Runtime",
                    process_id=0,
                    user="",
                    computer=hostname,
                )

        # Classify destination
        rel_type, dst_label = self._classify_destination(group.server_ip)
        server_node_id = self._ensure_network_service_node(
            ip=group.server_ip,
            port=group.service_port,
            protocol=connection_key.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            process_statements=process_statements,
            runs_statements=runs_statements,
            service_name=service_name,
            aggregation="modbus_monitor",
            note="Aggregated Modbus monitor server inferred from PCAP-only traffic",
        )

        relationship_properties = self._relationship_properties(connection_key, packets)
        relationship_properties.update(
            {
                "SourcePort": "aggregated",
                "aggregated": "modbus_monitor",
                "canonicalCount": len(group.connections),
                "uniqueSourcePorts": len({pkt.src_port for pkt in packets}),
            }
        )
        combined_bytes = self._combined_bytes(relationship_properties)
        if group.connections and combined_bytes is not None:
            relationship_properties["meanBytesPerConnection"] = round(
                combined_bytes / len(group.connections), 2
            )

        if client_is_process and process_context:
            if correlation_source == "telemetry":
                relationship_properties["correlatedFromTelemetry"] = True
                relationship_properties["note"] = (
                    f"HTTP monitor traffic correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) from telemetry connection"
                )

        # Use Process label if we found a matching process, otherwise NetworkService
        source_label = "Process"
        self._stage_connect_relationship(
            relationship_statements=relationship_statements,
            source_guid=client_node_id,
            dest_guid=server_node_id,
            properties=relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
            source_ports=source_ports,
        )
        return rel_type

    def _add_collapsed_group(
        self,
        group: CollapsedConnectionGroup,
        connection_key: ConnectionKey,
        packets: Sequence[PacketRecord],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        host_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
        relationship_statements: List[str],
        telemetry_index: Optional["TelemetryConnectionIndex"] = None,
    ) -> str:
        """Add a collapsed group and return the relationship type used."""
        # Try to find a Process node that matches this traffic via telemetry.
        client_node_id: Optional[str] = None
        client_is_process = False
        process_context: Optional[ProcessContext] = None
        correlation_source = "pcap_only"

        if telemetry_index is not None:
            process_context = self._find_telemetry_process_context(
                telemetry_index=telemetry_index,
                client_ip=group.client_ip,
                server_ip=group.server_ip,
                service_port=group.service_port,
                protocol=connection_key.protocol,
                source_ports=sorted(group.client_ports),
            )
            if process_context and process_context.is_valid():
                client_node_id = process_context.process_guid
                client_is_process = True
                correlation_source = "telemetry"
                logger.debug(
                    "Attributed collapsed group to Process %s (%s) from telemetry",
                    process_context.process_guid,
                    process_context.process_image,
                )

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(group.client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname, asset_guid, process_statements, runs_statements
            )
            if client_node_id is None:
                return None
            client_is_process = True
            if process_context is None:
                process_context = ProcessContext(
                    process_guid=client_node_id,
                    process_image=f"{hostname} Runtime",
                    process_id=0,
                    user="",
                    computer=hostname,
                )

        # Classify destination
        rel_type, dst_label = self._classify_destination(group.server_ip)
        # Unified ontology uses NetworkService as the CONNECT_TO destination.
        server_node_id = self._ensure_network_service_node(
            ip=group.server_ip,
            port=group.service_port,
            protocol=connection_key.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            process_statements=process_statements,
            runs_statements=runs_statements,
            service_name=self._service_name_for_port(group.service_port),
            aggregation="port_group",
            note="Aggregated server inferred from PCAP-only traffic",
        )

        collapsed_source_ports = sorted(group.client_ports)
        relationship_properties = self._relationship_properties(connection_key, packets)
        relationship_properties.update(
            {
                "SourcePort": "aggregated",
                "aggregated": "port_group",
                "canonicalCount": len(group.connections),
                "uniqueSourcePorts": len(group.client_ports),
            }
        )
        combined_bytes = self._combined_bytes(relationship_properties)
        if group.connections and combined_bytes is not None:
            relationship_properties["meanBytesPerConnection"] = round(
                combined_bytes / len(group.connections), 2
            )
        if collapsed_source_ports:
            relationship_properties["sourcePortMin"] = collapsed_source_ports[0]
            relationship_properties["sourcePortMax"] = collapsed_source_ports[-1]
            if len(collapsed_source_ports) <= 8:
                relationship_properties["sourcePortSet"] = ",".join(
                    str(port) for port in collapsed_source_ports
                )

        if client_is_process and process_context:
            if correlation_source == "telemetry":
                relationship_properties["correlatedFromTelemetry"] = True
                relationship_properties["note"] = (
                    f"PCAP traffic correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) from telemetry connection"
                )

        # Use Process label if we found a matching process, otherwise NetworkService
        source_label = "Process"
        self._stage_connect_relationship(
            relationship_statements=relationship_statements,
            source_guid=client_node_id,
            dest_guid=server_node_id,
            properties=relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
            source_ports=collapsed_source_ports,
        )
        return rel_type

    def _write_output(
        self,
        asset_statements: List[str],
        service_statements: List[str],
        host_statements: List[str],
        register_statements: List[str],
        signal_statements: List[str],
        process_statements: List[str],
        runs_statements: List[str],
        relationship_statements: List[str],
    ) -> None:
        """Write augmented Cypher file, preserving the original content."""
        base_text = Path(self.config.base_cypher).read_text(encoding="utf-8")
        sanitized_base_text, stripped_blocks = self._strip_session_metadata_from_cypher(base_text)
        if stripped_blocks > 0:
            logger.info(
                "Stripped session metadata from %d base relationship property maps in final output",
                stripped_blocks,
            )

        with Path(self.config.output_cypher).open("w", encoding="utf-8") as handle:
            handle.write(sanitized_base_text)

            if (
                not asset_statements
                and not service_statements
                and not host_statements
                and not register_statements
                and not signal_statements
                and not process_statements
                and not runs_statements
                and not relationship_statements
            ):
                return

            handle.write("\n\n// === PCAP Augmentation (Missing Traffic) ===\n\n")

            if asset_statements:
                handle.write("// PCAP-Inferred NetworkEndpoint Nodes\n")
                for statement in asset_statements:
                    handle.write(statement + ";\n")
                handle.write("\n")

            if service_statements:
                handle.write("// PCAP-Inferred NetworkService Nodes\n")
                for statement in service_statements:
                    handle.write(statement + ";\n")
                handle.write("\n")

            if host_statements:
                handle.write("// PCAP-Inferred External NetworkEndpoint Nodes\n")
                for statement in host_statements:
                    handle.write(statement + ";\n")
                handle.write("\n")

            if register_statements:
                handle.write("// PCAP-Inferred ICSSignal Nodes\n")
                for statement in register_statements:
                    handle.write(statement + ";\n")
                handle.write("\n")

            if signal_statements:
                handle.write("// PCAP-Inferred SignalContainer Nodes\n")
                for statement in signal_statements:
                    handle.write(statement + ";\n")
                handle.write("\n")

            if process_statements:
                handle.write("// Virtual Process Nodes for PLCs/RTUs\n")
                for statement in process_statements:
                    handle.write(statement + ";\n")
                handle.write("\n")

            if runs_statements:
                handle.write("// Process Ownership Relationships (RUN_ON/BINDS)\n")
                for statement in runs_statements:
                    handle.write(statement + ";\n")
                handle.write("\n")

            if relationship_statements:
                handle.write("// PCAP-Inferred Network Relationships\n")
                for statement in relationship_statements:
                    handle.write(statement + ";\n")

    def _strip_session_metadata_from_cypher(self, text: str) -> Tuple[str, int]:
        """Remove transient session correlation properties from Cypher maps."""
        parts: List[str] = []
        cursor = 0
        stripped_blocks = 0

        while True:
            brace_start = text.find("{", cursor)
            if brace_start == -1:
                parts.append(text[cursor:])
                break

            block_content, brace_end = _consume_brace_block(text, brace_start)
            if brace_end == -1:
                parts.append(text[cursor:])
                break

            parts.append(text[cursor:brace_start])
            sanitized_block_content, removed = self._strip_session_metadata_from_block(block_content)
            if removed:
                stripped_blocks += 1
            parts.append("{" + sanitized_block_content + "}")
            cursor = brace_end + 1

        return "".join(parts), stripped_blocks

    def _strip_session_metadata_from_block(self, block_content: str) -> Tuple[str, bool]:
        """Remove session metadata keys from a single Cypher property block body."""
        if not any(key in block_content for key in _SESSION_METADATA_KEYS):
            return block_content, False

        entries = self._split_cypher_map_entries(block_content)
        kept_entries = [
            entry for entry in entries
            if self._entry_key(entry) not in _SESSION_METADATA_KEYS
        ]
        if len(kept_entries) == len(entries):
            return block_content, False
        return ", ".join(kept_entries), True

    def _split_cypher_map_entries(self, content: str) -> List[str]:
        """Split a Cypher map body on top-level commas."""
        entries: List[str] = []
        current: List[str] = []
        depth_braces = 0
        depth_brackets = 0
        depth_parens = 0
        in_string = False
        escaped = False

        for char in content:
            if in_string:
                current.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    in_string = False
                continue

            if char == "'":
                in_string = True
                current.append(char)
                continue
            if char == "{":
                depth_braces += 1
            elif char == "}":
                depth_braces = max(0, depth_braces - 1)
            elif char == "[":
                depth_brackets += 1
            elif char == "]":
                depth_brackets = max(0, depth_brackets - 1)
            elif char == "(":
                depth_parens += 1
            elif char == ")":
                depth_parens = max(0, depth_parens - 1)

            if char == "," and depth_braces == 0 and depth_brackets == 0 and depth_parens == 0:
                entry = "".join(current).strip()
                if entry:
                    entries.append(entry)
                current = []
                continue

            current.append(char)

        tail = "".join(current).strip()
        if tail:
            entries.append(tail)
        return entries

    def _entry_key(self, entry: str) -> str:
        """Extract a top-level Cypher map entry key."""
        match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", entry)
        return match.group(1) if match else ""
