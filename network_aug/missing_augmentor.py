"""
Add missing traffic connections, augments existing connections with traffic metadata, 
"""
import hashlib
import logging
from pathlib import Path
import shutil
from typing import Tuple, Optional, Dict, Set, List, Sequence
from tqdm import tqdm
import uuid
from .models import SignalContainerData, ConnectionKey, IndexedConnection, PacketRecord
from .enhancer import AugmentationConfig, AggregationMetrics, AugmentationArtifacts, AssetMetadata, _PendingModbusRequest, _RegisterAccumulator, _SignalAccumulator

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
    extract_mqtt_features,
    extract_opcua_features,
    extract_tls_sni,
    mean_interarrival_time,
    mean_rtt_ms,
    packet_count,
    resolve_mac_addresses,
    total_bytes,
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
    _is_service_port,
)

logger = logging.getLogger(__name__)

def _modbus_transaction_key(packet: PacketRecord, service_port: int) -> Optional[Tuple[str, int, str, Optional[int], int]]:
    return modbus_transaction_key(packet, service_port)

def _generate_node_guid(node_type: str, hostname: str, *identifiers: object) -> str:
    """Replicate the GUID scheme used by the base provenance notebook."""
    components = [node_type, hostname] + [str(value) for value in identifiers if value not in (None, "")]
    combined = "|".join(components).lower()
    guid_hash = hashlib.md5(combined.encode("utf-8")).digest()
    guid = uuid.UUID(bytes=guid_hash)
    return f"{{{guid}}}"


def _generate_signal_guid(protocol: str, host: str, port: int, *identifiers: object) -> str:
    """Generate deterministic ICSSignal GUID (case-preserving identifiers)."""
    components = [
        "ICSSignal",
        protocol.strip().lower(),
        host.strip().lower(),
        str(port),
    ] + [str(value) for value in identifiers if value not in (None, "")]
    combined = "|".join(components)
    guid_hash = hashlib.md5(combined.encode("utf-8")).digest()
    guid = uuid.UUID(bytes=guid_hash)
    return f"{{{guid}}}"


def _generate_signal_key(protocol: str, host: str, port: int, *identifiers: object) -> str:
    """Generate canonical ICSSignal identity key."""
    components = [
        protocol.strip().lower(),
        host.strip().lower(),
        str(port),
    ] + [str(value) for value in identifiers if value not in (None, "")]
    return "|".join(components)

def _register_type_from_function(function_code: Optional[int]) -> Optional[str]:
    return register_type_from_function(function_code)

class MissingTrafficAugmentor:
    """Coordinates loading graph outputs, indexing PCAP, and writing augmented Cypher."""

    def __init__(self, config: AugmentationConfig) -> None:
        self.config = config
        self._protocol_registry = build_default_registry()
        self._asset_ip_map = self._load_asset_lookup()
        self._asset_metadata: Dict[str, AssetMetadata] = {}  # hostname -> metadata
        self._ip_to_hostname: Dict[str, str] = {}  # IP -> hostname (multi-IP support)
        self._placeholder_processes: Dict[str, str] = {}  # hostname -> process_guid cache
        self._load_asset_metadata()

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

        existing_rel_updates, proc_register_stmts, correlated_cids, corr_stats, telemetry_index = self._augment_existing_relationships(
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

        # Build temporal process index for PCAP-to-Process attribution
        if self.config.enable_process_attribution:
            process_index = self._build_temporal_process_index()
            logger.info(
                "Temporal process attribution enabled: %d processes indexed across %d IPs",
                process_index.entry_count,
                process_index.ip_count,
            )
        else:
            process_index = None

        modbus_result = self._protocol_registry.run(
            "modbus",
            ProtocolBuildContext(
                augmentor=self,
                connections=connections,
                base_connection_ids=base_connection_ids,
                correlated_cids=correlated_cids,
                processed_cids=processed_cids,
                show_progress=show_progress,
                process_index=process_index,
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
                process_index=process_index,
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
                process_index=process_index,
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
        # MQTT phase 1 emits per-connection relationship enrichment and is
        # currently tracked under individual relationships.
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
                process_index=process_index,
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
        # OPC UA phase 1 is metadata-first and tracked under individual links.
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
                process_index=process_index,
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

            packets = indexed.records
            if not packets:
                continue

            connection_key = indexed.origin
            if not self.config.policy.is_interesting(connection_key, packets):
                continue

            # Normalize ephemeral ports to 0 for client-side nodes (same as collapsed groups)
            src_is_service = _is_service_port(connection_key.src_port)
            dst_is_service = _is_service_port(connection_key.dst_port)
            src_port = connection_key.src_port if src_is_service else 0
            dst_port = connection_key.dst_port if dst_is_service else 0

            # If both are ephemeral or both are service ports, use original ports
            if src_is_service == dst_is_service:
                src_port = connection_key.src_port
                dst_port = connection_key.dst_port

            # Try to find a Process node that matches this traffic temporally (for client side)
            # Skip if telemetry_attribution_only is set
            src_node_id: Optional[str] = None
            src_is_process = False
            matched_process_entry: Optional[TemporalProcessEntry] = None

            if process_index and packets and src_port == 0 and not self.config.telemetry_attribution_only:
                timestamps = [p.timestamp for p in packets]
                range_start = min(timestamps)
                range_end = max(timestamps)

                process_entry = process_index.find_process_for_range(
                    connection_key.src_ip, range_start, range_end
                )
                if process_entry:
                    src_node_id = process_entry.process_guid
                    src_is_process = True
                    matched_process_entry = process_entry

            if src_node_id is None:
                hostname, ip_address = self._resolve_host(connection_key.src_ip)
                asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
                src_node_id = self._ensure_placeholder_process(
                    hostname, asset_guid, process_statements, runs_statements
                )
                src_is_process = True

            # Classify destination
            rel_type, dst_label = self._classify_destination(connection_key.dst_ip)
            dst_node_id = self._ensure_network_service_node(
                ip=connection_key.dst_ip,
                port=dst_port,
                protocol=connection_key.protocol,
                asset_statements=asset_statements,
                service_statements=service_statements,
                process_statements=process_statements,
                runs_statements=runs_statements,
                service_name="Ephemeral Client" if dst_port == 0 else None,
            )

            if not src_node_id or not dst_node_id:
                continue

            # Build relationship properties with temporal inference metadata if applicable
            rel_props = self._relationship_properties(connection_key, packets)
            if src_is_process and matched_process_entry:
                rel_props["temporallyInferred"] = True
                rel_props["correlatedProcessGuid"] = matched_process_entry.process_guid
                rel_props["correlatedProcessImage"] = matched_process_entry.process_image
                rel_props["correlatedProcessId"] = matched_process_entry.process_id
                rel_props["note"] = (
                    f"PCAP traffic temporally correlated to process {matched_process_entry.process_image} "
                    f"(PID {matched_process_entry.process_id}) based on host activity overlap"
                )

            source_label = "Process"
            relationship_statement = cypher_emit.create_connection_statement(
                src_node_id,
                dst_node_id,
                rel_props,
                relationship_name=rel_type,
                source_label=source_label,
                dest_label=dst_label,
            )
            relationship_statements.append(relationship_statement)
            individual_relationships += 1


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
            temporal_matches=corr_stats.get("temporal_matches", 0),
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
            require_temporal_overlap=self.config.require_temporal_overlap,
            pcap_time_offset_seconds=self.config.pcap_time_offset_seconds,
        )
        correlation_engine = CorrelationEngine(
            config=correlation_config,
            ip_hostname_map=self._asset_ip_map,
        )

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

        def _record_service(ip: str, port: int) -> Tuple[str, str, int]:
            hostname, ip_address = self._resolve_host(ip)
            if ip_address and ip_address not in self._asset_ip_map:
                self._asset_ip_map[ip_address] = hostname
            asset_guids.add(_generate_node_guid("NetworkEndpoint", hostname))
            normalized_port = port if port and port >= 0 else 0
            service_guids.add(_generate_node_guid("NetworkService", hostname, normalized_port))
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

            _record_service(group.client_ip, group.service_port)
            server_hostname, server_ip, _ = _record_service(group.server_ip, group.service_port)

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

            _record_service(group.client_ip, group.service_port)
            _record_service(group.server_ip, group.service_port)

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

            _record_service(client_ip, 0)
            server_hostname, _, _ = _record_service(server_ip, service_port)
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

            _record_service(client_ip, 0)
            server_hostname, _, _ = _record_service(server_ip, service_port)
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

            _record_service(group.client_ip, 0)
            _record_service(group.server_ip, group.service_port)

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

            packets = indexed.records
            if not packets:
                continue

            connection_key = indexed.origin
            if not self.config.policy.is_interesting(connection_key, packets):
                continue

            _record_service(connection_key.src_ip, connection_key.src_port)
            _record_service(connection_key.dst_ip, connection_key.dst_port)
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
    ) -> str:
        """Create/return placeholder Process node for PLC/RTU.

        Creates a single Virtual Process node per device (not per protocol).
        Also creates the RUN_ON relationship from Process to NetworkEndpoint.
        """
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

    def _build_temporal_process_index(self) -> TemporalProcessIndex:
        """Parse Process nodes from base Cypher to build temporal process index.

        This enables attributing PCAP traffic to the correct Process node based
        on the timestamps of the traffic and the process lifetime (createdAt/terminatedAt).
        """
        from .correlation import _parse_timestamp

        index = TemporalProcessIndex(tolerance_seconds=self.config.temporal_tolerance_seconds)
        path = Path(self.config.base_cypher)
        if not path.exists():
            return index

        # Build reverse map: hostname -> IP
        # Include both asset lookups from base Cypher AND hardcoded config mappings
        hostname_to_ip: Dict[str, str] = {}
        for ip, hostname in self._asset_ip_map.items():
            hostname_to_ip[hostname] = ip
        # Also include hardcoded config mappings (don't override if already present)
        for ip, hostname in self.config.ip_hostname_map.items():
            hostname_to_ip.setdefault(hostname, ip)

        text = path.read_text(encoding="utf-8")
        cursor = 0
        token = ":Process"
        process_count = 0

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
            guid = str(properties.get("guid") or "")
            host = str(properties.get("host") or "")
            image = str(properties.get("image") or "")
            process_id = properties.get("processId") or properties.get("processid") or 0

            # Parse timestamps
            created_at = _parse_timestamp(properties.get("createdAt"))
            terminated_at = _parse_timestamp(properties.get("terminatedAt"))

            # Resolve host to IP
            ip_address = hostname_to_ip.get(host, "")

            if guid and host:
                try:
                    pid = int(process_id) if process_id else 0
                except (ValueError, TypeError):
                    pid = 0

                entry = TemporalProcessEntry(
                    process_guid=guid,
                    process_label="Process",
                    host=host,
                    ip_address=ip_address,
                    created_at=created_at,
                    terminated_at=terminated_at,
                    process_image=image,
                    process_id=pid,
                )
                index.add_entry(entry)
                process_count += 1

            cursor = brace_end + 1

        index.finalize()
        logger.info(
            "Built temporal process index: %d processes across %d IPs",
            index.entry_count,
            index.ip_count,
        )
        return index

    def _augment_existing_relationships(
        self,
        existing_connections: Sequence[ExistingConnection],
        indexed_connections: Sequence[IndexedConnection],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        register_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
    ) -> Tuple[List[str], List[str], Set[str], Dict[str, int], Optional["TelemetryConnectionIndex"]]:
        """Build Cypher statements that enrich existing CONNECT_TO edges.

        Uses the CorrelationEngine for temporal-anchored correlation with
        confidence scoring. Returns:
            - relationship_updates: SET statements for existing edges
            - process_register_statements: READ/WRITE register edges for process attribution
            - correlated_canonical_ids: set of PCAP canonical IDs that were successfully correlated
            - correlation_stats: statistics about the correlation process
            - telemetry_index: TelemetryConnectionIndex for process lookup (reusable)
        """
        empty_stats: Dict[str, int] = {
            "total_attempts": 0,
            "successful_correlations": 0,
            "temporal_matches": 0,
            "process_attributed_registers": 0,
        }

        if not existing_connections:
            return [], [], set(), empty_stats, None

        # Build correlation engine with config
        correlation_config = CorrelationConfig(
            min_confidence=self.config.min_correlation_confidence,
            temporal_tolerance_seconds=self.config.temporal_tolerance_seconds,
            require_temporal_overlap=self.config.require_temporal_overlap,
            pcap_time_offset_seconds=self.config.pcap_time_offset_seconds,
        )
        correlation_engine = CorrelationEngine(
            config=correlation_config,
            ip_hostname_map=self._asset_ip_map,
        )

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
        statements: List[str] = []
        process_register_statements: List[str] = []
        seen_edges: Set[Tuple[str, str]] = set()
        process_attributed_registers = 0

        # Group correlations by telemetry anchor (edge)
        anchor_correlations: Dict[Tuple[str, str], List[CorrelatedConnection]] = {}
        for correlated in correlations.values():
            anchor = correlated.telemetry_anchor
            edge_key = (anchor.src_guid, anchor.dst_guid)
            if edge_key not in anchor_correlations:
                anchor_correlations[edge_key] = []
            anchor_correlations[edge_key].append(correlated)

        # Process each unique telemetry edge
        for edge_key, edge_correlations in anchor_correlations.items():
            src_guid, dst_guid = edge_key
            if not src_guid or not dst_guid:
                continue
            if edge_key in seen_edges:
                continue

            # Combine all packets from correlated PCAP connections
            all_packets: List[PacketRecord] = []
            best_confidence = 0.0
            best_method = "unknown"
            representative_anchor: Optional[CorrelatedConnection] = None

            for corr in edge_correlations:
                all_packets.extend(corr.packets)
                if corr.confidence > best_confidence:
                    best_confidence = corr.confidence
                    best_method = corr.correlation_method
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

            # Add correlation metadata
            feature_props["correlationConfidence"] = round(best_confidence, 4)
            feature_props["correlationMethod"] = best_method
            feature_props["correlatedPcapConnections"] = len(edge_correlations)

            # Preserve process context reference
            proc_ctx = representative_anchor.process_context
            if proc_ctx.is_valid():
                feature_props["correlatedProcessGuid"] = proc_ctx.process_guid
                feature_props["correlatedProcessImage"] = proc_ctx.process_image

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
            feature_props.setdefault("Initiated", anchor.rel_properties.get("Initiated") or "true")
            if not feature_props.get("note"):
                feature_props["note"] = "Augmented with PCAP-derived metrics via temporal correlation"

            cypher_props = cypher_emit.format_properties(feature_props)
            src_label = anchor.src_label or "Process"
            dst_label = anchor.dst_label or "NetworkService"
            src_guid_escaped = cypher_emit.escape_cypher_string(src_guid)
            dst_guid_escaped = cypher_emit.escape_cypher_string(dst_guid)
            # Use the relationship type from the anchor (preserves INTERNAL vs EXTERNAL)
            anchor_rel_type = anchor.rel_type.upper()

            statement = (
                f"MATCH (src:{src_label} {{guid: '{src_guid_escaped}'}})\n"
                f"MATCH (dst:{dst_label} {{guid: '{dst_guid_escaped}'}})\n"
                f"MATCH (src)-[rel:{anchor_rel_type}]->(dst)\n"
                f"SET rel += {cypher_props}\n"
                f"SET rel.pcapAugmented = true"
            )

            statements.append(statement)
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
        return statements, process_register_statements, correlated_cids, correlation_stats, telemetry_index

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
        if ip_address and ip_address not in self._asset_ip_map:
            self._asset_ip_map[ip_address] = hostname
        if guid not in asset_statements:
            props = {
                "guid": guid,
                "hostname": hostname,
                "ipAddress": ip_address,
                "ipAddresses": [ip_address] if ip_address else [],
                "isExternal": False if self._is_known_host(ip_address) else True,
                "isManaged": self._is_known_host(ip_address),
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
        service_guid = _generate_node_guid("NetworkService", hostname, normalized_port)

        if service_guid not in service_statements:
            props: Dict[str, object] = {
                "guid": service_guid,
                "host": hostname,
                "port": normalized_port,
                "protocol": protocol.upper(),
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
        bytes_out, bytes_in, packets_out, packets_in = directional_totals(connection, sorted_packets)
        dir_index = directionality_ratio(bytes_out, bytes_in)
        inter_arrival = mean_interarrival_time(sorted_packets)
        tcp_flags = aggregate_tcp_flags(sorted_packets)
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
            "Initiated": "true",
            "inferredFrom": "pcap",
            "pcapAugmented": True,
            "note": "Observed in PCAP but missing from host telemetry",
            "totalBytes": total_bytes(sorted_packets),
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
            "packetsOut": packets_out,
            "packetsIn": packets_in,
            "directionalityIndex": round(dir_index, 6) if dir_index is not None else None,
            "meanInterArrivalPacketTime": round(inter_arrival, 6),
            "tcpFlags": tcp_flags or None,
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

    def _is_mqtt_indexed_connection(self, connection: IndexedConnection) -> bool:
        """Return True if this connection appears to carry MQTT traffic."""
        if connection.origin.src_port in MQTT_PORTS or connection.origin.dst_port in MQTT_PORTS:
            return True

        # For non-standard ports, require a parsed CONNECT packet to avoid
        # classifying arbitrary binary traffic as MQTT.
        for packet in connection.records:
            if packet.mqtt_packet_type_code == 1 and (packet.mqtt_packet_type or "").upper() == "CONNECT":
                return True
        return False

    def _orient_mqtt_connection(
        self,
        connection: IndexedConnection,
    ) -> Optional[Tuple[str, str, int, str]]:
        """Orient MQTT traffic as (client_ip, server_ip, service_port, protocol)."""
        origin = connection.origin
        if origin.dst_port in MQTT_PORTS and origin.src_port not in MQTT_PORTS:
            return origin.src_ip, origin.dst_ip, origin.dst_port, origin.protocol
        if origin.src_port in MQTT_PORTS and origin.dst_port not in MQTT_PORTS:
            return origin.dst_ip, origin.src_ip, origin.src_port, origin.protocol

        if not connection.records:
            return None

        first_packet = min(connection.records, key=lambda pkt: pkt.timestamp)
        if first_packet.dst_port in MQTT_PORTS and first_packet.src_port not in MQTT_PORTS:
            return first_packet.src_ip, first_packet.dst_ip, first_packet.dst_port, first_packet.protocol
        if first_packet.src_port in MQTT_PORTS and first_packet.dst_port not in MQTT_PORTS:
            return first_packet.dst_ip, first_packet.src_ip, first_packet.src_port, first_packet.protocol

        # Non-standard ports: orient by CONNECT packet (client -> broker).
        connect_packets = [
            pkt
            for pkt in connection.records
            if pkt.mqtt_packet_type_code == 1 and (pkt.mqtt_packet_type or "").upper() == "CONNECT"
        ]
        if not connect_packets:
            return None

        connect_pkt = min(connect_packets, key=lambda pkt: pkt.timestamp)
        service_port = connect_pkt.dst_port if connect_pkt.dst_port > 0 else connect_pkt.src_port
        if service_port <= 0:
            return None
        return connect_pkt.src_ip, connect_pkt.dst_ip, service_port, connect_pkt.protocol

    def _add_mqtt_connection(
        self,
        *,
        client_ip: str,
        server_ip: str,
        service_port: int,
        protocol: str,
        packets: Sequence[PacketRecord],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        host_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
        register_statements: Dict[str, str],
        relationship_statements: List[str],
        process_register_statements: List[str],
        process_index: Optional[TemporalProcessIndex] = None,
        telemetry_index: Optional[TelemetryConnectionIndex] = None,
    ) -> str:
        """Add MQTT connection artifacts and return the relationship type."""
        service_name = self.config.service_map.get(service_port, "MQTT")

        client_node_id: Optional[str] = None
        client_is_process = False
        process_entry: Optional[TemporalProcessEntry] = None
        correlation_confidence = 0.5
        process_image: Optional[str] = None
        process_id: Optional[int] = None

        if telemetry_index is not None:
            process_context = telemetry_index.find_process_for_connection(
                src_ip=client_ip,
                dst_ip=server_ip,
                dst_port=service_port,
                protocol=protocol,
            )
            if process_context and process_context.is_valid():
                client_node_id = process_context.process_guid
                client_is_process = True
                correlation_confidence = 1.0
                process_image = process_context.process_image
                process_id = process_context.process_id

        if client_node_id is None and process_index and packets and not self.config.telemetry_attribution_only:
            timestamps = [p.timestamp for p in packets]
            range_start = min(timestamps)
            range_end = max(timestamps)
            process_entry = process_index.find_process_for_range(client_ip, range_start, range_end)
            if process_entry:
                client_node_id = process_entry.process_guid
                client_is_process = True
                process_image = process_entry.process_image
                process_id = process_entry.process_id

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
            if client_is_process and client_node_id and not self.config.telemetry_attribution_only:
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
                "SourcePort": "aggregated",
                "aggregated": "mqtt",
                "canonicalCount": 1,
            }
        )

        if client_is_process and process_image:
            relationship_properties["correlatedProcessGuid"] = client_node_id
            relationship_properties["correlatedProcessImage"] = process_image
            relationship_properties["correlatedProcessId"] = process_id
            if process_entry:
                relationship_properties["temporallyInferred"] = True
                relationship_properties["note"] = (
                    f"MQTT traffic temporally correlated to process {process_image} "
                    f"(PID {process_id}) based on host activity overlap"
                )
            elif correlation_confidence >= 1.0:
                relationship_properties["telemetryCorrelated"] = True
                relationship_properties["note"] = (
                    f"MQTT traffic correlated to process {process_image} "
                    f"(PID {process_id}) via Sysmon telemetry"
                )

        source_label = "Process"
        relationship_statement = cypher_emit.create_connection_statement(
            client_node_id,
            server_node_id,
            relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
        )
        relationship_statements.append(relationship_statement)
        return rel_type

    def _is_opcua_indexed_connection(self, connection: IndexedConnection) -> bool:
        """Return True if this connection appears to carry OPC UA traffic."""
        if connection.origin.src_port in OPCUA_PORTS or connection.origin.dst_port in OPCUA_PORTS:
            return True

        # For non-standard ports, require high-confidence HEL/OPN metadata.
        for packet in connection.records:
            message_type = (packet.opcua_message_type or "").upper()
            if message_type == "HEL" and packet.opcua_endpoint_url:
                return True
            if message_type == "OPN" and packet.opcua_security_policy_uri:
                return True
        return False

    def _orient_opcua_connection(
        self,
        connection: IndexedConnection,
    ) -> Optional[Tuple[str, str, int, str]]:
        """Orient OPC UA traffic as (client_ip, server_ip, service_port, protocol)."""
        origin = connection.origin
        if origin.dst_port in OPCUA_PORTS and origin.src_port not in OPCUA_PORTS:
            return origin.src_ip, origin.dst_ip, origin.dst_port, origin.protocol
        if origin.src_port in OPCUA_PORTS and origin.dst_port not in OPCUA_PORTS:
            return origin.dst_ip, origin.src_ip, origin.src_port, origin.protocol

        if not connection.records:
            return None

        hel_packets = [
            pkt for pkt in connection.records if (pkt.opcua_message_type or "").upper() == "HEL"
        ]
        if hel_packets:
            hel_packet = min(hel_packets, key=lambda pkt: pkt.timestamp)
            service_port = hel_packet.dst_port if hel_packet.dst_port > 0 else hel_packet.src_port
            if service_port > 0:
                return hel_packet.src_ip, hel_packet.dst_ip, service_port, hel_packet.protocol

        opn_packets = [
            pkt for pkt in connection.records if (pkt.opcua_message_type or "").upper() == "OPN"
        ]
        if opn_packets:
            opn_packet = min(opn_packets, key=lambda pkt: pkt.timestamp)
            service_port = opn_packet.dst_port if opn_packet.dst_port > 0 else opn_packet.src_port
            if service_port > 0:
                return opn_packet.src_ip, opn_packet.dst_ip, service_port, opn_packet.protocol

        return None

    def _add_opcua_connection(
        self,
        *,
        client_ip: str,
        server_ip: str,
        service_port: int,
        protocol: str,
        packets: Sequence[PacketRecord],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        host_statements: Dict[str, str],
        process_statements: Dict[str, str],
        runs_statements: Dict[str, str],
        register_statements: Dict[str, str],
        relationship_statements: List[str],
        process_register_statements: List[str],
        process_index: Optional[TemporalProcessIndex] = None,
        telemetry_index: Optional[TelemetryConnectionIndex] = None,
    ) -> str:
        """Add OPC UA connection artifacts and return the relationship type."""
        service_name = self.config.service_map.get(service_port, "OPC UA")

        client_node_id: Optional[str] = None
        client_is_process = False
        process_entry: Optional[TemporalProcessEntry] = None
        correlation_confidence = 0.5
        process_image: Optional[str] = None
        process_id: Optional[int] = None

        if telemetry_index is not None:
            process_context = telemetry_index.find_process_for_connection(
                src_ip=client_ip,
                dst_ip=server_ip,
                dst_port=service_port,
                protocol=protocol,
            )
            if process_context and process_context.is_valid():
                client_node_id = process_context.process_guid
                client_is_process = True
                correlation_confidence = 1.0
                process_image = process_context.process_image
                process_id = process_context.process_id

        if client_node_id is None and process_index and packets and not self.config.telemetry_attribution_only:
            timestamps = [p.timestamp for p in packets]
            range_start = min(timestamps)
            range_end = max(timestamps)
            process_entry = process_index.find_process_for_range(client_ip, range_start, range_end)
            if process_entry:
                client_node_id = process_entry.process_guid
                client_is_process = True
                process_image = process_entry.process_image
                process_id = process_entry.process_id

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
            if client_is_process and client_node_id and not self.config.telemetry_attribution_only:
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
                "SourcePort": "aggregated",
                "aggregated": "opcua",
                "canonicalCount": 1,
            }
        )

        if client_is_process and process_image:
            relationship_properties["correlatedProcessGuid"] = client_node_id
            relationship_properties["correlatedProcessImage"] = process_image
            relationship_properties["correlatedProcessId"] = process_id
            if process_entry:
                relationship_properties["temporallyInferred"] = True
                relationship_properties["note"] = (
                    f"OPC UA traffic temporally correlated to process {process_image} "
                    f"(PID {process_id}) based on host activity overlap"
                )
            elif correlation_confidence >= 1.0:
                relationship_properties["telemetryCorrelated"] = True
                relationship_properties["note"] = (
                    f"OPC UA traffic correlated to process {process_image} "
                    f"(PID {process_id}) via Sysmon telemetry"
                )

        source_label = "Process"
        relationship_statement = cypher_emit.create_connection_statement(
            client_node_id,
            server_node_id,
            relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
        )
        relationship_statements.append(relationship_statement)
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
                        acc.observe(
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
                        acc.observe(
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
                        acc.observe(
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
                    acc.observe(
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

            # Generate SignalContainer GUID for client observer (primary reference)
            signal_guid = _generate_node_guid("SignalContainer", client_hostname, address, unit_id)

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
        signal_key = _generate_signal_key(protocol, host, port, signal_name)
        signal_guid = _generate_signal_guid(protocol, host, port, signal_name)
        if signal_guid in register_statements:
            return signal_guid

        props: Dict[str, object] = {
            "guid": signal_guid,
            "signalKey": signal_key,
            "protocol": protocol.lower(),
            "host": host,
            "port": port,
            "name": signal_name,
            "source": "pcap",
        }
        if signal_properties:
            props.update(signal_properties)

        register_statements[signal_guid] = cypher_emit.create_ics_signal_statement(
            signal_guid=signal_guid,
            properties=props,
            endpoint_guid=asset_guid,
        )
        return signal_guid

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
        statements: List[str] = []
        read_count = int(summary.get("readCount") or 0)
        write_count = int(summary.get("writeCount") or 0)
        if read_count <= 0 and write_count <= 0:
            return statements

        proc_guid_escaped = cypher_emit.escape_cypher_string(process_guid)
        signal_guid_escaped = cypher_emit.escape_cypher_string(signal_guid)
        common_props: Dict[str, object] = {
            "correlationConfidence": round(correlation_confidence, 4),
            "inferredFrom": "pcap",
            "pcapAugmented": True,
        }
        if process_image:
            common_props["processImage"] = process_image
        if process_id is not None:
            common_props["processId"] = process_id

        if read_count > 0:
            read_props = dict(common_props)
            read_props["readCount"] = read_count
            if summary.get("lastReadAt") is not None:
                read_props["lastReadAt"] = summary["lastReadAt"]
            cypher_props = cypher_emit.format_properties(read_props)
            statement = (
                f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
                f"MATCH (sig:ICSSignal {{guid: '{signal_guid_escaped}'}})\n"
                f"MERGE (proc)-[acc:READ_SIGNAL]->(sig)\n"
                f"SET acc += {cypher_props}\n"
                "SET acc.pcapAugmented = true"
            )
            statements.append(statement)

        if write_count > 0:
            write_props = dict(common_props)
            write_props["writeCount"] = write_count
            if summary.get("lastWriteAt") is not None:
                write_props["lastWriteAt"] = summary["lastWriteAt"]
            cypher_props = cypher_emit.format_properties(write_props)
            statement = (
                f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
                f"MATCH (sig:ICSSignal {{guid: '{signal_guid_escaped}'}})\n"
                f"MERGE (proc)-[acc:WRITE_SIGNAL]->(sig)\n"
                f"SET acc += {cypher_props}\n"
                "SET acc.pcapAugmented = true"
            )
            statements.append(statement)

        return statements

    def _collect_mqtt_signals(
        self,
        *,
        packets: Sequence[PacketRecord],
        server_ip: str,
        server_port: int,
    ) -> Dict[str, Dict[str, object]]:
        """Collect per-field MQTT summaries suitable for ICSSignal properties.

        Each numeric field in a PUBLISH payload produces a separate signal entry
        keyed by ``topic.field_name``.  The original topic is stored as the
        ``mqttTopic`` property so callers can trace back to the source.
        """
        # Per-topic shared metadata (timestamps, QoS, packet types).
        topic_meta: Dict[str, Dict[str, object]] = {}
        # Per-field accumulators keyed by "topic.field".
        accumulators: Dict[str, _SignalAccumulator] = {}
        # Map signal_key -> raw topic for reverse lookup.
        field_topics: Dict[str, str] = {}

        def _ensure_topic_meta(topic: str) -> Dict[str, object]:
            if topic not in topic_meta:
                topic_meta[topic] = {
                    "sampleCount": 0,
                    "readCount": 0,
                    "writeCount": 0,
                    "firstSeenAt": None,
                    "lastSeenAt": None,
                    "lastReadAt": None,
                    "lastWriteAt": None,
                    "_qos_levels": set(),
                    "_packet_types": set(),
                    "mqttRetainSeen": False,
                }
            return topic_meta[topic]

        def _get_accumulator(signal_key: str, topic: str) -> _SignalAccumulator:
            if signal_key not in accumulators:
                accumulators[signal_key] = _SignalAccumulator(
                    signal_id=signal_key, protocol="mqtt",
                )
                field_topics[signal_key] = topic
            return accumulators[signal_key]

        for packet in packets:
            topic = (packet.mqtt_topic or "").strip()
            if not topic:
                continue
            meta = _ensure_topic_meta(topic)
            meta["sampleCount"] = int(meta["sampleCount"]) + 1

            first_seen = meta.get("firstSeenAt")
            if first_seen is None or packet.timestamp < float(first_seen):
                meta["firstSeenAt"] = packet.timestamp
            last_seen = meta.get("lastSeenAt")
            if last_seen is None or packet.timestamp > float(last_seen):
                meta["lastSeenAt"] = packet.timestamp

            packet_type = (packet.mqtt_packet_type or "").upper()
            if packet_type:
                meta["_packet_types"].add(packet_type)
            if packet.mqtt_qos is not None and 0 <= packet.mqtt_qos <= 2:
                meta["_qos_levels"].add(packet.mqtt_qos)
            if packet.mqtt_retain is True:
                meta["mqttRetainSeen"] = True

            if packet_type == "PUBLISH":
                is_write = packet.dst_ip == server_ip and packet.dst_port == server_port
                is_read = packet.src_ip == server_ip and packet.src_port == server_port
                role = ""
                if is_write:
                    meta["writeCount"] = int(meta["writeCount"]) + 1
                    meta["lastWriteAt"] = packet.timestamp
                    role = "write"
                elif is_read:
                    meta["readCount"] = int(meta["readCount"]) + 1
                    meta["lastReadAt"] = packet.timestamp
                    role = "read"

                for field_name, value in packet.mqtt_payload_values:
                    signal_key = f"{topic}.{field_name}"
                    acc = _get_accumulator(signal_key, topic)
                    acc.observe(value, packet.timestamp, role)

        # Build output: one entry per field across all topics.
        result: Dict[str, Dict[str, object]] = {}
        for signal_key, acc in accumulators.items():
            raw_topic = field_topics[signal_key]
            meta = topic_meta.get(raw_topic, {})
            field_name = signal_key[len(raw_topic) + 1 :]

            out: Dict[str, object] = {}
            for k, v in meta.items():
                if not k.startswith("_"):
                    out[k] = v

            qos_levels = sorted(meta.get("_qos_levels", set()))  # type: ignore[arg-type]
            packet_types = sorted(meta.get("_packet_types", set()))  # type: ignore[arg-type]
            if qos_levels:
                out["mqttQosLevels"] = ",".join(str(q) for q in qos_levels[:8])
            if packet_types:
                out["mqttPacketTypes"] = ",".join(packet_types[:8])

            out["mqttTopic"] = raw_topic
            out["mqttField"] = field_name
            out.update(acc.to_properties())
            result[signal_key] = out

        return result

    def _collect_opcua_signals(
        self,
        *,
        packets: Sequence[PacketRecord],
        server_ip: str,
        server_port: int,
    ) -> Dict[str, Dict[str, object]]:
        """Collect per-signal OPC UA summaries for ICSSignal nodes.

        Preferred identity is decoded OPC UA NodeId. If unavailable, falls back
        to endpoint/secure-channel level metadata.
        """
        summaries: Dict[str, Dict[str, object]] = {}
        accumulators: Dict[str, _SignalAccumulator] = {}
        # Correlate response messages back to request NodeIds:
        # key = (client_ip, secure_channel_id_or_-1, request_id)
        request_node_ids: Dict[Tuple[str, int, int], Tuple[str, ...]] = {}
        request_operation: Dict[Tuple[str, int, int], str] = {}

        def _request_key(
            *,
            client_ip: str,
            secure_channel_id: Optional[int],
            request_id: Optional[int],
        ) -> Optional[Tuple[str, int, int]]:
            if request_id is None:
                return None
            channel = secure_channel_id if secure_channel_id is not None else -1
            return (client_ip, channel, request_id)

        def _display_tag(node_id: str) -> str:
            # Prefer human-meaningful string NodeIds (e.g., ns=2;s=Robot_Arm).
            marker = ";s="
            if marker in node_id:
                raw = node_id.split(marker, 1)[1] or node_id
                # Normalize common quoted dotted identifiers:
                #   "a"."b"."c" -> a.b.c
                if '".' in raw or '."' in raw:
                    raw = raw.replace('"."', ".").replace('."', ".").replace('"', "")
                return raw
            return node_id

        def _get_accumulator(signal_name: str) -> _SignalAccumulator:
            if signal_name not in accumulators:
                accumulators[signal_name] = _SignalAccumulator(signal_id=signal_name, protocol="opcua")
            return accumulators[signal_name]

        def _acc(signal_name: str) -> Dict[str, object]:
            if signal_name not in summaries:
                summaries[signal_name] = {
                    "sampleCount": 0,
                    "readCount": 0,
                    "writeCount": 0,
                    "firstSeenAt": None,
                    "lastSeenAt": None,
                    "lastReadAt": None,
                    "lastWriteAt": None,
                    "_message_types": set(),
                    "_service_types": set(),
                    "_chunk_types": set(),
                    "_security_policies": set(),
                    "_endpoint_urls": set(),
                    "_secure_channel_ids": set(),
                    "_identity_kind": "unknown",
                }
            return summaries[signal_name]

        for packet in packets:
            service_type = (packet.opcua_service_type or "").strip()
            operation = (packet.opcua_operation or "").strip().lower()
            message_type = (packet.opcua_message_type or "").upper()
            from_server = packet.src_ip == server_ip and packet.src_port == server_port
            to_server = packet.dst_ip == server_ip and packet.dst_port == server_port
            explicit_node_ids = tuple(dict.fromkeys(
                n for n in packet.opcua_node_ids
                if n and not n.startswith("ns=0;") and not n.startswith("ns=1;")
            ))

            # Remember request operation/tag context for response correlation.
            if to_server and explicit_node_ids and operation in {"read", "write"}:
                key = _request_key(
                    client_ip=packet.src_ip,
                    secure_channel_id=packet.opcua_secure_channel_id,
                    request_id=packet.opcua_request_id,
                )
                if key is not None:
                    request_node_ids[key] = explicit_node_ids
                    request_operation[key] = operation
                # Feed WriteRequest values to accumulators
                if operation == "write" and packet.opcua_values:
                    for i, nid in enumerate(explicit_node_ids):
                        val = packet.opcua_values[i] if i < len(packet.opcua_values) else None
                        _get_accumulator(nid).observe(val, packet.timestamp, "write")

            signal_names: Tuple[str, ...] = ()
            identity_kind = "unknown"

            if explicit_node_ids:
                signal_names = explicit_node_ids
                identity_kind = "nodeid"
            elif from_server and service_type in {"ReadResponse", "WriteResponse"}:
                # Correlate response to the originating request to recover NodeIds.
                key = _request_key(
                    client_ip=packet.dst_ip,
                    secure_channel_id=packet.opcua_secure_channel_id,
                    request_id=packet.opcua_request_id,
                )
                if key is not None:
                    mapped_ids = request_node_ids.get(key) or ()
                    mapped_op = request_operation.get(key)
                    if mapped_ids:
                        # Only accept a mapped context when service/operation family matches.
                        if service_type == "ReadResponse" and mapped_op == "read":
                            signal_names = mapped_ids
                            identity_kind = "nodeid"
                            # Feed ReadResponse values to accumulators
                            if packet.opcua_values:
                                for i, nid in enumerate(mapped_ids):
                                    val = packet.opcua_values[i] if i < len(packet.opcua_values) else None
                                    _get_accumulator(nid).observe(val, packet.timestamp, "read")
                        elif service_type == "WriteResponse" and mapped_op == "write":
                            signal_names = mapped_ids
                            identity_kind = "nodeid"

            if not signal_names:
                continue

            for signal_name in signal_names:
                summary = _acc(signal_name)
                summary["sampleCount"] = int(summary["sampleCount"]) + 1
                summary["_identity_kind"] = identity_kind

                first_seen = summary.get("firstSeenAt")
                if first_seen is None or packet.timestamp < float(first_seen):
                    summary["firstSeenAt"] = packet.timestamp
                last_seen = summary.get("lastSeenAt")
                if last_seen is None or packet.timestamp > float(last_seen):
                    summary["lastSeenAt"] = packet.timestamp

                if message_type:
                    summary["_message_types"].add(message_type)
                if service_type:
                    summary["_service_types"].add(service_type)
                chunk_type = (packet.opcua_chunk_type or "").upper()
                if chunk_type:
                    summary["_chunk_types"].add(chunk_type)
                if packet.opcua_security_policy_uri:
                    summary["_security_policies"].add(packet.opcua_security_policy_uri)
                if packet.opcua_endpoint_url:
                    summary["_endpoint_urls"].add(packet.opcua_endpoint_url)
                if packet.opcua_secure_channel_id is not None:
                    summary["_secure_channel_ids"].add(packet.opcua_secure_channel_id)

                if operation == "read":
                    summary["readCount"] = int(summary["readCount"]) + 1
                    summary["lastReadAt"] = packet.timestamp
                elif operation == "write":
                    summary["writeCount"] = int(summary["writeCount"]) + 1
                    summary["lastWriteAt"] = packet.timestamp
                else:
                    # Keep direction-based fallback only when service decoding is absent.
                    if not service_type and message_type in {"MSG", "ACK"}:
                        if from_server:
                            summary["readCount"] = int(summary["readCount"]) + 1
                            summary["lastReadAt"] = packet.timestamp
                        elif to_server:
                            summary["writeCount"] = int(summary["writeCount"]) + 1
                            summary["lastWriteAt"] = packet.timestamp

        result: Dict[str, Dict[str, object]] = {}
        for signal_name, summary in summaries.items():
            # Skip TypeDefinition schema reads — not physical process signals.
            if signal_name.startswith("TD_"):
                continue
            # Skip numeric-only NodeIds (ns=N;i=NNNN) — these are server
            # metadata/attribute reads, not physical process variables.
            # if ";i=" in signal_name and ";s=" not in signal_name:
            #     continue
            # Skip signals with no numeric value observations (strings,
            # datetimes, and other non-numeric OPC UA types).
            acc = accumulators.get(signal_name)
            if acc is None or acc.sample_count == 0:
                continue

            out = {k: v for k, v in summary.items() if not k.startswith("_")}
            message_types = sorted(summary["_message_types"])  # type: ignore[index]
            service_types = sorted(summary["_service_types"])  # type: ignore[index]
            chunk_types = sorted(summary["_chunk_types"])  # type: ignore[index]
            security_policies = sorted(summary["_security_policies"])  # type: ignore[index]
            endpoint_urls = sorted(summary["_endpoint_urls"])  # type: ignore[index]
            secure_channel_ids = sorted(summary["_secure_channel_ids"])  # type: ignore[index]
            identity_kind = str(summary.get("_identity_kind") or "unknown")
            if message_types:
                out["opcuaMessageTypes"] = ",".join(message_types[:8])
            if service_types:
                out["opcuaServiceTypes"] = ",".join(service_types[:8])
            if chunk_types:
                out["opcuaChunkTypes"] = ",".join(chunk_types[:3])
            if security_policies:
                out["opcuaSecurityPolicies"] = ",".join(security_policies[:4])
            if endpoint_urls:
                out["opcuaEndpointUrls"] = ",".join(endpoint_urls[:4])
            if secure_channel_ids:
                out["opcuaSecureChannelIds"] = ",".join(str(scid) for scid in secure_channel_ids[:8])
            out["opcuaIdentityKind"] = identity_kind
            out["opcuaNodeId"] = signal_name
            out["opcuaTag"] = _display_tag(signal_name)
            out.update(acc.to_properties())
            result[signal_name] = out
        return result

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
        ports: Set[int] = set()
        for pkt in packets:
            if (
                pkt.src_ip == client_ip
                and pkt.dst_ip == server_ip
                and pkt.dst_port == service_port
                and pkt.src_port > 0
            ):
                ports.add(pkt.src_port)
            elif (
                pkt.src_ip == server_ip
                and pkt.dst_ip == client_ip
                and pkt.src_port == service_port
                and pkt.dst_port > 0
            ):
                ports.add(pkt.dst_port)
        return sorted(ports)

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
        if telemetry_index is None:
            return None

        candidate_ports = sorted({int(port) for port in source_ports if int(port) > 0})
        if candidate_ports:
            matches_by_guid: Dict[str, Tuple[int, int, "ProcessContext"]] = {}
            for src_port in candidate_ports:
                process_context = telemetry_index.find_process_for_connection(
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    dst_port=service_port,
                    protocol=protocol,
                    src_port=src_port,
                    require_src_port_match=True,
                )
                if (
                    not process_context
                    or not process_context.is_valid()
                    or not process_context.process_guid
                ):
                    continue

                current = matches_by_guid.get(process_context.process_guid)
                if current is None:
                    matches_by_guid[process_context.process_guid] = (1, src_port, process_context)
                else:
                    matches_by_guid[process_context.process_guid] = (
                        current[0] + 1,
                        min(current[1], src_port),
                        current[2],
                    )

            if matches_by_guid:
                _, _, best_context = max(
                    matches_by_guid.values(),
                    key=lambda value: (value[0], -value[1]),
                )
                return best_context

            # Source ports were observed but had no deterministic telemetry match.
            # Avoid ambiguous endpoint-only attribution in this case.
            return None

        process_context = telemetry_index.find_process_for_connection(
            src_ip=client_ip,
            dst_ip=server_ip,
            dst_port=service_port,
            protocol=protocol,
        )
        if process_context and process_context.is_valid() and process_context.process_guid:
            return process_context
        return None

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
        process_index: Optional[TemporalProcessIndex] = None,
        telemetry_index: Optional["TelemetryConnectionIndex"] = None,
    ) -> str:
        """Add a Modbus group and return the relationship type used."""
        service_name = self.config.service_map.get(group.service_port, "Modbus")

        # Try to find a Process node that matches this traffic
        # PRIORITY 1: Check telemetry first - if telemetry shows which process made this connection, use it
        # PRIORITY 2: Fall back to temporal correlation if no telemetry match
        client_node_id: Optional[str] = None
        client_is_process = False
        process_context: Optional["ProcessContext"] = None
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

        # Fall back to temporal correlation if no telemetry match (unless telemetry_attribution_only is set)
        if client_node_id is None and process_index and packets and not self.config.telemetry_attribution_only:
            timestamps = [p.timestamp for p in packets]
            range_start = min(timestamps)
            range_end = max(timestamps)

            process_entry = process_index.find_process_for_range(
                group.client_ip, range_start, range_end
            )
            if process_entry:
                client_node_id = process_entry.process_guid
                client_is_process = True
                # Create ProcessContext for temporal match
                from .correlation import ProcessContext
                process_context = ProcessContext(
                    process_guid=process_entry.process_guid,
                    process_image=process_entry.process_image,
                    process_id=process_entry.process_id,
                    user="",
                    computer=process_entry.host,
                )
                correlation_source = "temporal"
                correlation_confidence = 0.8
                logger.debug(
                    "Attributed Modbus group to Process %s (%s) on %s via temporal correlation",
                    process_entry.process_guid,
                    process_entry.process_image,
                    process_entry.host,
                )

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(group.client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname, asset_guid, process_statements, runs_statements
            )
            client_is_process = True
            if process_context is None:
                from .correlation import ProcessContext
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
            if not (self.config.telemetry_attribution_only and correlation_source != "telemetry"):
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
        if group.connections:
            relationship_properties["meanBytesPerConnection"] = round(
                relationship_properties["totalBytes"] / len(group.connections), 2
            )

        # Add process correlation metadata
        if client_is_process and process_context:
            if correlation_source == "telemetry":
                relationship_properties["correlatedFromTelemetry"] = True
                relationship_properties["correlatedProcessGuid"] = process_context.process_guid
                relationship_properties["correlatedProcessImage"] = process_context.process_image
                relationship_properties["correlatedProcessId"] = process_context.process_id
                relationship_properties["note"] = (
                    f"Modbus traffic correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) from telemetry connection"
                )
            elif not self.config.telemetry_attribution_only:
                # Only add temporal inference properties when temporal attribution is allowed
                relationship_properties["temporallyInferred"] = True
                relationship_properties["correlatedProcessGuid"] = process_context.process_guid
                relationship_properties["correlatedProcessImage"] = process_context.process_image
                relationship_properties["correlatedProcessId"] = process_context.process_id
                relationship_properties["note"] = (
                    f"Modbus traffic temporally correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) based on host activity overlap"
                )

        # Use Process label if we found a matching process, otherwise NetworkService
        source_label = "Process"
        relationship_statement = cypher_emit.create_connection_statement(
            client_node_id,
            server_node_id,
            relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
        )
        relationship_statements.append(relationship_statement)
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
        process_index: Optional[TemporalProcessIndex] = None,
        telemetry_index: Optional["TelemetryConnectionIndex"] = None,
    ) -> str:
        """Add an HTTP monitor group and return the relationship type used."""
        service_name = "Modbus Monitor"

        # Try to find a Process node that matches this traffic.
        # Priority: deterministic telemetry match, then temporal fallback.
        client_node_id: Optional[str] = None
        client_is_process = False
        process_context: Optional["ProcessContext"] = None
        process_entry: Optional[TemporalProcessEntry] = None
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

        # Temporal correlation fallback (skip if telemetry_attribution_only)
        if client_node_id is None and process_index and packets and not self.config.telemetry_attribution_only:
            timestamps = [p.timestamp for p in packets]
            range_start = min(timestamps)
            range_end = max(timestamps)

            process_entry = process_index.find_process_for_range(
                group.client_ip, range_start, range_end
            )
            if process_entry:
                client_node_id = process_entry.process_guid
                client_is_process = True
                from .correlation import ProcessContext
                process_context = ProcessContext(
                    process_guid=process_entry.process_guid,
                    process_image=process_entry.process_image,
                    process_id=process_entry.process_id,
                    user="",
                    computer=process_entry.host,
                )
                correlation_source = "temporal"
                logger.debug(
                    "Attributed HTTP monitor group to Process %s (%s) on %s",
                    process_entry.process_guid,
                    process_entry.process_image,
                    process_entry.host,
                )

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(group.client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname, asset_guid, process_statements, runs_statements
            )
            client_is_process = True
            if process_context is None:
                from .correlation import ProcessContext
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
        if group.connections:
            relationship_properties["meanBytesPerConnection"] = round(
                relationship_properties["totalBytes"] / len(group.connections), 2
            )

        if client_is_process and process_context:
            if correlation_source == "telemetry":
                relationship_properties["correlatedFromTelemetry"] = True
                relationship_properties["correlatedProcessGuid"] = process_context.process_guid
                relationship_properties["correlatedProcessImage"] = process_context.process_image
                relationship_properties["correlatedProcessId"] = process_context.process_id
                relationship_properties["note"] = (
                    f"HTTP monitor traffic correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) from telemetry connection"
                )
            elif correlation_source == "temporal" and not self.config.telemetry_attribution_only:
                relationship_properties["temporallyInferred"] = True
                relationship_properties["correlatedProcessGuid"] = process_context.process_guid
                relationship_properties["correlatedProcessImage"] = process_context.process_image
                relationship_properties["correlatedProcessId"] = process_context.process_id
                relationship_properties["note"] = (
                    f"HTTP monitor traffic temporally correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) based on host activity overlap"
                )

        # Use Process label if we found a matching process, otherwise NetworkService
        source_label = "Process"
        relationship_statement = cypher_emit.create_connection_statement(
            client_node_id,
            server_node_id,
            relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
        )
        relationship_statements.append(relationship_statement)
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
        process_index: Optional[TemporalProcessIndex] = None,
        telemetry_index: Optional["TelemetryConnectionIndex"] = None,
    ) -> str:
        """Add a collapsed group and return the relationship type used."""
        # Try to find a Process node that matches this traffic.
        # Priority: deterministic telemetry match, then temporal fallback.
        client_node_id: Optional[str] = None
        client_is_process = False
        process_context: Optional["ProcessContext"] = None
        process_entry: Optional[TemporalProcessEntry] = None
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

        if client_node_id is None and process_index and packets and not self.config.telemetry_attribution_only:
            # Get time range from packets
            timestamps = [p.timestamp for p in packets]
            range_start = min(timestamps)
            range_end = max(timestamps)

            process_entry = process_index.find_process_for_range(
                group.client_ip, range_start, range_end
            )
            if process_entry:
                # Use the Process node instead of creating an Ephemeral Client
                client_node_id = process_entry.process_guid
                client_is_process = True
                from .correlation import ProcessContext
                process_context = ProcessContext(
                    process_guid=process_entry.process_guid,
                    process_image=process_entry.process_image,
                    process_id=process_entry.process_id,
                    user="",
                    computer=process_entry.host,
                )
                correlation_source = "temporal"
                logger.debug(
                    "Attributed collapsed group to Process %s (%s) on %s",
                    process_entry.process_guid,
                    process_entry.process_image,
                    process_entry.host,
                )

        if client_node_id is None:
            hostname, ip_address = self._resolve_host(group.client_ip)
            asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
            client_node_id = self._ensure_placeholder_process(
                hostname, asset_guid, process_statements, runs_statements
            )
            client_is_process = True
            if process_context is None:
                from .correlation import ProcessContext
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

        relationship_properties = self._relationship_properties(connection_key, packets)
        relationship_properties.update(
            {
                "SourcePort": "aggregated",
                "aggregated": "port_group",
                "canonicalCount": len(group.connections),
                "uniqueSourcePorts": len(group.client_ports),
            }
        )
        if group.connections:
            relationship_properties["meanBytesPerConnection"] = round(
                relationship_properties["totalBytes"] / len(group.connections), 2
            )
        if group.client_ports:
            sorted_ports = sorted(group.client_ports)
            relationship_properties["sourcePortMin"] = sorted_ports[0]
            relationship_properties["sourcePortMax"] = sorted_ports[-1]
            if len(sorted_ports) <= 8:
                relationship_properties["sourcePortSet"] = ",".join(str(port) for port in sorted_ports)

        if client_is_process and process_context:
            if correlation_source == "telemetry":
                relationship_properties["correlatedFromTelemetry"] = True
                relationship_properties["correlatedProcessGuid"] = process_context.process_guid
                relationship_properties["correlatedProcessImage"] = process_context.process_image
                relationship_properties["correlatedProcessId"] = process_context.process_id
                relationship_properties["note"] = (
                    f"PCAP traffic correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) from telemetry connection"
                )
            elif correlation_source == "temporal" and not self.config.telemetry_attribution_only:
                relationship_properties["temporallyInferred"] = True
                relationship_properties["correlatedProcessGuid"] = process_context.process_guid
                relationship_properties["correlatedProcessImage"] = process_context.process_image
                relationship_properties["correlatedProcessId"] = process_context.process_id
                relationship_properties["note"] = (
                    f"PCAP traffic temporally correlated to process {process_context.process_image} "
                    f"(PID {process_context.process_id}) based on host activity overlap"
                )

        # Use Process label if we found a matching process, otherwise NetworkService
        source_label = "Process"
        relationship_statement = cypher_emit.create_connection_statement(
            client_node_id,
            server_node_id,
            relationship_properties,
            relationship_name=rel_type,
            source_label=source_label,
            dest_label=dst_label,
        )
        relationship_statements.append(relationship_statement)
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
            shutil.copyfile(self.config.base_cypher, self.config.output_cypher)
            return

        base_text = Path(self.config.base_cypher).read_text(encoding="utf-8")
        with Path(self.config.output_cypher).open("w", encoding="utf-8") as handle:
            handle.write(base_text)
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
