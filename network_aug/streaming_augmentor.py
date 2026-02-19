"""Streaming augmentor for memory-efficient processing of large PCAP datasets.

This module provides a complete augmentation pipeline that uses the streaming
PCAP index, processing files one at a time to handle multi-GB captures without
running out of memory.

It keeps the streaming memory profile while emitting non-streaming-compatible
Modbus register artifacts:
- Register nodes with HAS_REGISTER edges
- READ_REGISTER / WRITE_REGISTER process attribution edges
- SDT-based register summary properties
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from tqdm import tqdm

from . import cypher_emit
from .correlation import (
    CorrelatedConnection,
    CorrelationConfig,
    CorrelationEngine,
    ProcessContext,
    TelemetryAnchor,
    TelemetryConnectionIndex,
)
from .cypher_reader import CypherConnectionExtractor, ExistingConnection
from .enhancer import (
    AugmentationConfig,
    _SDTCompressor,
)
from .features import (
    PreSortedPackets,
    aggregate_tcp_flags,
    average_packet_size,
    count_tcp_retransmits,
    directional_totals,
    directionality_ratio,
    dominant_protocol,
    duration_seconds,
    extract_http_features,
    extract_tls_sni,
    mean_interarrival_time,
    mean_rtt_ms,
    resolve_mac_addresses,
    total_bytes,
)
from .grouping import _is_service_port
from .models import ConnectionKey, PacketRecord
from .streaming import ConnectionStats, StreamingPCAPIndex


def _generate_node_guid(*components: object) -> str:
    """Generate a deterministic UUID from components."""
    raw = ":".join(str(c) for c in components)
    digest = hashlib.md5(raw.encode("utf-8")).hexdigest()
    return str(uuid.UUID(digest))


def _generate_node_guid_v2(node_type: str, hostname: str, *identifiers: object) -> str:
    """Replicate the GUID scheme used by the base provenance notebook."""
    components = [node_type, hostname] + [str(value) for value in identifiers if value not in (None, "")]
    combined = "|".join(components).lower()
    digest = hashlib.md5(combined.encode("utf-8")).hexdigest()
    return str(uuid.UUID(digest))


def _generate_node_guid_v2_braced(node_type: str, hostname: str, *identifiers: object) -> str:
    """Generate a deterministic GUID compatible with brace-wrapped base exports."""
    return f"{{{_generate_node_guid_v2(node_type, hostname, *identifiers)}}}"


@dataclass
class CorrelationStats:
    """Statistics about the correlation process."""
    total_pcap_connections: int = 0
    correlation_attempts: int = 0
    successful_correlations: int = 0
    session_port_matches: int = 0
    temporal_matches: int = 0
    pcap_only_connections: int = 0
    process_attributed_registers: int = 0


class StreamingAugmentor:
    """Memory-efficient augmentor for large PCAP datasets with full correlation support.

    Unlike the original streaming augmentor which only added new edges,
    this version also:
    - Correlates PCAP connections to existing telemetry
    - Enriches existing edges with PCAP-derived metrics
    - Creates Register nodes and READ/WRITE_REGISTER relationships for Modbus
    """

    def __init__(self, config: AugmentationConfig) -> None:
        self.config = config
        self._asset_ip_map = self._load_asset_lookup()
        self._correlation_stats = CorrelationStats()

    def _load_asset_lookup(self) -> Dict[str, str]:
        """Build IP-to-hostname mapping from config and asset file."""
        mapping = dict(self.config.ip_hostname_map)

        if self.config.asset_file and self.config.asset_file.exists():
            try:
                import yaml
                with open(self.config.asset_file) as f:
                    assets = yaml.safe_load(f)
                    for asset in assets.get("assets", []):
                        hostname = asset.get("hostname")
                        ip = asset.get("ip")
                        if hostname and ip:
                            mapping[ip] = hostname
            except Exception:
                pass

        return mapping

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname, or return IP if unknown."""
        return self._asset_ip_map.get(ip, ip)

    def _load_existing_connections(self) -> Tuple[Set[str], List[ExistingConnection]]:
        """Load existing connection identifiers from the base Cypher file."""
        # Resolve asset file path (same logic as non-streaming version)
        asset_file = self.config.asset_file
        if asset_file and not asset_file.is_absolute():
            cwd_candidate = Path.cwd() / asset_file
            if cwd_candidate.exists():
                asset_file = cwd_candidate.resolve()
            else:
                asset_file = (self.config.base_cypher.parent / asset_file).resolve()
        if asset_file is None:
            cwd_candidate = Path.cwd() / "assets.yaml"
            cypher_candidate = self.config.base_cypher.parent / "assets.yaml"
            if cwd_candidate.exists():
                asset_file = cwd_candidate
            elif cypher_candidate.exists():
                asset_file = cypher_candidate

        extractor = CypherConnectionExtractor(self.config.base_cypher, asset_file=asset_file)
        existing = extractor.load_connections()

        # Filter for target relationship type
        target_rels = {self.config.relationship_name.upper()}
        filtered = [conn for conn in existing if conn.rel_type in target_rels]
        existing_ids = {conn.key.bidirectional_id() for conn in filtered}
        return existing_ids, filtered

    def run(self) -> Tuple[int, int]:
        """Execute streaming augmentation with correlation and return (node_count, relationship_count)."""
        print("Loading base graph...")
        base_connection_ids, existing_connections = self._load_existing_connections()
        print(f"Found {len(base_connection_ids)} existing connections in base graph")

        # Build telemetry index for correlation
        print("Building telemetry index for correlation...")
        telemetry_index = TelemetryConnectionIndex(existing_connections)
        print(f"  - {telemetry_index.anchor_count} anchors indexed")
        print(f"  - {telemetry_index.anchors_with_session_metadata} anchors with session metadata")
        print(f"  - {telemetry_index.total_session_ports} total session ports")

        # Build correlation engine
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

        print("Processing PCAP files in streaming mode...")
        pcap_index = StreamingPCAPIndex(
            self.config.pcap_directory,
            packet_limit_per_file=self.config.packet_limit,
        )
        pcap_index.build()

        print("Generating augmented graph with correlation...")
        asset_statements: Dict[str, str] = {}
        service_statements: Dict[str, str] = {}
        register_statements: Dict[str, str] = {}
        relationship_statements: List[str] = []
        edge_update_statements: List[str] = []
        process_register_statements: List[str] = []

        # Track which PCAP connections have been correlated
        correlated_cids: Set[str] = set()

        # Group for PCAP-only connections by server endpoint
        pcap_only_groups: Dict[str, List[ConnectionStats]] = defaultdict(list)

        # Phase 1: Correlate PCAP connections to telemetry
        print("Phase 1: Correlating PCAP connections to telemetry...")

        # Group correlations by telemetry anchor (edge)
        anchor_correlations: Dict[Tuple[str, str], List[Tuple[ConnectionStats, CorrelatedConnection]]] = defaultdict(list)

        for stats in tqdm(pcap_index.iter_stats(), desc="Correlating", unit="conn"):
            self._correlation_stats.total_pcap_connections += 1

            # Try to correlate this PCAP connection
            indexed_conn = stats.to_indexed_connection()
            correlated = correlation_engine.correlate(indexed_conn, telemetry_index)

            if correlated:
                # Successfully correlated to telemetry
                correlated_cids.add(stats.canonical_id)
                anchor = correlated.telemetry_anchor
                edge_key = (anchor.src_guid, anchor.dst_guid)
                anchor_correlations[edge_key].append((stats, correlated))
                self._correlation_stats.successful_correlations += 1
            else:
                # PCAP-only connection - group for later processing
                if self._is_interesting(stats):
                    self._correlation_stats.pcap_only_connections += 1

                    # Determine server endpoint for grouping
                    src_is_service = _is_service_port(stats.origin.src_port)
                    dst_is_service = _is_service_port(stats.origin.dst_port)

                    if dst_is_service and not src_is_service:
                        server_key = f"{stats.origin.dst_ip}:{stats.origin.dst_port}"
                    elif src_is_service and not dst_is_service:
                        server_key = f"{stats.origin.src_ip}:{stats.origin.src_port}"
                    else:
                        server_key = stats.canonical_id

                    pcap_only_groups[server_key].append(stats)

        # Get correlation engine statistics
        engine_stats = correlation_engine.get_statistics()
        self._correlation_stats.correlation_attempts = engine_stats.get("total_attempts", 0)
        self._correlation_stats.session_port_matches = engine_stats.get("session_port_matches", 0)
        self._correlation_stats.temporal_matches = engine_stats.get("temporal_matches", 0)

        print(f"Correlation: {self._correlation_stats.successful_correlations}/{self._correlation_stats.total_pcap_connections} "
              f"({100.0 * self._correlation_stats.successful_correlations / max(1, self._correlation_stats.total_pcap_connections):.1f}%)")
        print(f"  - Session port matches: {self._correlation_stats.session_port_matches}")
        print(f"  - Temporal matches: {self._correlation_stats.temporal_matches}")
        print(f"  - PCAP-only connections: {self._correlation_stats.pcap_only_connections}")

        # Phase 2: Generate edge update statements for correlated connections
        print("Phase 2: Generating edge updates for correlated connections...")
        for edge_key, correlations in tqdm(anchor_correlations.items(), desc="Edge updates", unit="edge"):
            src_guid, dst_guid = edge_key
            if not src_guid or not dst_guid:
                continue

            # Combine sampled packets from correlated PCAP connections for edge features
            all_packets: List[PacketRecord] = []
            best_confidence = 0.0
            best_method = "unknown"
            representative_anchor: Optional[TelemetryAnchor] = None
            representative_corr: Optional[CorrelatedConnection] = None

            for stats, corr in correlations:
                all_packets.extend(stats._sample_packets)
                if corr.confidence > best_confidence:
                    best_confidence = corr.confidence
                    best_method = corr.correlation_method
                    representative_anchor = corr.telemetry_anchor
                    representative_corr = corr

            if not all_packets or representative_anchor is None or representative_corr is None:
                continue

            anchor = representative_anchor
            base_key = anchor.connection_key
            proto = base_key.protocol.lower()

            # Determine source port from PCAP if telemetry doesn't have it
            if base_key.src_port > 0:
                src_port = base_key.src_port
            elif all_packets:
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

            # Compute feature properties from packets
            feature_props = self._relationship_properties(connection_view, all_packets)

            # Add correlation metadata
            feature_props["correlationConfidence"] = round(best_confidence, 4)
            feature_props["correlationMethod"] = best_method
            feature_props["correlatedPcapConnections"] = len(correlations)

            # Preserve process context reference
            proc_ctx = representative_corr.process_context

            if proc_ctx and proc_ctx.is_valid():
                feature_props["correlatedProcessGuid"] = proc_ctx.process_guid
                feature_props["correlatedProcessImage"] = proc_ctx.process_image

            # Fill in missing network properties
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
            anchor_rel_type = anchor.rel_type.upper()

            statement = (
                f"MATCH (src:{src_label} {{guid: '{src_guid_escaped}'}})\n"
                f"MATCH (dst:{dst_label} {{guid: '{dst_guid_escaped}'}})\n"
                f"MATCH (src)-[rel:{anchor_rel_type}]->(dst)\n"
                f"SET rel += {cypher_props}\n"
                f"SET rel.pcapAugmented = true;"
            )

            edge_update_statements.append(statement)

            # Generate process-to-register attribution for Modbus
            if (
                self.config.enable_process_attribution
                and proc_ctx
                and proc_ctx.is_valid()
                and base_key.dst_port == 502  # Modbus port
            ):
                server_hostname = self._resolve_hostname(base_key.dst_ip)
                server_asset_guid = self._ensure_asset_node(
                    ip=base_key.dst_ip,
                    asset_statements=asset_statements,
                )
                register_summaries = self._merge_register_summaries(
                    [stats.get_register_summaries() for stats, _ in correlations]
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

                register_stmts, register_count = self._generate_process_register_access(
                    process_context=proc_ctx,
                    register_summaries=register_summaries,
                    server_hostname=server_hostname,
                    server_port=base_key.dst_port,
                    correlation_confidence=best_confidence,
                )
                process_register_statements.extend(register_stmts)
                self._correlation_stats.process_attributed_registers += register_count

        print(f"Generated {len(edge_update_statements)} edge updates")
        print(f"Generated {len(process_register_statements)} READ/WRITE_REGISTER relationships")

        # Phase 3: Process PCAP-only connections (not in telemetry)
        print(f"Phase 3: Processing {len(pcap_only_groups)} PCAP-only server groups...")
        for server_key, group_stats in tqdm(pcap_only_groups.items(), desc="PCAP-only", unit="group"):
            if len(group_stats) == 1:
                stats = group_stats[0]
                rel_stmt = self._emit_connection(
                    stats,
                    asset_statements,
                    service_statements,
                    register_statements,
                )
                if rel_stmt:
                    relationship_statements.append(rel_stmt)
            else:
                rel_stmt = self._emit_aggregated_group(
                    group_stats,
                    asset_statements,
                    service_statements,
                    register_statements,
                )
                if rel_stmt:
                    relationship_statements.append(rel_stmt)

        print(f"Generated {len(relationship_statements)} new PCAP-only relationships")

        # Write output
        total_rels = len(edge_update_statements) + len(relationship_statements) + len(process_register_statements)
        print(f"Writing {total_rels} statements to output...")
        self._write_output(
            asset_statements,
            service_statements,
            register_statements,
            relationship_statements,
            edge_update_statements,
            process_register_statements,
        )

        # Print summary
        self._print_summary()

        node_count = len(asset_statements) + len(service_statements) + len(register_statements)
        return node_count, total_rels

    def _relationship_properties(
        self,
        connection: ConnectionKey,
        packets: Sequence[PacketRecord],
    ) -> Dict[str, object]:
        """Compute relationship properties from packets."""
        sorted_packets = PreSortedPackets.from_packets(packets)
        timestamps = [pkt.timestamp for pkt in sorted_packets]
        bytes_out, bytes_in, packets_out, packets_in = directional_totals(connection, sorted_packets)
        dir_index = directionality_ratio(bytes_out, bytes_in)
        inter_arrival = mean_interarrival_time(sorted_packets)
        tcp_flags = aggregate_tcp_flags(sorted_packets)
        retransmits = count_tcp_retransmits(sorted_packets)
        src_mac, dst_mac = resolve_mac_addresses(connection, sorted_packets)
        http_features = extract_http_features(sorted_packets)
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
            "rttMs": round(rtt_ms, 3) if rtt_ms > 0.0 else None,
        }

    def _is_interesting(self, stats: ConnectionStats) -> bool:
        """Check if a connection is interesting based on policy."""
        if stats.packet_count < 3:
            return False

        for ip in (stats.origin.src_ip, stats.origin.dst_ip):
            if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                return False

        noisy_ports = {137, 138, 5353, 1900}
        if stats.origin.src_port in noisy_ports or stats.origin.dst_port in noisy_ports:
            return False

        return True

    def _emit_connection(
        self,
        stats: ConnectionStats,
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        register_statements: Dict[str, str],
    ) -> Optional[str]:
        """Emit Cypher statements for a single connection."""
        src_is_service = _is_service_port(stats.origin.src_port)
        dst_is_service = _is_service_port(stats.origin.dst_port)

        if dst_is_service and not src_is_service:
            client_ip, client_port = stats.origin.src_ip, 0
            server_ip, server_port = stats.origin.dst_ip, stats.origin.dst_port
        elif src_is_service and not dst_is_service:
            client_ip, client_port = stats.origin.dst_ip, 0
            server_ip, server_port = stats.origin.src_ip, stats.origin.src_port
        else:
            client_ip, client_port = stats.origin.src_ip, stats.origin.src_port
            server_ip, server_port = stats.origin.dst_ip, stats.origin.dst_port

        src_node_id = self._ensure_network_service_node(
            ip=client_ip,
            port=client_port,
            protocol=stats.origin.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            service_name="Ephemeral Client" if client_port == 0 else None,
        )

        dst_node_id = self._ensure_network_service_node(
            ip=server_ip,
            port=server_port,
            protocol=stats.origin.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
        )

        if not src_node_id or not dst_node_id:
            return None

        if server_port == 502:
            server_asset_guid = self._ensure_asset_node(
                ip=server_ip,
                asset_statements=asset_statements,
            )
            server_hostname = self._resolve_hostname(server_ip)
            register_summaries = stats.get_register_summaries()
            for (address, unit_id, register_type), summary in register_summaries.items():
                self._ensure_register_node(
                    host=server_hostname,
                    port=server_port,
                    asset_guid=server_asset_guid,
                    register_address=address,
                    unit_id=unit_id,
                    register_type=register_type,
                    register_statements=register_statements,
                    register_summary=summary,
                )

        rel_props = stats.to_properties()

        return cypher_emit.create_connection_statement(
            src_node_id,
            dst_node_id,
            rel_props,
            relationship_name=self.config.relationship_name,
        )

    def _emit_aggregated_group(
        self,
        group_stats: List[ConnectionStats],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        register_statements: Dict[str, str],
    ) -> Optional[str]:
        """Emit Cypher for an aggregated group of connections."""
        if not group_stats:
            return None

        first = group_stats[0]
        src_is_service = _is_service_port(first.origin.src_port)
        dst_is_service = _is_service_port(first.origin.dst_port)

        if dst_is_service and not src_is_service:
            server_ip, server_port = first.origin.dst_ip, first.origin.dst_port
            client_ip = first.origin.src_ip
        elif src_is_service and not dst_is_service:
            server_ip, server_port = first.origin.src_ip, first.origin.src_port
            client_ip = first.origin.dst_ip
        else:
            return self._emit_connection(first, asset_statements, service_statements, register_statements)

        client_ips: Set[str] = set()
        for stats in group_stats:
            if stats.origin.dst_port == server_port:
                client_ips.add(stats.origin.src_ip)
            elif stats.origin.src_port == server_port:
                client_ips.add(stats.origin.dst_ip)

        if len(client_ips) > 1:
            client_groups: Dict[str, List[ConnectionStats]] = defaultdict(list)
            for stats in group_stats:
                if stats.origin.dst_port == server_port:
                    client_groups[stats.origin.src_ip].append(stats)
                elif stats.origin.src_port == server_port:
                    client_groups[stats.origin.dst_ip].append(stats)

            first_client = next(iter(client_groups.keys()))
            group_stats = client_groups[first_client]
            client_ip = first_client

        total_packets = sum(s.packet_count for s in group_stats)
        total_bytes = sum(s.total_bytes for s in group_stats)
        first_seen = min(s.first_seen for s in group_stats if s.first_seen != float('inf'))
        last_seen = max(s.last_seen for s in group_stats if s.last_seen > 0)
        unique_client_ports = len(set().union(*(s.client_ports_seen for s in group_stats)))

        all_function_codes: Set[int] = set()
        all_unit_ids: Set[int] = set()
        all_registers: Set[int] = set()
        total_transactions = 0
        for stats in group_stats:
            all_function_codes.update(stats.modbus_function_codes)
            all_unit_ids.update(stats.modbus_unit_ids)
            all_registers.update(stats.modbus_registers_seen)
            total_transactions += stats.modbus_transaction_count

        protocols: Dict[str, int] = defaultdict(int)
        for stats in group_stats:
            protocols[stats.high_level_protocol] += stats.packet_count
        dominant_protocol = max(protocols.keys(), key=lambda p: protocols[p]) if protocols else "UNKNOWN"

        src_node_id = self._ensure_network_service_node(
            ip=client_ip,
            port=0,
            protocol=first.origin.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            service_name="Ephemeral Client",
        )

        dst_node_id = self._ensure_network_service_node(
            ip=server_ip,
            port=server_port,
            protocol=first.origin.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
        )

        if not src_node_id or not dst_node_id:
            return None

        if server_port == 502:
            server_asset_guid = self._ensure_asset_node(
                ip=server_ip,
                asset_statements=asset_statements,
            )
            server_hostname = self._resolve_hostname(server_ip)
            register_summaries = self._merge_register_summaries(
                [stats.get_register_summaries() for stats in group_stats]
            )
            for (address, unit_id, register_type), summary in register_summaries.items():
                self._ensure_register_node(
                    host=server_hostname,
                    port=server_port,
                    asset_guid=server_asset_guid,
                    register_address=address,
                    unit_id=unit_id,
                    register_type=register_type,
                    register_statements=register_statements,
                    register_summary=summary,
                )

        rel_props: Dict[str, object] = {
            "pcapAugmented": True,
            "aggregatedConnections": len(group_stats),
            "uniqueClientPorts": unique_client_ports,
            "packetCount": total_packets,
            "totalBytes": total_bytes,
        }

        if first_seen != float('inf') and last_seen > 0:
            rel_props["durationSeconds"] = round(last_seen - first_seen, 3)
            rel_props["firstPacketTime"] = round(first_seen, 3)
            rel_props["lastPacketTime"] = round(last_seen, 3)

        if dominant_protocol != "UNKNOWN":
            rel_props["dominantProtocol"] = dominant_protocol

        if all_function_codes:
            rel_props["modbusFunctionCodes"] = ",".join(str(fc) for fc in sorted(all_function_codes))
        if all_unit_ids:
            rel_props["modbusUnitIds"] = ",".join(str(uid) for uid in sorted(all_unit_ids))
        if all_registers:
            rel_props["modbusRegisterCount"] = len(all_registers)
        if total_transactions > 0:
            rel_props["modbusTransactions"] = total_transactions

        return cypher_emit.create_connection_statement(
            src_node_id,
            dst_node_id,
            rel_props,
            relationship_name=self.config.relationship_name,
        )

    def _merge_register_summaries(
        self,
        summary_maps: Sequence[Dict[Tuple[int, Optional[int], str], Dict[str, object]]],
    ) -> Dict[Tuple[int, Optional[int], str], Dict[str, object]]:
        """Merge per-connection register summaries into one map."""
        merged: Dict[Tuple[int, Optional[int], str], Dict[str, object]] = {}
        timeline_source_score: Dict[Tuple[int, Optional[int], str], Tuple[int, int, int, int]] = {}
        timeline_points_by_key: Dict[Tuple[int, Optional[int], str], List[Tuple[float, int]]] = defaultdict(list)
        timeline_tolerance_by_key: Dict[Tuple[int, Optional[int], str], List[float]] = defaultdict(list)

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
                    result[int(value_raw)] = result.get(int(value_raw), 0) + int(count_raw)
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
            """Rank compressed summaries by detail richness.

            Prefer summaries with:
            1) more SDT points,
            2) more distinct values,
            3) more RLE runs,
            4) more samples.
            """
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
                    timeline_points_by_key[key].extend(parsed_timeline)
                if incoming_tolerance is not None and incoming_tolerance > 0:
                    timeline_tolerance_by_key[key].append(incoming_tolerance)

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

                # Preserve truncation signal if any contributing chunk was truncated.
                if current.get("rleTruncated") or incoming_dict.get("rleTruncated"):
                    current["rleTruncated"] = True

                # Keep compressed timeline fields from the most informative summary.
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

        # Rebuild SDT timelines from all contributing timeline points per register.
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

        # Recompute ratios against merged sample counts to keep fields consistent.
        for summary in merged.values():
            samples = _to_int(summary, "valueSamples")
            rle_runs = _to_int(summary, "rleRuns")
            timeline_points = _to_int(summary, "timelinePoints")

            if samples > 0 and rle_runs > 0:
                summary["rleCompressionRatio"] = round(samples / rle_runs, 2)
            if samples > 0 and timeline_points > 0:
                summary["compressionRatio"] = round(samples / timeline_points, 2)

        return merged

    def _generate_process_register_access(
        self,
        process_context: ProcessContext,
        register_summaries: Dict[Tuple[int, Optional[int], str], Dict[str, object]],
        server_hostname: str,
        server_port: int,
        correlation_confidence: float,
    ) -> Tuple[List[str], int]:
        """Generate READ/WRITE_REGISTER relationship statements for process attribution."""
        statements: List[str] = []
        edge_count = 0
        if not register_summaries:
            return [], 0

        proc_guid_escaped = cypher_emit.escape_cypher_string(process_context.process_guid)
        for (register_address, unit_id, register_type), summary in register_summaries.items():
            register_guid = _generate_node_guid_v2_braced(
                "Register",
                server_hostname,
                server_port,
                unit_id,
                register_address,
                register_type,
            )
            register_guid_escaped = cypher_emit.escape_cypher_string(register_guid)

            read_count = int(summary.get("readCount") or 0)
            write_count = int(summary.get("writeCount") or 0)

            common_props: Dict[str, object] = {
                "correlationConfidence": round(correlation_confidence, 4),
                "inferredFrom": "pcap",
                "pcapAugmented": True,
                "processImage": process_context.process_image,
                "processId": process_context.process_id,
            }

            if read_count > 0:
                read_props = {**common_props, "readCount": read_count}
                if "lastSeenAt" in summary:
                    read_props["lastSeenAt"] = summary["lastSeenAt"]
                cypher_props = cypher_emit.format_properties(read_props)
                statements.append(
                    f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
                    f"MATCH (reg:Register {{guid: '{register_guid_escaped}'}})\n"
                    f"MERGE (proc)-[acc:READ_REGISTER]->(reg)\n"
                    f"SET acc += {cypher_props}\n"
                    f"SET acc.pcapAugmented = true;"
                )
                edge_count += 1

            if write_count > 0:
                write_props = {**common_props, "writeCount": write_count}
                if "lastWriteAt" in summary:
                    write_props["lastWriteAt"] = summary["lastWriteAt"]
                cypher_props = cypher_emit.format_properties(write_props)
                statements.append(
                    f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
                    f"MATCH (reg:Register {{guid: '{register_guid_escaped}'}})\n"
                    f"MERGE (proc)-[acc:WRITE_REGISTER]->(reg)\n"
                    f"SET acc += {cypher_props}\n"
                    f"SET acc.pcapAugmented = true;"
                )
                edge_count += 1

        return statements, edge_count

    def _ensure_asset_node(
        self,
        ip: str,
        asset_statements: Dict[str, str],
    ) -> str:
        """Ensure an Asset node exists and return its GUID."""
        hostname = self._resolve_hostname(ip)
        asset_guid = _generate_node_guid("Asset", hostname)
        if asset_guid not in asset_statements:
            asset_props = {"hostname": hostname, "pcapAugmented": True}
            if ip != hostname:
                asset_props["ip"] = ip
            asset_statements[asset_guid] = cypher_emit.create_asset_statement(asset_guid, asset_props)
        return asset_guid

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
        """Ensure a Register node and HAS_REGISTER edge exist in the output."""
        register_guid = _generate_node_guid_v2_braced(
            "Register",
            host,
            port,
            unit_id,
            register_address,
            register_type,
        )
        if register_guid in register_statements:
            return

        props: Dict[str, object] = {
            "guid": register_guid,
            "host": host,
            "address": register_address,
            "port": port,
            "source": "pcap",
            "registerType": register_type,
        }
        if unit_id is not None:
            props["unitId"] = unit_id
        if register_summary:
            props.update(register_summary)

        register_statements[register_guid] = cypher_emit.create_register_statement(
            register_guid,
            props,
            asset_guid,
        )

    def _ensure_network_service_node(
        self,
        ip: str,
        port: int,
        protocol: str,
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        service_name: Optional[str] = None,
    ) -> Optional[str]:
        """Ensure Asset and NetworkService nodes exist, return NetworkService GUID."""
        hostname = self._resolve_hostname(ip)
        asset_guid = self._ensure_asset_node(ip=ip, asset_statements=asset_statements)

        service_guid = _generate_node_guid("NetworkService", hostname, port)
        if service_guid not in service_statements:
            svc_props: Dict[str, object] = {
                "port": port,
                "protocol": protocol,
                "pcapAugmented": True,
            }

            if service_name:
                svc_props["serviceName"] = service_name
            elif port in self.config.service_map:
                svc_props["serviceName"] = self.config.service_map[port]

            service_statements[service_guid] = cypher_emit.create_network_service_statement(
                service_guid,
                svc_props,
                asset_guid,
            )

        return service_guid

    def _write_output(
        self,
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        register_statements: Dict[str, str],
        relationship_statements: List[str],
        edge_update_statements: List[str],
        process_register_statements: List[str],
    ) -> None:
        """Write augmented Cypher to output file."""
        import shutil
        shutil.copy(self.config.base_cypher, self.config.output_cypher)

        with open(self.config.output_cypher, "a") as f:
            f.write("\n// === PCAP Augmentation (Streaming Mode with Correlation) ===\n\n")

            # Edge updates for correlated connections
            if edge_update_statements:
                f.write("// Edge updates for correlated telemetry connections\n")
                for stmt in edge_update_statements:
                    f.write(stmt + "\n")
                f.write("\n")

            # Process-to-register relationships
            if process_register_statements:
                f.write("// READ/WRITE_REGISTER relationships for process attribution\n")
                for stmt in process_register_statements:
                    f.write(stmt + "\n")
                f.write("\n")

            # New nodes for PCAP-only connections
            if asset_statements:
                f.write("// Asset nodes for PCAP-only connections\n")
                for stmt in sorted(asset_statements.values()):
                    f.write(stmt + "\n")
                f.write("\n")

            if service_statements:
                f.write("// NetworkService nodes for PCAP-only connections\n")
                for stmt in sorted(service_statements.values()):
                    f.write(stmt + "\n")
                f.write("\n")

            if register_statements:
                f.write("// PCAP-Inferred Register Nodes\n")
                for stmt in sorted(register_statements.values()):
                    f.write(stmt + "\n")
                f.write("\n")

            # New relationships for PCAP-only connections
            if relationship_statements:
                f.write("// New relationships for PCAP-only connections\n")
                for stmt in relationship_statements:
                    f.write(stmt + "\n")

    def _print_summary(self) -> None:
        """Print correlation statistics summary."""
        print("\n=== Streaming Augmentation Summary ===")
        print(f"Total PCAP connections: {self._correlation_stats.total_pcap_connections}")
        print(f"Correlation attempts: {self._correlation_stats.correlation_attempts}")
        if self._correlation_stats.correlation_attempts > 0:
            rate = 100.0 * self._correlation_stats.successful_correlations / self._correlation_stats.correlation_attempts
            print(f"Successful correlations: {self._correlation_stats.successful_correlations} ({rate:.1f}%)")
        else:
            print(f"Successful correlations: {self._correlation_stats.successful_correlations}")
        print(f"  - Session port matches: {self._correlation_stats.session_port_matches}")
        print(f"  - Temporal matches: {self._correlation_stats.temporal_matches}")
        print(f"PCAP-only connections: {self._correlation_stats.pcap_only_connections}")
        print(f"Process-attributed registers: {self._correlation_stats.process_attributed_registers}")
