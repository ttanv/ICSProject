"""MQTT protocol handler for metadata-first augmentation."""

from __future__ import annotations

from tqdm import tqdm

from ..models import ConnectionKey
from .base import ProtocolBuildResult
from .context import ProtocolBuildContext


class MqttProtocolHandler:
    """Emit MQTT connection artifacts before generic grouping."""

    name = "mqtt"

    def build_artifacts(self, context: ProtocolBuildContext) -> ProtocolBuildResult:
        relationship_count = 0
        consumed = set()
        asset_ips = getattr(context.augmentor, '_asset_ips', set())
        grouped_packets = {}
        grouped_cids = {}

        iterable = (
            tqdm(context.connections, desc="Processing MQTT connections", unit="connection")
            if context.show_progress
            else context.connections
        )
        for indexed in iterable:
            if indexed.canonical_id in context.base_connection_ids:
                continue
            if indexed.canonical_id in context.correlated_cids:
                continue
            if indexed.canonical_id in context.processed_cids:
                continue
            # Asset-IP scope filter
            if asset_ips and indexed.origin.src_ip not in asset_ips and indexed.origin.dst_ip not in asset_ips:
                continue
            if not indexed.records:
                continue
            if not context.augmentor._is_mqtt_indexed_connection(indexed):
                continue

            orientation = context.augmentor._orient_mqtt_connection(indexed)
            if orientation is None:
                continue
            client_ip, server_ip, service_port, protocol = orientation
            connection_key = ConnectionKey(
                src_ip=client_ip,
                src_port=0,
                dst_ip=server_ip,
                dst_port=service_port,
                protocol=protocol.lower(),
            )
            if not context.augmentor.config.policy.is_interesting(connection_key, indexed.records):
                continue

            group_key = (client_ip, server_ip, service_port, protocol.lower())
            grouped_packets.setdefault(group_key, []).extend(indexed.records)
            grouped_cids.setdefault(group_key, set()).add(indexed.canonical_id)

        for (client_ip, server_ip, service_port, protocol) in sorted(grouped_packets.keys()):
            packets = sorted(grouped_packets[(client_ip, server_ip, service_port, protocol)], key=lambda pkt: pkt.timestamp)
            if not packets:
                continue

            canonical_ids = grouped_cids[(client_ip, server_ip, service_port, protocol)]
            source_ports = context.augmentor._extract_client_source_ports(
                packets=packets,
                client_ip=client_ip,
                server_ip=server_ip,
                service_port=service_port,
            )

            before_count = len(context.relationship_statements)
            context.augmentor._add_mqtt_connection(
                client_ip=client_ip,
                server_ip=server_ip,
                service_port=service_port,
                protocol=protocol,
                packets=packets,
                canonical_count=len(canonical_ids),
                group_source_ports=source_ports,
                asset_statements=context.asset_statements,
                service_statements=context.service_statements,
                host_statements=context.host_statements,
                process_statements=context.process_statements,
                runs_statements=context.runs_statements,
                register_statements=context.register_statements,
                relationship_statements=context.relationship_statements,
                process_register_statements=context.process_register_statements,
                telemetry_index=context.telemetry_index,
            )
            relationship_count += max(len(context.relationship_statements) - before_count, 0)
            consumed.update(canonical_ids)
            context.processed_cids.update(canonical_ids)

        return ProtocolBuildResult(
            relationship_count=relationship_count,
            consumed_cids=consumed,
        )
