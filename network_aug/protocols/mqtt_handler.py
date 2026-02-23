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
                protocol=protocol,
            )
            if not context.augmentor.config.policy.is_interesting(connection_key, indexed.records):
                continue

            before_count = len(context.relationship_statements)
            context.augmentor._add_mqtt_connection(
                client_ip=client_ip,
                server_ip=server_ip,
                service_port=service_port,
                protocol=protocol,
                packets=indexed.records,
                asset_statements=context.asset_statements,
                service_statements=context.service_statements,
                host_statements=context.host_statements,
                process_statements=context.process_statements,
                runs_statements=context.runs_statements,
                register_statements=context.register_statements,
                relationship_statements=context.relationship_statements,
                process_register_statements=context.process_register_statements,
                process_index=context.process_index,
            )
            relationship_count += max(len(context.relationship_statements) - before_count, 0)
            consumed.add(indexed.canonical_id)
            context.processed_cids.add(indexed.canonical_id)

        return ProtocolBuildResult(
            relationship_count=relationship_count,
            consumed_cids=consumed,
        )
