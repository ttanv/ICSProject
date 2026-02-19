"""Modbus protocol handler for grouped augmentation artifacts."""

from __future__ import annotations

from tqdm import tqdm

from ..models import ConnectionKey
from ..grouping import group_modbus_connections
from .base import ProtocolBuildResult
from .context import ProtocolBuildContext


class ModbusProtocolHandler:
    """Protocol plugin that emits Modbus-specific graph artifacts."""

    name = "modbus"

    def build_artifacts(self, context: ProtocolBuildContext) -> ProtocolBuildResult:
        modbus_groups, modbus_consumed = group_modbus_connections(context.connections)
        relationship_count = 0

        group_iterable = (
            tqdm(modbus_groups, desc="Processing Modbus groups", unit="group")
            if context.show_progress
            else modbus_groups
        )
        for group in group_iterable:
            # Skip groups fully represented by base telemetry or already-correlated flows.
            if all(
                cid in context.base_connection_ids or cid in context.correlated_cids
                for cid in group.canonical_ids()
            ):
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
            if not context.augmentor.config.policy.is_interesting(connection_key, packets):
                continue

            before_count = len(context.relationship_statements)
            context.augmentor._add_modbus_group(
                group=group,
                connection_key=connection_key,
                packets=packets,
                asset_statements=context.asset_statements,
                service_statements=context.service_statements,
                host_statements=context.host_statements,
                register_statements=context.register_statements,
                process_statements=context.process_statements,
                runs_statements=context.runs_statements,
                relationship_statements=context.relationship_statements,
                process_register_statements=context.process_register_statements,
                process_index=context.process_index,
                telemetry_index=context.telemetry_index,
            )
            relationship_count += max(len(context.relationship_statements) - before_count, 0)
            context.processed_cids.update(group.canonical_ids())

        context.processed_cids.update(modbus_consumed)
        return ProtocolBuildResult(
            relationship_count=relationship_count,
            consumed_cids=modbus_consumed,
        )
