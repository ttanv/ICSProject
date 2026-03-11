from tqdm import tqdm


from .context import ProtocolBuildContext
from .base import ProtocolBuildResult
from ..models import ConnectionKey
from ..grouping import group_http_monitor_connections

class HttpMonitorHandler: 
    name = "http_monitor"
    
    def build_artifacts(self, context: ProtocolBuildContext) -> ProtocolBuildResult:
        "Build artifacts for the HTTP connections"
        monitor_groups, monitor_consumed = group_http_monitor_connections(context.connections)
        
        monitor_iterable = (
            tqdm(monitor_groups, desc="Processing HTTP monitor groups", unit="group") if context.show_progress else monitor_groups
        )
        
        asset_ips = getattr(context.augmentor, '_asset_ips', set())
        http_relationships = 0
        for group in monitor_iterable:
            # Skip if all connections are either in base telemetry OR already correlated
            if all(cid in context.base_connection_ids or cid in context.correlated_cids for cid in group.canonical_ids()):
                continue
            # Asset-IP scope filter
            if asset_ips and group.client_ip not in asset_ips and group.server_ip not in asset_ips:
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
            context.augmentor._add_http_monitor_group(
                group,
                connection_key,
                packets,
                context.asset_statements,
                context.service_statements,
                context.host_statements,
                context.process_statements,
                context.runs_statements,
                context.relationship_statements,
                telemetry_index=context.telemetry_index,
            )
            added = len(context.relationship_statements) - before_count
            http_relationships += max(added, 0)
            context.processed_cids.update(group.canonical_ids())
            
        context.processed_cids.update(monitor_consumed)
        return ProtocolBuildResult(http_relationships, monitor_consumed)
