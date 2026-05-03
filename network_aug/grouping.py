"""Utilities for grouping noisy network conversations into logical streams."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set, Tuple

from .models import IndexedConnection, PacketRecord
from .orientation import orient_connection

SERVICE_MODBUS_PORT = 502
HTTP_MONITOR_PORT = 8080
HTTP_MONITOR_KEYWORDS = ("monitor", "mb_port")


@dataclass
class ModbusGroup:
    """Aggregated Modbus conversation spanning multiple ephemeral connections."""

    client_ip: str
    server_ip: str
    service_port: int
    protocol: str
    connections: List[IndexedConnection] = field(default_factory=list)

    def add(self, connection: IndexedConnection) -> None:
        self.connections.append(connection)

    def canonical_ids(self) -> Set[str]:
        return {connection.canonical_id for connection in self.connections}

    def packets(self) -> List[PacketRecord]:
        # Build packets on demand without caching the merged list. In streaming
        # mode these merged groups can be very large, and retaining them after
        # one handler pass defeats the point of spill-backed materialization.
        packets: List[PacketRecord] = []
        for connection in self.connections:
            packets.extend(connection.records)
        packets.sort(key=lambda pkt: pkt.timestamp)
        return packets


def group_modbus_connections(
    connections: Sequence[IndexedConnection],
) -> Tuple[List[ModbusGroup], Set[str]]:
    """Aggregate Modbus traffic that only differs by ephemeral client ports."""
    groups: dict[Tuple[str, str, int, str], ModbusGroup] = {}
    consumed: Set[str] = set()

    for connection in connections:
        if not connection.records:
            continue
        if not _is_modbus_connection(connection):
            continue

        first_pkt: PacketRecord = min(connection.records, key=lambda x: x.timestamp)
        src_ip = first_pkt.src_ip
        dst_ip = first_pkt.dst_ip
        src_port = first_pkt.src_port
        dst_port = first_pkt.dst_port
        protocol = first_pkt.protocol.lower()
        
        if src_port == SERVICE_MODBUS_PORT:
            # reverse connection
            dst_port = SERVICE_MODBUS_PORT
            src_ip, dst_ip = dst_ip, src_ip
            
        if dst_port != SERVICE_MODBUS_PORT:
            continue
        
        search_tuple = (src_ip, dst_ip, dst_port, protocol)
        if search_tuple in groups:
            old_mb_group: ModbusGroup = groups[search_tuple]
            old_mb_group.add(connection)
        else:
            groups[search_tuple] = ModbusGroup(client_ip=src_ip, server_ip=dst_ip, service_port=dst_port, protocol=protocol, connections=[connection])
            
        
        consumed.add(connection.canonical_id)

    return list(groups.values()), consumed


@dataclass
class HTTPMonitorGroup:
    """Aggregated Modbus HTTP monitor traffic spanning multiple ephemeral connections."""

    client_ip: str
    server_ip: str
    service_port: int
    protocol: str
    connections: List[IndexedConnection] = field(default_factory=list)

    def add(self, connection: IndexedConnection) -> None:
        self.connections.append(connection)

    def canonical_ids(self) -> Set[str]:
        return {connection.canonical_id for connection in self.connections}

    def packets(self) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        for connection in self.connections:
            packets.extend(connection.records)
        packets.sort(key=lambda pkt: pkt.timestamp)
        return packets


def group_http_monitor_connections(
    connections: Sequence[IndexedConnection],
) -> Tuple[List[HTTPMonitorGroup], Set[str]]:
    """Aggregate Modbus HTTP monitor polling traffic observed on TCP/8080."""
    groups: dict[Tuple[str, str, int, str], HTTPMonitorGroup] = {}
    consumed: Set[str] = set()

    for connection in connections:
        if not connection.records:
            continue
        if not _is_http_monitor_connection(connection):
            continue

        first_packet = min(connection.records, key=lambda pkt: pkt.timestamp)
        client_ip = first_packet.src_ip
        client_port = first_packet.src_port
        server_ip = first_packet.dst_ip
        server_port = first_packet.dst_port
        protocol = first_packet.protocol.lower()

        if server_port != HTTP_MONITOR_PORT and client_port == HTTP_MONITOR_PORT:
            client_ip, server_ip = server_ip, client_ip
            server_port = client_port

        if server_port != HTTP_MONITOR_PORT:
            continue

        key = (client_ip, server_ip, server_port, protocol)
        group = groups.setdefault(
            key,
            HTTPMonitorGroup(
                client_ip=client_ip,
                server_ip=server_ip,
                service_port=server_port,
                protocol=protocol,
            ),
        )
        group.add(connection)
        consumed.add(connection.canonical_id)

    return list(groups.values()), consumed


def _is_modbus_connection(connection: IndexedConnection) -> bool:
    """Return True if a connection should be grouped as Modbus."""
    if connection.origin.dst_port == SERVICE_MODBUS_PORT or connection.origin.src_port == SERVICE_MODBUS_PORT:
        return True
    for packet in connection.records:
        if packet.high_level_protocol.lower() == "modbus":
            return True
    return False


def _is_http_monitor_connection(connection: IndexedConnection) -> bool:
    """Return True if a connection should be grouped as Modbus HTTP monitor polling."""
    if connection.origin.dst_port != HTTP_MONITOR_PORT and connection.origin.src_port != HTTP_MONITOR_PORT:
        return False
    for packet in connection.records:
        if packet.high_level_protocol.lower() != "http":
            continue
        path = (packet.http_path or "").lower()
        host = (packet.http_host or "").lower()
        if any(token in path for token in HTTP_MONITOR_KEYWORDS):
            return True
        if any(token in host for token in HTTP_MONITOR_KEYWORDS):
            return True
    return False


@dataclass
class CollapsedConnectionGroup:
    """General aggregation for clients hitting the same server port with many source ports."""

    client_ip: str
    server_ip: str
    service_port: int
    protocol: str
    connections: List[IndexedConnection] = field(default_factory=list)
    client_ports: Set[int] = field(default_factory=set)

    def add(self, connection: IndexedConnection, client_port: int) -> None:
        self.connections.append(connection)
        if client_port:
            self.client_ports.add(client_port)

    def canonical_ids(self) -> Set[str]:
        return {connection.canonical_id for connection in self.connections}

    def packets(self) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        for connection in self.connections:
            packets.extend(connection.records)
        packets.sort(key=lambda pkt: pkt.timestamp)
        return packets


def group_collapsed_connections(
    connections: Sequence[IndexedConnection],
    exclude_ids: Optional[Set[str]] = None,
    min_unique_ports: int = 2,
) -> Tuple[List[CollapsedConnectionGroup], Set[str]]:
    """Aggregate connections that only differ by ephemeral client ports regardless of protocol."""
    exclude_ids = exclude_ids or set()
    groups: dict[Tuple[str, str, int, str], CollapsedConnectionGroup] = {}
    consumed: Set[str] = set()

    for connection in connections:
        if connection.canonical_id in exclude_ids:
            continue
        if not connection.records:
            continue

        orientation = orient_connection(connection.origin, connection.records)
        if orientation is None:
            continue

        client_ip, client_port, server_ip, server_port, protocol = orientation
        if client_port <= 0 or server_port <= 0:
            continue

        key = (client_ip, server_ip, server_port, protocol)
        group = groups.setdefault(
            key,
            CollapsedConnectionGroup(
                client_ip=client_ip,
                server_ip=server_ip,
                service_port=server_port,
                protocol=protocol,
            ),
        )
        group.add(connection, client_port)

    aggregated_groups: List[CollapsedConnectionGroup] = []
    for group in groups.values():
        if len(group.client_ports) < min_unique_ports:
            continue
        aggregated_groups.append(group)
        consumed.update(group.canonical_ids())

    return aggregated_groups, consumed
