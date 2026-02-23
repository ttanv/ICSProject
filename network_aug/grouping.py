"""Utilities for grouping noisy network conversations into logical streams."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .models import IndexedConnection, PacketRecord

SERVICE_MODBUS_PORT = 502
HTTP_MONITOR_PORT = 8080
HTTP_MONITOR_KEYWORDS = ("monitor", "mb_port")

# Well-known service ports that should never be considered ephemeral.
# This is the authoritative list for client/server orientation.
WELL_KNOWN_SERVICE_PORTS: frozenset[int] = frozenset({
    # Standard services
    20, 21,       # FTP
    22,           # SSH
    23,           # Telnet
    25,           # SMTP
    53,           # DNS
    67, 68,       # DHCP
    69,           # TFTP
    80,           # HTTP
    88,           # Kerberos
    110,          # POP3
    111,          # RPC
    123,          # NTP
    135,          # MS-RPC
    137, 138, 139,  # NetBIOS
    143,          # IMAP
    161, 162,     # SNMP
    389,          # LDAP
    443,          # HTTPS
    445,          # SMB
    465,          # SMTPS
    500,          # IKE/IPsec
    502,          # Modbus
    514,          # Syslog
    515,          # LPD
    520,          # RIP
    587,          # SMTP submission
    636,          # LDAPS
    873,          # rsync
    993,          # IMAPS
    995,          # POP3S
    1080,         # SOCKS
    1433,         # MSSQL
    1434,         # MSSQL Browser
    1521,         # Oracle
    1883,         # MQTT
    2049,         # NFS
    2222,         # SSH alternate
    3306,         # MySQL
    3389,         # RDP
    4443,         # HTTPS alternate
    5044,         # Logstash Beats
    5060, 5061,   # SIP
    5432,         # PostgreSQL
    5672,         # AMQP
    5900,         # VNC
    6379,         # Redis
    6443,         # Kubernetes API
    7474,         # Neo4j HTTP
    7687,         # Neo4j Bolt
    8000,         # HTTP alternate
    8008,         # HTTP alternate
    8080,         # HTTP proxy/alternate
    8081,         # HTTP alternate
    8088,         # Ignition Gateway / HTTP alternate
    8443,         # HTTPS alternate
    8880,         # HTTP alternate
    8883,         # MQTT TLS
    9000,         # Various services
    9090,         # Prometheus
    9092,         # Kafka
    9200, 9300,   # Elasticsearch
    9418,         # Git
    9999,         # Various services
    10000,        # Webmin / various
    11211,        # Memcached
    27017,        # MongoDB
    44818,        # EtherNet/IP
    4840,         # OPC UA
    47808,        # BACnet
})

# Threshold below which ports are always considered service ports
# (privileged ports on Unix systems)
PRIVILEGED_PORT_THRESHOLD = 1024


@dataclass
class ModbusGroup:
    """Aggregated Modbus conversation spanning multiple ephemeral connections."""

    client_ip: str
    server_ip: str
    service_port: int
    protocol: str
    connections: List[IndexedConnection] = field(default_factory=list)
    _cached_packets: Optional[List[PacketRecord]] = field(default=None, repr=False)

    def add(self, connection: IndexedConnection) -> None:
        self.connections.append(connection)
        self._cached_packets = None  # Invalidate cache

    def canonical_ids(self) -> Set[str]:
        return {connection.canonical_id for connection in self.connections}

    def packets(self) -> List[PacketRecord]:
        if self._cached_packets is not None:
            return self._cached_packets
        packets: List[PacketRecord] = []
        for connection in self.connections:
            packets.extend(connection.records)
        packets.sort(key=lambda pkt: pkt.timestamp)
        self._cached_packets = packets
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
    _cached_packets: Optional[List[PacketRecord]] = field(default=None, repr=False)

    def add(self, connection: IndexedConnection) -> None:
        self.connections.append(connection)
        self._cached_packets = None  # Invalidate cache

    def canonical_ids(self) -> Set[str]:
        return {connection.canonical_id for connection in self.connections}

    def packets(self) -> List[PacketRecord]:
        if self._cached_packets is not None:
            return self._cached_packets
        packets: List[PacketRecord] = []
        for connection in self.connections:
            packets.extend(connection.records)
        packets.sort(key=lambda pkt: pkt.timestamp)
        self._cached_packets = packets
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
    _cached_packets: Optional[List[PacketRecord]] = field(default=None, repr=False)

    def add(self, connection: IndexedConnection, client_port: int) -> None:
        self.connections.append(connection)
        if client_port:
            self.client_ports.add(client_port)
        self._cached_packets = None  # Invalidate cache

    def canonical_ids(self) -> Set[str]:
        return {connection.canonical_id for connection in self.connections}

    def packets(self) -> List[PacketRecord]:
        if self._cached_packets is not None:
            return self._cached_packets
        packets: List[PacketRecord] = []
        for connection in self.connections:
            packets.extend(connection.records)
        packets.sort(key=lambda pkt: pkt.timestamp)
        self._cached_packets = packets
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

        orientation = _infer_client_server(connection)
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


def _infer_client_server(connection: IndexedConnection) -> Optional[Tuple[str, int, str, int, str]]:
    """Derive a stable (client, server) orientation for aggregation heuristics."""
    if not connection.records:
        return None

    first_packet = min(connection.records, key=lambda pkt: pkt.timestamp)
    orientation = _orient(first_packet.src_ip, first_packet.src_port, first_packet.dst_ip, first_packet.dst_port, first_packet.protocol)
    if orientation:
        return orientation

    origin = connection.origin
    orientation = _orient(origin.src_ip, origin.src_port, origin.dst_ip, origin.dst_port, origin.protocol)
    if orientation:
        return orientation

    return None


def _orient(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
) -> Optional[Tuple[str, int, str, int, str]]:
    """Determine client/server orientation based on port characteristics.

    Returns (client_ip, client_port, server_ip, server_port, protocol) if
    orientation can be determined, None otherwise.
    """
    if src_port <= 0 or dst_port <= 0:
        return None

    src_is_service = _is_service_port(src_port)
    dst_is_service = _is_service_port(dst_port)

    # If both are service ports or neither is, we can't determine orientation
    if src_is_service == dst_is_service:
        return None

    # The service port side is the server, the other side is the client
    if dst_is_service and not src_is_service:
        # src is client, dst is server
        return src_ip, src_port, dst_ip, dst_port, protocol.lower()
    elif src_is_service and not dst_is_service:
        # dst is client, src is server
        return dst_ip, dst_port, src_ip, src_port, protocol.lower()

    return None


def _is_service_port(port: int) -> bool:
    """Check if a port is a known service port (i.e., NOT ephemeral).

    A port is considered a service port if:
    1. It's in the well-known service ports list, OR
    2. It's a privileged port (< 1024)
    """
    if port < PRIVILEGED_PORT_THRESHOLD:
        return True
    return port in WELL_KNOWN_SERVICE_PORTS


def _is_ephemeral_port(port: int) -> bool:
    """Check if a port is likely an ephemeral/client port.

    This is the inverse of _is_service_port.
    """
    return not _is_service_port(port)
