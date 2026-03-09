"""Connection orientation helpers shared across the augmentation pipeline."""

from __future__ import annotations

from typing import Optional, Sequence, Tuple

from .models import ConnectionKey, PacketRecord

# Well-known service ports that should never be considered ephemeral.
WELL_KNOWN_SERVICE_PORTS: frozenset[int] = frozenset({
    20, 21,
    22,
    23,
    25,
    53,
    67, 68,
    69,
    80,
    88,
    110,
    111,
    123,
    135,
    137, 138, 139,
    143,
    161, 162,
    389, 5353, 5355,
    443,
    445,
    465,
    500,
    502,
    514,
    515,
    520,
    587,
    636,
    873,
    993,
    995,
    1080,
    1433,
    1434,
    1521,
    1883,
    2049,
    2222,
    3306,
    3389,
    4443,
    5044,
    5060, 5061,
    5432,
    5672,
    5900,
    6379,
    6443,
    7474,
    7687,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8880,
    8883,
    9000,
    9090,
    9092,
    9200, 9300,
    9418,
    9999,
    10000,
    11211,
    27017,
    44818,
    4840,
    47808,
})

PRIVILEGED_PORT_THRESHOLD = 1024
EPHEMERAL_PORT_THRESHOLD = 32768


def is_service_port(port: int) -> bool:
    """Return True if the port should be treated as a server/service port."""
    if port < PRIVILEGED_PORT_THRESHOLD:
        return True
    if port >= EPHEMERAL_PORT_THRESHOLD:
        return False
    return port in WELL_KNOWN_SERVICE_PORTS


def orient_connection(
    first_observed: ConnectionKey,
    records: Sequence[PacketRecord],
) -> Optional[Tuple[str, int, str, int, str]]:
    """Determine client/server orientation for a connection.

    Returns `(client_ip, client_port, server_ip, server_port, protocol)` or
    `None` when orientation is ambiguous.
    """
    protocol = first_observed.protocol.lower()

    # TCP SYN without ACK is definitive client evidence.
    for pkt in records:
        flags = pkt.tcp_flags or ""
        if "S" in flags and "A" not in flags:
            return pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, protocol

    src_port, dst_port = first_observed.src_port, first_observed.dst_port
    if src_port <= 0 or dst_port <= 0:
        return None

    src_is_service = is_service_port(src_port)
    dst_is_service = is_service_port(dst_port)
    if src_is_service == dst_is_service:
        return None

    if dst_is_service:
        return first_observed.src_ip, src_port, first_observed.dst_ip, dst_port, protocol
    return first_observed.dst_ip, dst_port, first_observed.src_ip, src_port, protocol


def oriented_connection_key(
    first_observed: ConnectionKey,
    records: Sequence[PacketRecord],
) -> Optional[ConnectionKey]:
    """Return a client->server key for the flow, or None if ambiguous."""
    oriented = orient_connection(first_observed, records)
    if oriented is None:
        return None

    client_ip, client_port, server_ip, server_port, protocol = oriented
    return ConnectionKey(
        src_ip=client_ip,
        src_port=client_port,
        dst_ip=server_ip,
        dst_port=server_port,
        protocol=protocol,
    )
