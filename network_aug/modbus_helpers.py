"""Shared Modbus helper utilities used by both augmentors."""

from __future__ import annotations

from typing import Optional, Tuple

from .models import PacketRecord


def modbus_transaction_key(
    packet: PacketRecord,
    service_port: int,
) -> Optional[Tuple[str, int, str, Optional[int], int]]:
    """Build a stable request/response key for a Modbus transaction."""
    transaction_id = packet.modbus_transaction_id
    if transaction_id is None:
        return None

    unit_id = packet.modbus_unit_id
    if packet.dst_port == service_port:
        client_ip, client_port = packet.src_ip, packet.src_port
        server_ip = packet.dst_ip
    elif packet.src_port == service_port:
        client_ip, client_port = packet.dst_ip, packet.dst_port
        server_ip = packet.src_ip
    else:
        return None

    return (client_ip, client_port, server_ip, unit_id, transaction_id)


def register_type_from_function(function_code: Optional[int]) -> Optional[str]:
    """Map Modbus function code to logical register type."""
    mapping = {
        1: "coil",
        2: "discreteInput",
        3: "holdingRegister",
        4: "inputRegister",
        5: "coil",
        6: "holdingRegister",
        15: "coil",
        16: "holdingRegister",
        23: "holdingRegister",
    }
    if function_code is None:
        return None
    return mapping.get(int(function_code))
