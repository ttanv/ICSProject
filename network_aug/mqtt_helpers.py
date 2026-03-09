"""Shared MQTT parsing helpers used by parser backends."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional, Tuple

MQTT_PORTS = frozenset({1883, 8883})

_PACKET_TYPE_REQUIRED_FLAGS = {
    1: 0x00,  # CONNECT
    2: 0x00,  # CONNACK
    4: 0x00,  # PUBACK
    5: 0x00,  # PUBREC
    6: 0x02,  # PUBREL
    7: 0x00,  # PUBCOMP
    8: 0x02,  # SUBSCRIBE
    9: 0x00,  # SUBACK
    10: 0x02,  # UNSUBSCRIBE
    11: 0x00,  # UNSUBACK
    12: 0x00,  # PINGREQ
    13: 0x00,  # PINGRESP
    14: 0x00,  # DISCONNECT
    15: 0x00,  # AUTH (MQTT v5)
}

MQTT_PACKET_TYPE_NAMES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}


@dataclass(frozen=True)
class MQTTDetails:
    """Best-effort MQTT metadata extracted from a transport payload."""

    packet_type_code: Optional[int] = None
    packet_type: Optional[str] = None
    topic: Optional[str] = None
    qos: Optional[int] = None
    retain: Optional[bool] = None
    dup: Optional[bool] = None
    client_id: Optional[str] = None
    keepalive: Optional[int] = None
    packet_id: Optional[int] = None
    payload_size: Optional[int] = None
    payload_values: Tuple[Tuple[str, float], ...] = ()


def _parse_payload_fields(payload_bytes: bytes) -> Tuple[Tuple[str, float], ...]:
    """Extract named numeric fields from an MQTT PUBLISH payload.

    Returns a tuple of (field_name, value) pairs:
    - Plain numeric string: single pair with field name "value"
    - JSON object: one pair per numeric field (bools excluded)
    - Non-parsable payloads: empty tuple
    """
    if not payload_bytes or len(payload_bytes) > 4096:
        return ()

    try:
        text = payload_bytes.decode("utf-8", errors="strict").strip()
    except (UnicodeDecodeError, ValueError):
        return ()

    if not text:
        return ()

    # Try plain numeric string
    try:
        return (("value", float(text)),)
    except ValueError:
        pass

    # Try JSON
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            if not isinstance(obj, dict):
                return ()
            fields: list[tuple[str, float]] = []
            for k, v in obj.items():
                if isinstance(v, bool):
                    continue
                if isinstance(v, (int, float)):
                    fields.append((k, float(v)))
            return tuple(fields)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    return ()


def parse_mqtt_details(payload: bytes, src_port: int, dst_port: int) -> MQTTDetails:
    """Parse MQTT metadata from a TCP payload using best-effort decoding."""
    if not payload:
        return MQTTDetails()

    header = payload[0]
    packet_type_code = (header >> 4) & 0x0F
    if packet_type_code <= 0 or packet_type_code > 15:
        return MQTTDetails()

    flags = header & 0x0F
    if not _has_valid_fixed_header_flags(packet_type_code, flags):
        return MQTTDetails()

    packet_type = MQTT_PACKET_TYPE_NAMES.get(packet_type_code, f"TYPE_{packet_type_code}")
    qos = (flags >> 1) & 0x03 if packet_type_code == 3 else None
    if packet_type_code == 3 and qos == 3:
        return MQTTDetails()
    retain = bool(flags & 0x01) if packet_type_code == 3 else None
    dup = bool(flags & 0x08) if packet_type_code in {3, 8, 10} else None

    remaining_length, start_idx = _decode_remaining_length(payload, 1)
    if remaining_length is None or start_idx is None:
        return MQTTDetails()

    frame_end = start_idx + remaining_length
    if frame_end > len(payload) or frame_end < start_idx:
        return MQTTDetails()

    client_id: Optional[str] = None
    keepalive: Optional[int] = None
    topic: Optional[str] = None
    packet_id: Optional[int] = None
    payload_size: Optional[int] = None
    payload_values: Tuple[Tuple[str, float], ...] = ()

    try:
        if packet_type_code == 1:  # CONNECT
            idx = start_idx
            protocol_name, idx = _read_utf8(payload, idx, frame_end, sanitize=False)
            if protocol_name is None or idx + 4 > frame_end:
                return MQTTDetails()
            protocol_level = payload[idx]
            idx += 1
            connect_flags = payload[idx]
            idx += 1
            if connect_flags & 0x01:
                return MQTTDetails()
            if idx + 2 > frame_end:
                return MQTTDetails()
            keepalive = int.from_bytes(payload[idx : idx + 2], "big")
            idx += 2
            if not _is_supported_connect_header(protocol_name, protocol_level):
                return MQTTDetails()
            cid, _ = _read_utf8(payload, idx, frame_end)
            client_id = cid or None
        elif packet_type_code == 3:  # PUBLISH
            idx = start_idx
            topic, idx = _read_utf8(payload, idx, frame_end)
            if topic is None:
                return MQTTDetails()
            if qos and qos > 0 and idx + 2 <= frame_end:
                packet_id = int.from_bytes(payload[idx : idx + 2], "big")
                idx += 2
            payload_size = max(0, frame_end - idx)
            if payload_size > 0:
                payload_bytes = payload[idx : idx + payload_size]
                payload_values = _parse_payload_fields(payload_bytes)
        elif packet_type_code in {8, 10}:  # SUBSCRIBE / UNSUBSCRIBE
            idx = start_idx
            if idx + 2 <= frame_end:
                packet_id = int.from_bytes(payload[idx : idx + 2], "big")
                idx += 2
            topic, idx = _read_utf8(payload, idx, frame_end)
            if topic is None:
                return MQTTDetails()
            if packet_type_code == 8 and idx < frame_end:
                qos = payload[idx] & 0x03
        elif packet_type_code in {4, 5, 6, 7, 9, 11}:  # Ack family with packet id
            if start_idx + 2 <= frame_end:
                packet_id = int.from_bytes(payload[start_idx : start_idx + 2], "big")
    except Exception:
        return MQTTDetails()

    # Non-standard ports are only accepted with strong CONNECT evidence.
    if src_port not in MQTT_PORTS and dst_port not in MQTT_PORTS:
        if packet_type_code != 1:
            return MQTTDetails()
        if keepalive is None:
            return MQTTDetails()

    return MQTTDetails(
        packet_type_code=packet_type_code,
        packet_type=packet_type,
        topic=topic,
        qos=qos,
        retain=retain,
        dup=dup,
        client_id=client_id,
        keepalive=keepalive,
        packet_id=packet_id,
        payload_size=payload_size,
        payload_values=payload_values,
    )


def _decode_remaining_length(payload: bytes, start: int) -> Tuple[Optional[int], Optional[int]]:
    """Decode MQTT variable-length remaining length value."""
    multiplier = 1
    value = 0
    idx = start
    for _ in range(4):  # MQTT spec caps this at 4 bytes
        if idx >= len(payload):
            return None, None
        encoded_byte = payload[idx]
        idx += 1
        value += (encoded_byte & 0x7F) * multiplier
        if (encoded_byte & 0x80) == 0:
            return value, idx
        multiplier *= 128
    return None, None


def _read_utf8(
    payload: bytes,
    idx: int,
    limit: int,
    *,
    sanitize: bool = True,
) -> Tuple[Optional[str], int]:
    """Read MQTT UTF-8 string prefixed with uint16 length."""
    if idx + 2 > limit:
        return None, idx
    length = int.from_bytes(payload[idx : idx + 2], "big")
    idx += 2
    end = idx + length
    if end > limit or end > len(payload):
        return None, idx
    try:
        value = payload[idx:end].decode("utf-8")
    except Exception:
        return None, end
    if sanitize:
        value = _sanitize_mqtt_text(value)
    return value, end


def _has_valid_fixed_header_flags(packet_type_code: int, flags: int) -> bool:
    if packet_type_code == 3:
        return True
    expected_flags = _PACKET_TYPE_REQUIRED_FLAGS.get(packet_type_code)
    if expected_flags is None:
        return False
    return flags == expected_flags


def _is_supported_connect_header(protocol_name: str, protocol_level: int) -> bool:
    if protocol_name == "MQTT":
        return protocol_level in {4, 5}
    if protocol_name == "MQIsdp":
        return protocol_level == 3
    return False


def _sanitize_mqtt_text(value: str) -> Optional[str]:
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > 1024:
        return None

    printable = 0
    for ch in cleaned:
        code_point = ord(ch)
        if code_point < 32 or code_point == 127:
            return None
        if ch.isprintable():
            printable += 1

    if printable / len(cleaned) < 0.95:
        return None
    return cleaned
