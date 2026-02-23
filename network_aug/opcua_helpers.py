"""Shared OPC UA parsing helpers used by parser backends."""

from __future__ import annotations

from dataclasses import dataclass
import uuid
from typing import List, Optional, Tuple

OPCUA_PORTS = frozenset({4840})

_OPCUA_MESSAGE_TYPES = frozenset({"HEL", "ACK", "ERR", "RHE", "OPN", "MSG", "CLO"})
_OPCUA_CHUNK_TYPES = frozenset({"F", "C", "A"})
_MAX_OPCUA_MESSAGE_SIZE = 64 * 1024 * 1024
_MAX_ARRAY_ITEMS = 8192

_SERVICE_TYPE_ID_TO_NAME = {
    527: "BrowseRequest",
    530: "BrowseResponse",
    631: "ReadRequest",
    634: "ReadResponse",
    673: "WriteRequest",
    676: "WriteResponse",
}
_REQUEST_SERVICE_TO_OPERATION = {
    "ReadRequest": "read",
    "WriteRequest": "write",
}


@dataclass(frozen=True)
class OPCUADetails:
    """Best-effort OPC UA metadata extracted from a transport payload."""

    message_type: Optional[str] = None
    chunk_type: Optional[str] = None
    message_size: Optional[int] = None
    secure_channel_id: Optional[int] = None
    endpoint_url: Optional[str] = None
    security_policy_uri: Optional[str] = None
    service_type: Optional[str] = None
    operation: Optional[str] = None
    request_id: Optional[int] = None
    node_ids: Tuple[str, ...] = ()
    strong_match: bool = False


def parse_opcua_details(payload: bytes, src_port: int, dst_port: int) -> OPCUADetails:
    """Parse OPC UA TCP/UASC metadata from a TCP payload."""
    if len(payload) < 8:
        return OPCUADetails()

    try:
        message_type = payload[0:3].decode("ascii")
        chunk_type = payload[3:4].decode("ascii")
    except Exception:
        return OPCUADetails()

    if message_type not in _OPCUA_MESSAGE_TYPES:
        return OPCUADetails()
    if chunk_type not in _OPCUA_CHUNK_TYPES:
        return OPCUADetails()

    message_size = int.from_bytes(payload[4:8], "little", signed=False)
    if message_size < 8 or message_size > _MAX_OPCUA_MESSAGE_SIZE:
        return OPCUADetails()

    # We can still parse header fields from truncated packet payloads.
    frame_end = min(len(payload), message_size)

    secure_channel_id: Optional[int] = None
    endpoint_url: Optional[str] = None
    security_policy_uri: Optional[str] = None
    service_type: Optional[str] = None
    operation: Optional[str] = None
    request_id: Optional[int] = None
    node_ids: Tuple[str, ...] = ()

    if message_type in {"OPN", "MSG", "CLO"} and frame_end >= 12:
        secure_channel_id = int.from_bytes(payload[8:12], "little", signed=False)

    if message_type == "HEL" and frame_end >= 28:
        # HEL body starts with 5x UInt32 before endpointUrl String.
        endpoint_url, _ = _read_ua_string(payload, 28, frame_end)
    elif message_type == "OPN" and frame_end >= 16:
        # OPN starts with SecureChannelId then AsymmetricSecurityHeader String.
        security_policy_uri, _ = _read_ua_string(payload, 12, frame_end)

    if message_type == "MSG" and chunk_type == "F" and frame_end <= len(payload) and frame_end >= 24:
        service_type, operation, request_id, node_ids = _parse_msg_service(payload, frame_end)

    strong_match = _is_strong_nonstandard_match(
        src_port=src_port,
        dst_port=dst_port,
        message_type=message_type,
        message_size=message_size,
        payload_len=len(payload),
        endpoint_url=endpoint_url,
        security_policy_uri=security_policy_uri,
    )

    return OPCUADetails(
        message_type=message_type,
        chunk_type=chunk_type,
        message_size=message_size,
        secure_channel_id=secure_channel_id,
        endpoint_url=endpoint_url,
        security_policy_uri=security_policy_uri,
        service_type=service_type,
        operation=operation,
        request_id=request_id,
        node_ids=node_ids,
        strong_match=strong_match,
    )


@dataclass(frozen=True)
class _NodeId:
    namespace: int
    identifier_type: str
    identifier: object

    @property
    def canonical(self) -> str:
        if self.identifier_type == "i":
            return f"ns={self.namespace};i={int(self.identifier)}"
        if self.identifier_type == "s":
            return f"ns={self.namespace};s={str(self.identifier)}"
        if self.identifier_type == "g":
            return f"ns={self.namespace};g={str(self.identifier)}"
        if self.identifier_type == "b":
            return f"ns={self.namespace};b={str(self.identifier)}"
        return f"ns={self.namespace};{self.identifier_type}={str(self.identifier)}"


def _parse_msg_service(
    payload: bytes,
    frame_end: int,
) -> Tuple[Optional[str], Optional[str], Optional[int], Tuple[str, ...]]:
    """Parse OPC UA MSG payload and extract request service + NodeIds when present."""
    # [8:12] is SecureChannelId. MSG then carries:
    # SymmetricSecurityHeader(tokenId) + SequenceHeader(seqNo, requestId) + ExtensionObject(service)
    idx = 12
    if idx + 12 > frame_end:
        return None, None, None, ()
    # token_id is currently unused, but consumed for alignment.
    _token_id = int.from_bytes(payload[idx : idx + 4], "little", signed=False)
    idx += 4
    _seq_no = int.from_bytes(payload[idx : idx + 4], "little", signed=False)
    idx += 4
    request_id = int.from_bytes(payload[idx : idx + 4], "little", signed=False)
    idx += 4

    # In OPC UA SecureConversation MSG frames, the message body is an
    # EncodeableObject: TypeId(ExpandedNodeId) followed directly by body bytes.
    # It is not wrapped as ExtensionObject (no encoding byte / length field).
    type_id, idx = _read_node_id(payload, idx, frame_end)
    if type_id is None or idx is None:
        return None, None, request_id, ()
    service_name = _service_name_for_type(type_id)
    operation = _REQUEST_SERVICE_TO_OPERATION.get(service_name or "")

    if service_name == "ReadRequest":
        node_ids = _extract_read_request_node_ids(payload, idx, frame_end)
    elif service_name == "WriteRequest":
        node_ids = _extract_write_request_node_ids(payload, idx, frame_end)
    else:
        node_ids = []

    deduped = tuple(dict.fromkeys(node_ids))
    return service_name, operation, request_id, deduped


def _service_name_for_type(node_id: _NodeId) -> Optional[str]:
    if node_id.namespace != 0 or node_id.identifier_type != "i":
        return None
    try:
        return _SERVICE_TYPE_ID_TO_NAME.get(int(node_id.identifier))
    except Exception:
        return None


def _extract_read_request_node_ids(payload: bytes, idx: int, end: int) -> List[str]:
    result: List[str] = []
    idx = _skip_request_header(payload, idx, end)
    if idx is None or idx + 12 > end:
        return result

    # maxAge: Double, timestampsToReturn: Int32
    idx += 8
    idx += 4

    count, idx = _read_int32(payload, idx, end)
    if count is None or count <= 0:
        return result
    count = min(count, _MAX_ARRAY_ITEMS)
    for _ in range(count):
        node_id, idx = _read_node_id(payload, idx, end)
        if node_id is None:
            return result
        result.append(node_id.canonical)
        if idx + 4 > end:
            return result
        idx += 4  # AttributeId UInt32
        _, idx = _read_ua_string(payload, idx, end)  # IndexRange
        idx = _skip_qualified_name(payload, idx, end)
        if idx is None:
            return result
    return result


def _extract_write_request_node_ids(payload: bytes, idx: int, end: int) -> List[str]:
    result: List[str] = []
    idx = _skip_request_header(payload, idx, end)
    if idx is None:
        return result
    count, idx = _read_int32(payload, idx, end)
    if count is None or count <= 0:
        return result
    count = min(count, _MAX_ARRAY_ITEMS)
    for _ in range(count):
        node_id, idx = _read_node_id(payload, idx, end)
        if node_id is None:
            return result
        result.append(node_id.canonical)
        if idx + 4 > end:
            return result
        idx += 4  # AttributeId UInt32
        _, idx = _read_ua_string(payload, idx, end)  # IndexRange
        idx = _skip_data_value(payload, idx, end)
        if idx is None:
            return result
    return result


def _skip_request_header(payload: bytes, idx: int, end: int) -> Optional[int]:
    """Skip RequestHeader and return new index."""
    _, idx = _read_node_id(payload, idx, end)  # authenticationToken
    if idx is None or idx + 8 + 4 + 4 > end:
        return None
    idx += 8  # timestamp DateTime
    idx += 4  # requestHandle
    idx += 4  # returnDiagnostics
    _, idx = _read_ua_string(payload, idx, end)  # auditEntryId
    if idx + 4 > end:
        return None
    idx += 4  # timeoutHint
    idx = _skip_extension_object(payload, idx, end)  # additionalHeader
    return idx


def _skip_extension_object(payload: bytes, idx: int, end: int) -> Optional[int]:
    _, idx = _read_node_id(payload, idx, end)
    if idx is None or idx >= end:
        return None
    encoding = payload[idx]
    idx += 1
    if encoding == 0:
        return idx
    if encoding not in {1, 2}:
        return None
    length, idx = _read_int32(payload, idx, end)
    if length is None:
        return None
    if length < 0:
        return idx
    if idx + length > end:
        return None
    return idx + length


def _skip_qualified_name(payload: bytes, idx: int, end: int) -> Optional[int]:
    if idx + 2 > end:
        return None
    idx += 2
    _, idx = _read_ua_string(payload, idx, end)
    return idx


def _skip_data_value(payload: bytes, idx: int, end: int) -> Optional[int]:
    if idx >= end:
        return None
    mask = payload[idx]
    idx += 1
    if mask & 0x01:
        idx = _skip_variant(payload, idx, end)
        if idx is None:
            return None
    if mask & 0x02:
        if idx + 4 > end:
            return None
        idx += 4
    if mask & 0x04:
        if idx + 8 > end:
            return None
        idx += 8
    if mask & 0x08:
        if idx + 2 > end:
            return None
        idx += 2
    if mask & 0x10:
        if idx + 8 > end:
            return None
        idx += 8
    if mask & 0x20:
        if idx + 2 > end:
            return None
        idx += 2
    return idx


def _skip_variant(payload: bytes, idx: int, end: int, depth: int = 0) -> Optional[int]:
    if depth > 4 or idx >= end:
        return None
    encoding = payload[idx]
    idx += 1
    is_array = (encoding & 0x80) != 0
    has_dims = (encoding & 0x40) != 0
    variant_type = encoding & 0x3F

    if is_array:
        length, idx = _read_int32(payload, idx, end)
        if length is None:
            return None
        if length > 0:
            for _ in range(min(length, _MAX_ARRAY_ITEMS)):
                idx = _skip_variant_scalar(payload, idx, end, variant_type, depth + 1)
                if idx is None:
                    return None
    else:
        idx = _skip_variant_scalar(payload, idx, end, variant_type, depth + 1)
        if idx is None:
            return None

    if has_dims:
        dim_count, idx = _read_int32(payload, idx, end)
        if dim_count is None:
            return None
        if dim_count > 0:
            need = dim_count * 4
            if idx + need > end:
                return None
            idx += need
    return idx


def _skip_variant_scalar(
    payload: bytes,
    idx: int,
    end: int,
    variant_type: int,
    depth: int,
) -> Optional[int]:
    # Null
    if variant_type == 0:
        return idx
    # Fixed-size primitive widths
    fixed_sizes = {
        1: 1,   # Boolean
        2: 1,   # SByte
        3: 1,   # Byte
        4: 2,   # Int16
        5: 2,   # UInt16
        6: 4,   # Int32
        7: 4,   # UInt32
        8: 8,   # Int64
        9: 8,   # UInt64
        10: 4,  # Float
        11: 8,  # Double
        13: 8,  # DateTime
        14: 16, # Guid
        19: 4,  # StatusCode
    }
    if variant_type in fixed_sizes:
        size = fixed_sizes[variant_type]
        if idx + size > end:
            return None
        return idx + size
    if variant_type in {12, 16}:  # String / XmlElement
        _, idx = _read_ua_string(payload, idx, end)
        return idx
    if variant_type == 15:  # ByteString
        _, idx = _read_ua_bytes(payload, idx, end)
        return idx
    if variant_type in {17, 18}:  # NodeId / ExpandedNodeId
        _, idx = _read_node_id(payload, idx, end)
        return idx
    if variant_type == 20:  # QualifiedName
        return _skip_qualified_name(payload, idx, end)
    if variant_type == 21:  # LocalizedText
        return _skip_localized_text(payload, idx, end)
    if variant_type == 22:  # ExtensionObject
        return _skip_extension_object(payload, idx, end)
    if variant_type == 23:  # DataValue
        return _skip_data_value(payload, idx, end)
    if variant_type == 24:  # Variant
        return _skip_variant(payload, idx, end, depth=depth + 1)
    if variant_type == 25:  # DiagnosticInfo
        return _skip_diagnostic_info(payload, idx, end, depth=depth + 1)
    return None


def _skip_localized_text(payload: bytes, idx: int, end: int) -> Optional[int]:
    if idx >= end:
        return None
    mask = payload[idx]
    idx += 1
    if mask & 0x01:
        _, idx = _read_ua_string(payload, idx, end)  # locale
    if mask & 0x02:
        _, idx = _read_ua_string(payload, idx, end)  # text
    return idx


def _skip_diagnostic_info(payload: bytes, idx: int, end: int, depth: int) -> Optional[int]:
    if depth > 4 or idx >= end:
        return None
    mask = payload[idx]
    idx += 1
    for bit in (0x01, 0x02, 0x04, 0x08):
        if mask & bit:
            _, idx = _read_int32(payload, idx, end)
            if idx is None:
                return None
    if mask & 0x10:
        _, idx = _read_ua_string(payload, idx, end)
    if mask & 0x20:
        if idx + 4 > end:
            return None
        idx += 4
    if mask & 0x40:
        idx = _skip_diagnostic_info(payload, idx, end, depth + 1)
    return idx


def _read_node_id(payload: bytes, idx: int, end: int) -> Tuple[Optional[_NodeId], Optional[int]]:
    if idx >= end:
        return None, None
    encoding = payload[idx]
    idx += 1
    node_type = encoding & 0x3F
    has_namespace_uri = bool(encoding & 0x80)
    has_server_index = bool(encoding & 0x40)

    namespace = 0
    identifier_type = "i"
    identifier: object = 0

    if node_type == 0x00:  # TwoByte
        if idx + 1 > end:
            return None, None
        identifier = payload[idx]
        idx += 1
    elif node_type == 0x01:  # FourByte
        if idx + 3 > end:
            return None, None
        namespace = payload[idx]
        idx += 1
        identifier = int.from_bytes(payload[idx : idx + 2], "little", signed=False)
        idx += 2
    elif node_type == 0x02:  # Numeric
        if idx + 6 > end:
            return None, None
        namespace = int.from_bytes(payload[idx : idx + 2], "little", signed=False)
        idx += 2
        identifier = int.from_bytes(payload[idx : idx + 4], "little", signed=False)
        idx += 4
    elif node_type == 0x03:  # String
        if idx + 2 > end:
            return None, None
        namespace = int.from_bytes(payload[idx : idx + 2], "little", signed=False)
        idx += 2
        string_id, idx = _read_ua_string(payload, idx, end)
        if idx is None:
            return None, None
        identifier_type = "s"
        identifier = string_id or ""
    elif node_type == 0x04:  # Guid
        if idx + 2 + 16 > end:
            return None, None
        namespace = int.from_bytes(payload[idx : idx + 2], "little", signed=False)
        idx += 2
        raw = payload[idx : idx + 16]
        idx += 16
        identifier_type = "g"
        identifier = str(uuid.UUID(bytes_le=raw))
    elif node_type == 0x05:  # ByteString
        if idx + 2 > end:
            return None, None
        namespace = int.from_bytes(payload[idx : idx + 2], "little", signed=False)
        idx += 2
        blob, idx = _read_ua_bytes(payload, idx, end)
        if idx is None:
            return None, None
        identifier_type = "b"
        identifier = (blob or b"").hex()
    else:
        return None, None

    if has_namespace_uri:
        _, idx = _read_ua_string(payload, idx, end)
        if idx is None:
            return None, None
    if has_server_index:
        if idx + 4 > end:
            return None, None
        idx += 4

    return _NodeId(namespace=namespace, identifier_type=identifier_type, identifier=identifier), idx


def _read_int32(payload: bytes, idx: int, end: int) -> Tuple[Optional[int], Optional[int]]:
    if idx + 4 > end:
        return None, None
    return int.from_bytes(payload[idx : idx + 4], "little", signed=True), idx + 4


def _read_ua_bytes(payload: bytes, idx: int, end: int) -> Tuple[Optional[bytes], Optional[int]]:
    if idx + 4 > end:
        return None, None
    length = int.from_bytes(payload[idx : idx + 4], "little", signed=True)
    idx += 4
    if length == -1:
        return None, idx
    if length < 0:
        return None, None
    if idx + length > end:
        return None, None
    return payload[idx : idx + length], idx + length


def _read_ua_string(payload: bytes, idx: int, limit: int) -> Tuple[Optional[str], int]:
    """Read an OPC UA String (Int32 length + UTF-8 bytes)."""
    if idx + 4 > limit or idx + 4 > len(payload):
        return None, idx
    length = int.from_bytes(payload[idx : idx + 4], "little", signed=True)
    idx += 4

    if length == -1:
        return None, idx
    if length < 0:
        return None, idx

    end = idx + length
    if end > limit or end > len(payload):
        return None, idx

    try:
        value = payload[idx:end].decode("utf-8")
    except Exception:
        return None, end

    return _sanitize_opcua_text(value), end


def _sanitize_opcua_text(value: str) -> Optional[str]:
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > 2048:
        return None
    for ch in cleaned:
        code = ord(ch)
        if code < 32 or code == 127:
            return None
    return cleaned


def _is_strong_nonstandard_match(
    *,
    src_port: int,
    dst_port: int,
    message_type: str,
    message_size: int,
    payload_len: int,
    endpoint_url: Optional[str],
    security_policy_uri: Optional[str],
) -> bool:
    # Known OPC UA service ports do not require extra heuristics.
    if src_port in OPCUA_PORTS or dst_port in OPCUA_PORTS:
        return False

    # Non-standard ports require a complete frame and strong semantic fields.
    if payload_len < message_size:
        return False

    if message_type == "HEL":
        return bool(endpoint_url and endpoint_url.lower().startswith("opc.tcp://"))
    if message_type == "OPN":
        return bool(
            security_policy_uri
            and "opcfoundation.org/ua/securitypolicy#" in security_policy_uri.lower()
        )
    return False
