"""Shared protocol detection, orientation, and signal collection utilities.

These pure-logic functions are extracted from MissingTrafficAugmentor so that
both the batch and streaming augmentors can share identical protocol handling.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import cypher_emit
from .correlation import ProcessContext, TelemetryConnectionIndex
from .enhancer import _SignalAccumulator
from .models import ConnectionKey, PacketRecord, SignalContainerData
from .modbus_helpers import modbus_transaction_key, register_type_from_function
from .mqtt_helpers import MQTT_PORTS
from .opcua_helpers import OPCUA_PORTS


# ---------------------------------------------------------------------------
# GUID / key generation
# ---------------------------------------------------------------------------

def generate_signal_guid(protocol: str, host: str, port: int, *identifiers: object) -> str:
    """Generate deterministic ICSSignal GUID (case-preserving identifiers)."""
    components = [
        "ICSSignal",
        protocol.strip().lower(),
        host.strip().lower(),
        str(port),
    ] + [str(value) for value in identifiers if value not in (None, "")]
    combined = "|".join(components)
    guid_hash = hashlib.md5(combined.encode("utf-8")).digest()
    guid = uuid.UUID(bytes=guid_hash)
    return f"{{{guid}}}"


def generate_signal_key(protocol: str, host: str, port: int, *identifiers: object) -> str:
    """Generate canonical ICSSignal identity key."""
    components = [
        protocol.strip().lower(),
        host.strip().lower(),
        str(port),
    ] + [str(value) for value in identifiers if value not in (None, "")]
    return "|".join(components)


# ---------------------------------------------------------------------------
# MQTT detection & orientation
# ---------------------------------------------------------------------------

def is_mqtt_connection(origin: ConnectionKey, packets: Sequence[PacketRecord]) -> bool:
    """Return True if this connection appears to carry MQTT traffic."""
    if origin.src_port in MQTT_PORTS or origin.dst_port in MQTT_PORTS:
        return True
    for packet in packets:
        if packet.mqtt_packet_type_code == 1 and (packet.mqtt_packet_type or "").upper() == "CONNECT":
            return True
    return False


def orient_mqtt_connection(
    origin: ConnectionKey,
    packets: Sequence[PacketRecord],
) -> Optional[Tuple[str, str, int, str]]:
    """Orient MQTT traffic as (client_ip, server_ip, service_port, protocol)."""
    if origin.dst_port in MQTT_PORTS and origin.src_port not in MQTT_PORTS:
        return origin.src_ip, origin.dst_ip, origin.dst_port, origin.protocol
    if origin.src_port in MQTT_PORTS and origin.dst_port not in MQTT_PORTS:
        return origin.dst_ip, origin.src_ip, origin.src_port, origin.protocol

    if not packets:
        return None

    first_packet = min(packets, key=lambda pkt: pkt.timestamp)
    if first_packet.dst_port in MQTT_PORTS and first_packet.src_port not in MQTT_PORTS:
        return first_packet.src_ip, first_packet.dst_ip, first_packet.dst_port, first_packet.protocol
    if first_packet.src_port in MQTT_PORTS and first_packet.dst_port not in MQTT_PORTS:
        return first_packet.dst_ip, first_packet.src_ip, first_packet.src_port, first_packet.protocol

    # Non-standard ports: orient by CONNECT packet (client -> broker).
    connect_packets = [
        pkt
        for pkt in packets
        if pkt.mqtt_packet_type_code == 1 and (pkt.mqtt_packet_type or "").upper() == "CONNECT"
    ]
    if not connect_packets:
        return None

    connect_pkt = min(connect_packets, key=lambda pkt: pkt.timestamp)
    service_port = connect_pkt.dst_port if connect_pkt.dst_port > 0 else connect_pkt.src_port
    if service_port <= 0:
        return None
    return connect_pkt.src_ip, connect_pkt.dst_ip, service_port, connect_pkt.protocol


# ---------------------------------------------------------------------------
# OPC UA detection & orientation
# ---------------------------------------------------------------------------

def is_opcua_connection(origin: ConnectionKey, packets: Sequence[PacketRecord]) -> bool:
    """Return True if this connection appears to carry OPC UA traffic."""
    if origin.src_port in OPCUA_PORTS or origin.dst_port in OPCUA_PORTS:
        return True
    for packet in packets:
        message_type = (packet.opcua_message_type or "").upper()
        if message_type == "HEL" and packet.opcua_endpoint_url:
            return True
        if message_type == "OPN" and packet.opcua_security_policy_uri:
            return True
    return False


def orient_opcua_connection(
    origin: ConnectionKey,
    packets: Sequence[PacketRecord],
) -> Optional[Tuple[str, str, int, str]]:
    """Orient OPC UA traffic as (client_ip, server_ip, service_port, protocol)."""
    if origin.dst_port in OPCUA_PORTS and origin.src_port not in OPCUA_PORTS:
        return origin.src_ip, origin.dst_ip, origin.dst_port, origin.protocol
    if origin.src_port in OPCUA_PORTS and origin.dst_port not in OPCUA_PORTS:
        return origin.dst_ip, origin.src_ip, origin.src_port, origin.protocol

    if not packets:
        return None

    hel_packets = [
        pkt for pkt in packets if (pkt.opcua_message_type or "").upper() == "HEL"
    ]
    if hel_packets:
        hel_packet = min(hel_packets, key=lambda pkt: pkt.timestamp)
        service_port = hel_packet.dst_port if hel_packet.dst_port > 0 else hel_packet.src_port
        if service_port > 0:
            return hel_packet.src_ip, hel_packet.dst_ip, service_port, hel_packet.protocol

    opn_packets = [
        pkt for pkt in packets if (pkt.opcua_message_type or "").upper() == "OPN"
    ]
    if opn_packets:
        opn_packet = min(opn_packets, key=lambda pkt: pkt.timestamp)
        service_port = opn_packet.dst_port if opn_packet.dst_port > 0 else opn_packet.src_port
        if service_port > 0:
            return opn_packet.src_ip, opn_packet.dst_ip, service_port, opn_packet.protocol

    return None


# ---------------------------------------------------------------------------
# Signal collection
# ---------------------------------------------------------------------------

def collect_mqtt_signals(
    *,
    packets: Sequence[PacketRecord],
    server_ip: str,
    server_port: int,
) -> Dict[str, Dict[str, object]]:
    """Collect per-field MQTT summaries suitable for ICSSignal properties.

    Each numeric field in a PUBLISH payload produces a separate signal entry
    keyed by ``topic.field_name``.  The original topic is stored as the
    ``mqttTopic`` property so callers can trace back to the source.
    """
    topic_meta: Dict[str, Dict[str, object]] = {}
    accumulators: Dict[str, _SignalAccumulator] = {}
    field_topics: Dict[str, str] = {}

    def _ensure_topic_meta(topic: str) -> Dict[str, object]:
        if topic not in topic_meta:
            topic_meta[topic] = {
                "sampleCount": 0,
                "readCount": 0,
                "writeCount": 0,
                "firstSeenAt": None,
                "lastSeenAt": None,
                "lastReadAt": None,
                "lastWriteAt": None,
                "_qos_levels": set(),
                "_packet_types": set(),
                "mqttRetainSeen": False,
            }
        return topic_meta[topic]

    def _get_accumulator(signal_key: str, topic: str) -> _SignalAccumulator:
        if signal_key not in accumulators:
            accumulators[signal_key] = _SignalAccumulator(
                signal_id=signal_key, protocol="mqtt",
            )
            field_topics[signal_key] = topic
        return accumulators[signal_key]

    for packet in packets:
        topic = (packet.mqtt_topic or "").strip()
        if not topic:
            continue
        meta = _ensure_topic_meta(topic)
        meta["sampleCount"] = int(meta["sampleCount"]) + 1

        first_seen = meta.get("firstSeenAt")
        if first_seen is None or packet.timestamp < float(first_seen):
            meta["firstSeenAt"] = packet.timestamp
        last_seen = meta.get("lastSeenAt")
        if last_seen is None or packet.timestamp > float(last_seen):
            meta["lastSeenAt"] = packet.timestamp

        packet_type = (packet.mqtt_packet_type or "").upper()
        if packet_type:
            meta["_packet_types"].add(packet_type)
        if packet.mqtt_qos is not None and 0 <= packet.mqtt_qos <= 2:
            meta["_qos_levels"].add(packet.mqtt_qos)
        if packet.mqtt_retain is True:
            meta["mqttRetainSeen"] = True

        if packet_type == "PUBLISH":
            is_write = packet.dst_ip == server_ip and packet.dst_port == server_port
            is_read = packet.src_ip == server_ip and packet.src_port == server_port
            if is_write:
                meta["writeCount"] = int(meta["writeCount"]) + 1
                meta["lastWriteAt"] = packet.timestamp
                role = "write"
            elif is_read:
                meta["readCount"] = int(meta["readCount"]) + 1
                meta["lastReadAt"] = packet.timestamp
                role = "read"
            else:
                role = ""

            for field_name, value in packet.mqtt_payload_values:
                signal_key = f"{topic}.{field_name}"
                acc = _get_accumulator(signal_key, topic)
                acc.observe(value, packet.timestamp, role)

    # Build output: one entry per field across all topics.
    result: Dict[str, Dict[str, object]] = {}
    for signal_key, acc in accumulators.items():
        raw_topic = field_topics[signal_key]
        meta = topic_meta.get(raw_topic, {})
        field_name = signal_key[len(raw_topic) + 1:]

        out: Dict[str, object] = {}
        for k, v in meta.items():
            if not k.startswith("_"):
                out[k] = v

        qos_levels = sorted(meta.get("_qos_levels", set()))  # type: ignore[arg-type]
        packet_types = sorted(meta.get("_packet_types", set()))  # type: ignore[arg-type]
        if qos_levels:
            out["mqttQosLevels"] = ",".join(str(q) for q in qos_levels[:8])
        if packet_types:
            out["mqttPacketTypes"] = ",".join(packet_types[:8])

        out["mqttTopic"] = raw_topic
        out["mqttField"] = field_name
        out.update(acc.to_properties())
        result[signal_key] = out

    return result


def collect_opcua_signals(
    *,
    packets: Sequence[PacketRecord],
    server_ip: str,
    server_port: int,
) -> Dict[str, Dict[str, object]]:
    """Collect per-signal OPC UA summaries for ICSSignal nodes.

    Preferred identity is decoded OPC UA NodeId. If unavailable, falls back
    to endpoint/secure-channel level metadata.
    """
    summaries: Dict[str, Dict[str, object]] = {}
    accumulators: Dict[str, _SignalAccumulator] = {}
    request_node_ids: Dict[Tuple[str, int, int], Tuple[str, ...]] = {}
    request_operation: Dict[Tuple[str, int, int], str] = {}

    def _request_key(
        *,
        client_ip: str,
        secure_channel_id: Optional[int],
        request_id: Optional[int],
    ) -> Optional[Tuple[str, int, int]]:
        if request_id is None:
            return None
        channel = secure_channel_id if secure_channel_id is not None else -1
        return (client_ip, channel, request_id)

    def _display_tag(node_id: str) -> str:
        marker = ";s="
        if marker in node_id:
            raw = node_id.split(marker, 1)[1] or node_id
            if '".' in raw or '."' in raw:
                raw = raw.replace('"."', ".").replace('."', ".").replace('"', "")
            return raw
        return node_id

    def _get_accumulator(signal_name: str) -> _SignalAccumulator:
        if signal_name not in accumulators:
            accumulators[signal_name] = _SignalAccumulator(signal_id=signal_name, protocol="opcua")
        return accumulators[signal_name]

    def _acc(signal_name: str) -> Dict[str, object]:
        if signal_name not in summaries:
            summaries[signal_name] = {
                "sampleCount": 0,
                "readCount": 0,
                "writeCount": 0,
                "firstSeenAt": None,
                "lastSeenAt": None,
                "lastReadAt": None,
                "lastWriteAt": None,
                "_message_types": set(),
                "_service_types": set(),
                "_chunk_types": set(),
                "_security_policies": set(),
                "_endpoint_urls": set(),
                "_secure_channel_ids": set(),
                "_identity_kind": "unknown",
            }
        return summaries[signal_name]

    for packet in packets:
        service_type = (packet.opcua_service_type or "").strip()
        operation = (packet.opcua_operation or "").strip().lower()
        message_type = (packet.opcua_message_type or "").upper()
        from_server = packet.src_ip == server_ip and packet.src_port == server_port
        to_server = packet.dst_ip == server_ip and packet.dst_port == server_port
        explicit_node_ids = tuple(dict.fromkeys(
            n for n in packet.opcua_node_ids
            if n and not n.startswith("ns=0;") and not n.startswith("ns=1;")
        ))

        # Remember request operation/tag context for response correlation.
        if to_server and explicit_node_ids and operation in {"read", "write"}:
            key = _request_key(
                client_ip=packet.src_ip,
                secure_channel_id=packet.opcua_secure_channel_id,
                request_id=packet.opcua_request_id,
            )
            if key is not None:
                request_node_ids[key] = explicit_node_ids
                request_operation[key] = operation
            if operation == "write" and packet.opcua_values:
                for i, nid in enumerate(explicit_node_ids):
                    val = packet.opcua_values[i] if i < len(packet.opcua_values) else None
                    _get_accumulator(nid).observe(val, packet.timestamp, "write")

        signal_names: Tuple[str, ...] = ()
        identity_kind = "unknown"

        if explicit_node_ids:
            signal_names = explicit_node_ids
            identity_kind = "nodeid"
        elif from_server and service_type in {"ReadResponse", "WriteResponse"}:
            key = _request_key(
                client_ip=packet.dst_ip,
                secure_channel_id=packet.opcua_secure_channel_id,
                request_id=packet.opcua_request_id,
            )
            if key is not None:
                mapped_ids = request_node_ids.get(key) or ()
                mapped_op = request_operation.get(key)
                if mapped_ids:
                    if service_type == "ReadResponse" and mapped_op == "read":
                        signal_names = mapped_ids
                        identity_kind = "nodeid"
                        if packet.opcua_values:
                            for i, nid in enumerate(mapped_ids):
                                val = packet.opcua_values[i] if i < len(packet.opcua_values) else None
                                _get_accumulator(nid).observe(val, packet.timestamp, "read")
                    elif service_type == "WriteResponse" and mapped_op == "write":
                        signal_names = mapped_ids
                        identity_kind = "nodeid"

        if not signal_names:
            continue

        for signal_name in signal_names:
            summary = _acc(signal_name)
            summary["sampleCount"] = int(summary["sampleCount"]) + 1
            summary["_identity_kind"] = identity_kind

            first_seen = summary.get("firstSeenAt")
            if first_seen is None or packet.timestamp < float(first_seen):
                summary["firstSeenAt"] = packet.timestamp
            last_seen = summary.get("lastSeenAt")
            if last_seen is None or packet.timestamp > float(last_seen):
                summary["lastSeenAt"] = packet.timestamp

            if message_type:
                summary["_message_types"].add(message_type)
            if service_type:
                summary["_service_types"].add(service_type)
            chunk_type = (packet.opcua_chunk_type or "").upper()
            if chunk_type:
                summary["_chunk_types"].add(chunk_type)
            if packet.opcua_security_policy_uri:
                summary["_security_policies"].add(packet.opcua_security_policy_uri)
            if packet.opcua_endpoint_url:
                summary["_endpoint_urls"].add(packet.opcua_endpoint_url)
            if packet.opcua_secure_channel_id is not None:
                summary["_secure_channel_ids"].add(packet.opcua_secure_channel_id)

            if operation == "read":
                summary["readCount"] = int(summary["readCount"]) + 1
                summary["lastReadAt"] = packet.timestamp
            elif operation == "write":
                summary["writeCount"] = int(summary["writeCount"]) + 1
                summary["lastWriteAt"] = packet.timestamp
            else:
                if not service_type and message_type in {"MSG", "ACK"}:
                    if from_server:
                        summary["readCount"] = int(summary["readCount"]) + 1
                        summary["lastReadAt"] = packet.timestamp
                    elif to_server:
                        summary["writeCount"] = int(summary["writeCount"]) + 1
                        summary["lastWriteAt"] = packet.timestamp

    result: Dict[str, Dict[str, object]] = {}
    for signal_name, summary in summaries.items():
        if signal_name.startswith("TD_"):
            continue
        acc = accumulators.get(signal_name)
        if acc is None or acc.sample_count == 0:
            continue

        out = {k: v for k, v in summary.items() if not k.startswith("_")}
        message_types = sorted(summary["_message_types"])  # type: ignore[index]
        service_types = sorted(summary["_service_types"])  # type: ignore[index]
        chunk_types = sorted(summary["_chunk_types"])  # type: ignore[index]
        security_policies = sorted(summary["_security_policies"])  # type: ignore[index]
        endpoint_urls = sorted(summary["_endpoint_urls"])  # type: ignore[index]
        secure_channel_ids = sorted(summary["_secure_channel_ids"])  # type: ignore[index]
        identity_kind = str(summary.get("_identity_kind") or "unknown")
        if message_types:
            out["opcuaMessageTypes"] = ",".join(message_types[:8])
        if service_types:
            out["opcuaServiceTypes"] = ",".join(service_types[:8])
        if chunk_types:
            out["opcuaChunkTypes"] = ",".join(chunk_types[:3])
        if security_policies:
            out["opcuaSecurityPolicies"] = ",".join(security_policies[:4])
        if endpoint_urls:
            out["opcuaEndpointUrls"] = ",".join(endpoint_urls[:4])
        if secure_channel_ids:
            out["opcuaSecureChannelIds"] = ",".join(str(scid) for scid in secure_channel_ids[:8])
        out["opcuaIdentityKind"] = identity_kind
        out["opcuaNodeId"] = signal_name
        out["opcuaTag"] = _display_tag(signal_name)
        out.update(acc.to_properties())
        result[signal_name] = out
    return result


# ---------------------------------------------------------------------------
# ICSSignal node creation
# ---------------------------------------------------------------------------

def ensure_ics_signal_node(
    *,
    protocol: str,
    host: str,
    port: int,
    asset_guid: str,
    signal_name: str,
    register_statements: Dict[str, str],
    signal_properties: Optional[Dict[str, object]] = None,
) -> str:
    """Ensure an ICSSignal node and ownership edge exist in output."""
    signal_key = generate_signal_key(protocol, host, port, signal_name)
    signal_guid = generate_signal_guid(protocol, host, port, signal_name)
    if signal_guid in register_statements:
        return signal_guid

    props: Dict[str, object] = {
        "guid": signal_guid,
        "signalKey": signal_key,
        "protocol": protocol.lower(),
        "host": host,
        "port": port,
        "name": signal_name,
        "source": "pcap",
    }
    if signal_properties:
        props.update(signal_properties)

    register_statements[signal_guid] = cypher_emit.create_ics_signal_statement(
        signal_guid=signal_guid,
        properties=props,
        endpoint_guid=asset_guid,
    )
    return signal_guid


# ---------------------------------------------------------------------------
# Process signal attribution
# ---------------------------------------------------------------------------

def build_process_signal_statements(
    *,
    process_guid: str,
    signal_guid: str,
    summary: Dict[str, object],
    correlation_confidence: float,
    process_image: Optional[str] = None,
    process_id: Optional[int] = None,
) -> List[str]:
    """Build READ_SIGNAL / WRITE_SIGNAL statements for one process+signal pair."""
    statements: List[str] = []
    read_count = int(summary.get("readCount") or 0)
    write_count = int(summary.get("writeCount") or 0)
    if read_count <= 0 and write_count <= 0:
        return statements

    proc_guid_escaped = cypher_emit.escape_cypher_string(process_guid)
    signal_guid_escaped = cypher_emit.escape_cypher_string(signal_guid)
    common_props: Dict[str, object] = {
        "correlationConfidence": round(correlation_confidence, 4),
        "inferredFrom": "pcap",
        "pcapAugmented": True,
    }
    if process_image:
        common_props["processImage"] = process_image
    if process_id is not None:
        common_props["processId"] = process_id

    if read_count > 0:
        read_props = dict(common_props)
        read_props["readCount"] = read_count
        if summary.get("lastReadAt") is not None:
            read_props["lastReadAt"] = summary["lastReadAt"]
        cypher_props = cypher_emit.format_properties(read_props)
        statement = (
            f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
            f"MATCH (sig:ICSSignal {{guid: '{signal_guid_escaped}'}})\n"
            f"MERGE (proc)-[acc:READ_SIGNAL]->(sig)\n"
            f"SET acc += {cypher_props}\n"
            "SET acc.pcapAugmented = true"
        )
        statements.append(statement)

    if write_count > 0:
        write_props = dict(common_props)
        write_props["writeCount"] = write_count
        if summary.get("lastWriteAt") is not None:
            write_props["lastWriteAt"] = summary["lastWriteAt"]
        cypher_props = cypher_emit.format_properties(write_props)
        statement = (
            f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
            f"MATCH (sig:ICSSignal {{guid: '{signal_guid_escaped}'}})\n"
            f"MERGE (proc)-[acc:WRITE_SIGNAL]->(sig)\n"
            f"SET acc += {cypher_props}\n"
            "SET acc.pcapAugmented = true"
        )
        statements.append(statement)

    return statements


# ---------------------------------------------------------------------------
# Telemetry process context lookup
# ---------------------------------------------------------------------------

def find_telemetry_process_context(
    *,
    telemetry_index: Optional[TelemetryConnectionIndex],
    client_ip: str,
    server_ip: str,
    service_port: int,
    protocol: str,
    source_ports: Sequence[int],
) -> Optional[ProcessContext]:
    """Resolve process context from telemetry with deterministic source-port matching."""
    if telemetry_index is None:
        return None

    candidate_ports = sorted({int(port) for port in source_ports if int(port) > 0})
    if candidate_ports:
        matches_by_guid: Dict[str, Tuple[int, int, ProcessContext]] = {}
        for src_port in candidate_ports:
            process_context = telemetry_index.find_process_for_connection(
                src_ip=client_ip,
                dst_ip=server_ip,
                dst_port=service_port,
                protocol=protocol,
                src_port=src_port,
                require_src_port_match=True,
            )
            if (
                not process_context
                or not process_context.is_valid()
                or not process_context.process_guid
            ):
                continue

            current = matches_by_guid.get(process_context.process_guid)
            if current is None:
                matches_by_guid[process_context.process_guid] = (1, src_port, process_context)
            else:
                matches_by_guid[process_context.process_guid] = (
                    current[0] + 1,
                    min(current[1], src_port),
                    current[2],
                )

        if matches_by_guid:
            _, _, best_context = max(
                matches_by_guid.values(),
                key=lambda value: (value[0], -value[1]),
            )
            return best_context

        return None

    return None


# ---------------------------------------------------------------------------
# Client source port extraction
# ---------------------------------------------------------------------------

def extract_client_source_ports(
    *,
    packets: Sequence[PacketRecord],
    client_ip: str,
    server_ip: str,
    service_port: int,
) -> List[int]:
    """Extract client ephemeral source ports observed for a client->server flow."""
    ports: Set[int] = set()
    for pkt in packets:
        if (
            pkt.src_ip == client_ip
            and pkt.dst_ip == server_ip
            and pkt.dst_port == service_port
            and pkt.src_port > 0
        ):
            ports.add(pkt.src_port)
        elif (
            pkt.src_ip == server_ip
            and pkt.dst_ip == client_ip
            and pkt.src_port == service_port
            and pkt.dst_port > 0
        ):
            ports.add(pkt.dst_port)
    return sorted(ports)


# ---------------------------------------------------------------------------
# Modbus signal collection (DuckDB storage)
# ---------------------------------------------------------------------------

def collect_modbus_signals(
    *,
    packets: Sequence[PacketRecord],
    client_ip: str,
    server_ip: str,
    server_port: int,
    client_hostname: str,
    server_hostname: str,
    signal_db: object = None,
) -> Dict[str, Dict[Tuple[int, Optional[int]], "SignalContainerData"]]:
    """Collect signal observations for both endpoints, storing raw data in DuckDB.

    This is the shared implementation used by both batch and streaming augmentors.
    """
    from .enhancer import _PendingModbusRequest

    client_signals: Dict[Tuple[int, Optional[int]], SignalContainerData] = {}
    server_signals: Dict[Tuple[int, Optional[int]], SignalContainerData] = {}
    pending: Dict[Tuple[str, int, str, Optional[int], int], _PendingModbusRequest] = {}
    pending_write_txids: Dict[int, float] = {}
    observations_to_insert: List[tuple] = []
    total_observations_inserted = 0
    BATCH_SIZE = 100_000

    def _flush_observations() -> int:
        nonlocal observations_to_insert, total_observations_inserted
        if not observations_to_insert:
            return 0
        count = len(observations_to_insert)
        signal_db.insert_tuples_fast(observations_to_insert)  # type: ignore[union-attr]
        total_observations_inserted += count
        observations_to_insert = []
        return count

    pcap_file = packets[0].pcap_file if packets else "unknown"

    def _get_or_create_signal_data(
        address: int, unit_id: Optional[int], observer: str, reg_type: Optional[str],
    ) -> SignalContainerData:
        key = (address, unit_id)
        hostname = client_hostname if observer == "client" else server_hostname
        target_dict = client_signals if observer == "client" else server_signals
        if key not in target_dict:
            target_dict[key] = SignalContainerData(
                address=address, unit_id=unit_id,
                observer_host=hostname, port=server_port,
                modbus_register_type=reg_type,
            )
        elif reg_type and not target_dict[key].modbus_register_type:
            target_dict[key].modbus_register_type = reg_type
        return target_dict[key]

    def _record_observation(
        address: int, unit_id: Optional[int], value: int, timestamp: float,
        access_type: str, function_code: int, transaction_id: Optional[int],
        request_timestamp: Optional[float], response_timestamp: Optional[float],
        write_acknowledged: Optional[bool], reg_type: Optional[str],
    ) -> None:
        for observer in ["client", "server"]:
            sd = _get_or_create_signal_data(address, unit_id, observer, reg_type)
            sd.total_observations += 1
            if access_type == "read":
                sd.read_count += 1
            else:
                sd.write_count += 1
            if sd.first_seen_at is None or timestamp < sd.first_seen_at:
                sd.first_seen_at = timestamp
            if sd.last_seen_at is None or timestamp > sd.last_seen_at:
                sd.last_seen_at = timestamp

        signal_guid = _generate_node_guid_for_signal_container(client_hostname, address, unit_id)

        if signal_db:
            observations_to_insert.append((
                timestamp, address, value, access_type, function_code, unit_id,
                client_hostname, server_hostname, client_ip, server_ip,
                transaction_id, request_timestamp, response_timestamp,
                write_acknowledged, signal_guid, pcap_file,
            ))
            if len(observations_to_insert) >= BATCH_SIZE:
                _flush_observations()

    for packet in packets:
        if packet.modbus_function is None:
            continue
        if packet.dst_ip != server_ip and packet.src_ip != server_ip:
            continue

        function_code = packet.modbus_function
        reg_type = register_type_from_function(function_code)
        unit_id = packet.modbus_unit_id
        read_registers = packet.modbus_read_registers or ()
        write_registers = packet.modbus_write_registers or ()
        if not read_registers and not write_registers and packet.modbus_registers:
            read_registers = packet.modbus_registers

        transaction_id = packet.modbus_transaction_id

        # Request packet (client -> server)
        if packet.dst_port == server_port:
            key = modbus_transaction_key(packet, server_port)
            if key is not None:
                pending[key] = _PendingModbusRequest(
                    timestamp=packet.timestamp,
                    unit_id=unit_id,
                    function_code=function_code,
                    read_registers=read_registers,
                    write_registers=write_registers,
                )
            if write_registers and packet.modbus_register_values:
                for address, value in zip(write_registers, packet.modbus_register_values):
                    if address is None or address < 0:
                        continue
                    _record_observation(
                        address=address, unit_id=unit_id, value=value,
                        timestamp=packet.timestamp, access_type="write",
                        function_code=function_code, transaction_id=transaction_id,
                        request_timestamp=packet.timestamp, response_timestamp=None,
                        write_acknowledged=None, reg_type=reg_type,
                    )
                if transaction_id is not None:
                    pending_write_txids[transaction_id] = packet.timestamp
            continue

        # Response packet (server -> client)
        if packet.src_port != server_port:
            continue

        key = modbus_transaction_key(packet, server_port)
        request = pending.pop(key, None)
        response_values = tuple(packet.modbus_register_values or ())

        if request:
            req_type = register_type_from_function(request.function_code)
            if request.read_registers and response_values:
                trimmed_values = response_values[:len(request.read_registers)]
                for address, value in zip(request.read_registers, trimmed_values):
                    if address is None or address < 0:
                        continue
                    _record_observation(
                        address=address, unit_id=request.unit_id, value=value,
                        timestamp=packet.timestamp, access_type="read",
                        function_code=request.function_code, transaction_id=transaction_id,
                        request_timestamp=request.timestamp, response_timestamp=packet.timestamp,
                        write_acknowledged=None, reg_type=req_type,
                    )
            if request.write_registers and transaction_id is not None:
                if transaction_id in pending_write_txids:
                    del pending_write_txids[transaction_id]
                    if signal_db:
                        signal_db.update_write_acknowledgment(  # type: ignore[union-attr]
                            client_ip=client_ip, server_ip=server_ip,
                            transaction_id=transaction_id,
                            response_timestamp=packet.timestamp, acknowledged=True,
                        )

    if signal_db:
        _flush_observations()

    return {"client": client_signals, "server": server_signals}


def _generate_node_guid_for_signal_container(hostname: str, address: int, unit_id: Optional[int]) -> str:
    """Generate a deterministic GUID for a SignalContainer node."""
    components = ["SignalContainer", hostname] + [str(v) for v in [address, unit_id] if v not in (None, "")]
    combined = "|".join(components).lower()
    digest = hashlib.md5(combined.encode("utf-8")).digest()
    guid = uuid.UUID(bytes=digest)
    return f"{{{guid}}}"
