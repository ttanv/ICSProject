"""Parity test: streaming accumulator produces same output as list-based path.

The streaming accumulator (`RelationshipFeatureAccumulator`) replaces the
materialize-then-compute pattern in `_augment_existing_relationships`. To
ensure that's a safe substitution, this test feeds the same fixture packet
sequence through both paths and asserts equal feature dicts.
"""
from __future__ import annotations

from typing import List

import pytest

from network_aug.features import (
    PreSortedPackets,
    RelationshipFeatureAccumulator,
    average_packet_size,
    count_tcp_retransmits,
    directional_totals,
    directionality_ratio,
    dominant_protocol,
    duration_seconds,
    extract_http_features,
    extract_mqtt_features,
    extract_opcua_features,
    extract_tls_sni,
    mean_interarrival_time,
    mean_rtt_ms,
    resolve_mac_addresses,
    stream_relationship_features,
)
from network_aug.models import ConnectionKey, PacketRecord


def _pkt(
    *,
    ts: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    size: int = 64,
    payload_len: int = 0,
    high_level: str = "UNKNOWN",
    src_mac: str = "",
    dst_mac: str = "",
    tcp_seq: int | None = None,
    tcp_ack: int | None = None,
    tcp_flags: str = "",
    tls_sni: str | None = None,
    http_method: str | None = None,
    http_status: int | None = None,
    http_host: str | None = None,
    http_path: str | None = None,
    mqtt_packet_type: str | None = None,
    mqtt_topic: str | None = None,
    mqtt_qos: int | None = None,
    mqtt_retain: bool | None = None,
    mqtt_client_id: str | None = None,
    opcua_message_type: str | None = None,
    opcua_chunk_type: str | None = None,
    opcua_endpoint_url: str | None = None,
    opcua_security_policy_uri: str | None = None,
    opcua_secure_channel_id: int | None = None,
    protocol: str = "tcp",
) -> PacketRecord:
    return PacketRecord(
        pcap_file="x.pcap",
        packet_index=0,
        timestamp=ts,
        size=size,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        high_level_protocol=high_level,
        ip_layer_index=0,
        ip_layer_count=1,
        src_mac=src_mac,
        dst_mac=dst_mac,
        tcp_flags=tcp_flags,
        tcp_seq=tcp_seq,
        tcp_ack=tcp_ack,
        payload_len=payload_len,
        tls_sni=tls_sni,
        http_method=http_method,
        http_status=http_status,
        http_host=http_host,
        http_path=http_path,
        mqtt_packet_type=mqtt_packet_type,
        mqtt_topic=mqtt_topic,
        mqtt_qos=mqtt_qos,
        mqtt_retain=mqtt_retain,
        mqtt_client_id=mqtt_client_id,
        opcua_message_type=opcua_message_type,
        opcua_chunk_type=opcua_chunk_type,
        opcua_endpoint_url=opcua_endpoint_url,
        opcua_security_policy_uri=opcua_security_policy_uri,
        opcua_secure_channel_id=opcua_secure_channel_id,
    )


def _legacy_feature_dict(connection: ConnectionKey, packets: List[PacketRecord]) -> dict:
    """Replica of MissingTrafficAugmentor._relationship_properties (list-based)."""
    sorted_packets = PreSortedPackets.from_packets(packets)
    timestamps = [pkt.timestamp for pkt in sorted_packets]
    bytes_out, bytes_in, _, _ = directional_totals(connection, sorted_packets)
    dir_index = directionality_ratio(bytes_out, bytes_in)
    inter_arrival = mean_interarrival_time(sorted_packets)
    retransmits = count_tcp_retransmits(sorted_packets)
    src_mac, dst_mac = resolve_mac_addresses(connection, sorted_packets)
    http_features = extract_http_features(sorted_packets)
    mqtt_features = extract_mqtt_features(sorted_packets)
    opcua_features = extract_opcua_features(sorted_packets)
    tls_sni = extract_tls_sni(sorted_packets)
    rtt_ms = mean_rtt_ms(connection, sorted_packets)
    return {
        "SourceIp": connection.src_ip,
        "SourcePort": connection.src_port,
        "DestinationIp": connection.dst_ip,
        "DestinationPort": connection.dst_port,
        "Protocol": connection.protocol.lower(),
        "inferredFrom": "pcap",
        "pcapAugmented": True,
        "note": "Observed in PCAP but missing from host telemetry",
        "packetCount": len(sorted_packets),
        "durationSeconds": duration_seconds(sorted_packets),
        "avgPacketSize": round(average_packet_size(sorted_packets), 2),
        "highLevelProtocol": dominant_protocol(sorted_packets),
        "firstSeen": min(timestamps) if timestamps else None,
        "lastSeen": max(timestamps) if timestamps else None,
        "srcMac": src_mac or None,
        "dstMac": dst_mac or None,
        "bytesOut": bytes_out,
        "bytesIn": bytes_in,
        "directionalityIndex": round(dir_index, 6) if dir_index is not None else None,
        "meanInterArrivalPacketTime": round(inter_arrival, 6),
        "retransmits": retransmits,
        "tlsSNI": tls_sni or None,
        "httpMethod": http_features.get("method"),
        "httpStatus": http_features.get("status"),
        "httpContent": http_features.get("content"),
        "mqttPacketTypes": mqtt_features.get("packetTypes"),
        "mqttTopics": mqtt_features.get("topics"),
        "mqttClientIds": mqtt_features.get("clientIds"),
        "mqttQosLevels": mqtt_features.get("qosLevels"),
        "mqttPublishCount": mqtt_features.get("publishCount"),
        "mqttSubscribeCount": mqtt_features.get("subscribeCount"),
        "mqttRetainSeen": mqtt_features.get("retainSeen"),
        "opcuaMessageTypes": opcua_features.get("messageTypes"),
        "opcuaChunkTypes": opcua_features.get("chunkTypes"),
        "opcuaEndpointUrls": opcua_features.get("endpointUrls"),
        "opcuaSecurityPolicies": opcua_features.get("securityPolicies"),
        "opcuaSecureChannelIds": opcua_features.get("secureChannelIds"),
        "opcuaOpenCount": opcua_features.get("openCount"),
        "opcuaMsgCount": opcua_features.get("msgCount"),
        "opcuaCloseCount": opcua_features.get("closeCount"),
        "rttMs": round(rtt_ms, 3) if rtt_ms > 0.0 else None,
    }


def _make_modbus_traffic() -> tuple[ConnectionKey, List[PacketRecord]]:
    """Realistic Modbus request/response sequence with timing irregularities."""
    conn = ConnectionKey(src_ip="10.0.0.1", src_port=4001, dst_ip="10.0.0.2",
                          dst_port=502, protocol="tcp")
    packets = [
        # SYN
        _pkt(ts=1.000, src_ip="10.0.0.1", src_port=4001, dst_ip="10.0.0.2", dst_port=502,
             size=66, tcp_seq=100, tcp_flags="S", src_mac="aa:aa:aa", dst_mac="bb:bb:bb"),
        # SYN-ACK
        _pkt(ts=1.001, src_ip="10.0.0.2", src_port=502, dst_ip="10.0.0.1", dst_port=4001,
             size=66, tcp_seq=200, tcp_ack=101, tcp_flags="SA"),
        # Modbus read request (FC=3)
        _pkt(ts=1.010, src_ip="10.0.0.1", src_port=4001, dst_ip="10.0.0.2", dst_port=502,
             size=78, tcp_seq=101, tcp_ack=201, payload_len=12, high_level="MODBUS"),
        # Modbus read response
        _pkt(ts=1.020, src_ip="10.0.0.2", src_port=502, dst_ip="10.0.0.1", dst_port=4001,
             size=84, tcp_seq=201, tcp_ack=113, payload_len=18, high_level="MODBUS"),
        # Retransmit of req
        _pkt(ts=1.500, src_ip="10.0.0.1", src_port=4001, dst_ip="10.0.0.2", dst_port=502,
             size=78, tcp_seq=101, tcp_ack=201, payload_len=12, high_level="MODBUS"),
        # Modbus write request
        _pkt(ts=2.000, src_ip="10.0.0.1", src_port=4001, dst_ip="10.0.0.2", dst_port=502,
             size=80, tcp_seq=113, tcp_ack=219, payload_len=14, high_level="MODBUS"),
        # Modbus write response
        _pkt(ts=2.010, src_ip="10.0.0.2", src_port=502, dst_ip="10.0.0.1", dst_port=4001,
             size=72, tcp_seq=219, tcp_ack=127, payload_len=6, high_level="MODBUS"),
    ]
    return conn, packets


def _make_mqtt_traffic() -> tuple[ConnectionKey, List[PacketRecord]]:
    conn = ConnectionKey(src_ip="10.0.0.5", src_port=51000, dst_ip="10.0.0.6",
                          dst_port=1883, protocol="tcp")
    packets = [
        _pkt(ts=10.0, src_ip="10.0.0.5", src_port=51000, dst_ip="10.0.0.6", dst_port=1883,
             high_level="MQTT", mqtt_packet_type="CONNECT", mqtt_client_id="device-01"),
        _pkt(ts=10.1, src_ip="10.0.0.6", src_port=1883, dst_ip="10.0.0.5", dst_port=51000,
             high_level="MQTT", mqtt_packet_type="CONNACK"),
        _pkt(ts=10.2, src_ip="10.0.0.5", src_port=51000, dst_ip="10.0.0.6", dst_port=1883,
             high_level="MQTT", mqtt_packet_type="PUBLISH", mqtt_topic="sensors/temp",
             mqtt_qos=1, mqtt_retain=True),
        _pkt(ts=10.3, src_ip="10.0.0.5", src_port=51000, dst_ip="10.0.0.6", dst_port=1883,
             high_level="MQTT", mqtt_packet_type="PUBLISH", mqtt_topic="sensors/temp",
             mqtt_qos=0),
        _pkt(ts=10.4, src_ip="10.0.0.5", src_port=51000, dst_ip="10.0.0.6", dst_port=1883,
             high_level="MQTT", mqtt_packet_type="SUBSCRIBE", mqtt_topic="cmd/#",
             mqtt_qos=2),
    ]
    return conn, packets


def _make_opcua_traffic() -> tuple[ConnectionKey, List[PacketRecord]]:
    conn = ConnectionKey(src_ip="10.0.0.7", src_port=52001, dst_ip="10.0.0.8",
                          dst_port=4840, protocol="tcp")
    packets = [
        _pkt(ts=20.0, src_ip="10.0.0.7", src_port=52001, dst_ip="10.0.0.8", dst_port=4840,
             high_level="OPCUA", opcua_message_type="HEL"),
        _pkt(ts=20.1, src_ip="10.0.0.7", src_port=52001, dst_ip="10.0.0.8", dst_port=4840,
             high_level="OPCUA", opcua_message_type="OPN", opcua_chunk_type="F",
             opcua_endpoint_url="opc.tcp://server:4840", opcua_secure_channel_id=42,
             opcua_security_policy_uri="http://opcfoundation.org/UA/SecurityPolicy#None"),
        _pkt(ts=20.2, src_ip="10.0.0.7", src_port=52001, dst_ip="10.0.0.8", dst_port=4840,
             high_level="OPCUA", opcua_message_type="MSG", opcua_chunk_type="F",
             opcua_secure_channel_id=42),
        _pkt(ts=20.3, src_ip="10.0.0.7", src_port=52001, dst_ip="10.0.0.8", dst_port=4840,
             high_level="OPCUA", opcua_message_type="MSG", opcua_chunk_type="F",
             opcua_secure_channel_id=42),
        _pkt(ts=20.4, src_ip="10.0.0.7", src_port=52001, dst_ip="10.0.0.8", dst_port=4840,
             high_level="OPCUA", opcua_message_type="CLO", opcua_chunk_type="F"),
    ]
    return conn, packets


def _make_https_traffic() -> tuple[ConnectionKey, List[PacketRecord]]:
    conn = ConnectionKey(src_ip="10.0.0.10", src_port=44000, dst_ip="8.8.8.8",
                          dst_port=443, protocol="tcp")
    packets = [
        _pkt(ts=30.0, src_ip="10.0.0.10", src_port=44000, dst_ip="8.8.8.8", dst_port=443,
             tls_sni="example.com", high_level="TLS"),
        _pkt(ts=30.1, src_ip="10.0.0.10", src_port=44000, dst_ip="8.8.8.8", dst_port=443,
             http_method="GET", http_host="example.com", http_path="/api"),
        _pkt(ts=30.2, src_ip="8.8.8.8", src_port=443, dst_ip="10.0.0.10", dst_port=44000,
             http_status=200, high_level="HTTP"),
    ]
    return conn, packets


@pytest.mark.parametrize("traffic_fn,name", [
    (_make_modbus_traffic, "modbus"),
    (_make_mqtt_traffic, "mqtt"),
    (_make_opcua_traffic, "opcua"),
    (_make_https_traffic, "https"),
])
def test_streaming_feature_parity(traffic_fn, name):
    conn, packets = traffic_fn()
    legacy = _legacy_feature_dict(conn, packets)
    # Streaming consumes packets in already-sorted order (matches what
    # heapq.merge will produce in the real call site).
    streamed = stream_relationship_features(
        conn, iter(sorted(packets, key=lambda p: p.timestamp))
    )

    # All keys present in both
    assert set(legacy.keys()) == set(streamed.keys()), \
        f"{name}: feature dict keys differ"

    # Compare each value with tolerance for floats
    for key in legacy:
        if isinstance(legacy[key], float):
            assert streamed[key] == pytest.approx(legacy[key], rel=1e-6, abs=1e-6), \
                f"{name}: {key} legacy={legacy[key]} streamed={streamed[key]}"
        else:
            assert streamed[key] == legacy[key], \
                f"{name}: {key} legacy={legacy[key]} streamed={streamed[key]}"


def test_accumulator_empty_input():
    """No packets fed → feature dict still produces valid all-zeros output."""
    conn = ConnectionKey(src_ip="a", src_port=1, dst_ip="b", dst_port=2, protocol="tcp")
    acc = RelationshipFeatureAccumulator(connection=conn)
    out = acc.feature_dict()
    assert out["packetCount"] == 0
    assert out["bytesOut"] == 0
    assert out["bytesIn"] == 0
    assert out["highLevelProtocol"] == "UNKNOWN"
    assert out["firstSeen"] is None
    assert out["lastSeen"] is None
    assert out["rttMs"] is None
    assert out["meanInterArrivalPacketTime"] == 0.0
