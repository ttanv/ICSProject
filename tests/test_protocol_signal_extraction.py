from network_aug.models import PacketRecord
from network_aug.protocol_signal_extractors import (
    MqttSignalStreamExtractor,
    OpcUaSignalStreamExtractor,
    extract_mqtt_signal_observations,
    extract_opcua_signal_observations,
)


def _packet(**overrides) -> PacketRecord:
    base = dict(
        pcap_file="test.pcap",
        packet_index=0,
        timestamp=0.0,
        size=100,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1111,
        dst_port=2222,
        protocol="tcp",
        high_level_protocol="UNKNOWN",
        ip_layer_index=0,
        ip_layer_count=1,
    )
    base.update(overrides)
    return PacketRecord(**base)


def test_extract_mqtt_signal_observations_uses_connect_client_id_and_roles() -> None:
    packets = [
        _packet(
            timestamp=1.0,
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=34567,
            dst_port=1883,
            high_level_protocol="MQTT",
            mqtt_packet_type="CONNECT",
            mqtt_packet_type_code=1,
            mqtt_client_id="sensor-client",
        ),
        _packet(
            timestamp=2.0,
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=34567,
            dst_port=1883,
            high_level_protocol="MQTT",
            mqtt_packet_type="PUBLISH",
            mqtt_packet_type_code=3,
            mqtt_topic="factory/temp",
            mqtt_qos=1,
            mqtt_packet_id=7,
            mqtt_payload_values=(("value", 42.5),),
        ),
        _packet(
            timestamp=3.0,
            src_ip="10.0.0.20",
            dst_ip="10.0.0.10",
            src_port=1883,
            dst_port=34567,
            high_level_protocol="MQTT",
            mqtt_packet_type="PUBLISH",
            mqtt_packet_type_code=3,
            mqtt_topic="factory/temp",
            mqtt_qos=1,
            mqtt_packet_id=8,
            mqtt_payload_values=(("value", 43.5),),
        ),
    ]

    rows = extract_mqtt_signal_observations(
        packets=packets,
        client_ip="10.0.0.10",
        server_ip="10.0.0.20",
        server_port=1883,
        ip_to_host={"10.0.0.10": "SENSOR", "10.0.0.20": "BROKER"},
    )

    assert len(rows) == 2
    assert rows[0][5] == "write"
    assert rows[1][5] == "read"
    assert rows[0][15] == rows[1][15]
    assert rows[0][14] == "sensor-client"
    assert rows[0][3] == "factory/temp.value"


def test_extract_opcua_signal_observations_correlates_read_responses_and_writes() -> None:
    packets = [
        _packet(
            timestamp=1.0,
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=50000,
            dst_port=4840,
            high_level_protocol="OPCUA",
            opcua_message_type="MSG",
            opcua_service_type="WriteRequest",
            opcua_operation="write",
            opcua_request_id=10,
            opcua_secure_channel_id=1,
            opcua_node_ids=("ns=2;s=Pump.Speed",),
            opcua_values=(1200.0,),
        ),
        _packet(
            timestamp=2.0,
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=50000,
            dst_port=4840,
            high_level_protocol="OPCUA",
            opcua_message_type="MSG",
            opcua_service_type="ReadRequest",
            opcua_operation="read",
            opcua_request_id=11,
            opcua_secure_channel_id=1,
            opcua_node_ids=("ns=2;s=Pump.Speed",),
        ),
        _packet(
            timestamp=3.0,
            src_ip="10.0.0.20",
            dst_ip="10.0.0.10",
            src_port=4840,
            dst_port=50000,
            high_level_protocol="OPCUA",
            opcua_message_type="MSG",
            opcua_service_type="ReadResponse",
            opcua_request_id=11,
            opcua_secure_channel_id=1,
            opcua_values=(1195.0,),
        ),
    ]

    rows = extract_opcua_signal_observations(
        packets=packets,
        client_ip="10.0.0.10",
        server_ip="10.0.0.20",
        server_port=4840,
        ip_to_host={"10.0.0.10": "HMI", "10.0.0.20": "PLC"},
    )

    assert len(rows) == 2
    assert rows[0][4] == "write"
    assert rows[0][1] == "ns=2;s=Pump.Speed"
    assert rows[0][2] == "Pump.Speed"
    assert rows[1][4] == "read"
    assert rows[1][3] == 1195.0
    assert rows[0][13] == rows[1][13]


def test_streaming_mqtt_extractor_matches_batch_behavior() -> None:
    packets = [
        _packet(
            timestamp=1.0,
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=34567,
            dst_port=1883,
            high_level_protocol="MQTT",
            mqtt_packet_type="CONNECT",
            mqtt_packet_type_code=1,
            mqtt_client_id="sensor-client",
        ),
        _packet(
            timestamp=2.0,
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=34567,
            dst_port=1883,
            high_level_protocol="MQTT",
            mqtt_packet_type="PUBLISH",
            mqtt_packet_type_code=3,
            mqtt_topic="factory/temp",
            mqtt_qos=1,
            mqtt_packet_id=7,
            mqtt_payload_values=(("value", 42.5),),
        ),
        _packet(
            timestamp=3.0,
            src_ip="10.0.0.20",
            dst_ip="10.0.0.10",
            src_port=1883,
            dst_port=34567,
            high_level_protocol="MQTT",
            mqtt_packet_type="PUBLISH",
            mqtt_packet_type_code=3,
            mqtt_topic="factory/temp",
            mqtt_qos=1,
            mqtt_packet_id=8,
            mqtt_payload_values=(("value", 43.5),),
        ),
    ]

    extractor = MqttSignalStreamExtractor(
        ip_to_host={"10.0.0.10": "SENSOR", "10.0.0.20": "BROKER"}
    )
    rows = []
    for packet in packets:
        rows.extend(extractor.consume(packet))
    rows.extend(extractor.finish())

    assert len(rows) == 2
    assert rows[0][5] == "write"
    assert rows[1][5] == "read"
    assert rows[0][15] == rows[1][15]
    assert rows[0][14] == "sensor-client"


def test_streaming_opcua_extractor_correlates_requests_without_packet_buffer_growth() -> None:
    packets = [
        _packet(
            timestamp=1.0,
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=50000,
            dst_port=4840,
            high_level_protocol="OPCUA",
            opcua_message_type="MSG",
            opcua_service_type="WriteRequest",
            opcua_operation="write",
            opcua_request_id=10,
            opcua_secure_channel_id=1,
            opcua_node_ids=("ns=2;s=Pump.Speed",),
            opcua_values=(1200.0,),
        ),
        _packet(
            timestamp=2.0,
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=50000,
            dst_port=4840,
            high_level_protocol="OPCUA",
            opcua_message_type="MSG",
            opcua_service_type="ReadRequest",
            opcua_operation="read",
            opcua_request_id=11,
            opcua_secure_channel_id=1,
            opcua_node_ids=("ns=2;s=Pump.Speed",),
        ),
        _packet(
            timestamp=3.0,
            src_ip="10.0.0.20",
            dst_ip="10.0.0.10",
            src_port=4840,
            dst_port=50000,
            high_level_protocol="OPCUA",
            opcua_message_type="MSG",
            opcua_service_type="ReadResponse",
            opcua_request_id=11,
            opcua_secure_channel_id=1,
            opcua_values=(1195.0,),
        ),
    ]

    extractor = OpcUaSignalStreamExtractor(
        ip_to_host={"10.0.0.10": "HMI", "10.0.0.20": "PLC"}
    )
    rows = []
    for packet in packets:
        rows.extend(extractor.consume(packet))
    rows.extend(extractor.finish())

    assert len(rows) == 2
    assert rows[0][4] == "write"
    assert rows[1][4] == "read"
    assert rows[0][13] == rows[1][13]
