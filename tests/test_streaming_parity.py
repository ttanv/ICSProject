"""Tests verifying streaming augmentor produces the same artifacts as batch."""

from __future__ import annotations

from pathlib import Path

import pytest
from network_aug.correlation import CorrelationConfig, CorrelationEngine, TelemetryConnectionIndex
from network_aug.cypher_reader import ExistingConnection
from network_aug.models import ConnectionKey, IndexedConnection, PacketRecord
from network_aug.streaming import ConnectionStats, StreamingPCAPIndex, describe_streaming_worker_failure
from network_aug import protocol_utils


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkt(
    ts: float,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 49152,
    dst_port: int = 1883,
    **kwargs,
) -> PacketRecord:
    defaults = dict(
        pcap_file="test.pcap",
        packet_index=0,
        timestamp=ts,
        size=100,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="tcp",
        high_level_protocol="TCP",
        ip_layer_index=0,
        ip_layer_count=1,
    )
    defaults.update(kwargs)
    return PacketRecord(**defaults)


def _build_stats(origin: ConnectionKey, packets: list[PacketRecord]) -> ConnectionStats:
    """Build a ConnectionStats from a list of packets."""
    cid = origin.bidirectional_id()
    stats = ConnectionStats(
        canonical_id=cid,
        origin=origin,
        origin_timestamp=packets[0].timestamp if packets else 0.0,
    )
    for pkt in packets:
        stats.add_packet(pkt)
    return stats


# ---------------------------------------------------------------------------
# MQTT detection & orientation
# ---------------------------------------------------------------------------

class TestMqttDetection:
    def test_standard_port_detected(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 1883, "tcp")
        assert protocol_utils.is_mqtt_connection(origin, []) is True

    def test_non_standard_port_with_connect(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 9999, "tcp")
        pkt = _pkt(1.0, dst_port=9999, mqtt_packet_type_code=1, mqtt_packet_type="CONNECT")
        assert protocol_utils.is_mqtt_connection(origin, [pkt]) is True

    def test_non_standard_port_without_connect(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 9999, "tcp")
        pkt = _pkt(1.0, dst_port=9999)
        assert protocol_utils.is_mqtt_connection(origin, [pkt]) is False

    def test_orient_standard_port(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 1883, "tcp")
        result = protocol_utils.orient_mqtt_connection(origin, [])
        assert result == ("10.0.0.1", "10.0.0.2", 1883, "tcp")

    def test_orient_reversed_port(self):
        origin = ConnectionKey("10.0.0.2", 1883, "10.0.0.1", 49152, "tcp")
        result = protocol_utils.orient_mqtt_connection(origin, [])
        assert result == ("10.0.0.1", "10.0.0.2", 1883, "tcp")


# ---------------------------------------------------------------------------
# OPC UA detection & orientation
# ---------------------------------------------------------------------------

class TestOpcuaDetection:
    def test_standard_port_detected(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 4840, "tcp")
        assert protocol_utils.is_opcua_connection(origin, []) is True

    def test_hel_with_endpoint_detected(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 9999, "tcp")
        pkt = _pkt(
            1.0, dst_port=9999,
            opcua_message_type="HEL",
            opcua_endpoint_url="opc.tcp://10.0.0.2:9999",
        )
        assert protocol_utils.is_opcua_connection(origin, [pkt]) is True

    def test_no_evidence_not_detected(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 9999, "tcp")
        pkt = _pkt(1.0, dst_port=9999)
        assert protocol_utils.is_opcua_connection(origin, [pkt]) is False

    def test_orient_standard_port(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 4840, "tcp")
        result = protocol_utils.orient_opcua_connection(origin, [])
        assert result == ("10.0.0.1", "10.0.0.2", 4840, "tcp")


# ---------------------------------------------------------------------------
# MQTT signal collection
# ---------------------------------------------------------------------------

class TestMqttSignalCollection:
    def test_publish_creates_signal_per_field(self):
        packets = [
            _pkt(
                1.0, src_ip="10.0.0.2", dst_ip="10.0.0.1",
                src_port=1883, dst_port=49152,
                mqtt_packet_type="PUBLISH", mqtt_packet_type_code=3,
                mqtt_topic="/sensors/temp",
                mqtt_payload_values=(("temperature", 25.5), ("humidity", 60.0)),
            ),
            _pkt(
                2.0, src_ip="10.0.0.2", dst_ip="10.0.0.1",
                src_port=1883, dst_port=49152,
                mqtt_packet_type="PUBLISH", mqtt_packet_type_code=3,
                mqtt_topic="/sensors/temp",
                mqtt_payload_values=(("temperature", 26.0),),
            ),
        ]
        result = protocol_utils.collect_mqtt_signals(
            packets=packets, server_ip="10.0.0.2", server_port=1883,
        )
        assert "/sensors/temp.temperature" in result
        assert "/sensors/temp.humidity" in result
        temp = result["/sensors/temp.temperature"]
        assert temp["mqttTopic"] == "/sensors/temp"
        assert temp["mqttField"] == "temperature"
        assert temp.get("valueSamples", 0) >= 2

    def test_empty_packets_returns_empty(self):
        result = protocol_utils.collect_mqtt_signals(
            packets=[], server_ip="10.0.0.2", server_port=1883,
        )
        assert result == {}


# ---------------------------------------------------------------------------
# OPC UA signal collection
# ---------------------------------------------------------------------------

class TestOpcuaSignalCollection:
    def test_read_request_response_creates_signal(self):
        packets = [
            _pkt(
                1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=49152, dst_port=4840,
                opcua_message_type="MSG", opcua_service_type="ReadRequest",
                opcua_operation="read", opcua_request_id=1,
                opcua_secure_channel_id=100,
                opcua_node_ids=("ns=2;s=Robot_Arm",),
            ),
            _pkt(
                1.1, src_ip="10.0.0.2", dst_ip="10.0.0.1",
                src_port=4840, dst_port=49152,
                opcua_message_type="MSG", opcua_service_type="ReadResponse",
                opcua_operation="read", opcua_request_id=1,
                opcua_secure_channel_id=100,
                opcua_values=(42.0,),
            ),
        ]
        result = protocol_utils.collect_opcua_signals(
            packets=packets, server_ip="10.0.0.2", server_port=4840,
        )
        assert "ns=2;s=Robot_Arm" in result
        sig = result["ns=2;s=Robot_Arm"]
        assert sig.get("opcuaTag") == "Robot_Arm"
        assert sig.get("valueSamples", 0) >= 1


# ---------------------------------------------------------------------------
# ICSSignal GUID determinism
# ---------------------------------------------------------------------------

class TestSignalGuid:
    def test_same_inputs_same_guid(self):
        g1 = protocol_utils.generate_signal_guid("mqtt", "broker1", 1883, "/sensors/temp.field")
        g2 = protocol_utils.generate_signal_guid("mqtt", "broker1", 1883, "/sensors/temp.field")
        assert g1 == g2

    def test_different_inputs_different_guid(self):
        g1 = protocol_utils.generate_signal_guid("mqtt", "broker1", 1883, "/sensors/temp")
        g2 = protocol_utils.generate_signal_guid("mqtt", "broker1", 1883, "/sensors/humidity")
        assert g1 != g2

    def test_guid_format(self):
        g = protocol_utils.generate_signal_guid("mqtt", "host", 1883, "topic")
        assert g.startswith("{") and g.endswith("}")


# ---------------------------------------------------------------------------
# ensure_ics_signal_node
# ---------------------------------------------------------------------------

class TestEnsureIcsSignalNode:
    def test_creates_node_on_first_call(self):
        stmts: dict[str, str] = {}
        guid = protocol_utils.ensure_ics_signal_node(
            protocol="mqtt", host="broker1", port=1883,
            asset_guid="{asset-1}", signal_name="/sensors/temp.field",
            register_statements=stmts,
        )
        assert guid in stmts
        assert "ICSSignal" in stmts[guid]

    def test_idempotent_on_second_call(self):
        stmts: dict[str, str] = {}
        g1 = protocol_utils.ensure_ics_signal_node(
            protocol="mqtt", host="broker1", port=1883,
            asset_guid="{asset-1}", signal_name="/sensors/temp.field",
            register_statements=stmts,
        )
        g2 = protocol_utils.ensure_ics_signal_node(
            protocol="mqtt", host="broker1", port=1883,
            asset_guid="{asset-1}", signal_name="/sensors/temp.field",
            register_statements=stmts,
        )
        assert g1 == g2
        assert len(stmts) == 1


# ---------------------------------------------------------------------------
# build_process_signal_statements
# ---------------------------------------------------------------------------

class TestBuildProcessSignalStatements:
    def test_read_signal_emitted(self):
        stmts = protocol_utils.build_process_signal_statements(
            process_guid="{proc-1}",
            signal_guid="{sig-1}",
            summary={"readCount": 5, "writeCount": 0},
            correlation_confidence=0.5,
        )
        assert len(stmts) == 1
        assert "READ_SIGNAL" in stmts[0]

    def test_write_signal_emitted(self):
        stmts = protocol_utils.build_process_signal_statements(
            process_guid="{proc-1}",
            signal_guid="{sig-1}",
            summary={"readCount": 0, "writeCount": 3},
            correlation_confidence=0.5,
        )
        assert len(stmts) == 1
        assert "WRITE_SIGNAL" in stmts[0]

    def test_both_signals_emitted(self):
        stmts = protocol_utils.build_process_signal_statements(
            process_guid="{proc-1}",
            signal_guid="{sig-1}",
            summary={"readCount": 5, "writeCount": 3},
            correlation_confidence=0.5,
        )
        assert len(stmts) == 2

    def test_zero_counts_no_statements(self):
        stmts = protocol_utils.build_process_signal_statements(
            process_guid="{proc-1}",
            signal_guid="{sig-1}",
            summary={"readCount": 0, "writeCount": 0},
            correlation_confidence=0.5,
        )
        assert stmts == []


# ---------------------------------------------------------------------------
# ConnectionStats MQTT/OPC UA tracking
# ---------------------------------------------------------------------------

class TestConnectionStatsProtocolTracking:
    def test_mqtt_fields_populated(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 1883, "tcp")
        pkt = _pkt(
            1.0, mqtt_packet_type_code=3, mqtt_topic="/sensors/temp",
        )
        stats = _build_stats(origin, [pkt])
        assert 3 in stats.mqtt_packet_type_codes_seen
        assert "/sensors/temp" in stats.mqtt_topics_seen

    def test_opcua_fields_populated(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 4840, "tcp")
        pkt = _pkt(
            1.0, src_port=49152, dst_port=4840,
            opcua_message_type="HEL",
            opcua_endpoint_url="opc.tcp://10.0.0.2:4840",
        )
        stats = _build_stats(origin, [pkt])
        assert "HEL" in stats.opcua_message_types_seen
        assert stats.opcua_has_hel_with_endpoint is True

    def test_service_port_infer_mqtt(self):
        pkt = _pkt(1.0, src_port=49152, dst_port=1883)
        assert ConnectionStats._infer_service_port(pkt) == 1883

    def test_service_port_infer_opcua(self):
        pkt = _pkt(1.0, src_port=49152, dst_port=4840)
        assert ConnectionStats._infer_service_port(pkt) == 4840


# ---------------------------------------------------------------------------
# Relationship properties have MQTT/OPC UA keys
# ---------------------------------------------------------------------------

class TestStreamingRelationshipProperties:
    def test_mqtt_properties_present(self):
        """Verify streaming _relationship_properties includes MQTT feature keys."""
        from network_aug.streaming_augmentor import StreamingAugmentor
        from network_aug.enhancer import AugmentationConfig
        from pathlib import Path
        import tempfile, os

        # Create minimal config (won't actually run, just need the method)
        with tempfile.NamedTemporaryFile(suffix=".cypher", delete=False, mode="w") as f:
            f.write("// empty\n")
            base_path = f.name
        try:
            config = AugmentationConfig(
                base_cypher=Path(base_path),
                output_cypher=Path("/dev/null"),
                pcap_directory=Path("/tmp"),
            )
            aug = StreamingAugmentor(config)
            conn = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 1883, "tcp")
            packets = [
                _pkt(1.0, mqtt_packet_type="PUBLISH", mqtt_packet_type_code=3,
                     mqtt_topic="/t", mqtt_qos=0),
            ]
            props = aug._relationship_properties(conn, packets)
            # Must contain MQTT keys
            assert "mqttPacketTypes" in props
            assert "mqttTopics" in props
            # Must contain OPC UA keys
            assert "opcuaMessageTypes" in props
        finally:
            os.unlink(base_path)


# ---------------------------------------------------------------------------
# Streaming correlation should not eagerly copy packets
# ---------------------------------------------------------------------------

class TestStreamingCorrelationMemory:
    def test_correlate_keeps_original_packet_sequence(self):
        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 502, "tcp")
        packets = [
            _pkt(
                1.0,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=49152,
                dst_port=502,
                tcp_flags="S",
            ),
            _pkt(
                1.1,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                src_port=502,
                dst_port=49152,
                tcp_flags="SA",
            ),
        ]
        indexed = IndexedConnection(
            canonical_id=origin.bidirectional_id(),
            origin=origin,
            records=packets,
            origin_timestamp=1.0,
        )

        existing = ExistingConnection(
            key=ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 502, "tcp"),
            rel_type="CONNECT_TO",
            src_guid="{proc-1}",
            dst_guid="{svc-1}",
            src_label="Process",
            dst_label="NetworkService",
            properties={
                "sessionPorts": [49152],
                "sessionTimestamps": [1.0],
            },
        )
        telemetry_index = TelemetryConnectionIndex([existing])
        engine = CorrelationEngine(CorrelationConfig())

        correlated = engine.correlate(indexed, telemetry_index)

        assert correlated is not None
        assert correlated.packets is packets


# ---------------------------------------------------------------------------
# Streaming parser fallback / failure reporting
# ---------------------------------------------------------------------------

class TestStreamingParserFallback:
    def test_failure_message_includes_signal_name(self, tmp_path: Path):
        pcap_path = tmp_path / "bad.pcapng"
        pcap_path.write_bytes(b"")

        message = describe_streaming_worker_failure(
            pcap_path=pcap_path,
            backend="dpkt",
            phase="Streaming parse",
            exitcode=-11,
        )

        assert "bad.pcapng" in message
        assert "dpkt" in message
        assert "SIGSEGV" in message

    def test_streaming_index_retries_with_scapy(self, tmp_path: Path, capsys, monkeypatch):
        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()
        pcap_path = pcap_dir / "capture_01.pcapng"
        pcap_path.write_bytes(b"")

        index = StreamingPCAPIndex(
            pcap_directory=pcap_dir,
            parser_backend="dpkt",
        )

        origin = ConnectionKey("10.0.0.1", 49152, "10.0.0.2", 502, "tcp")
        stats = _build_stats(
            origin,
            [_pkt(1.0, dst_port=502, modbus_function=3)],
        )
        calls: list[str] = []

        def fake_run_stats_worker(path: Path, backend: str):
            calls.append(backend)
            if backend == "dpkt":
                raise RuntimeError(
                    describe_streaming_worker_failure(
                        pcap_path=path,
                        backend=backend,
                        phase="Streaming parse",
                        exitcode=-11,
                    )
                )
            return {stats.canonical_id: stats}, 1

        monkeypatch.setattr(index, "_run_stats_worker", fake_run_stats_worker)

        index._process_single_file_isolated(pcap_path)
        captured = capsys.readouterr()

        assert calls == ["dpkt", "scapy"]
        assert "Retrying capture_01.pcapng with parser backend 'scapy'" in captured.out
        assert "Recovered capture_01.pcapng with parser backend 'scapy'" in captured.out
        assert index._total_packets == 1
        assert index._processed_files == ["capture_01.pcapng"]

    def test_materialization_retries_with_scapy(self, tmp_path: Path, capsys, monkeypatch):
        from network_aug.enhancer import AugmentationConfig
        from network_aug.streaming_augmentor import StreamingAugmentor

        base_path = tmp_path / "base.cypher"
        base_path.write_text("// empty\n", encoding="utf-8")
        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()
        pcap_path = pcap_dir / "capture_01.pcapng"
        pcap_path.write_bytes(b"")
        spool_dir = tmp_path / "spool"
        spool_dir.mkdir()

        aug = StreamingAugmentor(
            AugmentationConfig(
                base_cypher=base_path,
                output_cypher=tmp_path / "out.cypher",
                pcap_directory=pcap_dir,
            )
        )
        aug._parser_backend = "dpkt"

        calls: list[str] = []

        def fake_run_materialization_worker(**kwargs):
            backend = kwargs["backend"]
            calls.append(backend)
            if backend == "dpkt":
                raise RuntimeError(
                    describe_streaming_worker_failure(
                        pcap_path=kwargs["pcap_path"],
                        backend=backend,
                        phase="Candidate materialization",
                        exitcode=-11,
                    )
                )

        monkeypatch.setattr(aug, "_run_materialization_worker", fake_run_materialization_worker)

        aug._materialize_candidate_file_isolated(
            pcap_path=pcap_path,
            candidate_ids={"dummy"},
            spool_dir=spool_dir,
            ignored_ips=tuple(StreamingPCAPIndex._IGNORED_IPS),
        )
        captured = capsys.readouterr()

        assert calls == ["dpkt", "scapy"]
        assert "Retrying materialization for capture_01.pcapng with parser backend 'scapy'" in captured.out
        assert "Recovered materialization for capture_01.pcapng with parser backend 'scapy'" in captured.out
