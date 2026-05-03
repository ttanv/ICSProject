from __future__ import annotations

import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from invariantExperiments.extract_mqtt_invariants import (
    MqttInvariantConfig,
    mine_inter_signal_correlations,
    mine_mqtt_invariants,
    mine_value_ranges,
)


def _create_mqtt_signal_db(path) -> None:
    conn = duckdb.connect(str(path))
    conn.execute(
        """
        CREATE TABLE signal_observations (
            timestamp DOUBLE NOT NULL,
            topic VARCHAR NOT NULL,
            field_name VARCHAR NOT NULL,
            signal_name VARCHAR NOT NULL,
            value DOUBLE NOT NULL,
            access_type VARCHAR NOT NULL,
            client_host VARCHAR NOT NULL,
            server_host VARCHAR NOT NULL,
            client_ip VARCHAR NOT NULL,
            server_ip VARCHAR NOT NULL,
            packet_id INTEGER,
            qos INTEGER,
            retain BOOLEAN,
            dup BOOLEAN,
            client_id VARCHAR,
            signal_guid VARCHAR NOT NULL,
            pcap_file VARCHAR NOT NULL
        )
        """
    )

    rows = []
    for i in range(80):
        ts = 1000.0 + i
        temp = 20.0 + i * 0.25
        pressure = 100.0 + temp * 3.0
        rows.extend(
            [
                (
                    ts,
                    "factory/sensor",
                    "temp",
                    "factory/sensor.temp",
                    temp,
                    "write",
                    "PUBLISHER",
                    "BROKER",
                    "10.0.0.10",
                    "10.0.0.20",
                    i,
                    1,
                    False,
                    False,
                    "pub-1",
                    "guid-temp",
                    "test.pcap",
                ),
                (
                    ts,
                    "factory/sensor",
                    "pressure",
                    "factory/sensor.pressure",
                    pressure,
                    "write",
                    "PUBLISHER",
                    "BROKER",
                    "10.0.0.10",
                    "10.0.0.20",
                    i + 1000,
                    1,
                    False,
                    False,
                    "pub-1",
                    "guid-pressure",
                    "test.pcap",
                ),
                (
                    ts,
                    "factory/state",
                    "active",
                    "factory/state.active",
                    1.0,
                    "read",
                    "SUBSCRIBER",
                    "BROKER",
                    "10.0.0.30",
                    "10.0.0.20",
                    i + 2000,
                    0,
                    False,
                    False,
                    "sub-1",
                    "guid-active",
                    "test.pcap",
                ),
            ]
        )

    conn.executemany(
        "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.close()


def test_mqtt_value_ranges_use_topic_field_identity_and_keep_state_flags(tmp_path) -> None:
    db_path = tmp_path / "mqtt.duckdb"
    _create_mqtt_signal_db(db_path)

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        invariants = mine_value_ranges(conn, 0.0, 2000.0, min_observations=10)
    finally:
        conn.close()

    by_guid = {inv["signal_guid"]: inv for inv in invariants}
    assert set(by_guid) == {"guid-temp", "guid-pressure", "guid-active"}
    assert by_guid["guid-temp"]["topic"] == "factory/sensor"
    assert by_guid["guid-temp"]["field_name"] == "temp"
    assert by_guid["guid-temp"]["parameters"]["min"] == 20.0
    assert by_guid["guid-temp"]["parameters"]["qos_levels"] == ["1"]
    assert by_guid["guid-active"]["parameters"]["binary_like"] is True
    assert by_guid["guid-active"]["parameters"]["constant"] is True


def test_mqtt_correlations_are_broker_scoped_and_use_signal_names(tmp_path) -> None:
    db_path = tmp_path / "mqtt.duckdb"
    _create_mqtt_signal_db(db_path)

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        invariants = mine_inter_signal_correlations(
            conn,
            0.0,
            2000.0,
            min_observations=10,
            correlation_threshold=0.99,
        )
    finally:
        conn.close()

    assert len(invariants) == 1
    inv = invariants[0]
    assert inv["type"] == "inter_signal"
    assert inv["server_host"] == "BROKER"
    assert inv["parameters"]["signal_guid_a"] in {"guid-temp", "guid-pressure"}
    assert inv["parameters"]["signal_guid_b"] in {"guid-temp", "guid-pressure"}
    assert inv["parameters"]["relationship"] == "positive"


def test_mine_mqtt_invariants_builds_graph(tmp_path) -> None:
    db_path = tmp_path / "mqtt.duckdb"
    _create_mqtt_signal_db(db_path)

    result = mine_mqtt_invariants(
        MqttInvariantConfig(
            signal_db=db_path,
            output=tmp_path / "mqtt_invariants.json",
            min_observations=10,
            correlation_threshold=0.99,
        )
    )

    assert result["protocol"] == "mqtt"
    assert result["total_observations_used"] == 240
    assert result["signal_summary"]["signals"] == 3
    assert len(result["correlation_graph"]["nodes"]) == 3
    assert len(result["correlation_graph"]["edges"]) == 1
    assert {inv["type"] for inv in result["invariants"]} == {
        "value_range",
        "inter_signal",
    }
