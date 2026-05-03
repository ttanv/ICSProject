from __future__ import annotations

import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from invariantExperiments.extract_opcua_invariants import (
    OpcUaInvariantConfig,
    mine_inter_signal_correlations,
    mine_opcua_invariants,
    mine_value_ranges,
)


def _create_opcua_signal_db(path) -> None:
    conn = duckdb.connect(str(path))
    conn.execute(
        """
        CREATE TABLE signal_observations (
            timestamp DOUBLE NOT NULL,
            node_id VARCHAR NOT NULL,
            display_name VARCHAR NOT NULL,
            value DOUBLE NOT NULL,
            access_type VARCHAR NOT NULL,
            message_type VARCHAR,
            service_type VARCHAR,
            client_host VARCHAR NOT NULL,
            server_host VARCHAR NOT NULL,
            client_ip VARCHAR NOT NULL,
            server_ip VARCHAR NOT NULL,
            request_id INTEGER,
            secure_channel_id INTEGER,
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
                    "ns=2;s=Sensor.Temp",
                    "Sensor.Temp",
                    temp,
                    "read",
                    "MSG",
                    "ReadResponse",
                    "HMI",
                    "PLC-A",
                    "10.0.0.10",
                    "10.0.0.20",
                    i,
                    1,
                    "guid-temp",
                    "test.pcap",
                ),
                (
                    ts,
                    "ns=2;s=Sensor.Pressure",
                    "Sensor.Pressure",
                    pressure,
                    "read",
                    "MSG",
                    "ReadResponse",
                    "HMI",
                    "PLC-A",
                    "10.0.0.10",
                    "10.0.0.20",
                    i + 1000,
                    1,
                    "guid-pressure",
                    "test.pcap",
                ),
                (
                    ts,
                    "ns=2;s=State.Active",
                    "State.Active",
                    0.0,
                    "read",
                    "MSG",
                    "ReadResponse",
                    "HMI",
                    "PLC-A",
                    "10.0.0.10",
                    "10.0.0.20",
                    i + 2000,
                    1,
                    "guid-active",
                    "test.pcap",
                ),
            ]
        )

    conn.executemany(
        "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.close()


def test_opcua_value_ranges_use_signal_guid_and_keep_state_flags(tmp_path) -> None:
    db_path = tmp_path / "opcua.duckdb"
    _create_opcua_signal_db(db_path)

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        invariants = mine_value_ranges(conn, 0.0, 2000.0, min_observations=10)
    finally:
        conn.close()

    by_guid = {inv["signal_guid"]: inv for inv in invariants}
    assert set(by_guid) == {"guid-temp", "guid-pressure", "guid-active"}
    assert by_guid["guid-temp"]["node_id"] == "ns=2;s=Sensor.Temp"
    assert by_guid["guid-temp"]["parameters"]["min"] == 20.0
    assert by_guid["guid-active"]["parameters"]["binary_like"] is True
    assert by_guid["guid-active"]["parameters"]["constant"] is True


def test_opcua_correlations_are_server_scoped_and_use_node_names(tmp_path) -> None:
    db_path = tmp_path / "opcua.duckdb"
    _create_opcua_signal_db(db_path)

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
    assert inv["server_host"] == "PLC-A"
    assert inv["parameters"]["signal_guid_a"] in {"guid-temp", "guid-pressure"}
    assert inv["parameters"]["signal_guid_b"] in {"guid-temp", "guid-pressure"}
    assert inv["parameters"]["relationship"] == "positive"


def test_mine_opcua_invariants_builds_graph(tmp_path) -> None:
    db_path = tmp_path / "opcua.duckdb"
    _create_opcua_signal_db(db_path)

    result = mine_opcua_invariants(
        OpcUaInvariantConfig(
            signal_db=db_path,
            output=tmp_path / "opcua_invariants.json",
            min_observations=10,
            correlation_threshold=0.99,
        )
    )

    assert result["protocol"] == "opcua"
    assert result["total_observations_used"] == 240
    assert result["signal_summary"]["signals"] == 3
    assert len(result["correlation_graph"]["nodes"]) == 3
    assert len(result["correlation_graph"]["edges"]) == 1
    assert {inv["type"] for inv in result["invariants"]} == {
        "value_range",
        "inter_signal",
    }
