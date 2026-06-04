from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from invariantExperiments.validate_invariants import main, validate, validate_many


def _write_invariants(path: Path, invariants: list[dict]) -> Path:
    path.write_text(json.dumps({"invariants": invariants}))
    return path


def _create_modbus_signal_db(path: Path, rows: list[tuple]) -> None:
    conn = duckdb.connect(str(path))
    conn.execute(
        """
        CREATE TABLE signal_observations (
            timestamp DOUBLE NOT NULL,
            register_address INTEGER NOT NULL,
            value INTEGER NOT NULL,
            access_type VARCHAR NOT NULL,
            function_code INTEGER NOT NULL,
            unit_id INTEGER,
            client_host VARCHAR NOT NULL,
            server_host VARCHAR NOT NULL,
            client_ip VARCHAR NOT NULL,
            server_ip VARCHAR NOT NULL,
            transaction_id INTEGER,
            request_timestamp DOUBLE,
            response_timestamp DOUBLE,
            write_acknowledged BOOLEAN,
            signal_container_guid VARCHAR NOT NULL,
            pcap_file VARCHAR NOT NULL
        )
        """
    )
    conn.executemany(
        "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.close()


def _modbus_row(
    ts: float,
    register: int,
    value: int,
    guid: str,
    *,
    unit_id: int = 1,
    server_host: str = "PLC",
) -> tuple:
    return (
        ts,
        register,
        value,
        "read",
        3,
        unit_id,
        "HMI",
        server_host,
        "10.0.0.10",
        "10.0.0.20",
        int(ts),
        ts,
        ts,
        True,
        guid,
        "test.pcap",
    )


def _create_mqtt_signal_db(path: Path, rows: list[tuple]) -> None:
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
    conn.executemany(
        "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.close()


def _mqtt_row(ts: float, topic: str, field: str, name: str, value: float, guid: str) -> tuple:
    return (
        ts,
        topic,
        field,
        name,
        value,
        "write",
        "PUBLISHER",
        "BROKER",
        "10.0.0.10",
        "10.0.0.20",
        int(ts),
        1,
        False,
        False,
        "pub-1",
        guid,
        "test.pcap",
    )


def _create_opcua_signal_db(path: Path, rows: list[tuple]) -> None:
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
    conn.executemany(
        "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.close()


def _opcua_row(ts: float, node_id: str, name: str, value: float, guid: str) -> tuple:
    return (
        ts,
        node_id,
        name,
        value,
        "read",
        "MSG",
        "ReadResponse",
        "HMI",
        "PLC-A",
        "10.0.0.10",
        "10.0.0.20",
        int(ts),
        1,
        guid,
        "test.pcap",
    )


def test_validate_modbus_value_range_outputs_standard_violation(tmp_path) -> None:
    db_path = tmp_path / "modbus.duckdb"
    _create_modbus_signal_db(
        db_path,
        [
            _modbus_row(1000.0, 1, 4, "guid-temp"),
            _modbus_row(1001.0, 1, 6, "guid-temp"),
            _modbus_row(1002.0, 1, 12, "guid-temp"),
        ],
    )
    inv_path = _write_invariants(
        tmp_path / "invariants.json",
        [
            {
                "type": "value_range",
                "registers": [1],
                "unit_id": 1,
                "signal_container_guid": "guid-temp",
                "server_host": "PLC",
                "parameters": {"min": 0, "max": 10, "mean": 5, "stddev": 1},
            }
        ],
    )

    report = validate(inv_path, db_path)

    assert report["violations_detected"]["value_range"] == 1
    violation = report["violations"][0]
    assert violation["protocol"] == "modbus"
    assert violation["type"] == "value_range"
    assert violation["register"] == 1
    assert violation["first_violation_time"] == 1002.0
    assert violation["violations"]["above_max"] == "12.0 > 10"
    assert report["flat_violations"]["value_range"][0]["signal_container_guid"] == "guid-temp"


def test_validate_modbus_inter_register_correlation(tmp_path) -> None:
    db_path = tmp_path / "modbus.duckdb"
    rows = []
    for i in range(40):
        rows.append(_modbus_row(1000.0 + i, 1, i, "guid-a"))
        rows.append(_modbus_row(1000.0 + i, 2, (i * 7) % 11, "guid-b"))
    _create_modbus_signal_db(db_path, rows)
    inv_path = _write_invariants(
        tmp_path / "invariants.json",
        [
            {
                "type": "inter_register",
                "registers": [1, 2],
                "unit_id": 1,
                "server_host": "PLC",
                "parameters": {
                    "register_a": 1,
                    "register_b": 2,
                    "signal_guid_a": "guid-a",
                    "signal_guid_b": "guid-b",
                    "server_host_a": "PLC",
                    "server_host_b": "PLC",
                    "pearson_r": 1.0,
                    "slope": 2.0,
                    "intercept": 0.0,
                    "relationship": "positive",
                },
            }
        ],
    )

    report = validate(inv_path, db_path)

    assert report["violations_detected"]["inter_register"] == 1
    violation = report["violations"][0]
    assert violation["type"] == "inter_register"
    assert "correlation_drop" in violation["violations"]
    assert violation["registers"] == [1, 2]


def test_validate_mqtt_value_range_and_inter_signal(tmp_path) -> None:
    db_path = tmp_path / "mqtt.duckdb"
    rows = []
    for i in range(40):
        ts = 1000.0 + i
        rows.append(
            _mqtt_row(ts, "factory/sensor", "temp", "factory/sensor.temp", 20.0 + i, "guid-temp")
        )
        rows.append(
            _mqtt_row(
                ts,
                "factory/sensor",
                "pressure",
                "factory/sensor.pressure",
                float((i * 7) % 11),
                "guid-pressure",
            )
        )
    _create_mqtt_signal_db(db_path, rows)
    inv_path = _write_invariants(
        tmp_path / "mqtt_invariants.json",
        [
            {
                "type": "value_range",
                "protocol": "mqtt",
                "signal_guid": "guid-temp",
                "topic": "factory/sensor",
                "field_name": "temp",
                "signal_name": "factory/sensor.temp",
                "server_host": "BROKER",
                "parameters": {"min": 20.0, "max": 30.0, "mean": 25.0, "stddev": 1.0},
            },
            {
                "type": "inter_signal",
                "protocol": "mqtt",
                "server_host": "BROKER",
                "parameters": {
                    "signal_guid_a": "guid-temp",
                    "signal_guid_b": "guid-pressure",
                    "topic_a": "factory/sensor",
                    "topic_b": "factory/sensor",
                    "field_name_a": "temp",
                    "field_name_b": "pressure",
                    "signal_name_a": "factory/sensor.temp",
                    "signal_name_b": "factory/sensor.pressure",
                    "pearson_r": 1.0,
                    "slope": 3.0,
                    "intercept": 0.0,
                    "relationship": "positive",
                    "max_pair_lag_seconds": 5.0,
                },
            },
        ],
    )

    report = validate(inv_path, db_path)

    assert report["violations_detected"]["value_range"] == 1
    assert report["violations_detected"]["inter_signal"] == 1
    protocols = {violation["protocol"] for violation in report["violations"]}
    assert protocols == {"mqtt"}
    assert report["flat_violations"]["value_range"][0]["topic"] == "factory/sensor"


def test_validate_opcua_value_range_and_inter_signal(tmp_path) -> None:
    db_path = tmp_path / "opcua.duckdb"
    rows = []
    for i in range(40):
        ts = 1000.0 + i
        rows.append(_opcua_row(ts, "ns=2;i=1", "Sensor.Temp", float(i), "guid-temp"))
        rows.append(
            _opcua_row(ts, "ns=2;i=2", "Sensor.Pressure", float((i * 5) % 13), "guid-pressure")
        )
    _create_opcua_signal_db(db_path, rows)
    inv_path = _write_invariants(
        tmp_path / "opcua_invariants.json",
        [
            {
                "type": "value_range",
                "protocol": "opcua",
                "signal_guid": "guid-temp",
                "node_id": "ns=2;i=1",
                "display_name": "Sensor.Temp",
                "server_host": "PLC-A",
                "parameters": {"min": 0.0, "max": 10.0, "mean": 5.0, "stddev": 1.0},
            },
            {
                "type": "inter_signal",
                "protocol": "opcua",
                "server_host": "PLC-A",
                "parameters": {
                    "signal_guid_a": "guid-temp",
                    "signal_guid_b": "guid-pressure",
                    "node_id_a": "ns=2;i=1",
                    "node_id_b": "ns=2;i=2",
                    "display_name_a": "Sensor.Temp",
                    "display_name_b": "Sensor.Pressure",
                    "pearson_r": 1.0,
                    "slope": 2.0,
                    "intercept": 0.0,
                    "relationship": "positive",
                    "max_pair_lag_seconds": 5.0,
                },
            },
        ],
    )

    report = validate(inv_path, db_path)

    assert report["violations_detected"]["value_range"] == 1
    assert report["violations_detected"]["inter_signal"] == 1
    assert {violation["protocol"] for violation in report["violations"]} == {"opcua"}
    assert report["flat_violations"]["value_range"][0]["node_id"] == "ns=2;i=1"


def test_validate_modbus_state_transition_and_skips_malformed(tmp_path) -> None:
    db_path = tmp_path / "modbus.duckdb"
    _create_modbus_signal_db(
        db_path,
        [
            _modbus_row(1000.0, 99, 0, "guid-state"),
            _modbus_row(1001.0, 99, 0, "guid-state"),
            _modbus_row(1002.0, 99, 2, "guid-state"),
        ],
    )
    inv_path = _write_invariants(
        tmp_path / "invariants.json",
        [
            {
                "type": "state_transition",
                "registers": [99],
                "unit_id": 1,
                "parameters": {"from_state": 0, "to_state": 1},
            },
            {
                "type": "value_range",
                "parameters": {"min": 0, "max": 1},
            },
        ],
    )

    report = validate(inv_path, db_path)

    assert report["violations_detected"]["state_transition"] == 1
    violation = report["violations"][0]
    assert violation["type"] == "state_transition"
    assert violation["first_violation_time"] == 1002.0
    assert "unexpected_transition" in violation["violations"]
    assert report["invariants_checked"]["skipped"] == 1
    assert report["skipped_invariants"][0]["reason"] == "value_range invariant has no usable signal identity"


def test_validate_many_combines_protocol_pairs_and_cli_writes_single_file(tmp_path) -> None:
    modbus_db = tmp_path / "modbus.duckdb"
    _create_modbus_signal_db(
        modbus_db,
        [
            _modbus_row(1000.0, 1, 4, "guid-modbus"),
            _modbus_row(1001.0, 1, 15, "guid-modbus"),
        ],
    )
    modbus_inv = _write_invariants(
        tmp_path / "modbus_invariants.json",
        [
            {
                "type": "value_range",
                "registers": [1],
                "unit_id": 1,
                "signal_container_guid": "guid-modbus",
                "server_host": "PLC",
                "parameters": {"min": 0, "max": 10, "mean": 5, "stddev": 1},
            }
        ],
    )

    mqtt_db = tmp_path / "mqtt.duckdb"
    _create_mqtt_signal_db(
        mqtt_db,
        [
            _mqtt_row(1000.0, "factory/sensor", "temp", "factory/sensor.temp", 20.0, "guid-mqtt"),
            _mqtt_row(1001.0, "factory/sensor", "temp", "factory/sensor.temp", 50.0, "guid-mqtt"),
        ],
    )
    mqtt_inv = _write_invariants(
        tmp_path / "mqtt_invariants.json",
        [
            {
                "type": "value_range",
                "protocol": "mqtt",
                "signal_guid": "guid-mqtt",
                "topic": "factory/sensor",
                "field_name": "temp",
                "signal_name": "factory/sensor.temp",
                "server_host": "BROKER",
                "parameters": {"min": 20.0, "max": 30.0, "mean": 25.0, "stddev": 1.0},
            }
        ],
    )

    report = validate_many([(modbus_inv, modbus_db), (mqtt_inv, mqtt_db)], print_report=False)

    assert report["violations_detected"]["value_range"] == 2
    assert report["violations_detected"]["total"] == 2
    assert {violation["protocol"] for violation in report["violations"]} == {"modbus", "mqtt"}
    assert all("source" in violation for violation in report["violations"])

    output = tmp_path / "all_violations.json"
    rc = main(
        [
            "--pair",
            str(modbus_inv),
            str(modbus_db),
            "--pair",
            str(mqtt_inv),
            str(mqtt_db),
            "--output",
            str(output),
        ]
    )

    assert rc == 0
    parsed = json.loads(output.read_text())
    assert len(parsed["inputs"]) == 2
    assert parsed["violations_detected"]["total"] == 2
    assert {violation["protocol"] for violation in parsed["violations"]} == {"modbus", "mqtt"}
