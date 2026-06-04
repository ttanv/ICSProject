from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from invariantExperiments.collect_alerts import collect_alerts, main, normalize_geco_alerts
from tests.test_validate_invariants import (
    _create_modbus_signal_db,
    _modbus_row,
    _write_invariants,
)


def test_normalize_geco_modbus_and_opcua_alerts(tmp_path) -> None:
    modbus_path = tmp_path / "geco_alerts.json"
    modbus_path.write_text(
        json.dumps(
            {
                "signal_db_path": "attack_modbus.duckdb",
                "model_path": "modbus_model.json",
                "alerts": [
                    {
                        "target_guid": "guid-level",
                        "register_address": 40001,
                        "unit_id": 1,
                        "server_host": "PLC",
                        "start_timestamp": 100.0,
                        "end_timestamp": 110.0,
                        "first_trigger_timestamp": 101.0,
                        "peak_cusum": 30.0,
                        "threshold": 10.0,
                        "triggered_points": 5,
                        "max_abs_error": 7.5,
                    }
                ],
            }
        )
    )

    opcua_path = tmp_path / "opcua_geco_alerts.json"
    opcua_path.write_text(
        json.dumps(
            {
                "protocol": "opcua",
                "signal_db_path": "attack_opcua.duckdb",
                "model_path": "opcua_model.json",
                "alerts": [
                    {
                        "target_guid": "guid-pressure",
                        "node_id": "ns=2;i=10",
                        "display_name": "Sensor.Pressure",
                        "server_host": "PLC-A",
                        "start_timestamp": 120.0,
                        "end_timestamp": 130.0,
                        "first_trigger_timestamp": 121.0,
                        "peak_cusum": 12.0,
                        "threshold": 10.0,
                        "triggered_points": 2,
                        "max_abs_error": 3.5,
                    }
                ],
            }
        )
    )

    modbus_alert = normalize_geco_alerts(modbus_path)[0]
    opcua_alert = normalize_geco_alerts(opcua_path)[0]

    assert modbus_alert["source"] == "geco"
    assert modbus_alert["protocol"] == "modbus"
    assert modbus_alert["type"] == "geco_cusum"
    assert modbus_alert["name"] == "reg_40001"
    assert modbus_alert["severity"] == "high"
    assert modbus_alert["details"]["peak_cusum"] == 30.0

    assert opcua_alert["protocol"] == "opcua"
    assert opcua_alert["name"] == "Sensor.Pressure"
    assert opcua_alert["severity"] == "low"
    assert opcua_alert["identity"]["node_id"] == "ns=2;i=10"


def test_collect_alerts_combines_sain_and_geco_cli(tmp_path) -> None:
    modbus_db = tmp_path / "attack_modbus.duckdb"
    _create_modbus_signal_db(
        modbus_db,
        [
            _modbus_row(1000.0, 1, 4, "guid-modbus"),
            _modbus_row(1001.0, 1, 15, "guid-modbus"),
        ],
    )
    sain_inv = _write_invariants(
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

    geco_path = tmp_path / "geco_alerts.json"
    geco_path.write_text(
        json.dumps(
            {
                "signal_db_path": str(modbus_db),
                "model_path": "modbus_model.json",
                "alerts": [
                    {
                        "target_guid": "guid-level",
                        "register_address": 2,
                        "unit_id": 1,
                        "server_host": "PLC",
                        "start_timestamp": 1002.0,
                        "end_timestamp": 1005.0,
                        "first_trigger_timestamp": 1002.0,
                        "peak_cusum": 20.0,
                        "threshold": 10.0,
                        "triggered_points": 3,
                        "max_abs_error": 8.0,
                    }
                ],
            }
        )
    )

    report = collect_alerts(
        sain_pairs=[(sain_inv, modbus_db)],
        geco_alert_paths=[(geco_path, "modbus")],
    )

    assert report["summary"]["total_alerts"] == 2
    assert report["summary"]["by_source"] == {"sain": 1, "geco": 1}
    assert [alert["source"] for alert in report["alerts"]] == ["sain", "geco"]

    output = tmp_path / "unified_alerts.json"
    rc = main(
        [
            "--sain-pair",
            str(sain_inv),
            str(modbus_db),
            "--geco-alerts",
            f"modbus={geco_path}",
            "--output",
            str(output),
        ]
    )

    assert rc == 0
    parsed = json.loads(output.read_text())
    assert parsed["summary"]["total_alerts"] == 2
    assert {alert["type"] for alert in parsed["alerts"]} == {"value_range", "geco_cusum"}
