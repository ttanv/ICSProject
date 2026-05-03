"""Tests for the OPC UA GECO-style downstream detector."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from network_aug.geco_opcua import (
    GecoScoreConfig,
    GecoTrainConfig,
    score_geco,
    train_geco,
)
from network_aug.geco_opcua.export import render_alert_statements


SCHEMA = """
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


def _insert_process_rows(db_path: Path, *, attacked: bool) -> dict[str, str]:
    """Three coupled signals: inflow, outflow, level. Level drifts up under attack."""
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute(SCHEMA)
        rows = []
        guids = {
            "inflow": "{sig-inflow}",
            "outflow": "{sig-outflow}",
            "level": "{sig-level}",
        }
        node_ids = {
            "inflow": 'ns=3;s="Tank"."Inflow"',
            "outflow": 'ns=3;s="Tank"."Outflow"',
            "level": 'ns=3;s="Tank"."Level"',
        }
        display_names = {
            "inflow": "Tank.Inflow",
            "outflow": "Tank.Outflow",
            "level": "Tank.Level",
        }
        level = 100.0
        for i in range(240):
            ts = float(i)
            inflow = 40 + (i % 7)
            outflow = 18 + (i % 5)
            next_level = level + 0.25 * inflow - 0.30 * outflow
            if attacked and i >= 180:
                next_level += 15.0

            values = {
                "inflow": inflow,
                "outflow": outflow,
                "level": round(next_level),
            }
            for name, value in values.items():
                rows.append(
                    (
                        ts,
                        node_ids[name],
                        display_names[name],
                        float(value),
                        "read",
                        "MSG",
                        "ReadResponse",
                        "ft-gw-01",
                        "ft-plc-01",
                        "192.168.0.5",
                        "192.168.0.1",
                        i,
                        2_000_000,
                        guids[name],
                        "synthetic.pcap",
                    )
                )
            level = next_level

        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return guids
    finally:
        conn.close()


def _insert_constant_rows(db_path: Path, *, flip_at: int | None) -> dict[str, str]:
    """Two constant signals; optionally flip one at flip_at to test attack response."""
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute(SCHEMA)
        rows = []
        guids = {"flat_a": "{sig-flat-a}", "flat_b": "{sig-flat-b}"}
        node_ids = {"flat_a": 'ns=3;s="Flat"."A"', "flat_b": 'ns=3;s="Flat"."B"'}
        display_names = {"flat_a": "Flat.A", "flat_b": "Flat.B"}
        for i in range(240):
            ts = float(i)
            a = 7
            b = 42
            if flip_at is not None and i >= flip_at:
                a = 8
            for name, value in (("flat_a", a), ("flat_b", b)):
                rows.append(
                    (
                        ts,
                        node_ids[name],
                        display_names[name],
                        float(value),
                        "read",
                        "MSG",
                        "ReadResponse",
                        "ft-gw-02",
                        "ft-plc-02",
                        "192.168.0.6",
                        "192.168.0.2",
                        i,
                        2_000_001,
                        guids[name],
                        "flat.pcap",
                    )
                )
        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return guids
    finally:
        conn.close()


def test_geco_opcua_train_and_score_benign(tmp_path: Path) -> None:
    baseline_db = tmp_path / "baseline.duckdb"
    guids = _insert_process_rows(baseline_db, attacked=False)
    model_path = tmp_path / "model.json"
    alerts_path = tmp_path / "alerts.json"

    model_set = train_geco(
        GecoTrainConfig(
            signal_db=baseline_db,
            output=model_path,
            min_observations=20,
            min_rows=20,
            candidate_limit=4,
            max_function_length=2,
        )
    )
    assert model_set.models
    assert model_set.protocol == "opcua"

    level_models = [m for m in model_set.models if m.target_guid == guids["level"]]
    assert level_models
    assert level_models[0].row_count >= 20
    # OPC UA-specific identity carried through:
    assert level_models[0].node_id == 'ns=3;s="Tank"."Level"'
    assert level_models[0].display_name == "Tank.Level"

    score_result = score_geco(
        GecoScoreConfig(
            signal_db=baseline_db,
            model=model_path,
            output=alerts_path,
        )
    )
    benign_alerts = [a for a in score_result.alerts if a.target_guid == guids["level"]]
    assert benign_alerts == []


def test_geco_opcua_detects_attacked_signal_and_exports_cypher(tmp_path: Path) -> None:
    baseline_db = tmp_path / "baseline.duckdb"
    attack_db = tmp_path / "attack.duckdb"
    guids = _insert_process_rows(baseline_db, attacked=False)
    _insert_process_rows(attack_db, attacked=True)

    model_path = tmp_path / "model.json"
    alerts_path = tmp_path / "alerts.json"

    model_set = train_geco(
        GecoTrainConfig(
            signal_db=baseline_db,
            output=model_path,
            min_observations=20,
            min_rows=20,
            candidate_limit=4,
            max_function_length=2,
        )
    )
    assert model_set.models

    score_result = score_geco(
        GecoScoreConfig(
            signal_db=attack_db,
            model=model_path,
            output=alerts_path,
        )
    )
    level_alerts = [a for a in score_result.alerts if a.target_guid == guids["level"]]
    assert level_alerts

    statements = render_alert_statements(score_result)
    assert any("GECOAlert" in statement for statement in statements)
    assert any(guids["level"] in statement for statement in statements)
    assert any("'opcua'" in statement for statement in statements)

    written = json.loads(alerts_path.read_text())
    assert written["protocol"] == "opcua"
    assert written["alerts"]
    assert all("node_id" in a for a in written["alerts"])
    assert all("display_name" in a for a in written["alerts"])


def test_geco_opcua_skips_constant_training_signals(tmp_path: Path) -> None:
    baseline_db = tmp_path / "flat_baseline.duckdb"
    attack_db = tmp_path / "flat_attack.duckdb"
    _insert_constant_rows(baseline_db, flip_at=None)
    _insert_constant_rows(attack_db, flip_at=180)

    model_path = tmp_path / "flat_model.json"
    alerts_path = tmp_path / "flat_alerts.json"

    model_set = train_geco(
        GecoTrainConfig(
            signal_db=baseline_db,
            output=model_path,
            min_observations=20,
            min_rows=20,
            candidate_limit=4,
            max_function_length=2,
        )
    )
    assert model_set.models == []

    score_result = score_geco(
        GecoScoreConfig(
            signal_db=attack_db,
            model=model_path,
            output=alerts_path,
        )
    )
    assert score_result.alerts == []


def test_geco_opcua_rejects_non_opcua_schema(tmp_path: Path) -> None:
    """A Modbus-shaped DB should raise a clear schema error, not a silent miss."""
    bad_db = tmp_path / "modbus.duckdb"
    conn = duckdb.connect(str(bad_db))
    try:
        conn.execute(
            """
            CREATE TABLE signal_observations (
                timestamp DOUBLE NOT NULL,
                register_address INTEGER NOT NULL,
                value INTEGER NOT NULL,
                signal_container_guid VARCHAR NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO signal_observations VALUES (1.0, 100, 5, '{x}')"
        )
    finally:
        conn.close()

    import pytest

    with pytest.raises(ValueError, match="OPC UA signal table"):
        train_geco(
            GecoTrainConfig(
                signal_db=bad_db,
                output=tmp_path / "should_not_be_written.json",
                min_observations=1,
                min_rows=2,
            )
        )


def test_geco_opcua_cli_smoke(tmp_path: Path) -> None:
    baseline_db = tmp_path / "baseline.duckdb"
    attack_db = tmp_path / "attack.duckdb"
    _insert_process_rows(baseline_db, attacked=False)
    _insert_process_rows(attack_db, attacked=True)

    model_path = tmp_path / "cli_model.json"
    alerts_path = tmp_path / "cli_alerts.json"
    cypher_path = tmp_path / "cli_alerts.cypher"

    root = Path(__file__).resolve().parent.parent

    train_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "network_aug.geco_opcua",
            "train",
            "--signal-db",
            str(baseline_db),
            "--output",
            str(model_path),
            "--min-observations",
            "20",
            "--min-rows",
            "20",
            "--candidate-limit",
            "4",
            "--max-function-length",
            "2",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert train_proc.returncode == 0, train_proc.stderr
    assert model_path.exists()

    score_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "network_aug.geco_opcua",
            "score",
            "--signal-db",
            str(attack_db),
            "--model",
            str(model_path),
            "--output",
            str(alerts_path),
            "--emit-cypher",
            str(cypher_path),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert score_proc.returncode == 0, score_proc.stderr
    assert alerts_path.exists()
    assert cypher_path.exists()
    payload = json.loads(alerts_path.read_text())
    assert payload["protocol"] == "opcua"
    assert payload["alerts"]
