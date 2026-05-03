"""Tests for the GECO-style downstream detector."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from network_aug.geco import GecoScoreConfig, GecoTrainConfig, score_geco, train_geco
from network_aug.geco.export import render_alert_statements


SCHEMA = """
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


def _insert_process_rows(db_path: Path, *, attacked: bool) -> dict[str, str]:
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute(SCHEMA)
        rows = []
        guids = {
            "inflow": "{sig-inflow}",
            "outflow": "{sig-outflow}",
            "level": "{sig-level}",
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
                        {"inflow": 101, "outflow": 102, "level": 103}[name],
                        int(value),
                        "read",
                        3,
                        1,
                        "hmi-01",
                        "plc-01",
                        "10.0.0.10",
                        "10.0.0.20",
                        i,
                        ts,
                        ts + 0.01,
                        None,
                        guids[name],
                        "synthetic.pcap",
                    )
                )
            level = next_level

        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return guids
    finally:
        conn.close()


def _insert_predictor_rows(db_path: Path, *, attacked: bool) -> dict[str, str]:
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute(SCHEMA)
        rows = []
        guids = {
            "driver": "{sig-driver}",
            "target": "{sig-target}",
        }
        driver_values = [((i * 17) + 11) % 97 for i in range(240)]
        target_values = [50]
        for i in range(1, 240):
            next_value = 5 + (2 * driver_values[i - 1])
            if attacked and i >= 180:
                next_value += 25
            target_values.append(next_value)

        for i in range(240):
            ts = float(i)
            values = {
                "driver": driver_values[i],
                "target": target_values[i],
            }
            for name, value in values.items():
                rows.append(
                    (
                        ts,
                        {"driver": 201, "target": 202}[name],
                        int(value),
                        "read",
                        3,
                        1,
                        "hmi-02",
                        "plc-02",
                        "10.0.0.30",
                        "10.0.0.40",
                        i,
                        ts,
                        ts + 0.01,
                        None,
                        guids[name],
                        "predictor.pcap",
                    )
                )
        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return guids
    finally:
        conn.close()


def test_geco_train_and_score_benign(tmp_path: Path) -> None:
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

    level_models = [model for model in model_set.models if model.target_guid == guids["level"]]
    assert level_models
    assert level_models[0].row_count >= 20

    score_result = score_geco(
        GecoScoreConfig(
            signal_db=baseline_db,
            model=model_path,
            output=alerts_path,
        )
    )
    benign_alerts = [alert for alert in score_result.alerts if alert.target_guid == guids["level"]]
    assert benign_alerts == []


def test_geco_detects_attacked_signal_and_exports_cypher(tmp_path: Path) -> None:
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
    level_alerts = [alert for alert in score_result.alerts if alert.target_guid == guids["level"]]
    assert level_alerts

    statements = render_alert_statements(score_result)
    assert any("GECOAlert" in statement for statement in statements)
    assert any(guids["level"] in statement for statement in statements)

    written = json.loads(alerts_path.read_text())
    assert written["alerts"]


def test_geco_uses_predictor_series_for_multisignal_models(tmp_path: Path) -> None:
    baseline_db = tmp_path / "predictor_baseline.duckdb"
    attack_db = tmp_path / "predictor_attack.duckdb"
    guids = _insert_predictor_rows(baseline_db, attacked=False)
    _insert_predictor_rows(attack_db, attacked=True)

    model_path = tmp_path / "predictor_model.json"
    alerts_path = tmp_path / "predictor_alerts.json"

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

    target_models = [model for model in model_set.models if model.target_guid == guids["target"]]
    assert target_models
    assert target_models[0].predictor_series_ids

    score_result = score_geco(
        GecoScoreConfig(
            signal_db=attack_db,
            model=model_path,
            output=alerts_path,
        )
    )
    target_alerts = [alert for alert in score_result.alerts if alert.target_guid == guids["target"]]
    assert target_alerts


def _insert_constant_rows(db_path: Path, *, flip_at: int | None) -> dict[str, str]:
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute(SCHEMA)
        rows = []
        guids = {"flat_a": "{sig-flat-a}", "flat_b": "{sig-flat-b}"}
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
                        {"flat_a": 301, "flat_b": 302}[name],
                        int(value),
                        "read",
                        3,
                        1,
                        "hmi-03",
                        "plc-03",
                        "10.0.0.50",
                        "10.0.0.60",
                        i,
                        ts,
                        ts + 0.01,
                        None,
                        guids[name],
                        "flat.pcap",
                    )
                )
        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return guids
    finally:
        conn.close()


def test_geco_skips_constant_training_signals(tmp_path: Path) -> None:
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


def test_geco_cli_smoke(tmp_path: Path) -> None:
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
            "network_aug.geco",
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
            "network_aug.geco",
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
    assert json.loads(alerts_path.read_text())["alerts"]
