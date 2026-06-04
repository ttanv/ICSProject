"""Collect SAIN violations and GECO alerts into one normalized alert file."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
from typing import Any, Iterable, List, Optional, Tuple

from .validate_invariants import validate_many


def _json_number(value: Any, digits: int = 6) -> Optional[float]:
    if value is None:
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return round(result, digits)


def _alert_sort_key(alert: dict) -> tuple:
    start = alert.get("start_timestamp")
    return (
        start is None,
        float(start) if start is not None else float("inf"),
        alert.get("source") or "",
        alert.get("protocol") or "",
        alert.get("type") or "",
        alert.get("name") or "",
    )


def _sain_severity(violation: dict) -> str:
    if violation.get("type") in {"inter_register", "inter_signal", "state_transition"}:
        return "high"
    nested = violation.get("violations") or {}
    if "mean_shift" in nested and ("above_max" in nested or "below_min" in nested):
        return "high"
    if "above_max" in nested or "below_min" in nested:
        return "medium"
    return "low"


def _geco_severity(alert: dict) -> str:
    peak = alert.get("peak_cusum")
    threshold = alert.get("threshold")
    if peak is None or threshold in {None, 0}:
        return "medium"
    ratio = float(peak) / float(threshold)
    if ratio >= 3.0:
        return "high"
    if ratio >= 1.5:
        return "medium"
    return "low"


def _sain_identity_label(violation: dict) -> str:
    identity = violation.get("identity") or {}
    protocol = violation.get("protocol")
    if protocol == "modbus":
        reg = identity.get("register") or violation.get("register")
        return f"reg_{reg}"
    if protocol == "mqtt":
        return (
            identity.get("signal_name")
            or ".".join(
                part
                for part in [identity.get("topic"), identity.get("field_name")]
                if part
            )
            or violation.get("name")
            or "mqtt_signal"
        )
    if protocol == "opcua":
        return identity.get("display_name") or identity.get("node_id") or violation.get("name") or "opcua_signal"
    return violation.get("name") or "signal"


def normalize_sain_violations(report: dict) -> List[dict]:
    alerts = []
    for violation in report.get("violations", []):
        source = violation.get("source") or {}
        first_time = violation.get("first_violation_time")
        alerts.append(
            {
                "source": "sain",
                "protocol": violation.get("protocol") or "unknown",
                "type": violation.get("type") or "sain_violation",
                "name": _sain_identity_label(violation),
                "signal_ids": violation.get("signal_ids") or [],
                "start_timestamp": first_time,
                "end_timestamp": first_time,
                "severity": _sain_severity(violation),
                "details": {
                    "violations": violation.get("violations") or {},
                    "benign": violation.get("benign") or {},
                    "attack": violation.get("attack") or {},
                    "observation_count": violation.get("observation_count"),
                },
                "source_files": {
                    "invariants_path": source.get("invariants_path"),
                    "attack_db_path": source.get("attack_db_path"),
                },
                "raw": violation,
            }
        )
    return alerts


def _infer_geco_protocol(data: dict, alert: dict, explicit_protocol: Optional[str]) -> str:
    if explicit_protocol:
        return explicit_protocol
    protocol = data.get("protocol")
    if isinstance(protocol, str) and protocol:
        return protocol.lower()
    if "node_id" in alert or "display_name" in alert:
        return "opcua"
    return "modbus"


def normalize_geco_alerts(
    alerts_path: Path,
    *,
    protocol: Optional[str] = None,
) -> List[dict]:
    data = json.loads(alerts_path.read_text())
    alerts = []
    for alert in data.get("alerts", []):
        inferred_protocol = _infer_geco_protocol(data, alert, protocol)
        if inferred_protocol == "opcua":
            name = alert.get("display_name") or alert.get("node_id") or alert.get("target_guid")
            identity = {
                "target_guid": alert.get("target_guid"),
                "node_id": alert.get("node_id"),
                "display_name": alert.get("display_name"),
                "server_host": alert.get("server_host"),
            }
        else:
            register = alert.get("register_address")
            name = f"reg_{register}" if register is not None else alert.get("target_guid")
            identity = {
                "target_guid": alert.get("target_guid"),
                "register_address": register,
                "unit_id": alert.get("unit_id"),
                "server_host": alert.get("server_host"),
            }

        alerts.append(
            {
                "source": "geco",
                "protocol": inferred_protocol,
                "type": "geco_cusum",
                "name": name or "geco_signal",
                "signal_ids": [alert["target_guid"]] if alert.get("target_guid") else [],
                "start_timestamp": alert.get("start_timestamp"),
                "end_timestamp": alert.get("end_timestamp"),
                "severity": _geco_severity(alert),
                "details": {
                    "first_trigger_timestamp": alert.get("first_trigger_timestamp"),
                    "peak_cusum": _json_number(alert.get("peak_cusum")),
                    "threshold": _json_number(alert.get("threshold")),
                    "triggered_points": alert.get("triggered_points"),
                    "max_abs_error": _json_number(alert.get("max_abs_error")),
                },
                "identity": identity,
                "source_files": {
                    "geco_alerts_path": str(alerts_path),
                    "signal_db_path": data.get("signal_db_path"),
                    "model_path": data.get("model_path"),
                },
                "raw": alert,
            }
        )
    return alerts


def collect_alerts(
    *,
    sain_pairs: Iterable[Tuple[Path, Path]] = (),
    geco_alert_paths: Iterable[Tuple[Path, Optional[str]]] = (),
) -> dict:
    alerts: List[dict] = []
    inputs = {"sain_pairs": [], "geco_alerts": []}

    sain_pair_list = list(sain_pairs)
    if sain_pair_list:
        sain_report = validate_many(sain_pair_list, print_report=False)
        alerts.extend(normalize_sain_violations(sain_report))
        inputs["sain_pairs"] = [
            {"invariants_path": str(invariants), "attack_db_path": str(db)}
            for invariants, db in sain_pair_list
        ]

    for alerts_path, protocol in geco_alert_paths:
        alerts.extend(normalize_geco_alerts(alerts_path, protocol=protocol))
        inputs["geco_alerts"].append(
            {"alerts_path": str(alerts_path), "protocol": protocol}
        )

    alerts = sorted(alerts, key=_alert_sort_key)
    counts_by_source: dict[str, int] = defaultdict(int)
    counts_by_protocol: dict[str, int] = defaultdict(int)
    counts_by_type: dict[str, int] = defaultdict(int)
    for alert in alerts:
        counts_by_source[alert["source"]] += 1
        counts_by_protocol[alert["protocol"]] += 1
        counts_by_type[alert["type"]] += 1

    return {
        "summary": {
            "total_alerts": len(alerts),
            "by_source": dict(counts_by_source),
            "by_protocol": dict(counts_by_protocol),
            "by_type": dict(counts_by_type),
        },
        "inputs": inputs,
        "alerts": alerts,
    }


def _parse_geco_arg(value: str) -> Tuple[Path, Optional[str]]:
    if "=" not in value:
        return Path(value), None
    protocol, path = value.split("=", 1)
    protocol = protocol.strip().lower()
    if protocol not in {"modbus", "opcua", "mqtt"}:
        raise argparse.ArgumentTypeError(
            "GECO protocol prefix must be one of modbus=, opcua=, mqtt="
        )
    return Path(path), protocol


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect SAIN invariant violations and GECO alerts into one JSON file."
    )
    parser.add_argument(
        "--sain-pair",
        action="append",
        nargs=2,
        metavar=("INVARIANTS_JSON", "ATTACK_DUCKDB"),
        default=[],
        help="SAIN invariant/attack DB pair. Repeat for Modbus, MQTT, OPC UA.",
    )
    parser.add_argument(
        "--geco-alerts",
        action="append",
        type=_parse_geco_arg,
        default=[],
        metavar="[PROTOCOL=]ALERTS_JSON",
        help=(
            "GECO alerts JSON. Optionally prefix with modbus= or opcua= "
            "when the file has no protocol field."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Path for unified alerts JSON.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    sain_pairs = [(Path(invariants), Path(db)) for invariants, db in args.sain_pair]
    if not sain_pairs and not args.geco_alerts:
        parser.error("provide at least one --sain-pair or --geco-alerts input")

    report = collect_alerts(sain_pairs=sain_pairs, geco_alert_paths=args.geco_alerts)
    args.output.write_text(json.dumps(report, indent=2))
    print(
        f"Wrote {report['summary']['total_alerts']} unified alerts to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
