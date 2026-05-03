"""Export GECO alerts into Cypher for Neo4j import."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List

from .. import cypher_emit
from .models import GecoAlertEvent, GecoScoreResult


def _alert_guid(alert: GecoAlertEvent) -> str:
    raw = (
        f"GECOAlert|{alert.target_guid}|{alert.start_timestamp:.6f}|"
        f"{alert.end_timestamp:.6f}|{alert.peak_cusum:.6f}"
    )
    digest = hashlib.md5(raw.encode("utf-8")).hexdigest()
    return "{" + digest[:8] + "-" + digest[8:12] + "-" + digest[12:16] + "-" + digest[16:20] + "-" + digest[20:32] + "}"


def render_alert_statements(result: GecoScoreResult) -> List[str]:
    """Return Cypher statements that materialize GECO alerts."""
    statements: List[str] = []
    for alert in result.alerts:
        guid = cypher_emit.escape_cypher_string(_alert_guid(alert))
        target_guid = cypher_emit.escape_cypher_string(alert.target_guid)
        props = cypher_emit.format_properties(
            {
                "guid": guid,
                "source": "geco",
                "registerAddress": alert.register_address,
                "unitId": alert.unit_id,
                "serverHost": alert.server_host,
                "startTimestamp": round(alert.start_timestamp, 6),
                "endTimestamp": round(alert.end_timestamp, 6),
                "firstTriggerTimestamp": round(alert.first_trigger_timestamp, 6),
                "peakCusum": round(alert.peak_cusum, 6),
                "threshold": round(alert.threshold, 6),
                "triggeredPoints": alert.triggered_points,
                "maxAbsError": round(alert.max_abs_error, 6),
            }
        )
        statements.append(
            (
                f"MERGE (alert:GECOAlert {{guid: '{guid}'}})\n"
                f"SET alert += {props}\n"
                f"WITH alert\n"
                f"MATCH (sig:SignalContainer {{guid: '{target_guid}'}})\n"
                f"MERGE (alert)-[:ON_SIGNAL]->(sig);"
            )
        )
    return statements


def write_alert_cypher(*, result: GecoScoreResult, output_path: Path) -> None:
    statements = render_alert_statements(result)
    output_path.write_text("\n\n".join(statements) + ("\n" if statements else ""))
