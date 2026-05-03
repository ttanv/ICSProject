"""Dataset loading and alignment helpers for GECO-style training/scoring on OPC UA.

Mirrors network_aug.geco.dataset but reads from the standalone OPC UA signal
schema (signal_guid, node_id, display_name, server_host, ...) instead of the
Modbus schema. Series are identified by signal_guid, with composite series IDs
including client_host/server_host so multiple clients of the same node land in
separate series.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


REQUIRED_COLUMNS = {
    "timestamp",
    "node_id",
    "display_name",
    "value",
    "access_type",
    "client_host",
    "server_host",
    "signal_guid",
}

VALID_SIGNAL_PREDICATE = "isfinite(value) AND node_id NOT LIKE '%;s='"


@dataclass(frozen=True)
class SignalSeriesMeta:
    """Metadata for one raw OPC UA signal series."""

    series_id: str
    guid: str
    node_id: str
    display_name: str
    client_host: str
    server_host: str
    observation_count: int
    first_timestamp: float
    last_timestamp: float


@dataclass
class SignalSeries:
    """Ordered timestamp/value pairs for one OPC UA signal."""

    meta: SignalSeriesMeta
    timestamps: List[float] = field(default_factory=list)
    values: List[float] = field(default_factory=list)

    def append(self, timestamp: float, value: float) -> None:
        self.timestamps.append(timestamp)
        self.values.append(value)

    @property
    def count(self) -> int:
        return len(self.timestamps)


@dataclass
class TargetDataset:
    """Rows aligned to a target signal's update timestamps."""

    target: SignalSeries
    prev_timestamps: List[float]
    timestamps: List[float]
    prev_target_values: List[float]
    target_values: List[float]
    predictor_values: Dict[str, List[Optional[float]]]

    @property
    def row_count(self) -> int:
        return len(self.timestamps)


@dataclass
class DatasetWindow:
    """Loaded signal data for a time window."""

    signal_db_path: Path
    start_timestamp: float
    end_timestamp: float
    series_by_id: Dict[str, SignalSeries]

    @property
    def signals(self) -> List[SignalSeries]:
        return list(self.series_by_id.values())

    def group_by_device(self) -> Dict[str, List[SignalSeries]]:
        """Group series by server_host (OPC UA has no unit_id concept)."""
        grouped: Dict[str, List[SignalSeries]] = {}
        for series in self.series_by_id.values():
            grouped.setdefault(series.meta.server_host, []).append(series)
        return grouped


def make_series_id(
    *,
    guid: str,
    node_id: str,
    client_host: str,
    server_host: str,
) -> str:
    """Build a unique series identifier for one OPC UA signal-on-link."""
    return "|".join([guid, node_id, client_host, server_host])


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stdev(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean_value = _mean(values)
    variance = sum((value - mean_value) ** 2 for value in values) / len(values)
    return math.sqrt(max(variance, 0.0))


def pearson_correlation(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Return Pearson correlation or 0.0 for degenerate inputs."""
    if len(xs) != len(ys) or len(xs) < 2:
        return 0.0
    mean_x = _mean(xs)
    mean_y = _mean(ys)
    numerator = 0.0
    denom_x = 0.0
    denom_y = 0.0
    for x_val, y_val in zip(xs, ys):
        dx = x_val - mean_x
        dy = y_val - mean_y
        numerator += dx * dy
        denom_x += dx * dx
        denom_y += dy * dy
    if denom_x <= 0.0 or denom_y <= 0.0:
        return 0.0
    return numerator / math.sqrt(denom_x * denom_y)


def _ensure_schema(conn: Any) -> None:
    """Verify that the connected DuckDB has the OPC UA signal schema."""
    tables = {row[0] for row in conn.execute("SHOW TABLES").fetchall()}
    if "signal_observations" not in tables:
        raise ValueError("DuckDB file does not contain signal_observations")

    rows = conn.execute("DESCRIBE signal_observations").fetchall()
    columns = {row[0] for row in rows}
    missing = sorted(REQUIRED_COLUMNS - columns)
    if missing:
        raise ValueError(
            "signal_observations is not an OPC UA signal table; "
            f"missing columns: {', '.join(missing)}"
        )


def load_signal_window(
    *,
    signal_db_path: Path,
    baseline_hours: Optional[float] = None,
    min_observations: int = 10,
) -> DatasetWindow:
    """Load raw OPC UA signal observations from DuckDB into memory."""
    try:
        import duckdb
    except ImportError as exc:
        raise ImportError(
            "DuckDB is required for OPC UA GECO. Install it with: pip install duckdb"
        ) from exc

    conn = duckdb.connect(str(signal_db_path), read_only=True)
    try:
        _ensure_schema(conn)
        time_row = conn.execute(
            f"""
            SELECT MIN(timestamp), MAX(timestamp), COUNT(*)
            FROM signal_observations
            WHERE {VALID_SIGNAL_PREDICATE}
            """
        ).fetchone()
        if time_row is None or time_row[2] == 0:
            return DatasetWindow(
                signal_db_path=signal_db_path,
                start_timestamp=0.0,
                end_timestamp=0.0,
                series_by_id={},
            )

        start_ts = float(time_row[0])
        end_ts = float(time_row[1])
        if baseline_hours is not None:
            end_ts = min(end_ts, start_ts + baseline_hours * 3600.0)

        rows = conn.execute(
            f"""
            SELECT
                signal_guid,
                node_id,
                display_name,
                client_host,
                server_host,
                timestamp,
                value
            FROM signal_observations
            WHERE timestamp >= ? AND timestamp <= ?
              AND {VALID_SIGNAL_PREDICATE}
            ORDER BY signal_guid, timestamp
            """,
            [start_ts, end_ts],
        ).fetchall()

        series_by_id: Dict[str, SignalSeries] = {}
        for guid, node_id, display_name, client_host, server_host, timestamp, value in rows:
            series_id = make_series_id(
                guid=str(guid),
                node_id=str(node_id),
                client_host=str(client_host),
                server_host=str(server_host),
            )
            series = series_by_id.get(series_id)
            if series is None:
                meta = SignalSeriesMeta(
                    series_id=series_id,
                    guid=str(guid),
                    node_id=str(node_id),
                    display_name=str(display_name),
                    client_host=str(client_host),
                    server_host=str(server_host),
                    observation_count=0,
                    first_timestamp=float(timestamp),
                    last_timestamp=float(timestamp),
                )
                series = SignalSeries(meta=meta)
                series_by_id[series_id] = series
            series.append(float(timestamp), float(value))

        filtered: Dict[str, SignalSeries] = {}
        for series_id, series in series_by_id.items():
            if series.count < min_observations:
                continue
            timestamps = series.timestamps
            meta = series.meta
            filtered[series_id] = SignalSeries(
                meta=SignalSeriesMeta(
                    series_id=meta.series_id,
                    guid=meta.guid,
                    node_id=meta.node_id,
                    display_name=meta.display_name,
                    client_host=meta.client_host,
                    server_host=meta.server_host,
                    observation_count=series.count,
                    first_timestamp=timestamps[0],
                    last_timestamp=timestamps[-1],
                ),
                timestamps=timestamps,
                values=series.values,
            )

        logger.info(
            "Loaded %d OPC UA signals from %s in [%.3f, %.3f]",
            len(filtered),
            signal_db_path,
            start_ts,
            end_ts,
        )
        return DatasetWindow(
            signal_db_path=signal_db_path,
            start_timestamp=start_ts,
            end_timestamp=end_ts,
            series_by_id=filtered,
        )
    finally:
        conn.close()


def build_target_dataset(
    *,
    target: SignalSeries,
    candidate_series: Sequence[SignalSeries],
) -> TargetDataset:
    """Align candidate predictor series to a target signal timeline."""
    if target.count < 2:
        return TargetDataset(
            target=target,
            prev_timestamps=[],
            timestamps=[],
            prev_target_values=[],
            target_values=[],
            predictor_values={},
        )

    prev_timestamps = target.timestamps[:-1]
    timestamps = target.timestamps[1:]
    prev_target_values = target.values[:-1]
    target_values = target.values[1:]

    predictor_values: Dict[str, List[Optional[float]]] = {}
    for series in candidate_series:
        aligned: List[Optional[float]] = []
        idx = 0
        latest: Optional[float] = None
        for prev_ts in prev_timestamps:
            while idx < series.count and series.timestamps[idx] <= prev_ts:
                latest = series.values[idx]
                idx += 1
            aligned.append(latest)
        predictor_values[series.meta.series_id] = aligned

    return TargetDataset(
        target=target,
        prev_timestamps=prev_timestamps,
        timestamps=timestamps,
        prev_target_values=prev_target_values,
        target_values=target_values,
        predictor_values=predictor_values,
    )


def rank_candidate_predictors(
    *,
    dataset: TargetDataset,
    candidate_guids: Iterable[str],
    preferred_guids: Optional[Sequence[str]] = None,
    limit: int = 8,
) -> List[str]:
    """Rank predictors by absolute correlation to target deltas."""
    target_delta = [
        current - previous
        for previous, current in zip(dataset.prev_target_values, dataset.target_values)
    ]
    preferred_set = set(preferred_guids or [])
    preferred_order = {guid: index for index, guid in enumerate(preferred_guids or [])}
    scored: List[Tuple[int, int, float, str]] = []

    for guid in candidate_guids:
        aligned = dataset.predictor_values.get(guid)
        if not aligned:
            continue
        xs: List[float] = []
        ys: List[float] = []
        for predictor_value, delta in zip(aligned, target_delta):
            if predictor_value is None:
                continue
            xs.append(float(predictor_value))
            ys.append(float(delta))
        if len(xs) < 3:
            corr = 0.0
        else:
            corr = abs(pearson_correlation(xs, ys))
        scored.append(
            (
                0 if guid in preferred_set else 1,
                preferred_order.get(guid, 10_000),
                -corr,
                guid,
            )
        )

    scored.sort()
    return [guid for _, _, _, guid in scored[:limit]]


def load_invariant_adjacency(path: Optional[Path]) -> Dict[str, List[str]]:
    """Parse correlation adjacency from an OPC UA invariants JSON output.

    Compatible with the format emitted by
    invariantExperiments.extract_opcua_invariants — its correlation_graph.edges
    use signal_guid as source/target. Returns a guid -> [neighbor_guid] map.
    """
    if path is None or not path.exists():
        return {}

    data = json.loads(path.read_text())
    graph = data.get("correlation_graph") or {}
    adjacency: Dict[str, List[str]] = {}
    for edge in graph.get("edges", []):
        src = str(edge.get("source") or "")
        tgt = str(edge.get("target") or "")
        if not src or not tgt:
            continue
        adjacency.setdefault(src, []).append(tgt)
        adjacency.setdefault(tgt, []).append(src)
    return adjacency
