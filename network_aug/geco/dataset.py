"""Dataset loading and alignment helpers for GECO-style training/scoring."""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SignalSeriesMeta:
    """Metadata for one raw signal series."""

    series_id: str
    guid: str
    register_address: int
    unit_id: Optional[int]
    client_host: str
    server_host: str
    observation_count: int
    first_timestamp: float
    last_timestamp: float


@dataclass
class SignalSeries:
    """Ordered timestamp/value pairs for one signal."""

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

    def group_by_device(self) -> Dict[Tuple[str, Optional[int]], List[SignalSeries]]:
        grouped: Dict[Tuple[str, Optional[int]], List[SignalSeries]] = {}
        for series in self.series_by_id.values():
            key = (series.meta.server_host, series.meta.unit_id)
            grouped.setdefault(key, []).append(series)
        return grouped


def make_series_id(
    *,
    guid: str,
    register_address: int,
    unit_id: Optional[int],
    client_host: str,
    server_host: str,
) -> str:
    """Build a unique series identifier for one device-specific raw signal."""
    return "|".join(
        [
            guid,
            str(register_address),
            "" if unit_id is None else str(unit_id),
            client_host,
            server_host,
        ]
    )


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


def load_signal_window(
    *,
    signal_db_path: Path,
    baseline_hours: Optional[float] = None,
    min_observations: int = 10,
) -> DatasetWindow:
    """Load raw signal observations from DuckDB into memory."""
    try:
        import duckdb
    except ImportError as exc:
        raise ImportError(
            "DuckDB is required for GECO. Install it with: pip install duckdb"
        ) from exc

    conn = duckdb.connect(str(signal_db_path), read_only=True)
    try:
        time_row = conn.execute(
            "SELECT MIN(timestamp), MAX(timestamp), COUNT(*) FROM signal_observations"
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
            """
            SELECT
                signal_container_guid,
                register_address,
                unit_id,
                client_host,
                server_host,
                timestamp,
                value
            FROM signal_observations
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY signal_container_guid, timestamp
            """,
            [start_ts, end_ts],
        ).fetchall()

        series_by_id: Dict[str, SignalSeries] = {}
        for guid, reg, unit_id, client_host, server_host, timestamp, value in rows:
            series_id = make_series_id(
                guid=str(guid),
                register_address=int(reg),
                unit_id=None if unit_id is None else int(unit_id),
                client_host=str(client_host),
                server_host=str(server_host),
            )
            series = series_by_id.get(series_id)
            if series is None:
                meta = SignalSeriesMeta(
                    series_id=series_id,
                    guid=str(guid),
                    register_address=int(reg),
                    unit_id=None if unit_id is None else int(unit_id),
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
                    register_address=meta.register_address,
                    unit_id=meta.unit_id,
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
            "Loaded %d signals from %s in [%.3f, %.3f]",
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


def _adjacency_lookup_key(guid: Optional[str], server_host: Optional[str]) -> str:
    """Build the lookup key trainer.py uses against the loaded adjacency."""
    if not guid:
        return ""
    return f"{guid}@{server_host}" if server_host else guid


def load_invariant_adjacency(path: Optional[Path]) -> Dict[str, List[str]]:
    """Parse correlation adjacency from the invariants JSON output.

    Adjacency keys are composite "guid@server_host" strings when the invariants
    output includes server_host (post-fix format), or plain GUIDs for legacy
    outputs. Trainer code should build lookup keys via _adjacency_lookup_key.
    """
    if path is None or not path.exists():
        return {}

    data = json.loads(path.read_text())
    graph = data.get("correlation_graph") or {}
    adjacency: Dict[str, List[str]] = {}
    for edge in graph.get("edges", []):
        # Prefer the explicit per-end fields when present (post-fix format).
        src = _adjacency_lookup_key(
            edge.get("source_guid"), edge.get("source_server_host")
        ) or str(edge.get("source") or "")
        tgt = _adjacency_lookup_key(
            edge.get("target_guid"), edge.get("target_server_host")
        ) or str(edge.get("target") or "")
        if not src or not tgt:
            continue
        adjacency.setdefault(src, []).append(tgt)
        adjacency.setdefault(tgt, []).append(src)
    return adjacency
