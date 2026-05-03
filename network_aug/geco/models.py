"""Serializable model and alert structures for GECO-style scoring."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


MODEL_VERSION = 1


@dataclass
class GecoSignalModel:
    """Learned state-transition model for one target signal."""

    target_series_id: str
    target_guid: str
    register_address: int
    unit_id: Optional[int]
    server_host: str
    client_host: str
    template: str
    predictor_series_ids: List[str]
    predictor_guids: List[str]
    feature_names: List[str]
    weights: List[float]
    mse: float
    drift: float
    threshold: float
    scale_factor: float
    growth_factor: float
    row_count: int
    train_row_count: int
    first_timestamp: float
    last_timestamp: float
    candidate_guids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GecoSignalModel":
        return cls(
            target_series_id=str(data.get("target_series_id") or data["target_guid"]),
            target_guid=str(data["target_guid"]),
            register_address=int(data["register_address"]),
            unit_id=None if data.get("unit_id") is None else int(data["unit_id"]),
            server_host=str(data.get("server_host") or ""),
            client_host=str(data.get("client_host") or ""),
            template=str(data["template"]),
            predictor_series_ids=[
                str(item)
                for item in data.get("predictor_series_ids", data.get("predictor_guids", []))
            ],
            predictor_guids=[str(item) for item in data.get("predictor_guids", [])],
            feature_names=[str(item) for item in data.get("feature_names", [])],
            weights=[float(item) for item in data.get("weights", [])],
            mse=float(data["mse"]),
            drift=float(data["drift"]),
            threshold=float(data["threshold"]),
            scale_factor=float(data["scale_factor"]),
            growth_factor=float(data["growth_factor"]),
            row_count=int(data["row_count"]),
            train_row_count=int(data["train_row_count"]),
            first_timestamp=float(data["first_timestamp"]),
            last_timestamp=float(data["last_timestamp"]),
            candidate_guids=[str(item) for item in data.get("candidate_guids", [])],
        )


@dataclass
class GecoModelSet:
    """Collection of learned GECO-style signal models."""

    created_at: str
    signal_db_path: str
    baseline_hours: Optional[float]
    max_function_length: int
    candidate_limit: int
    min_observations: int
    min_rows: int
    fit_ratio: float
    scale_factor: float
    growth_factor: float
    candidate_invariants_path: Optional[str] = None
    models: List[GecoSignalModel] = field(default_factory=list)
    version: int = MODEL_VERSION

    @classmethod
    def new(
        cls,
        *,
        signal_db_path: Path,
        baseline_hours: Optional[float],
        max_function_length: int,
        candidate_limit: int,
        min_observations: int,
        min_rows: int,
        fit_ratio: float,
        scale_factor: float,
        growth_factor: float,
        candidate_invariants_path: Optional[Path],
    ) -> "GecoModelSet":
        return cls(
            created_at=datetime.now(timezone.utc).isoformat(),
            signal_db_path=str(signal_db_path),
            baseline_hours=baseline_hours,
            max_function_length=max_function_length,
            candidate_limit=candidate_limit,
            min_observations=min_observations,
            min_rows=min_rows,
            fit_ratio=fit_ratio,
            scale_factor=scale_factor,
            growth_factor=growth_factor,
            candidate_invariants_path=(
                str(candidate_invariants_path) if candidate_invariants_path is not None else None
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "signal_db_path": self.signal_db_path,
            "baseline_hours": self.baseline_hours,
            "max_function_length": self.max_function_length,
            "candidate_limit": self.candidate_limit,
            "min_observations": self.min_observations,
            "min_rows": self.min_rows,
            "fit_ratio": self.fit_ratio,
            "scale_factor": self.scale_factor,
            "growth_factor": self.growth_factor,
            "candidate_invariants_path": self.candidate_invariants_path,
            "models": [model.to_dict() for model in self.models],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GecoModelSet":
        return cls(
            version=int(data.get("version", MODEL_VERSION)),
            created_at=str(data["created_at"]),
            signal_db_path=str(data["signal_db_path"]),
            baseline_hours=None if data.get("baseline_hours") is None else float(data["baseline_hours"]),
            max_function_length=int(data["max_function_length"]),
            candidate_limit=int(data["candidate_limit"]),
            min_observations=int(data["min_observations"]),
            min_rows=int(data["min_rows"]),
            fit_ratio=float(data["fit_ratio"]),
            scale_factor=float(data["scale_factor"]),
            growth_factor=float(data["growth_factor"]),
            candidate_invariants_path=(
                None if data.get("candidate_invariants_path") is None else str(data["candidate_invariants_path"])
            ),
            models=[GecoSignalModel.from_dict(item) for item in data.get("models", [])],
        )

    @classmethod
    def from_json(cls, text: str) -> "GecoModelSet":
        return cls.from_dict(json.loads(text))


@dataclass
class GecoAlertEvent:
    """One alert episode for a signal model."""

    target_guid: str
    register_address: int
    unit_id: Optional[int]
    server_host: str
    start_timestamp: float
    end_timestamp: float
    first_trigger_timestamp: float
    peak_cusum: float
    threshold: float
    triggered_points: int
    max_abs_error: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GecoAlertEvent":
        return cls(
            target_guid=str(data["target_guid"]),
            register_address=int(data["register_address"]),
            unit_id=None if data.get("unit_id") is None else int(data["unit_id"]),
            server_host=str(data.get("server_host") or ""),
            start_timestamp=float(data["start_timestamp"]),
            end_timestamp=float(data["end_timestamp"]),
            first_trigger_timestamp=float(data["first_trigger_timestamp"]),
            peak_cusum=float(data["peak_cusum"]),
            threshold=float(data["threshold"]),
            triggered_points=int(data["triggered_points"]),
            max_abs_error=float(data["max_abs_error"]),
        )


@dataclass
class GecoSignalScore:
    """Per-signal scoring summary."""

    target_guid: str
    register_address: int
    unit_id: Optional[int]
    server_host: str
    row_count: int
    triggered_points: int
    max_cusum: float
    max_abs_error: float
    alerts: List[GecoAlertEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_guid": self.target_guid,
            "register_address": self.register_address,
            "unit_id": self.unit_id,
            "server_host": self.server_host,
            "row_count": self.row_count,
            "triggered_points": self.triggered_points,
            "max_cusum": self.max_cusum,
            "max_abs_error": self.max_abs_error,
            "alerts": [alert.to_dict() for alert in self.alerts],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GecoSignalScore":
        return cls(
            target_guid=str(data["target_guid"]),
            register_address=int(data["register_address"]),
            unit_id=None if data.get("unit_id") is None else int(data["unit_id"]),
            server_host=str(data.get("server_host") or ""),
            row_count=int(data["row_count"]),
            triggered_points=int(data["triggered_points"]),
            max_cusum=float(data["max_cusum"]),
            max_abs_error=float(data["max_abs_error"]),
            alerts=[GecoAlertEvent.from_dict(item) for item in data.get("alerts", [])],
        )


@dataclass
class GecoScoreResult:
    """Scoring output for one GECO model set against a signal database."""

    created_at: str
    signal_db_path: str
    model_path: str
    signal_scores: List[GecoSignalScore] = field(default_factory=list)
    version: int = MODEL_VERSION

    @classmethod
    def new(cls, *, signal_db_path: Path, model_path: Path) -> "GecoScoreResult":
        return cls(
            created_at=datetime.now(timezone.utc).isoformat(),
            signal_db_path=str(signal_db_path),
            model_path=str(model_path),
        )

    @property
    def alerts(self) -> List[GecoAlertEvent]:
        items: List[GecoAlertEvent] = []
        for score in self.signal_scores:
            items.extend(score.alerts)
        return items

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "signal_db_path": self.signal_db_path,
            "model_path": self.model_path,
            "signal_scores": [score.to_dict() for score in self.signal_scores],
            "alerts": [alert.to_dict() for alert in self.alerts],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "GecoScoreResult":
        data = json.loads(text)
        return cls(
            version=int(data.get("version", MODEL_VERSION)),
            created_at=str(data["created_at"]),
            signal_db_path=str(data["signal_db_path"]),
            model_path=str(data["model_path"]),
            signal_scores=[GecoSignalScore.from_dict(item) for item in data.get("signal_scores", [])],
        )
