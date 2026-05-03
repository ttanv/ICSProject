"""Scoring logic for GECO-style OPC UA signal models."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from .dataset import build_target_dataset, load_signal_window
from .models import GecoAlertEvent, GecoModelSet, GecoScoreResult, GecoSignalScore
from .templates import predict_from_model

logger = logging.getLogger(__name__)


@dataclass
class GecoScoreConfig:
    """Configuration for offline OPC UA GECO scoring."""

    signal_db: Path
    model: Path
    output: Path


def _finalize_alert(
    *,
    score: GecoSignalScore,
    current_event: Optional[Dict[str, float]],
) -> None:
    if not current_event:
        return
    score.alerts.append(
        GecoAlertEvent(
            target_guid=score.target_guid,
            node_id=score.node_id,
            display_name=score.display_name,
            server_host=score.server_host,
            start_timestamp=current_event["start_timestamp"],
            end_timestamp=current_event["end_timestamp"],
            first_trigger_timestamp=current_event["first_trigger_timestamp"],
            peak_cusum=current_event["peak_cusum"],
            threshold=current_event["threshold"],
            triggered_points=int(current_event["triggered_points"]),
            max_abs_error=current_event["max_abs_error"],
        )
    )


def score_geco(config: GecoScoreConfig) -> GecoScoreResult:
    """Score an OPC UA signal database against a trained GECO model set."""
    model_set = GecoModelSet.from_json(config.model.read_text())
    window = load_signal_window(
        signal_db_path=config.signal_db,
        baseline_hours=None,
        min_observations=2,
    )
    result = GecoScoreResult.new(signal_db_path=config.signal_db, model_path=config.model)

    for model in model_set.models:
        target = window.series_by_id.get(model.target_series_id)
        if target is None:
            logger.debug("Skipping missing target %s", model.target_series_id)
            continue
        candidates = [
            window.series_by_id[series_id]
            for series_id in model.predictor_series_ids
            if series_id in window.series_by_id
        ]
        if len(candidates) != len(model.predictor_series_ids):
            logger.debug(
                "Skipping %s because not all predictors are present",
                model.target_series_id,
            )
            continue

        dataset = build_target_dataset(target=target, candidate_series=candidates)
        score = GecoSignalScore(
            target_guid=model.target_guid,
            node_id=model.node_id,
            display_name=model.display_name,
            server_host=model.server_host,
            row_count=0,
            triggered_points=0,
            max_cusum=0.0,
            max_abs_error=0.0,
        )

        cusum = 0.0
        current_event: Optional[Dict[str, float]] = None
        trigger_threshold = model.threshold * model.scale_factor
        threshold_limit = max(
            model.threshold + model.drift * model.growth_factor,
            trigger_threshold,
        )

        for row_idx, previous_target in enumerate(dataset.prev_target_values):
            predictor_map: Dict[str, float] = {}
            missing = False
            for series_id in model.predictor_series_ids:
                aligned = dataset.predictor_values.get(series_id)
                if aligned is None:
                    missing = True
                    break
                value = aligned[row_idx]
                if value is None:
                    missing = True
                    break
                predictor_map[series_id] = float(value)
            if missing:
                continue

            predicted = predict_from_model(
                template=model.template,
                predictor_guids=model.predictor_series_ids,
                feature_names=model.feature_names,
                weights=model.weights,
                previous_target=previous_target,
                predictor_map=predictor_map,
            )
            diff = dataset.target_values[row_idx] - predicted
            abs_error = abs(diff)
            score.row_count += 1
            score.max_abs_error = max(score.max_abs_error, abs_error)
            cusum = max(cusum + abs_error - model.drift, 0.0)
            cusum = min(cusum, threshold_limit)
            score.max_cusum = max(score.max_cusum, cusum)

            current_ts = dataset.timestamps[row_idx]
            if cusum >= trigger_threshold:
                score.triggered_points += 1
                if current_event is None:
                    current_event = {
                        "start_timestamp": current_ts,
                        "end_timestamp": current_ts,
                        "first_trigger_timestamp": current_ts,
                        "peak_cusum": cusum,
                        "threshold": trigger_threshold,
                        "triggered_points": 1.0,
                        "max_abs_error": abs_error,
                    }
                else:
                    current_event["end_timestamp"] = current_ts
                    current_event["peak_cusum"] = max(current_event["peak_cusum"], cusum)
                    current_event["triggered_points"] += 1.0
                    current_event["max_abs_error"] = max(current_event["max_abs_error"], abs_error)
            elif current_event is not None:
                _finalize_alert(score=score, current_event=current_event)
                current_event = None

        _finalize_alert(score=score, current_event=current_event)
        result.signal_scores.append(score)

    config.output.write_text(result.to_json())
    logger.info(
        "Scored %d OPC UA GECO models against %s and wrote %d alerts to %s",
        len(result.signal_scores),
        config.signal_db,
        len(result.alerts),
        config.output,
    )
    return result
