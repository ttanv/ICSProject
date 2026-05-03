"""Training logic for GECO-style signal models."""

from __future__ import annotations

import itertools
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .dataset import (
    SignalSeries,
    _adjacency_lookup_key,
    build_target_dataset,
    load_invariant_adjacency,
    load_signal_window,
    rank_candidate_predictors,
)
from .models import GecoModelSet, GecoSignalModel
from .templates import TEMPLATE_NAMES, fit_template

logger = logging.getLogger(__name__)


@dataclass
class GecoTrainConfig:
    """Configuration for offline GECO training."""

    signal_db: Path
    output: Path
    baseline_hours: Optional[float] = None
    min_observations: int = 10
    min_rows: int = 12
    max_function_length: int = 3
    candidate_limit: int = 8
    fit_ratio: float = 0.8
    scale_factor: float = 1.5
    growth_factor: float = 1.0
    candidate_invariants: Optional[Path] = None


def _fit_best_model_for_target(
    *,
    target: SignalSeries,
    device_series: Sequence[SignalSeries],
    preferred_predictors: Sequence[str],
    config: GecoTrainConfig,
) -> Optional[GecoSignalModel]:
    candidates = [series for series in device_series if series.meta.guid != target.meta.guid]
    if not candidates:
        return None

    dataset = build_target_dataset(target=target, candidate_series=candidates)
    ranked_candidates = rank_candidate_predictors(
        dataset=dataset,
        candidate_guids=[series.meta.series_id for series in candidates],
        preferred_guids=[
            series.meta.series_id
            for series in candidates
            if series.meta.guid in set(preferred_predictors)
        ],
        limit=config.candidate_limit,
    )
    if not ranked_candidates and dataset.row_count >= config.min_rows:
        ranked_candidates = []

    best_fit = None
    for template in TEMPLATE_NAMES:
        max_subset_len = min(config.max_function_length, len(ranked_candidates))
        for subset_len in range(0, max_subset_len + 1):
            for subset in itertools.combinations(ranked_candidates, subset_len):
                candidate_fit = fit_template(
                    dataset=dataset,
                    template=template,
                    predictor_guids=subset,
                    fit_ratio=config.fit_ratio,
                    min_rows=config.min_rows,
                )
                if candidate_fit is None:
                    continue
                if best_fit is None or candidate_fit.mse < best_fit.mse:
                    best_fit = candidate_fit

    if best_fit is None:
        return None

    return GecoSignalModel(
        target_series_id=target.meta.series_id,
        target_guid=target.meta.guid,
        register_address=target.meta.register_address,
        unit_id=target.meta.unit_id,
        server_host=target.meta.server_host,
        client_host=target.meta.client_host,
        template=best_fit.template,
        predictor_series_ids=best_fit.predictor_guids,
        predictor_guids=[
            next(
                series.meta.guid
                for series in candidates
                if series.meta.series_id == predictor_series_id
            )
            for predictor_series_id in best_fit.predictor_guids
        ],
        feature_names=best_fit.feature_names,
        weights=best_fit.weights,
        mse=best_fit.mse,
        drift=best_fit.drift,
        threshold=best_fit.threshold,
        scale_factor=config.scale_factor,
        growth_factor=config.growth_factor,
        row_count=best_fit.row_count,
        train_row_count=best_fit.train_row_count,
        first_timestamp=target.meta.first_timestamp,
        last_timestamp=target.meta.last_timestamp,
        candidate_guids=ranked_candidates,
    )


def train_geco(config: GecoTrainConfig) -> GecoModelSet:
    """Train per-signal GECO-style models from baseline signal data."""
    window = load_signal_window(
        signal_db_path=config.signal_db,
        baseline_hours=config.baseline_hours,
        min_observations=config.min_observations,
    )
    invariant_adjacency = load_invariant_adjacency(config.candidate_invariants)

    model_set = GecoModelSet.new(
        signal_db_path=config.signal_db,
        baseline_hours=config.baseline_hours,
        max_function_length=config.max_function_length,
        candidate_limit=config.candidate_limit,
        min_observations=config.min_observations,
        min_rows=config.min_rows,
        fit_ratio=config.fit_ratio,
        scale_factor=config.scale_factor,
        growth_factor=config.growth_factor,
        candidate_invariants_path=config.candidate_invariants,
    )

    device_groups = window.group_by_device()
    for (server_host, unit_id), series_list in sorted(device_groups.items()):
        logger.info(
            "Training GECO models for device server=%s unit=%s (%d signals)",
            server_host,
            unit_id,
            len(series_list),
        )
        for target in sorted(series_list, key=lambda item: item.meta.guid):
            # Look up by composite (guid, server_host) when post-fix invariants
            # are present; fall back to plain guid for legacy invariants files.
            adj_key_composite = _adjacency_lookup_key(
                target.meta.guid, target.meta.server_host
            )
            preferred_raw = (
                invariant_adjacency.get(adj_key_composite)
                or invariant_adjacency.get(target.meta.guid, [])
            )
            # Strip "@server_host" suffix from each adjacency entry so candidate
            # matching (by plain meta.guid) works. Safe because we're already
            # iterating within a single (server_host, unit_id) device group.
            preferred = [
                entry.split("@", 1)[0] if "@" in entry else entry
                for entry in preferred_raw
            ]
            model = _fit_best_model_for_target(
                target=target,
                device_series=series_list,
                preferred_predictors=preferred,
                config=config,
            )
            if model is None:
                logger.debug("No GECO model for %s", target.meta.guid)
                continue
            logger.debug(
                "Selected %s model for %s with predictors=%s mse=%.6f",
                model.template,
                model.target_guid,
                model.predictor_guids,
                model.mse,
            )
            model_set.models.append(model)

    config.output.write_text(model_set.to_json())
    logger.info("Wrote %d GECO models to %s", len(model_set.models), config.output)
    return model_set
