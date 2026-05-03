"""Model templates and fitting helpers for GECO-style learning (OPC UA).

Algebra is protocol-agnostic; this is a verbatim copy of network_aug.geco.templates
to keep the OPC UA package self-contained.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .dataset import TargetDataset

logger = logging.getLogger(__name__)

TEMPLATE_AFFINE = "affine"
TEMPLATE_DELTA_AFFINE = "delta_affine"
TEMPLATE_AFFINE_INTERACTION = "affine_interaction"

TEMPLATE_NAMES = (
    TEMPLATE_AFFINE,
    TEMPLATE_DELTA_AFFINE,
    TEMPLATE_AFFINE_INTERACTION,
)


@dataclass
class TemplateFit:
    """One fitted template candidate for a target signal."""

    template: str
    predictor_guids: List[str]
    feature_names: List[str]
    weights: List[float]
    row_count: int
    train_row_count: int
    mse: float
    drift: float
    threshold: float


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stdev(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean_value = _mean(values)
    variance = sum((value - mean_value) ** 2 for value in values) / len(values)
    return math.sqrt(max(variance, 0.0))


def _gaussian_elimination(matrix: List[List[float]], vector: List[float]) -> Optional[List[float]]:
    """Solve A x = b with partial pivoting."""
    size = len(vector)
    augmented = [row[:] + [value] for row, value in zip(matrix, vector)]

    for pivot in range(size):
        best_row = max(range(pivot, size), key=lambda row: abs(augmented[row][pivot]))
        if abs(augmented[best_row][pivot]) < 1e-12:
            return None
        if best_row != pivot:
            augmented[pivot], augmented[best_row] = augmented[best_row], augmented[pivot]

        pivot_value = augmented[pivot][pivot]
        for col in range(pivot, size + 1):
            augmented[pivot][col] /= pivot_value

        for row in range(size):
            if row == pivot:
                continue
            factor = augmented[row][pivot]
            if abs(factor) < 1e-12:
                continue
            for col in range(pivot, size + 1):
                augmented[row][col] -= factor * augmented[pivot][col]

    return [augmented[row][size] for row in range(size)]


def _solve_ridge_regression(
    *,
    x_rows: Sequence[Sequence[float]],
    y_values: Sequence[float],
    ridge: float = 1e-8,
) -> Optional[List[float]]:
    if not x_rows:
        return None

    width = len(x_rows[0])
    xtx = [[0.0 for _ in range(width)] for _ in range(width)]
    xty = [0.0 for _ in range(width)]
    for row, y_val in zip(x_rows, y_values):
        for i in range(width):
            xty[i] += row[i] * y_val
            for j in range(width):
                xtx[i][j] += row[i] * row[j]
    for i in range(width):
        xtx[i][i] += ridge
    return _gaussian_elimination(xtx, xty)


def _build_feature_row(
    *,
    template: str,
    predictor_guids: Sequence[str],
    previous_target: float,
    predictor_map: Dict[str, float],
) -> Tuple[List[str], List[float], float]:
    feature_names = ["bias"]
    features = [1.0]

    if template != TEMPLATE_DELTA_AFFINE:
        feature_names.append("target_prev")
        features.append(previous_target)

    for guid in predictor_guids:
        feature_names.append(f"pred:{guid}")
        features.append(predictor_map[guid])

    if template == TEMPLATE_AFFINE_INTERACTION:
        for guid in predictor_guids:
            feature_names.append(f"interaction:{guid}")
            features.append(previous_target * predictor_map[guid])

    base_value = previous_target if template == TEMPLATE_DELTA_AFFINE else 0.0
    return feature_names, features, base_value


def predict_from_model(
    *,
    template: str,
    predictor_guids: Sequence[str],
    feature_names: Sequence[str],
    weights: Sequence[float],
    previous_target: float,
    predictor_map: Dict[str, float],
) -> float:
    """Evaluate a serialized model against one previous-state row."""
    names, features, base_value = _build_feature_row(
        template=template,
        predictor_guids=predictor_guids,
        previous_target=previous_target,
        predictor_map=predictor_map,
    )
    if list(feature_names) != names:
        raise ValueError(
            f"Feature mismatch for template {template}: expected {list(feature_names)}, got {names}"
        )
    predicted = sum(weight * feature for weight, feature in zip(weights, features))
    return base_value + predicted


def fit_template(
    *,
    dataset: TargetDataset,
    template: str,
    predictor_guids: Sequence[str],
    fit_ratio: float,
    min_rows: int,
) -> Optional[TemplateFit]:
    """Fit one template to the target dataset."""
    row_indexes: List[int] = []
    x_rows: List[List[float]] = []
    y_values: List[float] = []
    feature_names: Optional[List[str]] = None

    for row_idx, previous_target in enumerate(dataset.prev_target_values):
        predictor_map: Dict[str, float] = {}
        missing = False
        for guid in predictor_guids:
            aligned_values = dataset.predictor_values.get(guid)
            if aligned_values is None:
                missing = True
                break
            value = aligned_values[row_idx]
            if value is None:
                missing = True
                break
            predictor_map[guid] = float(value)
        if missing:
            continue

        names, features, base_value = _build_feature_row(
            template=template,
            predictor_guids=predictor_guids,
            previous_target=previous_target,
            predictor_map=predictor_map,
        )
        if feature_names is None:
            feature_names = names
        target_value = dataset.target_values[row_idx] - base_value
        row_indexes.append(row_idx)
        x_rows.append(features)
        y_values.append(target_value)

    if len(x_rows) < min_rows:
        return None

    if max(y_values) - min(y_values) < 1e-9:
        return None

    train_count = max(2, int(len(x_rows) * fit_ratio))
    train_count = min(train_count, len(x_rows))
    weights = _solve_ridge_regression(x_rows=x_rows[:train_count], y_values=y_values[:train_count])
    if weights is None or feature_names is None:
        return None

    residuals: List[float] = []
    for features, expected in zip(x_rows, y_values):
        predicted = sum(weight * value for weight, value in zip(weights, features))
        residuals.append(predicted - expected)

    mse = _mean([residual * residual for residual in residuals])
    abs_residuals = [abs(residual) for residual in residuals]
    drift = _mean(abs_residuals) + _stdev(abs_residuals)
    drift = max(drift, 1e-9)
    cusum = 0.0
    threshold = 0.0
    for residual in abs_residuals:
        cusum = max(cusum + residual - drift, 0.0)
        threshold = max(threshold, cusum)
    threshold = max(threshold, drift)

    return TemplateFit(
        template=template,
        predictor_guids=list(predictor_guids),
        feature_names=feature_names,
        weights=weights,
        row_count=len(row_indexes),
        train_row_count=train_count,
        mse=mse,
        drift=drift,
        threshold=threshold,
    )
