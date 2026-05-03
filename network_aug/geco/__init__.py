"""Optional downstream GECO-style anomaly detection module."""

from .models import (
    GecoAlertEvent,
    GecoModelSet,
    GecoScoreResult,
    GecoSignalModel,
    GecoSignalScore,
)
from .scorer import GecoScoreConfig, score_geco
from .trainer import GecoTrainConfig, train_geco

__all__ = [
    "GecoAlertEvent",
    "GecoModelSet",
    "GecoScoreConfig",
    "GecoScoreResult",
    "GecoSignalModel",
    "GecoSignalScore",
    "GecoTrainConfig",
    "score_geco",
    "train_geco",
]
