"""GECO-style anomaly detection for OPC UA signal observations.

Parallel to network_aug.geco (which is Modbus-only). Reads from the standalone
OPC UA signal DuckDB schema (signal_guid, node_id, display_name, server_host,
...). Templates and CUSUM logic are protocol-agnostic and shared by structure.
"""

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
