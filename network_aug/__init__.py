"""Network augmentation utilities for enriching the base graph output."""

from importlib import import_module
from typing import Any

__all__ = ["MissingTrafficAugmentor", "AugmentationConfig"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        enhancer = import_module(".enhancer", __name__)
        return getattr(enhancer, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
