"""Shared helper types and placeholder utilities."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import NoReturn

CommandHandler = Callable[[argparse.Namespace], int]


def raise_not_implemented(feature_name: str) -> NoReturn:
    """Raise a consistent error for intentionally empty feature modules."""
    raise NotImplementedError(f"{feature_name} are not implemented yet.")
