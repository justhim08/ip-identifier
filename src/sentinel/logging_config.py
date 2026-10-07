"""Consistent, low-noise logging setup for the SENTINEL command line."""

import logging
import sys

from .validation import validate_log_level


def configure_logging(level: str) -> None:
	"""Configure package logging without writing targets or secrets to logs."""
	normalized = validate_log_level(level)
	logging.basicConfig(
		level=getattr(logging, normalized),
		format="[%(levelname)s] %(message)s",
		stream=sys.stderr,
		force=True,
	)
