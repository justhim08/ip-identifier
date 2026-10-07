"""Allow SENTINEL to be launched with ``python -m sentinel``."""

from .cli import main


if __name__ == "__main__":
	raise SystemExit(main())
