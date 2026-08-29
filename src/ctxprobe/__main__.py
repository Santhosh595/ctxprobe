"""Allow `python -m ctxprobe` to run the CLI."""

from .cli import main

if __name__ == "__main__":
    import sys

    sys.exit(main())
