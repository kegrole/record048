"""Allow running the CLI via python -m cachepoison."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
