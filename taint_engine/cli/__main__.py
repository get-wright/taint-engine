"""Allow running the CLI via ``python -m taint_engine.cli``."""

from __future__ import annotations

import sys

from .main import main

sys.exit(main())
