"""PyInstaller entry point for the taint-trace CLI binary."""

import sys

from taint_engine.cli.main import main

sys.exit(main())
