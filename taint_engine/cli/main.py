"""CLI entry point for taint-trace.

Usage:
    taint-trace index <path> [--db DB] [--lang LANGS] [--force] [--python-path PATHS]
    taint-trace symbols <file> [--format {text,json}] [--kind KINDS]
    taint-trace trace <file>:<line> [--symbol SYM] [--format {text,json,sarif}] [...]
"""

from __future__ import annotations

import argparse
import sys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="taint-trace",
        description="Static taint flow analysis CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    idx = sub.add_parser("index", help="Build/update the symbol index")
    idx.add_argument("path", help="Directory or file to index")
    idx.add_argument("--db", default=".taint-index.db", help="SQLite database path")
    idx.add_argument("--lang", default=None, help="Comma-separated language filter")
    idx.add_argument("--force", action="store_true", help="Re-index everything")
    idx.add_argument(
        "--python-path",
        default=None,
        help="Additional Python search paths (comma-separated)",
    )

    sym = sub.add_parser("symbols", help="List symbols in a file")
    sym.add_argument("file", help="File path")
    sym.add_argument("--format", choices=["text", "json"], default="text")
    sym.add_argument("--kind", default=None, help="Filter by kind")

    trc = sub.add_parser("trace", help="Trace taint flow from a sink")
    trc.add_argument("target", help="file:line (e.g., app.py:42)")
    trc.add_argument("--symbol", default=None, help="Target specific symbol")
    trc.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    trc.add_argument("--check-id", default=None, help="Check ID for rule matching")
    trc.add_argument(
        "--rules-dir",
        default=None,
        help="Override packaged rules with a custom rules directory or JSON file",
    )
    trc.add_argument(
        "--cross-file",
        action="store_true",
        default=False,
        help="Enable cross-file tracing",
    )
    trc.add_argument("--max-depth", type=int, default=5, help="Max cross-file depth")
    trc.add_argument("--db", default=".taint-index.db", help="SQLite database path")
    trc.add_argument(
        "--python-path",
        default=None,
        help="Additional Python search paths (comma-separated)",
    )
    trc.add_argument(
        "--label",
        default=None,
        help="Taint label for sink-type matching (e.g., sql, html, url)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "index":
        from .cmd_index import run_index

        return run_index(args)
    elif args.command == "symbols":
        from .cmd_symbols import run_symbols

        return run_symbols(args)
    elif args.command == "trace":
        from .cmd_trace import run_trace

        return run_trace(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
