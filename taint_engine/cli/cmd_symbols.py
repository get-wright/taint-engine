"""Implementation of the ``taint-trace symbols`` subcommand."""

from __future__ import annotations

import json
import os
import sys

from ..resolver.symbol_extractor import extract_references, extract_symbols
from ..ts_parser import TreeSitterParser


def run_symbols(args) -> int:
    file_path = args.file
    if not os.path.isfile(file_path):
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 1

    ext = os.path.splitext(file_path)[1].lower()
    parser = TreeSitterParser()

    try:
        root = parser.parse_file(file_path)
        lang = parser.get_language(ext)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    symbols = extract_symbols(root, lang, ext)

    if args.kind:
        allowed_kinds = set(args.kind.split(","))
        symbols = [s for s in symbols if s.kind in allowed_kinds]

    refs = extract_references(root, lang, ext)
    ref_counts: dict[str, int] = {}
    for ref in refs:
        ref_counts[ref.symbol_name] = ref_counts.get(ref.symbol_name, 0) + 1

    if args.format == "json":
        data = {
            "file": file_path,
            "symbols": [
                {
                    "name": s.name,
                    "kind": s.kind,
                    "line": s.line,
                    "col": s.col,
                    "end_line": s.end_line,
                    "end_col": s.end_col,
                    "references": ref_counts.get(s.name, 0),
                }
                for s in symbols
            ],
        }
        print(json.dumps(data, indent=2))
    else:
        print(f"Symbols in {os.path.basename(file_path)}:")
        for s in symbols:
            count = ref_counts.get(s.name, 0)
            ref_label = f"({count} reference{'s' if count != 1 else ''})"
            print(
                f"  {s.kind:<10} {s.name:<25} line {s.line + 1:<6} {ref_label}"
            )

    return 0
