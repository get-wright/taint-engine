"""Symbol resolution and cross-file import tracking.

NOTE: This package requires tree-sitter at import time. It is only used by
the CLI (``taint_engine.cli``) and consumers that have installed the ``cli``
or ``dev`` optional dependency groups.  The core ``taint_engine`` package
(engine, models, rules) has zero runtime dependencies and does NOT import
this package.
"""

from .base import ImportEntry, ImportResolver, ResolvedSymbol, SymbolInfo
from .index_store import IndexStore
from .symbol_extractor import extract_symbols, extract_references, find_enclosing_function, find_symbols_at_line
from .python_resolver import PythonResolver
from .js_resolver import JsResolver

__all__ = [
    "ImportEntry",
    "ImportResolver",
    "IndexStore",
    "JsResolver",
    "PythonResolver",
    "ResolvedSymbol",
    "SymbolInfo",
    "extract_references",
    "extract_symbols",
    "find_enclosing_function",
    "find_symbols_at_line",
]
