"""Implementation of the ``taint-trace index`` subcommand."""

from __future__ import annotations

import hashlib
import os

from ..resolver.index_store import IndexStore
from ..resolver.js_resolver import JsResolver
from ..resolver.python_resolver import PythonResolver
from ..resolver.symbol_extractor import extract_references, extract_symbols
from ..ts_parser import TreeSitterParser
from ..ts_parser.parser import SUPPORTED_EXTENSIONS

_LANG_FILTER = {
    "python": frozenset({".py"}),
    "javascript": frozenset({".js", ".jsx"}),
    "typescript": frozenset({".ts", ".tsx"}),
}


def _collect_files(path: str, lang_filter: set[str] | None) -> list[str]:
    """Walk a directory tree and collect source files."""
    allowed: set[str] = set()
    if lang_filter:
        for lang in lang_filter:
            allowed |= _LANG_FILTER.get(lang, set())
    else:
        allowed = set(SUPPORTED_EXTENSIONS)

    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        return [os.path.abspath(path)] if ext in allowed else []

    files: list[str] = []
    skip_dirs = {"node_modules", "__pycache__", ".git", "venv", ".venv"}
    for root, dirs, filenames in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in skip_dirs]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in allowed:
                files.append(os.path.abspath(os.path.join(root, fname)))
    return files


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()[:16]


def run_index(args) -> int:
    lang_filter = set(args.lang.split(",")) if args.lang else None
    files = _collect_files(args.path, lang_filter)

    if not files:
        print(f"No source files found in {args.path}")
        return 0

    store = IndexStore(args.db)
    parser = TreeSitterParser()

    py_resolver = PythonResolver(
        search_paths=(
            args.python_path.split(",")
            if args.python_path
            else [os.path.abspath(args.path)]
        ),
    )
    js_resolver = JsResolver()

    changed = 0
    cached = 0

    for fpath in files:
        mtime = os.path.getmtime(fpath)
        content_hash = _file_hash(fpath)

        if not args.force and store.is_file_current(
            fpath, mtime=mtime, content_hash=content_hash,
        ):
            cached += 1
            continue

        ext = os.path.splitext(fpath)[1].lower()
        try:
            root = parser.parse_file(fpath)
            lang = parser.get_language(ext)
        except (ValueError, Exception):
            continue

        store.upsert_file(fpath, mtime=mtime, content_hash=content_hash)

        symbols = extract_symbols(root, lang, ext)
        store.replace_symbols(fpath, symbols)

        refs = extract_references(root, lang, ext)
        store.replace_references(fpath, refs)

        if ext == ".py":
            imports = py_resolver.parse_imports(fpath, root)
        elif ext in (".js", ".jsx", ".ts", ".tsx"):
            imports = js_resolver.parse_imports(fpath, root)
        else:
            imports = []
        store.replace_imports(fpath, imports)

        changed += 1

    store.close()
    print(f"Indexed {len(files)} files ({changed} changed, {cached} cached)")
    return 0
