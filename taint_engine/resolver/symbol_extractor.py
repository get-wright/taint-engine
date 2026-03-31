"""tree-sitter query-based symbol and reference extraction.

Uses S-expression patterns to extract definitions, references,
and structural information from parsed source files.
"""

from __future__ import annotations

from dataclasses import dataclass

from tree_sitter import Language, Query, QueryCursor

from .base import SymbolInfo


@dataclass(frozen=True)
class ReferenceInfo:
    """A reference (call, read) extracted from source."""

    symbol_name: str
    line: int
    col: int
    kind: str  # "call", "read"


# -- Query patterns per language family --

_PYTHON_SYMBOLS = """
(function_definition name: (identifier) @name) @definition.function
(class_definition name: (identifier) @name) @definition.class
(assignment left: (identifier) @name) @definition.variable
"""

_PYTHON_REFERENCES = """
(call function: (identifier) @name) @reference.call
(call function: (attribute attribute: (identifier) @name)) @reference.call
"""

_PYTHON_FUNCTIONS = """
(function_definition name: (identifier) @name) @func
"""

_JS_SYMBOLS = """
(function_declaration name: (identifier) @name) @definition.function
(class_declaration name: (identifier) @name) @definition.class
(variable_declarator name: (identifier) @name) @definition.variable
(method_definition name: (property_identifier) @name) @definition.method
"""

_JS_REFERENCES = """
(call_expression function: (identifier) @name) @reference.call
(call_expression function: (member_expression property: (property_identifier) @name)) @reference.call
"""

_JS_FUNCTIONS = """
(function_declaration name: (identifier) @name) @func
(method_definition name: (property_identifier) @name) @func
"""

# TypeScript uses type_identifier for class names
_TS_SYMBOLS = """
(function_declaration name: (identifier) @name) @definition.function
(class_declaration name: (type_identifier) @name) @definition.class
(variable_declarator name: (identifier) @name) @definition.variable
(method_definition name: (property_identifier) @name) @definition.method
"""

_TS_REFERENCES = _JS_REFERENCES

_TS_FUNCTIONS = _JS_FUNCTIONS

_SYMBOL_QUERIES: dict[str, str] = {
    ".py": _PYTHON_SYMBOLS,
    ".js": _JS_SYMBOLS,
    ".jsx": _JS_SYMBOLS,
    ".ts": _TS_SYMBOLS,
    ".tsx": _TS_SYMBOLS,
}

_REFERENCE_QUERIES: dict[str, str] = {
    ".py": _PYTHON_REFERENCES,
    ".js": _JS_REFERENCES,
    ".jsx": _JS_REFERENCES,
    ".ts": _TS_REFERENCES,
    ".tsx": _TS_REFERENCES,
}

_FUNCTION_QUERIES: dict[str, str] = {
    ".py": _PYTHON_FUNCTIONS,
    ".js": _JS_FUNCTIONS,
    ".jsx": _JS_FUNCTIONS,
    ".ts": _TS_FUNCTIONS,
    ".tsx": _TS_FUNCTIONS,
}


def _kind_from_capture(capture_name: str) -> str:
    """Extract kind from capture name like 'definition.function' -> 'function'."""
    if "." in capture_name:
        return capture_name.split(".")[-1]
    return capture_name


def _find_scope(node, lang: Language, ext: str) -> str | None:
    """Walk up the tree to find the enclosing function/class name.

    Skips the definition node that directly owns *node* (i.e. where
    node is the ``name`` field) so we return the true enclosing scope.
    """
    current = node.parent
    while current is not None:
        if current.type in (
            "function_definition",
            "function_declaration",
            "method_definition",
            "class_definition",
            "class_declaration",
        ):
            cur_name = current.child_by_field_name("name")
            if cur_name is not None and cur_name.id != node.id:
                return cur_name.text.decode("utf-8")
        current = current.parent
    return None


def extract_symbols(root, lang: Language, ext: str) -> list[SymbolInfo]:
    """Extract all symbol definitions from a parsed tree."""
    query_str = _SYMBOL_QUERIES.get(ext)
    if query_str is None:
        return []
    query = Query(lang, query_str)
    cursor = QueryCursor(query)

    symbols: list[SymbolInfo] = []
    seen: set[tuple[str, int]] = set()

    matches = cursor.matches(root)
    for _pattern_idx, match_captures in matches:
        name_nodes = match_captures.get("name")
        if not name_nodes:
            continue
        name_node = name_nodes[0]

        name_text = name_node.text.decode("utf-8")
        line = name_node.start_point[0]

        if (name_text, line) in seen:
            continue
        seen.add((name_text, line))

        kind = "variable"
        for cap_name in match_captures:
            if cap_name.startswith("definition."):
                kind = _kind_from_capture(cap_name)
                break

        def_node = None
        for cap_name, cap_nodes in match_captures.items():
            if cap_name.startswith("definition."):
                def_node = cap_nodes[0]
                break

        scope = _find_scope(name_node, lang, ext)

        if kind == "function" and scope is not None:
            parent = def_node.parent if def_node else name_node.parent
            while parent is not None:
                if parent.type in ("class_definition", "class_declaration"):
                    kind = "method"
                    break
                if parent.type in (
                    "function_definition",
                    "function_declaration",
                ):
                    break
                parent = parent.parent

        end_line = def_node.end_point[0] if def_node else line
        end_col = def_node.end_point[1] if def_node else name_node.end_point[1]

        symbols.append(
            SymbolInfo(
                name=name_text,
                kind=kind,
                line=line,
                col=name_node.start_point[1],
                end_line=end_line,
                end_col=end_col,
                scope=scope,
            )
        )

    return sorted(symbols, key=lambda s: s.line)


def extract_references(root, lang: Language, ext: str) -> list[ReferenceInfo]:
    """Extract all references (calls) from a parsed tree."""
    query_str = _REFERENCE_QUERIES.get(ext)
    if query_str is None:
        return []
    query = Query(lang, query_str)
    cursor = QueryCursor(query)
    matches = cursor.matches(root)

    refs: list[ReferenceInfo] = []
    seen: set[tuple[str, int, int]] = set()

    for _pattern_idx, match_captures in matches:
        name_nodes = match_captures.get("name")
        if not name_nodes:
            continue
        name_node = name_nodes[0]

        name_text = name_node.text.decode("utf-8")
        line = name_node.start_point[0]
        col = name_node.start_point[1]

        if (name_text, line, col) in seen:
            continue
        seen.add((name_text, line, col))

        kind = "call"
        for cap_name in match_captures:
            if cap_name.startswith("reference."):
                kind = _kind_from_capture(cap_name)
                break

        refs.append(
            ReferenceInfo(symbol_name=name_text, line=line, col=col, kind=kind),
        )

    return sorted(refs, key=lambda r: r.line)


def find_enclosing_function(
    root,
    lang: Language,
    ext: str,
    *,
    line: int,
) -> str | None:
    """Find the name of the function/method enclosing a 0-indexed line number."""
    query_str = _FUNCTION_QUERIES.get(ext)
    if query_str is None:
        return None
    query = Query(lang, query_str)
    cursor = QueryCursor(query)
    matches = cursor.matches(root)

    best_name: str | None = None
    best_start: int = -1

    for _pattern_idx, match_captures in matches:
        func_nodes = match_captures.get("func")
        name_nodes = match_captures.get("name")
        if not func_nodes or not name_nodes:
            continue
        func_node = func_nodes[0]
        name_node = name_nodes[0]

        start = func_node.start_point[0]
        end = func_node.end_point[0]

        if start <= line <= end and start > best_start:
            best_start = start
            best_name = name_node.text.decode("utf-8")

    return best_name


def find_symbols_at_line(
    root,
    lang: Language,
    ext: str,
    *,
    line: int,
) -> list[SymbolInfo]:
    """Find symbols (calls, assignments) at a specific 0-indexed line."""
    all_symbols: list[SymbolInfo] = []

    for sym in extract_symbols(root, lang, ext):
        if sym.line == line:
            all_symbols.append(sym)

    for ref in extract_references(root, lang, ext):
        if ref.line == line:
            all_symbols.append(
                SymbolInfo(
                    name=ref.symbol_name,
                    kind=ref.kind,
                    line=ref.line,
                    col=ref.col,
                    end_line=ref.line,
                    end_col=ref.col + len(ref.symbol_name),
                    scope=None,
                ),
            )

    return all_symbols
