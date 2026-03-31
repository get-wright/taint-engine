"""Concrete Parser protocol implementation using tree-sitter.

Loads language grammars from installed tree-sitter-* packages and
provides parsing + grammar config for Python, JavaScript, and TypeScript.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from tree_sitter import Language, Parser


@dataclass(frozen=True)
class GrammarConfig:
    """Satisfies taint_engine.parser_protocol.LanguageGrammar."""

    func_types: tuple[str, ...]
    call_types: tuple[str, ...]
    assignment_types: tuple[str, ...]
    parameter_types: tuple[str, ...]
    return_types: tuple[str, ...]
    conditional_types: tuple[str, ...]
    member_access_types: tuple[str, ...]
    has_arrow_functions: bool = False


PYTHON_GRAMMAR = GrammarConfig(
    func_types=("function_definition",),
    call_types=("call",),
    assignment_types=("assignment", "augmented_assignment"),
    parameter_types=("parameters",),
    return_types=("return_statement",),
    conditional_types=("if_statement",),
    member_access_types=("attribute",),
    has_arrow_functions=False,
)

JS_GRAMMAR = GrammarConfig(
    func_types=("function_declaration", "arrow_function", "method_definition"),
    call_types=("call_expression",),
    assignment_types=(
        "assignment_expression",
        "augmented_assignment_expression",
        "variable_declarator",
    ),
    parameter_types=("formal_parameters",),
    return_types=("return_statement",),
    conditional_types=("if_statement",),
    member_access_types=("member_expression",),
    has_arrow_functions=True,
)

_GRAMMAR_BY_EXT: dict[str, GrammarConfig] = {
    ".py": PYTHON_GRAMMAR,
    ".js": JS_GRAMMAR,
    ".jsx": JS_GRAMMAR,
    ".ts": JS_GRAMMAR,
    ".tsx": JS_GRAMMAR,
}

# Extensions grouped by language loader
_PYTHON_EXTS = frozenset({".py"})
_JS_EXTS = frozenset({".js", ".jsx"})
_TS_EXTS = frozenset({".ts"})
_TSX_EXTS = frozenset({".tsx"})

SUPPORTED_EXTENSIONS = _PYTHON_EXTS | _JS_EXTS | _TS_EXTS | _TSX_EXTS


def _load_language(ext: str) -> Language:
    """Load tree-sitter Language for a file extension."""
    if ext in _PYTHON_EXTS:
        import tree_sitter_python as tspython

        return Language(tspython.language())
    if ext in _JS_EXTS:
        import tree_sitter_javascript as tsjavascript

        return Language(tsjavascript.language())
    if ext in _TS_EXTS:
        import tree_sitter_typescript as tstypescript

        return Language(tstypescript.language_typescript())
    if ext in _TSX_EXTS:
        import tree_sitter_typescript as tstypescript

        return Language(tstypescript.language_tsx())
    raise ValueError(f"No grammar for extension: {ext}")


class TreeSitterParser:
    """Implements taint_engine.parser_protocol.Parser using tree-sitter.

    Lazily loads and caches tree-sitter parsers per file extension.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}

    def _get_parser(self, ext: str) -> Parser:
        if ext in self._parsers:
            return self._parsers[ext]
        lang = _load_language(ext)
        parser = Parser(lang)
        self._parsers[ext] = parser
        return parser

    def parse_file(self, path: str):
        ext = os.path.splitext(path)[1].lower()
        parser = self._get_parser(ext)
        with open(path, "rb") as f:
            source = f.read()
        tree = parser.parse(source)
        return tree.root_node

    def get_grammar(self, extension: str) -> GrammarConfig | None:
        return _GRAMMAR_BY_EXT.get(extension)

    def get_language(self, ext: str) -> Language:
        """Get the tree-sitter Language for an extension. Used by symbol_extractor."""
        return _load_language(ext)
