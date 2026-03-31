"""Test configuration and helpers for the standalone taint engine.

Provides a tree-sitter-based Parser implementation that satisfies
the taint_engine.parser_protocol.Parser protocol without depending
on the semgrep_analyzer codebase.
"""

from __future__ import annotations

from dataclasses import dataclass


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
    conditional_types=("if_statement", "try_statement"),
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
    conditional_types=("if_statement", "try_statement"),
    member_access_types=("member_expression",),
    has_arrow_functions=True,
)

_GRAMMAR_BY_EXT = {
    ".py": PYTHON_GRAMMAR,
    ".js": JS_GRAMMAR,
    ".jsx": JS_GRAMMAR,
    ".ts": JS_GRAMMAR,
    ".tsx": JS_GRAMMAR,
}


class TreeSitterParser:
    """Standalone Parser satisfying taint_engine.parser_protocol.Parser.

    Uses tree-sitter directly without the semgrep_analyzer TreeSitterReader.
    """

    def __init__(self):
        self._parsers = {}

    def _get_parser(self, ext: str):
        if ext in self._parsers:
            return self._parsers[ext]

        from tree_sitter import Language, Parser

        if ext == ".py":
            import tree_sitter_python as ts_python

            lang = Language(ts_python.language())
        elif ext in (".js", ".jsx"):
            import tree_sitter_javascript as ts_javascript

            lang = Language(ts_javascript.language())
        elif ext in (".ts", ".tsx"):
            try:
                import tree_sitter_typescript as ts_typescript

                lang = Language(ts_typescript.language_typescript())
            except ImportError:
                import tree_sitter_javascript as ts_javascript

                lang = Language(ts_javascript.language())
        else:
            return None

        parser = Parser(lang)
        self._parsers[ext] = parser
        return parser

    def parse_file(self, path: str):
        import os

        ext = os.path.splitext(path)[1]
        parser = self._get_parser(ext)
        if parser is None:
            raise ValueError(f"No grammar for extension: {ext}")
        with open(path, "rb") as f:
            source = f.read()
        tree = parser.parse(source)
        return tree.root_node

    def get_grammar(self, extension: str):
        return _GRAMMAR_BY_EXT.get(extension)
