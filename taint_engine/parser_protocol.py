"""Protocol definitions for parser injection into the taint engine.

The taint engine accepts any parser that satisfies these protocols.
TreeSitterReader + LanguageConfig already satisfy them — the enricher
wraps them in a trivial adapter.
"""

from __future__ import annotations

from typing import Protocol


class ASTNode(Protocol):
    @property
    def type(self) -> str: ...
    @property
    def start_point(self) -> tuple[int, int]: ...
    @property
    def end_point(self) -> tuple[int, int]: ...
    @property
    def text(self) -> bytes: ...
    @property
    def children(self) -> list[ASTNode]: ...
    @property
    def parent(self) -> ASTNode | None: ...
    def child_by_field_name(self, name: str) -> ASTNode | None: ...


class LanguageGrammar(Protocol):
    func_types: tuple[str, ...]
    call_types: tuple[str, ...]
    assignment_types: tuple[str, ...]
    parameter_types: tuple[str, ...]
    return_types: tuple[str, ...]
    conditional_types: tuple[str, ...]
    member_access_types: tuple[str, ...]
    has_arrow_functions: bool


class Parser(Protocol):
    def parse_file(self, path: str) -> ASTNode: ...
    def get_grammar(self, extension: str) -> LanguageGrammar | None: ...
