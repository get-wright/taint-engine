"""Shared types and protocols for the resolver package."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Protocol

if TYPE_CHECKING:
    from .index_store import IndexStore
    from ..parser_protocol import ASTNode


@dataclass(frozen=True)
class ResolvedSymbol:
    """A symbol resolved to a specific location in a file."""

    file_path: str
    name: str
    kind: str
    line: int
    col: int
    end_line: int
    end_col: int
    scope: str | None


@dataclass(frozen=True)
class ImportEntry:
    """A parsed import statement."""

    local_name: str  # name used in this file
    source_module: str  # module path (e.g., "flask.request")
    imported_name: str | None  # original name if aliased, None if same
    line: int


@dataclass(frozen=True)
class SymbolInfo:
    """A symbol extracted from a source file."""

    name: str
    kind: str  # "function", "class", "variable", "method"
    line: int
    col: int
    end_line: int
    end_col: int
    scope: str | None  # enclosing function/class name, None for top-level


class ImportResolver(Protocol):
    """Per-language import resolver."""

    def resolve_import(
        self,
        source_file: str,
        local_name: str,
        index: IndexStore,
    ) -> Optional[ResolvedSymbol]: ...

    def parse_imports(
        self,
        file_path: str,
        tree: ASTNode,
    ) -> list[ImportEntry]: ...
