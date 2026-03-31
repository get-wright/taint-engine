"""Python import resolution.

Resolves import statements by walking search paths to find
source files and looking up symbols in the index.
"""

from __future__ import annotations

import os

from .base import ImportEntry, ResolvedSymbol
from .index_store import IndexStore


class PythonResolver:
    """Resolves Python imports to file paths and symbol locations."""

    def __init__(self, search_paths: list[str] | None = None) -> None:
        self._search_paths = search_paths or ["."]

    def parse_imports(self, file_path: str, tree) -> list[ImportEntry]:
        """Extract import statements from a parsed Python file."""
        entries: list[ImportEntry] = []
        self._walk_imports(tree, entries, file_path)
        return entries

    def _walk_imports(self, node, entries: list[ImportEntry], file_path: str) -> None:
        """Recursively walk tree to find import nodes."""
        if node.type == "import_statement":
            self._handle_import(node, entries)
        elif node.type == "import_from_statement":
            self._handle_from_import(node, entries, file_path)
        else:
            for child in node.children:
                self._walk_imports(child, entries, file_path)

    def _handle_import(self, node, entries: list[ImportEntry]) -> None:
        """Handle ``import foo`` and ``import foo as bar``."""
        for child in node.children:
            if child.type == "aliased_import":
                name_part = child.child_by_field_name("name")
                alias_part = child.child_by_field_name("alias")
                if name_part:
                    module_name = name_part.text.decode("utf-8")
                    local = (
                        alias_part.text.decode("utf-8")
                        if alias_part
                        else module_name.split(".")[0]
                    )
                    entries.append(ImportEntry(
                        local_name=local,
                        source_module=module_name,
                        imported_name=None,
                        line=node.start_point[0],
                    ))
                return

        name_node = node.child_by_field_name("name")
        if name_node is not None:
            module_name = name_node.text.decode("utf-8")
            local = module_name.split(".")[0]
            entries.append(ImportEntry(
                local_name=local,
                source_module=module_name,
                imported_name=None,
                line=node.start_point[0],
            ))

    def _handle_from_import(
        self,
        node,
        entries: list[ImportEntry],
        file_path: str,
    ) -> None:
        """Handle ``from foo import bar`` including relative imports."""
        module_node = node.child_by_field_name("module_name")
        if module_node is None:
            return

        source_module = module_node.text.decode("utf-8")

        past_import_keyword = False
        for child in node.children:
            if not child.is_named and child.type == "import":
                past_import_keyword = True
                continue
            if not past_import_keyword:
                continue

            if child.type == "dotted_name":
                imported = child.text.decode("utf-8")
                entries.append(ImportEntry(
                    local_name=imported,
                    source_module=source_module,
                    imported_name=imported,
                    line=node.start_point[0],
                ))
            elif child.type == "aliased_import":
                name_part = child.child_by_field_name("name")
                alias_part = child.child_by_field_name("alias")
                if name_part:
                    imported = name_part.text.decode("utf-8")
                    local = (
                        alias_part.text.decode("utf-8")
                        if alias_part
                        else imported
                    )
                    entries.append(ImportEntry(
                        local_name=local,
                        source_module=source_module,
                        imported_name=imported,
                        line=node.start_point[0],
                    ))

    def _resolve_module_path(self, source_file: str, module_name: str) -> str | None:
        """Resolve a Python module string to a concrete file path."""
        if module_name.startswith("."):
            current_dir = os.path.dirname(os.path.abspath(source_file))
            dot_count = len(module_name) - len(module_name.lstrip("."))
            remainder = module_name.lstrip(".")

            base_dir = current_dir
            for _ in range(max(dot_count - 1, 0)):
                base_dir = os.path.dirname(base_dir)

            parts = remainder.split(".") if remainder else []
            candidates = [
                os.path.join(base_dir, *parts) + ".py" if parts else None,
                os.path.join(base_dir, *parts, "__init__.py"),
            ]
        else:
            parts = module_name.split(".")
            candidates = []
            for search_path in self._search_paths:
                candidates.extend([
                    os.path.join(search_path, *parts) + ".py",
                    os.path.join(search_path, *parts, "__init__.py"),
                ])

        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                return os.path.abspath(candidate)
        return None

    def resolve_import(
        self,
        source_file: str,
        local_name: str,
        index: IndexStore,
    ) -> ResolvedSymbol | None:
        """Resolve a local imported name using the source file's import map."""
        head, _, tail = local_name.partition(".")

        import_entry = index.lookup_import(source_file, head)
        if import_entry is None:
            fallback = index.resolve_symbol(local_name)
            return fallback[0] if len(fallback) == 1 else None

        module_path = self._resolve_module_path(source_file, import_entry.source_module)
        if module_path is None:
            return None

        target_name = tail or import_entry.imported_name or head
        symbol = index.lookup_symbol_in_file(module_path, target_name)
        if symbol is None:
            fallback = index.resolve_symbol(target_name)
            return fallback[0] if len(fallback) == 1 else None

        return ResolvedSymbol(
            file_path=module_path,
            name=symbol.name,
            kind=symbol.kind,
            line=symbol.line,
            col=symbol.col,
            end_line=symbol.end_line,
            end_col=symbol.end_col,
            scope=symbol.scope,
        )
