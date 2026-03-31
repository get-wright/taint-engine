"""JavaScript / TypeScript import resolution.

Handles CommonJS require() and ESM import/export for .js, .jsx, .ts, .tsx.
Does not resolve node_modules — third-party code is out of scope.
"""

from __future__ import annotations

import os

from .base import ImportEntry, ResolvedSymbol
from .index_store import IndexStore

_JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx")


class JsResolver:
    """Resolves JS/TS imports to file paths and symbol locations."""

    def parse_imports(self, file_path: str, tree) -> list[ImportEntry]:
        """Extract import/require statements from a parsed JS/TS file."""
        entries: list[ImportEntry] = []
        self._walk_imports(tree, entries)
        return entries

    def _walk_imports(self, node, entries: list[ImportEntry]) -> None:
        """Recursively walk tree to find import/require nodes."""
        if node.type == "import_statement":
            source_text = node.text.decode("utf-8")
            if source_text.lstrip().startswith("import type"):
                return

            source_node = node.child_by_field_name("source")
            if source_node is None:
                for child in node.children:
                    self._walk_imports(child, entries)
                return

            module_path = source_node.text.decode("utf-8").strip("'\"")

            for child in node.children:
                if child.type == "import_clause":
                    for sub in child.children:
                        if sub.type == "named_imports":
                            for spec in sub.named_children:
                                if spec.type == "import_specifier":
                                    name_node = spec.child_by_field_name("name")
                                    alias_node = spec.child_by_field_name("alias")
                                    if name_node:
                                        imported = name_node.text.decode("utf-8")
                                        local = (
                                            alias_node.text.decode("utf-8")
                                            if alias_node
                                            else imported
                                        )
                                        entries.append(ImportEntry(
                                            local_name=local,
                                            source_module=module_path,
                                            imported_name=imported,
                                            line=node.start_point[0],
                                        ))
                        elif sub.type == "identifier":
                            entries.append(ImportEntry(
                                local_name=sub.text.decode("utf-8"),
                                source_module=module_path,
                                imported_name="default",
                                line=node.start_point[0],
                            ))
                        elif sub.type == "namespace_import":
                            for ns_child in sub.children:
                                if ns_child.type == "identifier":
                                    entries.append(ImportEntry(
                                        local_name=ns_child.text.decode("utf-8"),
                                        source_module=module_path,
                                        imported_name="*",
                                        line=node.start_point[0],
                                    ))
            return

        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node and func_node.text == b"require":
                args = node.child_by_field_name("arguments")
                if args and args.named_children:
                    first_arg = args.named_children[0]
                    if first_arg.type == "string":
                        module_path = first_arg.text.decode("utf-8").strip("'\"")
                        parent = node.parent
                        if parent and parent.type == "variable_declarator":
                            name_node = parent.child_by_field_name("name")
                            if name_node:
                                if name_node.type == "object_pattern":
                                    for prop in name_node.named_children:
                                        if prop.type == "shorthand_property_identifier_pattern":
                                            local = prop.text.decode("utf-8")
                                            entries.append(ImportEntry(
                                                local_name=local,
                                                source_module=module_path,
                                                imported_name=local,
                                                line=node.start_point[0],
                                            ))
                                        elif prop.type == "pair_pattern":
                                            key = prop.child_by_field_name("key")
                                            value = prop.child_by_field_name("value")
                                            if key and value:
                                                entries.append(ImportEntry(
                                                    local_name=value.text.decode("utf-8"),
                                                    source_module=module_path,
                                                    imported_name=key.text.decode("utf-8"),
                                                    line=node.start_point[0],
                                                ))
                                else:
                                    entries.append(ImportEntry(
                                        local_name=name_node.text.decode("utf-8"),
                                        source_module=module_path,
                                        imported_name=None,
                                        line=node.start_point[0],
                                    ))

        for child in node.children:
            self._walk_imports(child, entries)

    def _resolve_module_path(
        self, source_file: str, module_specifier: str,
    ) -> str | None:
        """Resolve a module specifier to an absolute file path."""
        if not module_specifier.startswith("."):
            return None

        source_dir = os.path.dirname(os.path.abspath(source_file))
        base = os.path.normpath(os.path.join(source_dir, module_specifier))

        if os.path.isfile(base):
            return base

        for ext in _JS_EXTENSIONS:
            candidate = base + ext
            if os.path.isfile(candidate):
                return candidate

        if os.path.isdir(base):
            for ext in _JS_EXTENSIONS:
                candidate = os.path.join(base, "index" + ext)
                if os.path.isfile(candidate):
                    return candidate

        return None

    def resolve_import(
        self,
        source_file: str,
        local_name: str,
        index: IndexStore,
    ) -> ResolvedSymbol | None:
        """Resolve a local JS / TS imported name using the file import map."""
        head, _, tail = local_name.partition(".")
        import_entry = index.lookup_import(source_file, head)
        if import_entry is None:
            fallback = index.resolve_symbol(local_name)
            return fallback[0] if len(fallback) == 1 else None

        module_path = self._resolve_module_path(
            source_file, import_entry.source_module,
        )
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
