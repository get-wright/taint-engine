"""Tests for JavaScript/TypeScript import resolution."""

from __future__ import annotations

import os
import tempfile

import pytest

from taint_engine.resolver.js_resolver import JsResolver
from taint_engine.resolver.index_store import IndexStore
from taint_engine.resolver.base import ImportEntry, SymbolInfo


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "resolver_project_js")


@pytest.fixture
def store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    s = IndexStore(path)
    yield s
    s.close()
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def resolver():
    return JsResolver()


class TestParseImports:
    def test_require(self, resolver):
        from taint_engine.ts_parser import TreeSitterParser
        parser = TreeSitterParser()
        app_path = os.path.join(FIXTURES, "src", "app.js")
        root = parser.parse_file(app_path)
        imports = resolver.parse_imports(app_path, root)
        modules = {i.source_module for i in imports}
        assert "./utils" in modules
        assert "./handler" in modules

    def test_es_import(self, resolver):
        from taint_engine.ts_parser import TreeSitterParser
        parser = TreeSitterParser()
        typed_path = os.path.join(FIXTURES, "src", "typed.ts")
        root = parser.parse_file(typed_path)
        imports = resolver.parse_imports(typed_path, root)
        by_local = {i.local_name: i for i in imports}
        assert "sanitize" in by_local
        assert by_local["sanitize"].source_module == "./utils/helper"

    def test_import_type_skipped(self, resolver):
        from taint_engine.ts_parser import TreeSitterParser
        parser = TreeSitterParser()
        typed_path = os.path.join(FIXTURES, "src", "typed.ts")
        root = parser.parse_file(typed_path)
        imports = resolver.parse_imports(typed_path, root)
        local_names = {i.local_name for i in imports}
        assert "Request" not in local_names


class TestResolveImport:
    def test_resolve_relative_js_uses_import_map(self, resolver, store):
        source = os.path.join(FIXTURES, "src", "handler.js")
        helper_path = os.path.join(FIXTURES, "src", "utils", "helper.js")
        other_path = os.path.join(FIXTURES, "src", "other.js")
        store.upsert_file(helper_path, mtime=1.0, content_hash="h")
        store.replace_symbols(helper_path, [
            SymbolInfo("sanitize", "function", 0, 0, 2, 0, None),
        ])
        store.upsert_file(other_path, mtime=1.0, content_hash="o")
        store.replace_symbols(other_path, [
            SymbolInfo("sanitize", "function", 0, 0, 2, 0, None),
        ])
        store.upsert_file(source, mtime=1.0, content_hash="src")
        store.replace_imports(source, [
            ImportEntry("sanitize", "./utils/helper", "sanitize", 1),
        ])
        result = resolver.resolve_import(source, "sanitize", store)
        assert result is not None
        assert result.name == "sanitize"
        assert result.file_path.endswith("src/utils/helper.js")

    def test_resolve_index_js(self, resolver, store):
        """./utils should resolve to ./utils/index.js"""
        source = os.path.join(FIXTURES, "src", "app.js")
        index_path = os.path.join(FIXTURES, "src", "utils", "index.js")
        result = resolver._resolve_module_path(source, "./utils")
        assert result is not None
        assert result.endswith("index.js")

    def test_resolve_node_modules_skipped(self, resolver, store):
        source = os.path.join(FIXTURES, "src", "typed.ts")
        result = resolver.resolve_import(source, "Request", store)
        assert result is None
