"""Tests for Python import resolution."""

from __future__ import annotations

import os
import tempfile

import pytest

from taint_engine.resolver.python_resolver import PythonResolver
from taint_engine.resolver.index_store import IndexStore
from taint_engine.resolver.base import SymbolInfo, ImportEntry


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "resolver_project")


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
    return PythonResolver(search_paths=[FIXTURES])


class TestParseImports:
    def test_from_import(self, resolver):
        from taint_engine.ts_parser import TreeSitterParser
        parser = TreeSitterParser()
        app_path = os.path.join(FIXTURES, "app.py")
        root = parser.parse_file(app_path)
        imports = resolver.parse_imports(app_path, root)
        by_local = {i.local_name: i for i in imports}
        assert "helper" in by_local
        assert by_local["helper"].source_module == "mypackage.utils"
        assert by_local["helper"].imported_name == "helper"

    def test_plain_import(self, resolver):
        from taint_engine.ts_parser import TreeSitterParser
        parser = TreeSitterParser()
        app_path = os.path.join(FIXTURES, "app.py")
        root = parser.parse_file(app_path)
        imports = resolver.parse_imports(app_path, root)
        by_local = {i.local_name: i for i in imports}
        assert "os" in by_local
        assert by_local["os"].source_module == "os"

    def test_relative_import(self, resolver):
        from taint_engine.ts_parser import TreeSitterParser
        parser = TreeSitterParser()
        handler_path = os.path.join(FIXTURES, "mypackage", "sub", "handler.py")
        root = parser.parse_file(handler_path)
        imports = resolver.parse_imports(handler_path, root)
        by_local = {i.local_name: i for i in imports}
        assert "helper" in by_local


class TestResolveImport:
    def test_resolve_from_import_uses_import_map(self, resolver, store):
        target = os.path.join(FIXTURES, "mypackage", "utils.py")
        distractor = os.path.join(FIXTURES, "otherpkg", "helpers.py")
        store.upsert_file(target, mtime=1.0, content_hash="h")
        store.replace_symbols(target, [
            SymbolInfo("helper", "function", 0, 0, 2, 0, None),
            SymbolInfo("sanitize", "function", 4, 0, 5, 0, None),
        ])
        store.upsert_file(distractor, mtime=1.0, content_hash="d")
        store.replace_symbols(distractor, [
            SymbolInfo("helper", "function", 0, 0, 1, 0, None),
        ])
        source_file = os.path.join(FIXTURES, "app.py")
        store.upsert_file(source_file, mtime=1.0, content_hash="src")
        store.replace_imports(source_file, [
            ImportEntry("helper", "mypackage.utils", "helper", 1),
            ImportEntry("handle", "mypackage.sub.handler", "handle", 2),
            ImportEntry("os", "os", None, 3),
        ])
        result = resolver.resolve_import(source_file, "helper", store)
        assert result is not None
        assert result.name == "helper"
        assert result.file_path.endswith("mypackage/utils.py")

    def test_resolve_nonexistent(self, resolver, store):
        source_file = os.path.join(FIXTURES, "app.py")
        result = resolver.resolve_import(source_file, "nonexistent", store)
        assert result is None
