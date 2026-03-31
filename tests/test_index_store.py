"""Tests for SQLite index store."""

from __future__ import annotations

import tempfile
import os

import pytest

from taint_engine.resolver.index_store import IndexStore
from taint_engine.resolver.base import SymbolInfo, ImportEntry


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # IndexStore creates it
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def store(db_path):
    return IndexStore(db_path)


class TestFileTracking:
    def test_upsert_and_check_file(self, store):
        store.upsert_file("/tmp/a.py", mtime=1000.0, content_hash="abc123")
        assert store.is_file_current("/tmp/a.py", mtime=1000.0, content_hash="abc123")

    def test_stale_file(self, store):
        store.upsert_file("/tmp/a.py", mtime=1000.0, content_hash="abc123")
        assert not store.is_file_current("/tmp/a.py", mtime=2000.0, content_hash="def456")

    def test_unknown_file(self, store):
        assert not store.is_file_current("/tmp/unknown.py", mtime=1.0, content_hash="x")


class TestSymbols:
    def test_store_and_query_symbols(self, store):
        store.upsert_file("/tmp/a.py", mtime=1.0, content_hash="h")
        symbols = [
            SymbolInfo("greet", "function", 5, 0, 10, 0, None),
            SymbolInfo("MyClass", "class", 12, 0, 30, 0, None),
        ]
        store.replace_symbols("/tmp/a.py", symbols)
        result = store.lookup_symbol("greet")
        assert len(result) == 1
        assert result[0].name == "greet"
        assert result[0].kind == "function"
        assert result[0].line == 5

    def test_replace_clears_old(self, store):
        store.upsert_file("/tmp/a.py", mtime=1.0, content_hash="h")
        store.replace_symbols("/tmp/a.py", [SymbolInfo("old", "function", 1, 0, 5, 0, None)])
        store.replace_symbols("/tmp/a.py", [SymbolInfo("new", "function", 1, 0, 5, 0, None)])
        assert store.lookup_symbol("old") == []
        assert len(store.lookup_symbol("new")) == 1


class TestImports:
    def test_store_and_query_imports(self, store):
        store.upsert_file("/tmp/a.py", mtime=1.0, content_hash="h")
        imports = [
            ImportEntry("Request", "flask", "Request", 1),
            ImportEntry("os", "os", None, 2),
        ]
        store.replace_imports("/tmp/a.py", imports)
        result = store.lookup_imports_by_file("/tmp/a.py")
        assert len(result) == 2

    def test_replace_clears_old_imports(self, store):
        store.upsert_file("/tmp/a.py", mtime=1.0, content_hash="h")
        store.replace_imports("/tmp/a.py", [ImportEntry("old", "old_mod", None, 1)])
        store.replace_imports("/tmp/a.py", [ImportEntry("new", "new_mod", None, 1)])
        result = store.lookup_imports_by_file("/tmp/a.py")
        assert len(result) == 1
        assert result[0].local_name == "new"


class TestSymbolsByFile:
    def test_symbols_for_file(self, store):
        store.upsert_file("/tmp/a.py", mtime=1.0, content_hash="h")
        store.replace_symbols("/tmp/a.py", [
            SymbolInfo("foo", "function", 1, 0, 5, 0, None),
            SymbolInfo("bar", "function", 6, 0, 10, 0, None),
        ])
        result = store.get_symbols_for_file("/tmp/a.py")
        assert len(result) == 2
        assert result[0].name == "foo"

    def test_reference_count(self, store):
        store.upsert_file("/tmp/a.py", mtime=1.0, content_hash="h")
        store.replace_symbols("/tmp/a.py", [SymbolInfo("foo", "function", 1, 0, 5, 0, None)])
        from taint_engine.resolver.symbol_extractor import ReferenceInfo
        store.replace_references("/tmp/a.py", [
            ReferenceInfo("foo", 10, 4, "call"),
            ReferenceInfo("foo", 15, 4, "call"),
            ReferenceInfo("bar", 20, 4, "call"),
        ])
        count = store.count_references("/tmp/a.py", "foo")
        assert count == 2
