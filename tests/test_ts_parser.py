# tests/test_ts_parser.py
"""Tests for the production TreeSitterParser."""

from __future__ import annotations

import os
import tempfile

import pytest

from taint_engine.ts_parser import TreeSitterParser


@pytest.fixture
def parser():
    return TreeSitterParser()


PYTHON_CODE = b"""\
def greet(name):
    return f"Hello, {name}"
"""

JS_CODE = b"""\
function greet(name) {
    return "Hello, " + name;
}
"""

TS_CODE = b"""\
function greet(name: string): string {
    return "Hello, " + name;
}
"""

TSX_CODE = b"""\
function App(props: { name: string }) {
    return <div>{props.name}</div>;
}
"""


def _write_tmp(code: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, code)
    os.close(fd)
    return path


class TestParseFile:
    def test_python(self, parser):
        path = _write_tmp(PYTHON_CODE, ".py")
        try:
            root = parser.parse_file(path)
            assert root.type == "module"
            func = root.children[0]
            assert func.type == "function_definition"
            name_node = func.child_by_field_name("name")
            assert name_node.text == b"greet"
        finally:
            os.unlink(path)

    def test_javascript(self, parser):
        path = _write_tmp(JS_CODE, ".js")
        try:
            root = parser.parse_file(path)
            assert root.type == "program"
            func = root.children[0]
            assert func.type == "function_declaration"
        finally:
            os.unlink(path)

    def test_typescript(self, parser):
        path = _write_tmp(TS_CODE, ".ts")
        try:
            root = parser.parse_file(path)
            assert root.type == "program"
            func = root.children[0]
            assert func.type == "function_declaration"
        finally:
            os.unlink(path)

    def test_tsx(self, parser):
        path = _write_tmp(TSX_CODE, ".tsx")
        try:
            root = parser.parse_file(path)
            assert root.type == "program"
        finally:
            os.unlink(path)

    def test_unsupported_extension(self, parser):
        path = _write_tmp(b"hello", ".txt")
        try:
            with pytest.raises(ValueError, match="No grammar"):
                parser.parse_file(path)
        finally:
            os.unlink(path)


class TestGetGrammar:
    def test_python_grammar(self, parser):
        g = parser.get_grammar(".py")
        assert g is not None
        assert "function_definition" in g.func_types

    def test_js_grammar(self, parser):
        g = parser.get_grammar(".js")
        assert g is not None
        assert g.has_arrow_functions is True

    def test_ts_grammar(self, parser):
        g = parser.get_grammar(".ts")
        assert g is not None
        assert g.has_arrow_functions is True

    def test_tsx_grammar(self, parser):
        g = parser.get_grammar(".tsx")
        assert g is not None

    def test_unknown_extension(self, parser):
        assert parser.get_grammar(".rb") is None


class TestParserCaching:
    def test_same_extension_reuses_parser(self, parser):
        path1 = _write_tmp(PYTHON_CODE, ".py")
        path2 = _write_tmp(PYTHON_CODE, ".py")
        try:
            parser.parse_file(path1)
            parser.parse_file(path2)
            # Internal cache: only one parser instance per extension
            assert len(parser._parsers) == 1
        finally:
            os.unlink(path1)
            os.unlink(path2)
