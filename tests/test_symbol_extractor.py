"""Tests for tree-sitter query-based symbol extraction."""

from __future__ import annotations

import os
import tempfile

import pytest

from taint_engine.ts_parser import TreeSitterParser
from taint_engine.resolver.symbol_extractor import (
    extract_symbols,
    extract_references,
    find_enclosing_function,
    find_symbols_at_line,
)


@pytest.fixture
def parser():
    return TreeSitterParser()


PYTHON_CODE = b"""\
import os

logger = logging.getLogger(__name__)

class RequestHandler:
    def handle(self, request):
        user_input = request.args.get("q")
        query = "SELECT * FROM t WHERE name=" + user_input
        cursor.execute(query)
        return result

def helper(x):
    return x.strip()
"""

JS_CODE = b"""\
const logger = require("./logger");

function handleRequest(req, res) {
    const userInput = req.body.name;
    const query = "SELECT * FROM t WHERE name=" + userInput;
    db.execute(query);
}

const helper = (x) => x.trim();
"""

TS_CODE = b"""\
import { Logger } from "./logger";

function handleRequest(req: Request, res: Response): void {
    const userInput: string = req.body.name;
    const query: string = "SELECT * FROM t WHERE name=" + userInput;
    db.execute(query);
}
"""


def _write_tmp(code: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, code)
    os.close(fd)
    return path


class TestExtractSymbols:
    def test_python_functions_and_classes(self, parser):
        path = _write_tmp(PYTHON_CODE, ".py")
        try:
            root = parser.parse_file(path)
            lang = parser.get_language(".py")
            symbols = extract_symbols(root, lang, ".py")
            names = {s.name for s in symbols}
            assert "RequestHandler" in names
            assert "handle" in names
            assert "helper" in names
        finally:
            os.unlink(path)

    def test_python_symbol_kinds(self, parser):
        path = _write_tmp(PYTHON_CODE, ".py")
        try:
            root = parser.parse_file(path)
            lang = parser.get_language(".py")
            symbols = extract_symbols(root, lang, ".py")
            by_name = {s.name: s for s in symbols}
            assert by_name["RequestHandler"].kind == "class"
            assert by_name["handle"].kind == "method"
            assert by_name["helper"].kind == "function"
        finally:
            os.unlink(path)

    def test_javascript_functions(self, parser):
        path = _write_tmp(JS_CODE, ".js")
        try:
            root = parser.parse_file(path)
            lang = parser.get_language(".js")
            symbols = extract_symbols(root, lang, ".js")
            names = {s.name for s in symbols}
            assert "handleRequest" in names
        finally:
            os.unlink(path)

    def test_typescript_functions(self, parser):
        path = _write_tmp(TS_CODE, ".ts")
        try:
            root = parser.parse_file(path)
            lang = parser.get_language(".ts")
            symbols = extract_symbols(root, lang, ".ts")
            names = {s.name for s in symbols}
            assert "handleRequest" in names
        finally:
            os.unlink(path)


class TestExtractReferences:
    def test_python_calls(self, parser):
        path = _write_tmp(PYTHON_CODE, ".py")
        try:
            root = parser.parse_file(path)
            lang = parser.get_language(".py")
            refs = extract_references(root, lang, ".py")
            call_names = {r.symbol_name for r in refs if r.kind == "call"}
            assert "getLogger" in call_names or "logging.getLogger" in call_names
        finally:
            os.unlink(path)


class TestFindEnclosingFunction:
    def test_python_line_inside_method(self, parser):
        path = _write_tmp(PYTHON_CODE, ".py")
        try:
            root = parser.parse_file(path)
            lang = parser.get_language(".py")
            # line 8 (0-indexed) is cursor.execute(query) inside handle()
            func_name = find_enclosing_function(root, lang, ".py", line=8)
            assert func_name == "handle"
        finally:
            os.unlink(path)

    def test_python_line_in_standalone_function(self, parser):
        path = _write_tmp(PYTHON_CODE, ".py")
        try:
            root = parser.parse_file(path)
            lang = parser.get_language(".py")
            # line 12 (0-indexed) is return x.strip() inside helper()
            func_name = find_enclosing_function(root, lang, ".py", line=12)
            assert func_name == "helper"
        finally:
            os.unlink(path)


class TestFindSymbolsAtLine:
    def test_python_call_at_line(self, parser):
        path = _write_tmp(PYTHON_CODE, ".py")
        try:
            root = parser.parse_file(path)
            lang = parser.get_language(".py")
            # line 8 (0-indexed) has cursor.execute(query)
            syms = find_symbols_at_line(root, lang, ".py", line=8)
            names = {s.name for s in syms}
            assert "execute" in names or "cursor.execute" in names
        finally:
            os.unlink(path)
