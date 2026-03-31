"""Integration tests for the taint-trace CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_PY = os.path.join(FIXTURES, "taint_sample.py")
SAMPLE_JS = os.path.join(FIXTURES, "taint_sample.js")


def run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run the CLI via python -m taint_engine.cli."""
    return subprocess.run(
        [sys.executable, "-m", "taint_engine.cli", *args],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(FIXTURES),
    )


class TestSymbolsCommand:
    def test_symbols_python(self):
        result = run_cli("symbols", SAMPLE_PY)
        assert result.returncode == 0
        assert "func" in result.stdout or "function" in result.stdout

    def test_symbols_json(self):
        result = run_cli("symbols", SAMPLE_PY, "--format", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "symbols" in data
        assert len(data["symbols"]) > 0

    def test_symbols_nonexistent_file(self):
        result = run_cli("symbols", "/tmp/nonexistent.py")
        assert result.returncode != 0


class TestIndexCommand:
    def test_index_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = run_cli("index", FIXTURES, "--db", db_path)
            assert result.returncode == 0
            assert "Indexed" in result.stdout
            assert os.path.exists(db_path)

    def test_index_force(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            run_cli("index", FIXTURES, "--db", db_path)
            result = run_cli("index", FIXTURES, "--db", db_path, "--force")
            assert result.returncode == 0


class TestTraceCommand:
    def test_trace_finds_sqli_flow(self):
        """taint_sample.py line 8 is cursor.execute(query) inside vulnerable_sqli() — a known taint sink."""
        result = run_cli("trace", f"{SAMPLE_PY}:8")
        assert result.returncode == 0
        assert "user_input" in result.stdout or "sink" in result.stdout.lower()

    def test_trace_json_output(self):
        result = run_cli("trace", f"{SAMPLE_PY}:8", "--format", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "file" in data

    def test_trace_sarif_output(self):
        result = run_cli("trace", f"{SAMPLE_PY}:8", "--format", "sarif")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["version"] == "2.1.0"

    def test_trace_invalid_format(self):
        result = run_cli("trace", f"{SAMPLE_PY}:8", "--format", "xml")
        assert result.returncode != 0
