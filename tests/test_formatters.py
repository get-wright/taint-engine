"""Tests for output formatters (text, JSON, SARIF)."""

from __future__ import annotations

import json

import pytest

from taint_engine.models import FlowStep, SanitizerInfo, GuardInfo, TaintFlow, InferredSinkSource
from taint_engine.cli.formatters.text import format_text
from taint_engine.cli.formatters.json_fmt import format_json
from taint_engine.cli.formatters.sarif import format_sarif


@pytest.fixture
def sample_flow():
    return TaintFlow(
        path=[
            FlowStep(variable="user_input", line=5, expression='request.args.get("q")', kind="source"),
            FlowStep(variable="query", line=8, expression='"SELECT * FROM t WHERE name=" + user_input', kind="assignment"),
            FlowStep(variable="query", line=12, expression="cursor.execute(query)", kind="sink"),
        ],
        sanitizers=[],
        guards=[],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=["high"],
        inferred=InferredSinkSource(
            sink_expression="cursor.execute(query)",
            sink_type="sql_query",
            expected_sources=["user_input"],
            inferred_from="cwe",
        ),
    )


@pytest.fixture
def flow_with_sanitizer():
    return TaintFlow(
        path=[
            FlowStep(variable="user_input", line=5, expression='request.args.get("q")', kind="source"),
            FlowStep(variable="safe", line=7, expression="html.escape(user_input)", kind="assignment"),
            FlowStep(variable="safe", line=10, expression="response.write(safe)", kind="sink"),
        ],
        sanitizers=[SanitizerInfo(name="html.escape", line=7, cwe_categories=["CWE-79"], conditional=False, verified=True)],
        guards=[GuardInfo(name="isinstance", line=6, variable="user_input")],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=["medium"],
        inferred=None,
    )


class TestTextFormatter:
    def test_basic_flow(self, sample_flow):
        output = format_text(sample_flow, file_path="app.py")
        assert "[source]" in output
        assert "[sink]" in output
        assert "user_input" in output
        assert "cursor.execute" in output

    def test_sanitizer_shown(self, flow_with_sanitizer):
        output = format_text(flow_with_sanitizer, file_path="app.py")
        assert "html.escape" in output

    def test_no_flows(self):
        output = format_text(None, file_path="app.py")
        assert "No taint flow" in output


class TestJsonFormatter:
    def test_valid_json(self, sample_flow):
        output = format_json(sample_flow, file_path="app.py")
        data = json.loads(output)
        assert data["file"] == "app.py"
        assert len(data["flows"][0]["path"]) == 3

    def test_none_flow(self):
        output = format_json(None, file_path="app.py")
        data = json.loads(output)
        assert data["flows"] == []


class TestSarifFormatter:
    def test_valid_sarif_structure(self, sample_flow):
        output = format_sarif([sample_flow], file_path="app.py")
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "taint-trace"
        assert len(run["results"]) == 1

    def test_code_flow_locations(self, sample_flow):
        output = format_sarif([sample_flow], file_path="app.py")
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        assert "codeFlows" in result
        locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
        assert len(locations) == 3
        assert locations[0]["location"]["physicalLocation"]["region"]["startLine"] == 5

    def test_empty_flows(self):
        output = format_sarif([], file_path="app.py")
        data = json.loads(output)
        assert data["runs"][0]["results"] == []
