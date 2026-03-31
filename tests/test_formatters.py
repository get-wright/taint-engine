"""Tests for output formatters (text, JSON, SARIF)."""

from __future__ import annotations

import json

import pytest

from taint_engine.models import (
    FlowStep,
    GuardInfo,
    InferredSinkSource,
    SanitizerInfo,
    TaintFlow,
    TransformerInfo,
)
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


@pytest.fixture
def flow_with_effective_sanitizer():
    """Sanitizer that is effective with explicit label and state."""
    return TaintFlow(
        path=[
            FlowStep(variable="user_input", line=5, expression='request.args.get("q")', kind="source"),
            FlowStep(variable="safe", line=7, expression="html.escape(user_input)", kind="assignment"),
            FlowStep(variable="safe", line=10, expression="response.write(safe)", kind="sink"),
        ],
        sanitizers=[
            SanitizerInfo(
                name="html.escape",
                line=7,
                cwe_categories=["CWE-79"],
                conditional=False,
                verified=True,
                sets_state="html-encoded",
                effective=True,
                discovery_order=1,
            ),
        ],
        guards=[],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=["high"],
        inferred=None,
        active_label="html-encoded",
        final_state="html-encoded",
    )


@pytest.fixture
def flow_with_ineffective_sanitizer_wrong_label():
    """Sanitizer ineffective because it doesn't address the sink's label."""
    return TaintFlow(
        path=[
            FlowStep(variable="user_input", line=5, expression='request.args.get("q")', kind="source"),
            FlowStep(variable="escaped", line=7, expression="html.escape(user_input)", kind="assignment"),
            FlowStep(variable="escaped", line=12, expression="cursor.execute(escaped)", kind="sink"),
        ],
        sanitizers=[
            SanitizerInfo(
                name="html.escape",
                line=7,
                cwe_categories=["CWE-79"],
                conditional=False,
                verified=True,
                removes=["sql"],
                sets_state="html-encoded",
                effective=False,
            ),
        ],
        guards=[],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=[],
        inferred=None,
        active_label="sql",
    )


@pytest.fixture
def flow_with_ineffective_sanitizer_state_changed():
    """Sanitizer invalidated by a later transformer that changed state."""
    return TaintFlow(
        path=[
            FlowStep(variable="user_input", line=5, expression='request.args.get("q")', kind="source"),
            FlowStep(variable="safe", line=7, expression="html.escape(user_input)", kind="assignment"),
            FlowStep(variable="raw", line=9, expression="base64.b64decode(safe)", kind="assignment"),
            FlowStep(variable="raw", line=12, expression="response.write(raw)", kind="sink"),
        ],
        sanitizers=[
            SanitizerInfo(
                name="html.escape",
                line=7,
                cwe_categories=["CWE-79"],
                conditional=False,
                verified=True,
                sets_state="html-encoded",
                effective=False,
                invalidated_by="raw-bytes",
                discovery_order=1,
            ),
        ],
        guards=[],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=[],
        inferred=None,
        active_label="html-encoded",
        transformers=[
            TransformerInfo(name="base64.b64decode", line=9, sets_state="raw-bytes", discovery_order=2),
        ],
        final_state="raw-bytes",
    )


@pytest.fixture
def flow_with_transformers():
    """Flow with transformers producing a state chain."""
    return TaintFlow(
        path=[
            FlowStep(variable="data", line=1, expression="request.data", kind="source"),
            FlowStep(variable="encoded", line=3, expression="base64.b64encode(data)", kind="assignment"),
            FlowStep(variable="encoded", line=5, expression="send(encoded)", kind="sink"),
        ],
        sanitizers=[],
        guards=[],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=[],
        inferred=None,
        active_label="safe-encoding",
        transformers=[
            TransformerInfo(name="base64.b64encode", line=3, sets_state="base64", discovery_order=1),
        ],
        final_state="base64",
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

    def test_effective_sanitizer_display(self, flow_with_effective_sanitizer):
        output = format_text(flow_with_effective_sanitizer, file_path="app.py")
        assert "html.escape (effective, state: html-encoded)" in output

    def test_ineffective_sanitizer_wrong_label(self, flow_with_ineffective_sanitizer_wrong_label):
        output = format_text(flow_with_ineffective_sanitizer_wrong_label, file_path="app.py")
        assert "INEFFECTIVE" in output
        assert "does not address 'sql' sinks" in output

    def test_ineffective_sanitizer_state_changed(self, flow_with_ineffective_sanitizer_state_changed):
        output = format_text(flow_with_ineffective_sanitizer_state_changed, file_path="app.py")
        assert "INEFFECTIVE" in output
        assert "state changed to 'raw-bytes'" in output

    def test_flow_state_chain(self, flow_with_ineffective_sanitizer_state_changed):
        output = format_text(flow_with_ineffective_sanitizer_state_changed, file_path="app.py")
        assert "Flow state:" in output
        assert "raw" in output
        assert "html-encoded" in output
        assert "raw-bytes" in output
        assert "sink expects: html-encoded" in output

    def test_flow_state_chain_with_transformers(self, flow_with_transformers):
        output = format_text(flow_with_transformers, file_path="app.py")
        assert "Flow state:" in output
        assert "base64" in output
        assert "sink expects: safe-encoding" in output

    def test_no_state_chain_without_label(self, sample_flow):
        output = format_text(sample_flow, file_path="app.py")
        assert "Flow state:" not in output


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

    def test_new_fields_present(self, flow_with_effective_sanitizer):
        output = format_json(flow_with_effective_sanitizer, file_path="app.py")
        data = json.loads(output)
        flow_data = data["flows"][0]
        assert flow_data["active_label"] == "html-encoded"
        assert flow_data["final_state"] == "html-encoded"
        assert isinstance(flow_data["transformers"], list)

    def test_sanitizer_fields_in_json(self, flow_with_effective_sanitizer):
        output = format_json(flow_with_effective_sanitizer, file_path="app.py")
        data = json.loads(output)
        san = data["flows"][0]["sanitizers"][0]
        assert san["effective"] is True
        assert san["sets_state"] == "html-encoded"
        assert san["invalidated_by"] is None

    def test_transformer_in_json(self, flow_with_ineffective_sanitizer_state_changed):
        output = format_json(flow_with_ineffective_sanitizer_state_changed, file_path="app.py")
        data = json.loads(output)
        flow_data = data["flows"][0]
        assert len(flow_data["transformers"]) == 1
        assert flow_data["transformers"][0]["name"] == "base64.b64decode"
        assert flow_data["transformers"][0]["sets_state"] == "raw-bytes"


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

    def test_sarif_properties_with_label(self, flow_with_effective_sanitizer):
        output = format_sarif([flow_with_effective_sanitizer], file_path="app.py")
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        assert "properties" in result
        assert result["properties"]["active_label"] == "html-encoded"
        assert result["properties"]["final_state"] == "html-encoded"

    def test_sarif_no_properties_without_label(self, sample_flow):
        output = format_sarif([sample_flow], file_path="app.py")
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        assert "properties" not in result

    def test_sarif_sanitizer_effectiveness(self, flow_with_effective_sanitizer):
        output = format_sarif([flow_with_effective_sanitizer], file_path="app.py")
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        related = result["relatedLocations"]
        assert len(related) == 1
        assert "effective" in related[0]["message"]["text"]

    def test_sarif_ineffective_sanitizer(self, flow_with_ineffective_sanitizer_state_changed):
        output = format_sarif([flow_with_ineffective_sanitizer_state_changed], file_path="app.py")
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        related = result["relatedLocations"]
        assert "INEFFECTIVE" in related[0]["message"]["text"]

    def test_sarif_transformers_in_properties(self, flow_with_ineffective_sanitizer_state_changed):
        output = format_sarif([flow_with_ineffective_sanitizer_state_changed], file_path="app.py")
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        assert "properties" in result
        assert len(result["properties"]["transformers"]) == 1
        assert result["properties"]["transformers"][0]["name"] == "base64.b64decode"
