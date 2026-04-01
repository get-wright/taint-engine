"""Tests for taint_engine.engine — reaching-definitions-based taint tracing."""

import os
from taint_engine.engine import _find_function_node, _find_vars_at_line, trace_taint_flow
from taint_engine.rules import load_rules
from tests.parser_helpers import TreeSitterParser

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "taint_engine", "rules")

PARSER = TreeSitterParser()
RULES = load_rules(RULES_DIR)


# --- Straight-line tracing ---


def test_straight_line_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="straight_line",
        sink_line=8,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 2
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"


def test_straight_line_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.js"),
        function_name="straightLine",
        sink_line=4,
        check_id="javascript.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.variable == "userInput"


# --- Kill semantics ---


def test_kill_semantics_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="kill_semantics",
        sink_line=14,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is None  # taint killed by reassignment to hardcoded value


def test_kill_semantics_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.js"),
        function_name="killSemantics",
        sink_line=10,
        check_id="javascript.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is None  # taint killed by reassignment to hardcoded value


# --- Branch merging ---


def test_branch_merge_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="branch_merge",
        sink_line=22,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


def test_branch_no_else_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="branch_no_else",
        sink_line=29,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


# --- Unknown call propagation ---


def test_unknown_call_propagation_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="unknown_call_propagation",
        sink_line=42,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")
    assert len(flow.unresolved_calls) >= 1


# --- Guard detection ---


def test_guard_detected():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_guards.py"),
        function_name="guarded_sink",
        sink_line=8,
        check_id="python.ssrf",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.guards) >= 1
    assert flow.guards[0].name == "re.match"
    assert flow.guards[0].variable == "url"


def test_no_guard_when_unguarded():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_guards.py"),
        function_name="unguarded_sink",
        sink_line=20,
        check_id="python.ssrf",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.guards == []


# --- String propagation ---


def test_fstring_propagation():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_string_ops.py"),
        function_name="fstring_propagation",
        sink_line=7,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


def test_concat_propagation():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_string_ops.py"),
        function_name="concat_propagation",
        sink_line=13,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


def test_template_literal_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_string_ops.js"),
        function_name="templateLiteralPropagation",
        sink_line=4,
        check_id="javascript.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.variable == "userInput"


def test_sink_var_selection_ignores_promise_callback_identifiers():
    file_path = os.path.join(FIXTURES, "taint_sink_selection.js")
    root = PARSER.parse_file(file_path)
    grammar = PARSER.get_grammar(".js")
    assert grammar is not None

    func_node = _find_function_node(root, "chainedPromiseSql", grammar)
    assert func_node is not None

    sink_vars = _find_vars_at_line(func_node, 2, grammar, RULES, ".js")
    sink_names = {name for name, _, _ in sink_vars}
    sink_ids = {sink_id for _, _, sink_id in sink_vars}

    assert "error" not in sink_names
    assert "authenticatedUser" not in sink_names
    assert sink_ids == {"models.sequelize.query"}


def test_sink_var_selection_ignores_nested_call_callees():
    file_path = os.path.join(FIXTURES, "taint_sink_selection.js")
    root = PARSER.parse_file(file_path)
    grammar = PARSER.get_grammar(".js")
    assert grammar is not None

    func_node = _find_function_node(root, "nestedResolvedFile", grammar)
    assert func_node is not None

    sink_vars = _find_vars_at_line(func_node, 12, grammar, RULES, ".js")
    sink_names = {name for name, _, _ in sink_vars}

    assert "path.resolve" not in sink_names
    assert "file" in sink_names


# --- Access path tracking ---


def test_field_taint_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_access_paths.py"),
        function_name="field_taint",
        sink_line=8,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


def test_field_safe_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_access_paths.py"),
        function_name="field_safe",
        sink_line=15,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is None  # taint killed — sink reads from hardcoded field


# --- Format string propagation ---


def test_format_propagation():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_string_ops.py"),
        function_name="format_propagation",
        sink_line=19,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


# --- Guard with early return ---


def test_guard_with_return():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_guards.py"),
        function_name="guard_with_return",
        sink_line=15,
        check_id="python.ssrf",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.guards) >= 1


# --- Loop taint ---


def test_loop_taint_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="loop_taint",
        sink_line=36,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


# --- Tuple unpacking, destructuring, loop variable binding ---


def test_tuple_unpacking_python():
    """owner, repo = url.split(...) — both variables should trace back to param."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="tuple_unpacking",
        sink_line=59,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 3, (
        f"Expected >=3 steps (param->assignment->sink), got {len(flow.path)}"
    )
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"


def test_for_loop_variable_python():
    """for entry in entries: — entry should trace back to entries param."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="for_loop_variable",
        sink_line=65,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 3, (
        f"Expected >=3 steps (param->loop_var->sink), got {len(flow.path)}"
    )
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"


def test_destructuring_object_js():
    """const { name } = req.body — name should trace back to req.body source."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.js"),
        function_name="destructuringObject",
        sink_line=47,
        check_id="javascript.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 2, f"Expected >=2 steps, got {len(flow.path)}"
    assert flow.source.kind == "source", f"Expected source kind, got {flow.source.kind}"
    assert "req.body" in flow.source.expression
    assert flow.sink.kind == "sink"


def test_destructuring_array_js():
    """const [first, second] = req.query.items — first should trace back to source."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.js"),
        function_name="destructuringArray",
        sink_line=52,
        check_id="javascript.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 2, f"Expected >=2 steps, got {len(flow.path)}"
    assert flow.source.kind == "source", f"Expected source kind, got {flow.source.kind}"
    assert "req.query" in flow.source.expression
    assert flow.sink.kind == "sink"


def test_for_of_loop_js():
    """for (const item of items) — item should trace back to items param."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.js"),
        function_name="forOfLoop",
        sink_line=58,
        check_id="javascript.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 3, f"Expected >=3 steps, got {len(flow.path)}"
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"


# --- Parity tests: engine covers flow_tracker scenarios ---


def test_existing_fixture_direct_sqli():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="vulnerable_sqli",
        sink_line=8,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 2
    assert flow.source.variable == "user_input"


def test_existing_fixture_sanitized():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="sanitized_xss",
        sink_line=12,
        check_id="python.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.sanitizers) >= 1
    assert flow.sanitizers[0].name == "escape"


def test_existing_fixture_multiline():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="multiline_call",
        sink_line=39,
        check_id="python.ssrf",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 2


def test_existing_fixture_js_innerhtml():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="innerHtmlSink",
        sink_line=24,
        check_id="javascript.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind == "parameter"


# --- Source detection false positives ---


def test_source_false_positive_string():
    """String literal mentioning 'request.args' is NOT a real source."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_edge_cases.py"),
        function_name="source_false_positive_string",
        sink_line=7,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    # No taint flow — string literal is not a source, nothing traces back
    assert flow is None or flow.source.kind != "source"


def test_source_false_positive_validate_input():
    """validate_input() does NOT match source input()."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_edge_cases.py"),
        function_name="source_false_positive_validate",
        sink_line=12,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    # No taint flow — validate_input() is not a source
    assert flow is None or flow.source.kind != "source"


# --- Keyword arg filtering ---


def test_keyword_arg_not_in_sink_vars():
    """requests.get(url, timeout=5) — keyword arg name 'timeout' is not a sink var."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_edge_cases.py"),
        function_name="keyword_arg_filtering",
        sink_line=17,
        check_id="python.ssrf",
        rules=RULES,
        parser=PARSER,
    )
    # No taint flow when only keyword arg names (not values) reach the sink
    assert flow is None or flow.source.variable != "timeout"


# --- Label detection and state checking ---


def test_wrong_sanitizer_for_context():
    """html.escape before SQL sink → sanitizer marked effective=False."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="wrong_sanitizer_for_context",
        sink_line=10,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label == "sql"
    assert len(flow.sanitizers) >= 1
    san = flow.sanitizers[0]
    assert san.name == "html.escape"
    assert san.effective is False, (
        f"html.escape should be ineffective for SQL sink, got effective={san.effective}"
    )


def test_sanitization_invalidated_by_transformer():
    """html.escape then base64.b64decode before HTML sink → effective=False, invalidated_by set."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="sanitization_invalidated",
        sink_line=16,
        check_id="python.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label == "html"
    assert len(flow.sanitizers) >= 1
    san = flow.sanitizers[0]
    assert san.name == "html.escape"
    assert san.effective is False, (
        f"html.escape should be invalidated by b64decode, got effective={san.effective}"
    )
    assert san.invalidated_by is not None
    assert "base64.b64decode" in san.invalidated_by


def test_correct_sanitization_effective():
    """html.escape before HTML sink → sanitizer marked effective=True."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="correct_sanitization",
        sink_line=21,
        check_id="python.xss",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label == "html"
    assert len(flow.sanitizers) >= 1
    san = flow.sanitizers[0]
    assert san.name == "html.escape"
    assert san.effective is True, (
        f"html.escape should be effective for HTML sink, got effective={san.effective}"
    )


def test_no_label_all_sanitizers_count():
    """Unknown sink → no label detected, all sanitizers stay effective."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="unknown_sink_all_sanitizers",
        sink_line=26,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label is None
    assert len(flow.sanitizers) >= 1
    for san in flow.sanitizers:
        assert san.effective is True, (
            f"All sanitizers should be effective when no label, "
            f"got {san.name} effective={san.effective}"
        )


def test_label_detection_sql():
    """cursor.execute → label 'sql'."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="label_detection_sql",
        sink_line=30,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label == "sql"


def test_label_detection_ssrf():
    """requests.get → label 'ssrf'."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="label_detection_ssrf",
        sink_line=34,
        check_id="python.ssrf",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label == "ssrf"


# --- Control-flow edge cases with labels ---


def test_try_except_flow():
    """Taint traces through except handler to cursor.execute sink."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="try_except_flow",
        sink_line=41,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label == "sql"
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"


def test_with_statement_flow():
    """Taint propagates through with-statement binding to cursor.execute."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="with_statement_flow",
        sink_line=47,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label == "sql"
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"


def test_augmented_assignment_flow():
    """x += b propagates taint from both a and b to cursor.execute."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_labels_sample.py"),
        function_name="augmented_assignment_flow",
        sink_line=53,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.active_label == "sql"
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"
    assert len(flow.path) >= 3, (
        f"Expected >=3 steps (param->assignment->sink), got {len(flow.path)}"
    )


# --- Source recovery ---


def test_accessor_source_recovery():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_source_recovery.py"),
        function_name="accessor_source",
        sink_line=6,
        check_id="python.redirect",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("source", "parameter")
    assert "request" in flow.source.variable or "request" in flow.source.expression


def test_member_read_source_recovery():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_source_recovery.py"),
        function_name="member_read_source",
        sink_line=11,
        check_id="python.redirect",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("source", "parameter")


def test_alias_chain_recovery():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_source_recovery.py"),
        function_name="alias_chain",
        sink_line=25,
        check_id="python.sqli",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("source", "parameter")
    assert not any("hardcoded" in f.lower() for f in flow.confidence_factors)


def test_destructured_redirect_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_source_recovery.js"),
        function_name="destructuredRedirect",
        sink_line=6,
        check_id="javascript.redirect",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("source", "parameter")


def test_destructured_file_serve_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_source_recovery.js"),
        function_name="destructuredFileServe",
        sink_line=12,
        check_id="javascript.path",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("source", "parameter")


def test_direct_member_sink_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_source_recovery.js"),
        function_name="directMemberSink",
        sink_line=16,
        check_id="javascript.redirect",
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("source", "parameter")
