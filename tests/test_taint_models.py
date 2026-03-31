"""Tests for src/taint/models — taint data models."""

from taint_engine.models import (
    FlowStep,
    SanitizerInfo,
    TaintFlow,
    InferredSinkSource,
    CrossFileHop,
    GuardInfo,
    AccessPath,
    TransformerInfo,
)


def test_access_path_simple():
    ap = AccessPath(base="x", selectors=())
    assert ap.name == "x"


def test_access_path_dotted():
    ap = AccessPath(base="obj", selectors=("field",))
    assert ap.name == "obj.field"


def test_access_path_with_field():
    ap = AccessPath(base="obj", selectors=())
    extended = ap.with_field("field")
    assert extended.name == "obj.field"


def test_access_path_depth_cap():
    ap = AccessPath(base="a", selectors=("b", "c"))
    capped = ap.with_field("d")
    assert capped.name == "a.b.c"  # not extended beyond depth 2


def test_access_path_frozen():
    ap = AccessPath(base="x", selectors=())
    try:
        ap.base = "y"
        assert False, "Should raise"
    except AttributeError:
        pass


def test_guard_info():
    g = GuardInfo(name="re.match", line=10, variable="user_input")
    assert g.name == "re.match"
    assert g.line == 10
    assert g.variable == "user_input"


def test_guard_info_to_dict():
    g = GuardInfo(name="isinstance", line=5, variable="x")
    d = g.to_dict()
    assert d == {"name": "isinstance", "line": 5, "variable": "x"}


def test_guard_info_from_dict():
    d = {"name": "re.match", "line": 10, "variable": "url"}
    g = GuardInfo.from_dict(d)
    assert g.name == "re.match"
    assert g.variable == "url"


def test_flow_step_unchanged():
    s = FlowStep(variable="x", line=1, expression="x = input()", kind="source")
    assert s.to_dict() == {
        "variable": "x",
        "line": 1,
        "expression": "x = input()",
        "kind": "source",
    }


def test_sanitizer_info_unchanged():
    s = SanitizerInfo(
        name="escape",
        line=1,
        cwe_categories=["CWE-79"],
        conditional=False,
        verified=True,
    )
    d = s.to_dict()
    assert d["name"] == "escape"
    assert d["cwe_categories"] == ["CWE-79"]


def test_taint_flow_with_guards():
    flow = TaintFlow(
        path=[
            FlowStep(variable="x", line=1, expression="x = input()", kind="source"),
            FlowStep(variable="x", line=3, expression="eval(x)", kind="sink"),
        ],
        guards=[GuardInfo(name="re.match", line=2, variable="x")],
    )
    assert len(flow.guards) == 1
    assert flow.guards[0].name == "re.match"


def test_taint_flow_guards_default_empty():
    flow = TaintFlow(
        path=[FlowStep(variable="x", line=1, expression="x", kind="sink")],
    )
    assert flow.guards == []


def test_taint_flow_to_dict_includes_guards():
    flow = TaintFlow(
        path=[FlowStep(variable="x", line=1, expression="x", kind="sink")],
        guards=[GuardInfo(name="isinstance", line=5, variable="x")],
    )
    d = flow.to_dict()
    assert "guards" in d
    assert d["guards"][0]["name"] == "isinstance"


def test_taint_flow_from_dict_with_guards():
    d = {
        "path": [{"variable": "x", "line": 1, "expression": "x", "kind": "sink"}],
        "sanitizers": [],
        "unresolved_calls": [],
        "cross_file_hops": [],
        "confidence_factors": [],
        "inferred": None,
        "guards": [{"name": "re.match", "line": 2, "variable": "url"}],
    }
    flow = TaintFlow.from_dict(d)
    assert len(flow.guards) == 1
    assert flow.guards[0].name == "re.match"


def test_taint_flow_from_dict_without_guards_key():
    """Backward compat: old serialized dicts without 'guards' key."""
    d = {
        "path": [{"variable": "x", "line": 1, "expression": "x", "kind": "sink"}],
        "sanitizers": [],
        "unresolved_calls": [],
        "cross_file_hops": [],
        "confidence_factors": [],
        "inferred": None,
    }
    flow = TaintFlow.from_dict(d)
    assert flow.guards == []


def test_inferred_sink_source_unchanged():
    i = InferredSinkSource(
        sink_expression="eval(x)",
        sink_type="code_exec",
        expected_sources=["user_input"],
        inferred_from="cwe",
    )
    d = i.to_dict()
    restored = InferredSinkSource.from_dict(d)
    assert restored.sink_type == "code_exec"


def test_cross_file_hop_unchanged():
    h = CrossFileHop(callee="helper", file="utils.py", line=10, action="propagates")
    d = h.to_dict()
    assert d["callee"] == "helper"
    assert d["sub_flow"] is None


# --- TransformerInfo tests ---


def test_transformer_info_creation():
    t = TransformerInfo(name="json.loads", line=5, sets_state="deserialized")
    assert t.name == "json.loads"
    assert t.line == 5
    assert t.sets_state == "deserialized"
    assert t.discovery_order == 0


def test_transformer_info_to_dict():
    t = TransformerInfo(name="base64.decode", line=8, sets_state="decoded")
    d = t.to_dict()
    assert d == {"name": "base64.decode", "line": 8, "sets_state": "decoded"}
    assert "discovery_order" not in d


def test_transformer_info_from_dict():
    d = {"name": "json.loads", "line": 5, "sets_state": "deserialized"}
    t = TransformerInfo.from_dict(d)
    assert t.name == "json.loads"
    assert t.line == 5
    assert t.sets_state == "deserialized"
    assert t.discovery_order == 0


def test_transformer_info_roundtrip():
    original = TransformerInfo(
        name="url_decode", line=12, sets_state="url_decoded", discovery_order=3,
    )
    d = original.to_dict()
    restored = TransformerInfo.from_dict(d)
    assert restored.name == original.name
    assert restored.line == original.line
    assert restored.sets_state == original.sets_state
    assert restored.discovery_order == 0  # not serialized


def test_transformer_info_from_dict_with_discovery_order():
    d = {
        "name": "decompress",
        "line": 20,
        "sets_state": "decompressed",
        "discovery_order": 7,
    }
    t = TransformerInfo.from_dict(d)
    assert t.discovery_order == 7


# --- SanitizerInfo new fields tests ---


def test_sanitizer_info_new_field_defaults():
    s = SanitizerInfo(
        name="escape",
        line=1,
        cwe_categories=["CWE-79"],
        conditional=False,
        verified=True,
    )
    assert s.removes == ["*"]
    assert s.sets_state == "sanitized"
    assert s.discovery_order == 0
    assert s.effective is True
    assert s.invalidated_by is None


def test_sanitizer_info_new_fields_custom():
    s = SanitizerInfo(
        name="html_escape",
        line=10,
        cwe_categories=["CWE-79"],
        conditional=False,
        verified=True,
        removes=["xss"],
        sets_state="html_escaped",
        discovery_order=2,
        effective=False,
        invalidated_by="raw_output",
    )
    assert s.removes == ["xss"]
    assert s.sets_state == "html_escaped"
    assert s.discovery_order == 2
    assert s.effective is False
    assert s.invalidated_by == "raw_output"


def test_sanitizer_info_to_dict_includes_new_fields():
    s = SanitizerInfo(
        name="escape",
        line=1,
        cwe_categories=["CWE-79"],
        conditional=False,
        verified=True,
        removes=["xss"],
        sets_state="escaped",
    )
    d = s.to_dict()
    assert d["removes"] == ["xss"]
    assert d["sets_state"] == "escaped"
    assert d["discovery_order"] == 0
    assert d["effective"] is True
    assert d["invalidated_by"] is None


def test_sanitizer_info_from_dict_missing_new_keys():
    """Backward compat: old dicts without new fields get defaults."""
    d = {
        "name": "escape",
        "line": 1,
        "cwe_categories": ["CWE-79"],
        "conditional": False,
        "verified": True,
    }
    s = SanitizerInfo.from_dict(d)
    assert s.removes == ["*"]
    assert s.sets_state == "sanitized"
    assert s.discovery_order == 0
    assert s.effective is True
    assert s.invalidated_by is None


def test_sanitizer_info_from_dict_with_new_keys():
    d = {
        "name": "html_escape",
        "line": 10,
        "cwe_categories": ["CWE-79"],
        "conditional": False,
        "verified": True,
        "removes": ["xss"],
        "sets_state": "html_escaped",
        "discovery_order": 5,
        "effective": False,
        "invalidated_by": "raw_output",
    }
    s = SanitizerInfo.from_dict(d)
    assert s.removes == ["xss"]
    assert s.sets_state == "html_escaped"
    assert s.discovery_order == 5
    assert s.effective is False
    assert s.invalidated_by == "raw_output"


# --- TaintFlow new fields tests ---


def test_taint_flow_new_field_defaults():
    flow = TaintFlow(
        path=[FlowStep(variable="x", line=1, expression="x", kind="sink")],
    )
    assert flow.active_label is None
    assert flow.transformers == []
    assert flow.final_state is None


def test_taint_flow_new_fields_custom():
    flow = TaintFlow(
        path=[FlowStep(variable="x", line=1, expression="x", kind="sink")],
        active_label="tainted",
        transformers=[
            TransformerInfo(name="json.loads", line=3, sets_state="deserialized"),
        ],
        final_state="sanitized",
    )
    assert flow.active_label == "tainted"
    assert len(flow.transformers) == 1
    assert flow.transformers[0].name == "json.loads"
    assert flow.final_state == "sanitized"


def test_taint_flow_to_dict_includes_new_fields():
    flow = TaintFlow(
        path=[FlowStep(variable="x", line=1, expression="x", kind="sink")],
        active_label="tainted",
        transformers=[
            TransformerInfo(name="decode", line=2, sets_state="decoded"),
        ],
        final_state="decoded",
    )
    d = flow.to_dict()
    assert d["active_label"] == "tainted"
    assert len(d["transformers"]) == 1
    assert d["transformers"][0]["name"] == "decode"
    assert d["final_state"] == "decoded"


def test_taint_flow_from_dict_missing_new_keys():
    """Backward compat: old dicts without new fields get defaults."""
    d = {
        "path": [{"variable": "x", "line": 1, "expression": "x", "kind": "sink"}],
        "sanitizers": [],
        "unresolved_calls": [],
        "cross_file_hops": [],
        "confidence_factors": [],
        "inferred": None,
        "guards": [],
    }
    flow = TaintFlow.from_dict(d)
    assert flow.active_label is None
    assert flow.transformers == []
    assert flow.final_state is None


def test_taint_flow_from_dict_with_new_keys():
    d = {
        "path": [{"variable": "x", "line": 1, "expression": "x", "kind": "sink"}],
        "sanitizers": [],
        "unresolved_calls": [],
        "cross_file_hops": [],
        "confidence_factors": [],
        "inferred": None,
        "guards": [],
        "active_label": "user_input",
        "transformers": [
            {"name": "json.loads", "line": 3, "sets_state": "deserialized"},
        ],
        "final_state": "deserialized",
    }
    flow = TaintFlow.from_dict(d)
    assert flow.active_label == "user_input"
    assert len(flow.transformers) == 1
    assert flow.transformers[0].name == "json.loads"
    assert flow.final_state == "deserialized"


from taint_engine.parser_protocol import ASTNode, LanguageGrammar, Parser


def test_language_grammar_protocol_has_required_fields():
    """LanguageGrammar protocol defines expected fields."""
    import typing

    hints = typing.get_type_hints(LanguageGrammar)
    assert "func_types" in hints
    assert "call_types" in hints
    assert "assignment_types" in hints
    assert "parameter_types" in hints
    assert "return_types" in hints
    assert "conditional_types" in hints
    assert "member_access_types" in hints
    assert "has_arrow_functions" in hints
