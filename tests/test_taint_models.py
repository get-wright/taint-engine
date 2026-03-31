"""Tests for src/taint/models — taint data models."""

from taint_engine.models import (
    FlowStep,
    SanitizerInfo,
    TaintFlow,
    InferredSinkSource,
    CrossFileHop,
    GuardInfo,
    AccessPath,
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
