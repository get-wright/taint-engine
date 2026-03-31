"""Tests for taint_engine.walker — AST body walking with branch/loop handling."""

import os

import tree_sitter_python as ts_python
from tree_sitter import Language, Parser as TSParser

from taint_engine.walker import walk_body, WalkState, Definition
from taint_engine.models import AccessPath
from taint_engine.rules import load_rules
from tests.parser_helpers import PYTHON_GRAMMAR

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "taint_engine", "rules")


def _parse_python(code: str):
    """Parse Python code, return function_definition node."""
    parser = TSParser(Language(ts_python.language()))
    tree = parser.parse(code.encode())
    for child in tree.root_node.children:
        if child.type == "function_definition":
            return child
    raise ValueError("No function found in code")


def _make_grammar():
    """Return a grammar config for Python."""
    return PYTHON_GRAMMAR


def _param_def(name: str) -> Definition:
    """Create a parameter definition for testing."""
    return Definition(
        variable=AccessPath(name, ()),
        line=0,
        expression=f"parameter: {name}",
        node=None,
        deps=frozenset(),
        branch_context="",
    )


def test_walk_straight_line():
    code = "def f(x):\n    y = x\n    z = y\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    # z should have exactly one reaching def
    z_defs = state.active.reaching("z")
    assert len(z_defs) == 1


def test_walk_branch_merge():
    code = (
        "def f(x, flag):\n"
        "    if flag:\n"
        "        y = x\n"
        "    else:\n"
        "        y = 'safe'\n"
        "    z = y\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    state.active.define("flag", _param_def("flag"))
    walk_body(func, grammar, state)

    # y should have 2 reaching defs (one from each branch)
    y_defs = state.active.reaching("y")
    assert len(y_defs) == 2


def test_walk_kill_semantics():
    code = "def f(x):\n    y = x\n    y = 'safe'\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    # y should have exactly 1 def (the safe one killed the tainted one)
    y_defs = state.active.reaching("y")
    assert len(y_defs) == 1
    defn = next(iter(y_defs))
    assert "safe" in defn.expression


def test_walk_records_sanitizer():
    code = "def f(x):\n    y = escape(x)\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    assert len(state.sanitizers) >= 1
    assert state.sanitizers[0].name == "escape"


def test_walk_records_guard():
    code = "def f(x):\n    if re.match(r'^ok', x):\n        y = x\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    assert len(state.guards) >= 1
    assert state.guards[0].name == "re.match"


def test_walk_loop():
    code = (
        "def f(x):\n    y = ''\n    for i in range(10):\n        y = y + x\n    z = y\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    # y should have defs from both the pre-loop init and the loop body
    y_defs = state.active.reaching("y")
    assert len(y_defs) >= 2


def test_walk_tuple_unpacking():
    """owner, repo = expr1, expr2 — both owner and repo should get defs."""
    code = "def f(x):\n    owner, repo = x.split('/')[0], x.split('/')[1]\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    owner_defs = state.active.reaching("owner")
    repo_defs = state.active.reaching("repo")
    assert len(owner_defs) >= 1, "owner should have a reaching def from tuple unpacking"
    assert len(repo_defs) >= 1, "repo should have a reaching def from tuple unpacking"
    # Both should depend on x
    for d in owner_defs:
        assert "x" in d.deps, f"owner def should depend on x, got deps={d.deps}"


def test_walk_for_loop_variable():
    """for entry in entries: — entry should get a def from the iterable."""
    code = "def f(entries):\n    for entry in entries:\n        y = entry\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("entries", _param_def("entries"))
    walk_body(func, grammar, state)

    entry_defs = state.active.reaching("entry")
    assert len(entry_defs) >= 1, (
        "entry should have a reaching def from for-loop binding"
    )
    # entry should depend on entries
    any_dep_on_entries = any("entries" in d.deps for d in entry_defs)
    assert any_dep_on_entries, (
        f"entry should depend on entries, got {[d.deps for d in entry_defs]}"
    )


def test_sanitizer_branch_isolation():
    """Sanitizer in one branch doesn't leak to the other branch's flow."""
    code = (
        "def f(x, flag):\n"
        "    if flag:\n"
        "        y = html.escape(x)\n"
        "    else:\n"
        "        y = shlex.quote(x)\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    state.active.define("flag", _param_def("flag"))
    walk_body(func, grammar, state)

    names = {s.name for s in state.sanitizers}
    assert "html.escape" in names
    assert "shlex.quote" in names
    assert len(state.sanitizers) == 2
    for san in state.sanitizers:
        assert san.conditional, f"{san.name} should be conditional"


def test_transformer_detection():
    """base64.b64decode(x) on RHS records a TransformerInfo."""
    code = "def f(x):\n    y = base64.b64decode(x)\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    assert len(state.transformers) >= 1
    t = state.transformers[0]
    assert t.name == "base64.b64decode"
    assert t.sets_state == "raw-bytes"
    assert t.line == 2


def test_transformer_suffix_matching():
    """Bare b64decode matches rule base64.b64decode via suffix indexing."""
    code = "def f(x):\n    y = b64decode(x)\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    assert len(state.transformers) >= 1
    t = state.transformers[0]
    assert t.name == "base64.b64decode"
    assert t.sets_state == "raw-bytes"


def test_walk_state_transformers_populated():
    """WalkState.transformers list is populated with multiple transformers."""
    code = (
        "def f(x):\n"
        "    y = base64.b64decode(x)\n"
        "    z = json.loads(y)\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    assert len(state.transformers) == 2
    names = [t.name for t in state.transformers]
    assert "base64.b64decode" in names
    assert "json.loads" in names


def test_discovery_order_incremental():
    """discovery_order is assigned incrementally across sanitizers and transformers."""
    code = (
        "def f(x):\n"
        "    y = html.escape(x)\n"
        "    z = base64.b64decode(y)\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    assert len(state.sanitizers) >= 1
    assert len(state.transformers) >= 1
    san_order = state.sanitizers[0].discovery_order
    txf_order = state.transformers[0].discovery_order
    assert san_order < txf_order, (
        f"sanitizer order ({san_order}) should precede transformer order ({txf_order})"
    )
