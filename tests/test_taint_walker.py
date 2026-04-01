"""Tests for taint_engine.walker — AST body walking with branch/loop handling."""

import os

import tree_sitter_javascript as ts_javascript
import tree_sitter_python as ts_python
from tree_sitter import Language, Parser as TSParser

from taint_engine.walker import walk_body, WalkState, Definition
from taint_engine.models import AccessPath
from taint_engine.rules import load_rules
from tests.parser_helpers import JS_GRAMMAR, PYTHON_GRAMMAR

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "taint_engine", "rules")


def _parse_python(code: str):
    """Parse Python code, return function_definition node."""
    parser = TSParser(Language(ts_python.language()))
    tree = parser.parse(code.encode())
    for child in tree.root_node.children:
        if child.type == "function_definition":
            return child
    raise ValueError("No function found in code")


def _parse_js(code: str):
    """Parse JavaScript code, return function_declaration node."""
    parser = TSParser(Language(ts_javascript.language()))
    tree = parser.parse(code.encode())
    for child in tree.root_node.children:
        if child.type == "function_declaration":
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
        assert AccessPath.from_identifier("x") in d.deps, f"owner def should depend on x, got deps={d.deps}"


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
    any_dep_on_entries = any(AccessPath.from_identifier("entries") in d.deps for d in entry_defs)
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


# ---------------------------------------------------------------------------
# try/except and with statement tests
# ---------------------------------------------------------------------------


def test_try_except_handler_assignment():
    """Variable assigned in except handler has a reaching definition."""
    code = (
        "def f(x):\n"
        "    try:\n"
        "        y = x\n"
        "    except:\n"
        "        y = 'fallback'\n"
        "    z = y\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    y_defs = state.active.reaching("y")
    assert len(y_defs) == 2, (
        f"y should have 2 reaching defs (try body + except), got {len(y_defs)}"
    )
    z_defs = state.active.reaching("z")
    assert len(z_defs) == 1, "z should have a reaching def"


def test_try_except_as_binding():
    """except Exception as e: creates a definition for e."""
    code = (
        "def f(x):\n"
        "    try:\n"
        "        y = x\n"
        "    except Exception as e:\n"
        "        z = e\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    e_defs = state.active.reaching("e")
    assert len(e_defs) >= 1, "e should have a reaching def from except-as binding"
    z_defs = state.active.reaching("z")
    assert len(z_defs) >= 1, "z should have a reaching def from except handler body"
    any_dep_on_e = any(AccessPath.from_identifier("e") in d.deps for d in z_defs)
    assert any_dep_on_e, f"z should depend on e, got {[d.deps for d in z_defs]}"


def test_try_finally_definitions_active():
    """Definitions in finally block are active after the try statement."""
    code = (
        "def f(x):\n"
        "    try:\n"
        "        y = x\n"
        "    finally:\n"
        "        cleanup = 'done'\n"
        "    z = cleanup\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    cleanup_defs = state.active.reaching("cleanup")
    assert len(cleanup_defs) >= 1, (
        "cleanup should have a reaching def from finally block"
    )
    z_defs = state.active.reaching("z")
    assert len(z_defs) >= 1, "z should have a reaching def after try/finally"


def test_with_as_binding():
    """with open(path) as fh: creates a definition for fh; body is walked."""
    code = (
        "def f(path):\n"
        "    with open(path) as fh:\n"
        "        data = fh\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("path", _param_def("path"))
    walk_body(func, grammar, state)

    fh_defs = state.active.reaching("fh")
    assert len(fh_defs) >= 1, "fh should have a reaching def from with-as binding"
    data_defs = state.active.reaching("data")
    assert len(data_defs) >= 1, "data should have a reaching def from with body"
    any_dep_on_fh = any(AccessPath.from_identifier("fh") in d.deps for d in data_defs)
    assert any_dep_on_fh, (
        f"data should depend on fh, got {[d.deps for d in data_defs]}"
    )


# ---------------------------------------------------------------------------
# Assignment pattern tests (augmented, walrus, subscript, *args)
# ---------------------------------------------------------------------------


def test_augmented_assignment():
    """x = a; x += b → x should depend on both a and b."""
    code = "def f(a, b):\n    x = a\n    x += b\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("a", _param_def("a"))
    state.active.define("b", _param_def("b"))
    walk_body(func, grammar, state)

    x_defs = state.active.reaching("x")
    assert len(x_defs) == 1, (
        f"x should have 1 reaching def after augmented assignment, got {len(x_defs)}"
    )
    defn = next(iter(x_defs))
    assert AccessPath.from_identifier("a") in defn.deps, (
        f"x += b should carry forward dependency on a, got deps={defn.deps}"
    )
    assert AccessPath.from_identifier("b") in defn.deps, (
        f"x += b should depend on b, got deps={defn.deps}"
    )


def test_walrus_operator():
    """if (data := input()): → data should have a reaching definition."""
    code = "def f():\n    if (data := input()):\n        y = data\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    walk_body(func, grammar, state)

    data_defs = state.active.reaching("data")
    assert len(data_defs) >= 1, (
        "data should have a reaching def from walrus operator"
    )
    y_defs = state.active.reaching("y")
    assert len(y_defs) >= 1, "y should have a reaching def from branch body"
    any_dep_on_data = any(AccessPath.from_identifier("data") in d.deps for d in y_defs)
    assert any_dep_on_data, (
        f"y should depend on data, got {[d.deps for d in y_defs]}"
    )


def test_subscript_assignment():
    """d = {}; d["k"] = val → d should depend on val (merged, not killed)."""
    code = 'def f(val):\n    d = {}\n    d["k"] = val\n'
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("val", _param_def("val"))
    walk_body(func, grammar, state)

    d_defs = state.active.reaching("d")
    assert len(d_defs) >= 2, (
        f"d should have defs from both init and subscript assign, got {len(d_defs)}"
    )
    any_dep_on_val = any(AccessPath.from_identifier("val") in d.deps for d in d_defs)
    assert any_dep_on_val, (
        f"d should depend on val, got {[d.deps for d in d_defs]}"
    )


def test_star_args_parameter():
    """def f(*args): → args should be extracted as a parameter."""
    code = "def f(*args):\n    x = args[0]\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    from taint_engine.engine import _extract_parameters

    params = _extract_parameters(func, grammar)
    assert "args" in params, f"args should be extracted as parameter, got {params}"


def test_kwargs_parameter():
    """def f(**kwargs): → kwargs should be extracted as a parameter."""
    code = "def f(**kwargs):\n    x = kwargs['key']\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    from taint_engine.engine import _extract_parameters

    params = _extract_parameters(func, grammar)
    assert "kwargs" in params, (
        f"kwargs should be extracted as parameter, got {params}"
    )


# ---------------------------------------------------------------------------
# Control flow: switch/match, C-style for, branch termination
# ---------------------------------------------------------------------------


def test_js_switch_case_reaching_defs():
    """JS switch: variable assigned in case branches has reaching definitions."""
    code = (
        "function f(x) {\n"
        "  switch (x) {\n"
        "    case 'a':\n"
        "      y = 'alpha';\n"
        "      break;\n"
        "    case 'b':\n"
        "      y = 'beta';\n"
        "      break;\n"
        "    default:\n"
        "      y = 'other';\n"
        "  }\n"
        "}\n"
    )
    func = _parse_js(code)
    grammar = JS_GRAMMAR
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".js", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    y_defs = state.active.reaching("y")
    assert len(y_defs) >= 3, (
        f"y should have reaching defs from all 3 switch branches, got {len(y_defs)}"
    )


def test_python_match_reaching_defs():
    """Python match: variable assigned in case arms has reaching definitions."""
    code = (
        "def f(x):\n"
        "    match x:\n"
        "        case 'a':\n"
        "            y = 'alpha'\n"
        "        case 'b':\n"
        "            y = 'beta'\n"
        "    z = y\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()

    # Guard: skip if tree-sitter-python doesn't parse match_statement
    from taint_engine.ast_helpers import walk_tree

    has_match = any(n.type == "match_statement" for n in walk_tree(func))
    if not has_match:
        return

    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    y_defs = state.active.reaching("y")
    assert len(y_defs) >= 2, (
        f"y should have reaching defs from match arms, got {len(y_defs)}"
    )


def test_js_cstyle_for_initializer():
    """C-style for: for (let i = 0; ...) → i has definition from initializer."""
    code = (
        "function f(n) {\n"
        "  for (let i = 0; i < n; i++) {\n"
        "    var x = i;\n"
        "  }\n"
        "}\n"
    )
    func = _parse_js(code)
    grammar = JS_GRAMMAR
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".js", grammar=grammar)
    state.active.define("n", _param_def("n"))
    walk_body(func, grammar, state)

    i_defs = state.active.reaching("i")
    assert len(i_defs) >= 1, (
        f"i should have a reaching def from for-loop initializer, got {len(i_defs)}"
    )
    x_defs = state.active.reaching("x")
    assert len(x_defs) >= 1, (
        f"x should have a reaching def from loop body, got {len(x_defs)}"
    )
    any_dep_on_i = any(AccessPath.from_identifier("i") in d.deps for d in x_defs)
    assert any_dep_on_i, (
        f"x should depend on i, got {[d.deps for d in x_defs]}"
    )


def test_collect_identifiers_skips_callee():
    """collect_identifiers on len(x) returns {x}, not {len, x}."""
    code = "def f(x):\n    y = len(x)\n"
    func = _parse_python(code)
    from taint_engine.ast_helpers import collect_identifiers, walk_tree

    for n in walk_tree(func):
        if n.type == "assignment":
            right = n.child_by_field_name("right")
            if right:
                ids = collect_identifiers(right)
                assert "x" in ids, f"x should be in identifiers, got {ids}"
                assert "len" not in ids, (
                    f"callee 'len' should be skipped, got {ids}"
                )
                return
    assert False, "No assignment found in code"


def test_collect_identifiers_skips_method_name():
    """collect_identifiers on html.escape(x) skips method name 'escape'."""
    code = "def f(x):\n    y = html.escape(x)\n"
    func = _parse_python(code)
    from taint_engine.ast_helpers import collect_identifiers, walk_tree

    for n in walk_tree(func):
        if n.type == "assignment":
            right = n.child_by_field_name("right")
            if right:
                ids = collect_identifiers(right)
                assert "x" in ids, f"x should be in identifiers, got {ids}"
                assert "escape" not in ids, (
                    f"method name 'escape' should be skipped, got {ids}"
                )
                return
    assert False, "No assignment found in code"


def test_sanitizer_suffix_no_false_match():
    """custom_module.escape() does NOT match html.escape sanitizer."""
    code = "def f(x):\n    y = custom_module.escape(x)\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    sanitizer_names = {s.name for s in state.sanitizers}
    assert "custom_module.escape" not in sanitizer_names, (
        f"custom_module.escape should not match html.escape, "
        f"got sanitizers={sanitizer_names}"
    )


def test_branch_termination_return():
    """Branch ending in return doesn't merge its defs into the parent state."""
    code = (
        "def f(x, flag):\n"
        "    y = 'default'\n"
        "    if flag:\n"
        "        y = 'overridden'\n"
        "        return\n"
        "    z = y\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    state.active.define("flag", _param_def("flag"))
    walk_body(func, grammar, state)

    y_defs = state.active.reaching("y")
    assert len(y_defs) == 1, (
        f"y should have 1 reaching def (terminating branch excluded), got {len(y_defs)}"
    )
    defn = next(iter(y_defs))
    assert "default" in defn.expression, (
        f"y should be 'default' (not from terminated branch), got {defn.expression}"
    )
