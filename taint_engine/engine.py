"""Reaching-definitions taint engine.

Top-level ``trace_taint_flow()`` parses a file, finds the target function,
walks its body to build reaching definitions via the walker, then traces
backwards from sink variables to sources.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from .models import (
    AccessPath,
    FlowStep,
    GuardInfo,
    SanitizerInfo,
    TaintFlow,
    InferredSinkSource,
)
from .rules import TaintRuleSet
from .ast_helpers import (
    collect_identifiers,
    find_calls_in,
    get_callee_name,
    get_full_callee,
    get_member_object,
    get_member_property,
    walk_tree,
)
from .walker import (
    ActiveDefs,
    Definition,
    WalkState,
    walk_body,
)
from .sink_source_inference import infer_sink_source

logger = logging.getLogger(__name__)


def trace_taint_flow(
    *,
    file_path: str,
    function_name: str,
    sink_line: int,
    check_id: str,
    cwe_list: list[str],
    rules: TaintRuleSet,
    parser: object,
) -> Optional[TaintFlow]:
    """Trace taint from sink back to source within a single function.

    Returns None if the language doesn't support taint tracing or
    the function can't be found.
    """
    ext = Path(file_path).suffix.lower()
    grammar = parser.get_grammar(ext)
    if grammar is None or not grammar.assignment_types:
        return None

    root = parser.parse_file(file_path)
    if root is None:
        return None

    func_node = _find_function_node(root, function_name, grammar)
    if func_node is None:
        return None

    # Extract parameters and initialize reaching definitions
    params = _extract_parameters(func_node, grammar)
    state = WalkState(rules=rules, ext=ext, grammar=grammar)
    for param_name in params:
        defn = Definition(
            variable=AccessPath(param_name, ()),
            line=func_node.start_point[0] + 1,
            expression=f"parameter:{param_name}",
            node=None,
            deps=frozenset(),
            branch_context="",
        )
        state.active.define(param_name, defn)

    # Walk the function body to build reaching defs
    walk_body(func_node, grammar, state)

    # Find variables at the sink line
    sink_vars = _find_vars_at_line(func_node, sink_line, grammar, rules, ext)

    if not sink_vars:
        # Couldn't identify sink variables — return minimal flow
        inferred = infer_sink_source(check_id, cwe_list, "")
        return TaintFlow(
            path=[FlowStep(variable="?", line=sink_line, expression="", kind="sink")],
            sanitizers=state.sanitizers,
            guards=state.guards,
            unresolved_calls=state.unresolved,
            confidence_factors=["Could not identify sink variables"],
            inferred=inferred,
        )

    # Trace backwards from each sink variable to find sources
    best_flow: Optional[TaintFlow] = None

    for sink_var, sink_expr in sink_vars:
        path_steps = _trace_back(
            sink_var, state.active, params, rules, ext, grammar, set()
        )

        sink_step = FlowStep(
            variable=sink_var,
            line=sink_line,
            expression=sink_expr,
            kind="sink",
        )

        if path_steps:
            # Found a taint path — pick the best one (prefer tainted over safe)
            full_path = path_steps + [sink_step]
            flow = TaintFlow(
                path=full_path,
                sanitizers=state.sanitizers,
                guards=state.guards,
                unresolved_calls=state.unresolved,
                confidence_factors=[],
                inferred=infer_sink_source(check_id, cwe_list, sink_expr),
            )
            # Prefer flows that actually found a source/parameter
            if best_flow is None or (
                flow.source.kind in ("parameter", "source")
                and best_flow.source.kind not in ("parameter", "source")
            ):
                best_flow = flow
        else:
            # No taint source found for this variable
            if best_flow is None:
                full_path = [
                    FlowStep(
                        variable=sink_var,
                        line=sink_line,
                        expression=sink_expr,
                        kind="assignment",
                    ),
                    sink_step,
                ]
                best_flow = TaintFlow(
                    path=full_path,
                    sanitizers=state.sanitizers,
                    guards=state.guards,
                    unresolved_calls=state.unresolved,
                    confidence_factors=["No external source — values appear hardcoded"],
                    inferred=infer_sink_source(check_id, cwe_list, sink_expr),
                )

    return best_flow


# ---------------------------------------------------------------------------
# Function finding
# ---------------------------------------------------------------------------


def _find_function_node(root, function_name: str, grammar) -> object | None:
    """Find a function node by name in the AST."""
    func_types = set(grammar.func_types)

    for node in walk_tree(root):
        if node.type in func_types:
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() == function_name:
                return node

    # JS arrow functions: const foo = (...) => { ... }
    if getattr(grammar, "has_arrow_functions", False):
        for node in walk_tree(root):
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if (
                    name_node
                    and name_node.text.decode() == function_name
                    and value_node
                    and value_node.type in func_types
                ):
                    return value_node

    return None


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------


def _extract_parameters(func_node, grammar) -> list[str]:
    """Extract parameter names from a function node."""
    param_types = set(grammar.parameter_types)
    params: list[str] = []

    for child in func_node.children:
        if child.type in param_types:
            for param in child.children:
                if param.type == "identifier":
                    params.append(param.text.decode())
                elif param.type in (
                    "typed_parameter",
                    "default_parameter",
                    "typed_default_parameter",
                ):
                    name_node = param.child_by_field_name("name")
                    if name_node:
                        params.append(name_node.text.decode())
                    elif param.children and param.children[0].type == "identifier":
                        params.append(param.children[0].text.decode())
                elif param.type in (
                    "list_splat_pattern",
                    "dictionary_splat_pattern",
                ):
                    for sub in param.children:
                        if sub.type == "identifier":
                            params.append(sub.text.decode())
                            break
    return params


# ---------------------------------------------------------------------------
# Sink variable identification
# ---------------------------------------------------------------------------


def _find_vars_at_line(
    func_node, sink_line: int, grammar, rules: TaintRuleSet, ext: str
) -> list[tuple[str, str]]:
    """Find variables used at the sink line.

    Returns list of (variable_name, expression_text) tuples.
    Three passes:
      1. Call arguments (range match for multi-line calls)
      2. Return statements (exact line match)
      3. Property sink assignments (e.g. el.innerHTML = x)
    """
    call_types = set(grammar.call_types)
    member_types = set(grammar.member_access_types)
    return_types = set(grammar.return_types)
    assignment_types = set(grammar.assignment_types)
    results: list[tuple[str, str]] = []
    seen: set[str] = set()

    # Pass 1: Call arguments — range match for multi-line calls.
    # Match ANY call at the sink line; Semgrep already identified this line
    # as a finding, so the call here is the sink regardless of rule config.
    for node in walk_tree(func_node):
        if node.type not in call_types:
            continue
        start_row = node.start_point[0] + 1
        end_row = node.end_point[0] + 1
        if not (start_row <= sink_line <= end_row):
            continue

        # Collect variables from arguments
        args_node = node.child_by_field_name("arguments") or node.child_by_field_name(
            "argument_list"
        )
        if args_node is None:
            # Fallback: some grammars use a different child layout
            for child in node.children:
                if child.type == "argument_list":
                    args_node = child
                    break
        if not args_node:
            continue

        expr_text = node.text.decode()
        for arg_child in walk_tree(args_node):
            if arg_child.type == "identifier":
                if (
                    arg_child.parent
                    and arg_child.parent.type == "keyword_argument"
                    and arg_child
                    == arg_child.parent.child_by_field_name("name")
                ):
                    continue
                name = arg_child.text.decode()
                if name not in seen:
                    seen.add(name)
                    results.append((name, expr_text))
            elif arg_child.type in member_types:
                # Reconstruct dotted name: obj.field
                dotted = _reconstruct_dotted(arg_child)
                if dotted and dotted not in seen:
                    seen.add(dotted)
                    results.append((dotted, expr_text))

    if results:
        return results

    # Pass 2: Return statements (exact line match)
    for node in walk_tree(func_node):
        if node.type not in return_types:
            continue
        line = node.start_point[0] + 1
        if line != sink_line:
            continue

        expr_text = node.text.decode()
        for child in walk_tree(node):
            if child.type == "identifier":
                if child.parent and child.parent.type in member_types:
                    continue
                name = child.text.decode()
                if name not in seen:
                    seen.add(name)
                    results.append((name, expr_text))

    if results:
        return results

    # Pass 3: Property sink assignments (e.g. el.innerHTML = content)
    for node in walk_tree(func_node):
        if node.type not in assignment_types:
            continue

        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or not right:
            continue
        if left.type not in member_types:
            continue

        line = node.start_point[0] + 1
        if line != sink_line:
            continue

        prop_name = get_member_property(left)
        if rules.is_property_sink(ext, prop_name):
            expr_text = node.text.decode()
            for child in walk_tree(right):
                if child.type == "identifier":
                    name = child.text.decode()
                    if name not in seen:
                        seen.add(name)
                        results.append((name, expr_text))

    # Pass 3b: Also check expression_statements wrapping property assignments
    if not results:
        for node in walk_tree(func_node):
            if node.type != "expression_statement":
                continue
            line = node.start_point[0] + 1
            if line != sink_line:
                continue
            for child in node.children:
                if child.type in assignment_types:
                    left = child.child_by_field_name("left")
                    right = child.child_by_field_name("right")
                    if not left or not right or left.type not in member_types:
                        continue
                    prop_name = get_member_property(left)
                    if rules.is_property_sink(ext, prop_name):
                        expr_text = child.text.decode()
                        for rch in walk_tree(right):
                            if rch.type == "identifier":
                                name = rch.text.decode()
                                if name not in seen:
                                    seen.add(name)
                                    results.append((name, expr_text))

    return results


def _reconstruct_dotted(member_node) -> str:
    """Reconstruct a dotted name from a member access node (e.g. obj.field)."""
    obj = get_member_object(member_node)
    prop = get_member_property(member_node)
    if obj and prop:
        return f"{obj}.{prop}"
    return ""


# ---------------------------------------------------------------------------
# Source matching
# ---------------------------------------------------------------------------


def _is_source_in_node(source: str, node: object | None, expr: str) -> bool:
    """Check whether *source* appears structurally in *node*.

    When an AST node is available we walk it looking for actual attribute
    accesses or call expressions that match the source pattern.  This avoids
    false positives from substring matches inside string literals or
    unrelated identifiers (e.g. ``"request.args"`` inside a string, or
    ``validate_input()`` matching ``input()``).

    Falls back to word-boundary regex when no AST node is available.
    """
    is_call_source = source.endswith("()")
    source_name = source.rstrip("()")

    if node is not None:
        attr_types = {"attribute", "member_expression"}
        call_types = {"call", "call_expression"}
        for sub in walk_tree(node):
            if is_call_source:
                if sub.type in call_types:
                    callee = get_full_callee(sub)
                    if callee == source_name:
                        return True
            else:
                if "." in source_name:
                    if sub.type in attr_types:
                        if sub.text.decode() == source_name:
                            return True
                else:
                    if (
                        sub.type == "identifier"
                        and sub.text.decode() == source_name
                    ):
                        return True
        return False

    pattern = r"\b" + re.escape(source_name) + r"\b"
    return bool(re.search(pattern, expr))


# ---------------------------------------------------------------------------
# Backward tracing
# ---------------------------------------------------------------------------


def _trace_back(
    var: str,
    active: ActiveDefs,
    params: list[str],
    rules: TaintRuleSet,
    ext: str,
    grammar,
    visited: set[tuple[str, int]],
    max_depth: int = 50,
) -> Optional[list[FlowStep]]:
    """Trace backwards from a variable through reaching definitions to find a source.

    Returns a list of FlowSteps from source to the variable (not including the
    final sink step), or None if no taint source is found.
    """
    if max_depth <= 0:
        return None

    # Base case: var is a parameter
    if var in params:
        # Check if the parameter's reaching def still points to the parameter
        defs = active.reaching(var)
        for d in defs:
            if d.expression.startswith("parameter:"):
                return [
                    FlowStep(
                        variable=var,
                        line=d.line,
                        expression=d.expression,
                        kind="parameter",
                    )
                ]
        # Even if there's no explicit parameter def, if the var name is in params
        # and it has no reaching defs, treat it as a parameter source
        if not defs:
            return [
                FlowStep(
                    variable=var,
                    line=0,
                    expression=f"parameter:{var}",
                    kind="parameter",
                )
            ]

    defs = active.reaching(var)

    # Handle dotted names: if "obj.field" has no defs, try base "obj"
    if not defs and "." in var:
        base = var.split(".")[0]
        defs = active.reaching(base)

    if not defs:
        return None

    # Try each reaching definition
    for defn in sorted(defs, key=lambda d: d.line, reverse=True):
        key = (var, defn.line)
        if key in visited:
            continue
        visited.add(key)

        # Check if the expression contains a known source
        expr = defn.expression
        lang_rules = rules.for_extension(ext)
        if lang_rules:
            for source in lang_rules.sources:
                if _is_source_in_node(source, defn.node, expr):
                    return [
                        FlowStep(
                            variable=var,
                            line=defn.line,
                            expression=expr,
                            kind="source",
                        )
                    ]

        # Recurse into dependencies
        for dep in defn.deps:
            sub_path = _trace_back(
                dep,
                active,
                params,
                rules,
                ext,
                grammar,
                visited,
                max_depth=max_depth - 1,
            )
            if sub_path:
                step = FlowStep(
                    variable=var,
                    line=defn.line,
                    expression=expr,
                    kind="assignment",
                )
                return sub_path + [step]

    return None
