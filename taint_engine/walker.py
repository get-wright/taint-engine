"""AST body walker for reaching-definitions analysis.

Walks a function body statement-by-statement, maintaining an ActiveDefs
state that tracks which definitions reach each point. Handles branches
(fork-merge), loops (two-pass approximation), and records sanitizers/guards.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field as dataclass_field

from .ast_helpers import (
    collect_identifiers,
    find_calls_in,
    get_callee_name,
    get_full_callee,
    get_member_object,
    get_member_property,
    is_conditional_ancestor,
    walk_tree,
)
from .models import AccessPath, GuardInfo, SanitizerInfo, TransformerInfo

logger = logging.getLogger(__name__)


@dataclass(eq=False)
class Definition:
    """A single assignment/definition of a variable."""

    variable: AccessPath
    line: int
    expression: str
    node: object  # ASTNode or None (for parameters)
    deps: frozenset[str]  # variable names this definition reads from
    branch_context: str  # "" | "if_true" | "if_false" | "loop"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Definition):
            return NotImplemented
        return (self.variable, self.line, self.expression) == (
            other.variable,
            other.line,
            other.expression,
        )

    def __hash__(self) -> int:
        return hash((self.variable, self.line, self.expression))


@dataclass
class ActiveDefs:
    """Currently active definitions per variable — the state during analysis."""

    defs: dict[str, set[Definition]] = dataclass_field(default_factory=dict)

    def define(self, var: str, defn: Definition) -> None:
        """Kill prior defs, add new one."""
        self.defs[var] = {defn}

    def fork(self) -> ActiveDefs:
        """Snapshot for branch entry."""
        return ActiveDefs({k: set(v) for k, v in self.defs.items()})

    def merge(self, other: ActiveDefs) -> None:
        """Merge at branch join — union of definitions."""
        for var, other_defs in other.defs.items():
            self.defs.setdefault(var, set()).update(other_defs)

    def reaching(self, var: str) -> set[Definition]:
        """Which definitions of var are currently active?"""
        return self.defs.get(var, set())


@dataclass
class WalkState:
    """Mutable state accumulated during walk_body."""

    rules: object  # TaintRuleSet
    ext: str
    grammar: object  # LanguageGrammar
    active: ActiveDefs = dataclass_field(default_factory=ActiveDefs)
    sanitizers: list[SanitizerInfo] = dataclass_field(default_factory=list)
    guards: list[GuardInfo] = dataclass_field(default_factory=list)
    unresolved: list[str] = dataclass_field(default_factory=list)
    transformers: list[TransformerInfo] = dataclass_field(default_factory=list)
    _next_order: int = 0


def walk_body(func_node, grammar, state: WalkState) -> None:
    """Walk a function body, building reaching definitions in state.active."""
    body = _get_body(func_node)
    if body is None:
        return
    _walk_stmts(body.children, grammar, state)


def _walk_stmts(stmts: list, grammar, state: WalkState) -> None:
    """Walk a list of statements, updating state."""
    assignment_types = set(grammar.assignment_types)
    conditional_types = set(grammar.conditional_types)
    call_types = set(grammar.call_types)

    for stmt in stmts:
        if stmt.type in assignment_types:
            _handle_assignment(stmt, grammar, state)
        elif stmt.type in conditional_types:
            _handle_conditional(stmt, grammar, state)
        elif stmt.type in ("for_statement", "while_statement", "for_in_statement"):
            _handle_loop(stmt, grammar, state)
        elif stmt.type == "expression_statement":
            _handle_expression_statement(
                stmt, grammar, state, assignment_types, call_types
            )
        elif stmt.type in ("lexical_declaration", "variable_declaration"):
            # JS: const x = ...; / let x = ...;
            for child in stmt.children:
                if child.type in assignment_types:
                    _handle_assignment(child, grammar, state)
        elif stmt.type == "block":
            _walk_stmts(stmt.children, grammar, state)


def _handle_expression_statement(stmt, grammar, state, assignment_types, call_types):
    """Handle expression_statement: may contain assignments or mutating calls."""
    for child in stmt.children:
        if child.type in assignment_types:
            _handle_assignment(child, grammar, state)
        elif child.type in call_types:
            _handle_mutating_call(child, grammar, state)


def _handle_assignment(node, grammar, state: WalkState) -> None:
    """Process an assignment, record definition, check for sanitizers."""
    pairs = _extract_assignment(node, grammar)
    if not pairs:
        return

    line = node.start_point[0] + 1
    expr_text = node.text.decode()

    for lhs_name, rhs_node in pairs:
        if not lhs_name or rhs_node is None:
            continue
        rhs_ids = frozenset(collect_identifiers(rhs_node))

        defn = Definition(
            variable=AccessPath(lhs_name, ()),
            line=line,
            expression=expr_text,
            node=node,
            deps=rhs_ids,
            branch_context="",
        )
        state.active.define(lhs_name, defn)

        # Check RHS calls for sanitizers and transformers
        call_types = set(grammar.call_types)
        for call_node in find_calls_in(rhs_node, call_types):
            _check_sanitizer(call_node, line, node, grammar, state)
            _check_transformer(call_node, line, grammar, state)


def _check_sanitizer(call_node, line, context_node, grammar, state):
    """Check if a call is a known sanitizer and record it."""
    callee = get_callee_name(call_node)
    if not callee:
        return
    callee_full = get_full_callee(call_node) or callee

    # Try full dotted name first, then short name (suffix indexing)
    san = state.rules.check_sanitizer(state.ext, callee_full)
    if san is None and callee_full != callee:
        san = state.rules.check_sanitizer(state.ext, callee)

    if san is not None:
        san.line = line
        san.conditional = is_conditional_ancestor(
            context_node, set(grammar.conditional_types)
        )
        san.discovery_order = state._next_order
        state._next_order += 1
        state.sanitizers.append(san)
    else:
        if callee_full and callee_full not in state.unresolved:
            state.unresolved.append(callee_full)


def _check_transformer(call_node, line, grammar, state: WalkState) -> None:
    """Check if a call is a known transformer and record it."""
    callee = get_callee_name(call_node)
    if not callee:
        return
    callee_full = get_full_callee(call_node) or callee

    result = state.rules.check_transformer(state.ext, callee_full)
    if result is None and callee_full != callee:
        result = state.rules.check_transformer(state.ext, callee)

    if result is not None:
        canonical_name, sets_state = result
        state.transformers.append(
            TransformerInfo(
                name=canonical_name,
                line=line,
                sets_state=sets_state,
                discovery_order=state._next_order,
            )
        )
        state._next_order += 1


def _handle_conditional(node, grammar, state: WalkState) -> None:
    """Handle if/elif/switch: fork-walk-merge."""
    # Check condition for guards
    condition = node.child_by_field_name("condition")
    if condition:
        _check_guards_in(condition, node, grammar, state)

    # Snapshot list lengths so we can identify items added per branch
    pre_san = len(state.sanitizers)
    pre_guard = len(state.guards)
    pre_unresolved = len(state.unresolved)
    pre_txf = len(state.transformers)

    # Fork for true branch — shallow-copy all mutable lists
    true_active = state.active.fork()
    true_state = WalkState(
        rules=state.rules,
        ext=state.ext,
        grammar=grammar,
        active=true_active,
        sanitizers=list(state.sanitizers),
        guards=list(state.guards),
        unresolved=list(state.unresolved),
        transformers=list(state.transformers),
        _next_order=state._next_order,
    )

    # Walk true branch (consequence)
    consequence = node.child_by_field_name("consequence") or node.child_by_field_name(
        "body"
    )
    if consequence:
        _walk_stmts(consequence.children, grammar, true_state)

    # Sync discovery_order counter so false branch continues from true branch
    state._next_order = max(state._next_order, true_state._next_order)

    # Walk false branch (alternative) on original state
    alternative = node.child_by_field_name("alternative")
    if alternative:
        if alternative.type in ("else_clause", "else"):
            body = alternative.child_by_field_name("body")
            if body:
                _walk_stmts(body.children, grammar, state)
            else:
                _walk_stmts(alternative.children, grammar, state)
        elif alternative.type in ("elif_clause", "if_statement"):
            _handle_conditional(alternative, grammar, state)
        else:
            _walk_stmts(alternative.children, grammar, state)

    # Merge at join point — active defs
    state.active.merge(true_active)

    # Merge branch lists — append items added in true branch
    state.sanitizers.extend(true_state.sanitizers[pre_san:])
    state.guards.extend(true_state.guards[pre_guard:])
    state.transformers.extend(true_state.transformers[pre_txf:])
    for call in true_state.unresolved[pre_unresolved:]:
        if call not in state.unresolved:
            state.unresolved.append(call)


def _check_guards_in(condition, parent_node, grammar, state):
    """Check if condition contains guard function calls."""
    call_types = set(grammar.call_types)
    for call_node in find_calls_in(condition, call_types):
        callee = get_callee_name(call_node)
        if not callee:
            continue
        callee_full = get_full_callee(call_node) or callee
        is_guard = state.rules.is_guard(state.ext, callee_full) or (
            callee_full != callee and state.rules.is_guard(state.ext, callee)
        )
        if is_guard:
            checked_var = _find_checked_variable(call_node)
            state.guards.append(
                GuardInfo(
                    name=callee_full,
                    line=parent_node.start_point[0] + 1,
                    variable=checked_var,
                )
            )


def _find_checked_variable(call_node) -> str:
    """Find which variable is being checked in a guard call's arguments."""
    args_node = call_node.child_by_field_name(
        "arguments"
    ) or call_node.child_by_field_name("argument_list")
    if not args_node:
        return ""
    for child in walk_tree(args_node):
        if child.type == "identifier":
            return child.text.decode()
    return ""


def _handle_loop(node, grammar, state: WalkState) -> None:
    """Handle for/while: two-pass approximation with pre-loop snapshot merge.

    For for-in/for-of loops, also defines the loop variable from the iterable.
    """
    snapshot = state.active.fork()

    # Define loop variable from the iterable (for x in items / for const x of items)
    if node.type in ("for_statement", "for_in_statement"):
        _define_loop_variable(node, grammar, state)

    body = node.child_by_field_name("body")
    if body:
        # First pass
        _walk_stmts(body.children, grammar, state)
        # Second pass (picks up loop-carried defs)
        _walk_stmts(body.children, grammar, state)

    # Merge with pre-loop snapshot (loop might not execute)
    state.active.merge(snapshot)


def _define_loop_variable(node, grammar, state: WalkState) -> None:
    """Define the loop variable from a for/for-in/for-of loop header.

    Python: for entry in entries:  -> left=identifier("entry"), right=identifier("entries")
    JS:     for (const item of items) -> left=identifier("item"), right=identifier("items")
    """
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if not left or not right:
        return

    line = node.start_point[0] + 1
    iterable_ids = frozenset(collect_identifiers(right))
    expr_text = right.text.decode()

    # Single identifier loop variable
    if left.type == "identifier":
        var_name = left.text.decode()
        defn = Definition(
            variable=AccessPath(var_name, ()),
            line=line,
            expression=expr_text,
            node=node,
            deps=iterable_ids,
            branch_context="loop",
        )
        state.active.define(var_name, defn)
    # Tuple unpacking in loop: for a, b in pairs:
    elif left.type in ("pattern_list", "tuple_pattern"):
        for child in left.children:
            if child.type == "identifier":
                var_name = child.text.decode()
                defn = Definition(
                    variable=AccessPath(var_name, ()),
                    line=line,
                    expression=expr_text,
                    node=node,
                    deps=iterable_ids,
                    branch_context="loop",
                )
                state.active.define(var_name, defn)
    # JS destructuring in loop: for (const { a, b } of items)
    elif left.type in ("object_pattern", "array_pattern"):
        for pair in _extract_destructuring(left, right):
            var_name, _ = pair
            defn = Definition(
                variable=AccessPath(var_name, ()),
                line=line,
                expression=expr_text,
                node=node,
                deps=iterable_ids,
                branch_context="loop",
            )
            state.active.define(var_name, defn)


_MUTATING_METHODS = frozenset({"append", "extend", "insert", "update", "add"})


def _handle_mutating_call(call_node, grammar, state: WalkState) -> None:
    """Handle obj.method(arg) calls that taint the receiver.

    For calls like items.append(tainted), add a reaching definition for
    'items' that depends on the call arguments.
    """
    func_ref = call_node.child_by_field_name("function")
    if func_ref is None:
        return
    member_types = set(grammar.member_access_types)
    if func_ref.type not in member_types:
        return
    method_name = get_member_property(func_ref)
    if method_name not in _MUTATING_METHODS:
        return
    obj_name = get_member_object(func_ref)
    if not obj_name:
        return

    # Collect identifiers from arguments as dependencies
    args_node = call_node.child_by_field_name(
        "arguments"
    ) or call_node.child_by_field_name("argument_list")
    arg_ids: frozenset[str] = frozenset()
    if args_node:
        arg_ids = frozenset(collect_identifiers(args_node))

    line = call_node.start_point[0] + 1
    expr_text = call_node.text.decode()

    # Merge (not kill) — the object retains its prior defs plus this new one
    defn = Definition(
        variable=AccessPath(obj_name, ()),
        line=line,
        expression=expr_text,
        node=call_node,
        deps=arg_ids,
        branch_context="",
    )
    state.active.defs.setdefault(obj_name, set()).add(defn)


# ---------------------------------------------------------------------------
# AST helpers (local to walker)
# ---------------------------------------------------------------------------


def _get_body(func_node) -> object | None:
    """Get the body node of a function."""
    body = func_node.child_by_field_name("body")
    if body:
        return body
    for child in func_node.children:
        if child.type in ("block", "statement_block"):
            return child
    return None


def _extract_assignment(node, grammar) -> list[tuple[str, object | None]]:
    """Extract (lhs_name, rhs_node) pairs from an assignment node.

    Returns a list because tuple unpacking and destructuring produce
    multiple variable bindings from a single assignment node.
    """
    # JS variable_declarator: const x = ...; / const { a, b } = ...; / const [a, b] = ...;
    if node.type == "variable_declarator":
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None:
            return []
        if name_node.type == "identifier":
            return [(name_node.text.decode(), value_node)]
        # JS destructuring: object_pattern or array_pattern
        if name_node.type in ("object_pattern", "array_pattern"):
            return _extract_destructuring(name_node, value_node)
        return []

    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if not left or not right:
        return []

    # Simple identifier LHS
    if left.type == "identifier":
        return [(left.text.decode(), right)]

    # Tuple/pattern unpacking: owner, repo = expr1, expr2
    if left.type in ("pattern_list", "tuple_pattern"):
        names = [ch.text.decode() for ch in left.children if ch.type == "identifier"]
        # All unpacked variables depend on the full RHS expression
        return [(name, right) for name in names]

    # Member access on LHS: obj.field = value
    member_types = set(grammar.member_access_types)
    if left.type in member_types:
        prop = get_member_property(left)
        obj = get_member_object(left)
        if obj and prop:
            return [(f"{obj}.{prop}", right)]

    return []


def _extract_destructuring(pattern_node, value_node) -> list[tuple[str, object | None]]:
    """Extract variable names from JS object_pattern or array_pattern."""
    results = []
    for child in pattern_node.children:
        if child.type == "identifier":
            results.append((child.text.decode(), value_node))
        elif child.type == "shorthand_property_identifier_pattern":
            results.append((child.text.decode(), value_node))
        elif child.type == "pair_pattern":
            # { key: value } — the value is the binding
            val = child.child_by_field_name("value")
            if val and val.type == "identifier":
                results.append((val.text.decode(), value_node))
        elif child.type == "assignment_pattern":
            # { x = default } or [x = default]
            left = child.child_by_field_name("left")
            if left and left.type == "identifier":
                results.append((left.text.decode(), value_node))
        elif child.type == "rest_pattern":
            # ...rest
            for sub in child.children:
                if sub.type == "identifier":
                    results.append((sub.text.decode(), value_node))
    return results
