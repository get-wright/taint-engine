"""Shared AST helper functions for the taint engine.

Extracted from walker.py so both walker and engine can import them
without reaching into private names.
"""

from __future__ import annotations


def walk_tree(node):
    """Depth-first walk of AST nodes."""
    yield node
    for child in node.children:
        yield from walk_tree(child)


def find_calls_in(node, call_types: set[str]) -> list:
    """Find all call nodes in a subtree."""
    calls = []
    for n in walk_tree(node):
        if n.type in call_types:
            calls.append(n)
    return calls


def get_callee_name(call_node) -> str:
    """Get the simple callee name from a call node."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref:
        return ""
    if func_ref.type == "identifier":
        return func_ref.text.decode()
    if func_ref.type in ("attribute", "member_expression"):
        attr = func_ref.child_by_field_name(
            "attribute"
        ) or func_ref.child_by_field_name("property")
        if attr:
            return attr.text.decode()
    return ""


def get_full_callee(call_node) -> str:
    """Get full dotted callee name (e.g. 're.match')."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref:
        return ""
    return func_ref.text.decode()


def get_member_property(member_node) -> str:
    """Extract property name from member-access node."""
    for field_name in ("property", "attribute", "field"):
        prop = member_node.child_by_field_name(field_name)
        if prop is not None:
            return prop.text.decode()
    return ""


def get_member_object(member_node) -> str:
    """Extract object name from member-access node."""
    obj = member_node.child_by_field_name("object")
    if obj and obj.type == "identifier":
        return obj.text.decode()
    return ""


def collect_identifiers(node) -> set[str]:
    """Collect all identifier names in a subtree."""
    ids: set[str] = set()
    for n in walk_tree(node):
        if n.type == "identifier":
            ids.add(n.text.decode())
    return ids


def is_conditional_ancestor(node, conditional_types: set[str]) -> bool:
    """Check if node is inside a conditional block."""
    current = node.parent
    while current is not None:
        if current.type in conditional_types:
            return True
        if current.type in (
            "function_definition",
            "function_declaration",
            "method_definition",
            "method_declaration",
            "arrow_function",
        ):
            break
        current = current.parent
    return False
