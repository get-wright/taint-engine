"""Detect known sanitizers and check conditional placement.

This module delegates to the JSON rule system for sanitizer lookup.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .models import SanitizerInfo
from .rules import TaintRuleSet, load_rules

_DEFAULT_RULES: TaintRuleSet | None = None


def _get_default_rules() -> TaintRuleSet:
    """Lazily load the default rule set."""
    global _DEFAULT_RULES
    if _DEFAULT_RULES is None:
        rules_dir = Path(__file__).parent / "rules"
        _DEFAULT_RULES = load_rules(str(rules_dir))
    return _DEFAULT_RULES


def check_known_sanitizer(callee_name: str) -> Optional[SanitizerInfo]:
    """Check if a callee is a known sanitizer using the JSON rules.

    Tries all language rule sets. Returns the first match.
    """
    rules = _get_default_rules()
    for ext in rules._by_ext:
        san = rules.check_sanitizer(ext, callee_name)
        if san is not None:
            return san
    return None


def is_conditional_ancestor(node, conditional_types: tuple[str, ...]) -> bool:
    """Check if a node is nested inside a conditional block."""
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
            "constructor_declaration",
        ):
            break
        current = current.parent
    return False
