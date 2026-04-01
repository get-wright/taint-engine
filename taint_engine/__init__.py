"""Taint engine — decoupled taint tracing with JSON rules.

Public API:
    from taint_engine import load_rules
    from taint_engine import FlowStep, SanitizerInfo, TaintFlow, GuardInfo, AccessPath
    from taint_engine import trace_taint_flow
"""

from .models import (
    AccessPath,
    CrossFileHop,
    FlowStep,
    GuardInfo,
    InferredSinkSource,
    SanitizerInfo,
    Selector,
    TaintFlow,
)
from .rules import TaintRuleSet, LanguageRules, load_rules
from .parser_protocol import ASTNode, LanguageGrammar, Parser

__all__ = [
    "AccessPath",
    "ASTNode",
    "CrossFileHop",
    "FlowStep",
    "GuardInfo",
    "InferredSinkSource",
    "LanguageGrammar",
    "LanguageRules",
    "load_rules",
    "Parser",
    "SanitizerInfo",
    "Selector",
    "TaintFlow",
    "TaintRuleSet",
    "trace_taint_flow",
]


def __getattr__(name: str):
    # Lazy import required to break circular dependency:
    #   src.taint.__init__ → engine → sink_source_inference
    #   → src.models.analysis → src.taint.models (partially initialized)
    # Eager import of engine triggers this chain before __init__ finishes.
    if name == "trace_taint_flow":
        from .engine import trace_taint_flow

        return trace_taint_flow
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
