"""Taint engine data models.

Canonical home for all taint-related dataclasses. These were originally
defined in src/models/analysis.py and are re-exported from there for
backward compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class AccessPath:
    """A variable path like 'obj.field' for field-sensitive taint tracking."""

    base: str
    selectors: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        if self.selectors:
            return f"{self.base}.{'.'.join(self.selectors)}"
        return self.base

    def with_field(self, field_name: str) -> AccessPath:
        if len(self.selectors) >= 2:
            return self
        return AccessPath(self.base, self.selectors + (field_name,))


@dataclass
class FlowStep:
    """One step in a taint flow trace."""

    variable: str
    line: int
    expression: str
    kind: (
        str  # "source" | "parameter" | "assignment" | "call_result" | "return" | "sink"
    )

    def to_dict(self) -> dict:
        return {
            "variable": self.variable,
            "line": self.line,
            "expression": self.expression,
            "kind": self.kind,
        }

    @classmethod
    def from_dict(cls, d: dict) -> FlowStep:
        return cls(
            variable=d["variable"],
            line=d["line"],
            expression=d["expression"],
            kind=d["kind"],
        )


@dataclass
class SanitizerInfo:
    """A sanitizer found in the taint path."""

    name: str
    line: int
    cwe_categories: list[str]
    conditional: bool
    verified: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "line": self.line,
            "cwe_categories": self.cwe_categories,
            "conditional": self.conditional,
            "verified": self.verified,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SanitizerInfo:
        return cls(
            name=d["name"],
            line=d["line"],
            cwe_categories=d["cwe_categories"],
            conditional=d["conditional"],
            verified=d["verified"],
        )


@dataclass
class GuardInfo:
    """A guard function call that restricts a tainted variable's domain."""

    name: str
    line: int
    variable: str

    def to_dict(self) -> dict:
        return {"name": self.name, "line": self.line, "variable": self.variable}

    @classmethod
    def from_dict(cls, d: dict) -> GuardInfo:
        return cls(name=d["name"], line=d["line"], variable=d["variable"])


@dataclass
class InferredSinkSource:
    """Sink/source inferred from finding metadata when rule lacks explicit taint mode."""

    sink_expression: str
    sink_type: str
    expected_sources: list[str]
    inferred_from: str

    def to_dict(self) -> dict:
        return {
            "sink_expression": self.sink_expression,
            "sink_type": self.sink_type,
            "expected_sources": self.expected_sources,
            "inferred_from": self.inferred_from,
        }

    @classmethod
    def from_dict(cls, d: dict) -> InferredSinkSource:
        return cls(
            sink_expression=d["sink_expression"],
            sink_type=d["sink_type"],
            expected_sources=d["expected_sources"],
            inferred_from=d["inferred_from"],
        )


@dataclass
class CrossFileHop:
    """A cross-file resolution step in the taint chain."""

    callee: str
    file: str
    line: int
    action: str  # "propagates" | "sanitizes" | "transforms" | "unknown"
    sub_flow: Optional[TaintFlow] = None

    def to_dict(self) -> dict:
        return {
            "callee": self.callee,
            "file": self.file,
            "line": self.line,
            "action": self.action,
            "sub_flow": self.sub_flow.to_dict() if self.sub_flow else None,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CrossFileHop:
        sub = TaintFlow.from_dict(d["sub_flow"]) if d.get("sub_flow") else None
        return cls(
            callee=d["callee"],
            file=d["file"],
            line=d["line"],
            action=d["action"],
            sub_flow=sub,
        )


@dataclass
class TaintFlow:
    """Complete taint flow trace for a single finding."""

    path: list[FlowStep]
    sanitizers: list[SanitizerInfo] = field(default_factory=list)
    unresolved_calls: list[str] = field(default_factory=list)
    cross_file_hops: list[CrossFileHop] = field(default_factory=list)
    confidence_factors: list[str] = field(default_factory=list)
    inferred: Optional[InferredSinkSource] = None
    guards: list[GuardInfo] = field(default_factory=list)

    @property
    def source(self) -> FlowStep:
        return self.path[0]

    @property
    def sink(self) -> FlowStep:
        return self.path[-1]

    def to_dict(self) -> dict:
        return {
            "path": [s.to_dict() for s in self.path],
            "sanitizers": [s.to_dict() for s in self.sanitizers],
            "unresolved_calls": self.unresolved_calls,
            "cross_file_hops": [h.to_dict() for h in self.cross_file_hops],
            "confidence_factors": self.confidence_factors,
            "inferred": self.inferred.to_dict() if self.inferred else None,
            "guards": [g.to_dict() for g in self.guards],
        }

    @classmethod
    def from_dict(cls, d) -> TaintFlow | None:
        if d is None:
            return None
        return cls(
            path=[FlowStep.from_dict(s) for s in d["path"]],
            sanitizers=[SanitizerInfo.from_dict(s) for s in d.get("sanitizers", [])],
            unresolved_calls=d.get("unresolved_calls", []),
            cross_file_hops=[
                CrossFileHop.from_dict(h) for h in d.get("cross_file_hops", [])
            ],
            confidence_factors=d.get("confidence_factors", []),
            inferred=InferredSinkSource.from_dict(d["inferred"])
            if d.get("inferred")
            else None,
            guards=[GuardInfo.from_dict(g) for g in d.get("guards", [])],
        )
