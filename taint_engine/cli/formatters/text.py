"""Human-readable text formatter for taint flows."""

from __future__ import annotations

from typing import Optional

from ...models import TaintFlow


def format_text(flow: Optional[TaintFlow], *, file_path: str) -> str:
    """Format a taint flow as human-readable text."""
    if flow is None:
        return f"No taint flow found in {file_path}"

    lines: list[str] = []

    source_expr = flow.source.expression
    sink_expr = flow.sink.expression
    lines.append(f"Taint Flow: {source_expr} \u2192 {sink_expr}")
    lines.append("")

    for step in flow.path:
        kind_tag = f"[{step.kind}]"
        lines.append(f"  {kind_tag:<14} line {step.line}:  {step.expression}")

    lines.append("")

    if flow.inferred:
        lines.append(f"  Sink type: {flow.inferred.sink_type}")

    if flow.sanitizers:
        sanitizer_names = ", ".join(s.name for s in flow.sanitizers)
        lines.append(f"  Sanitizers: {sanitizer_names}")
    else:
        lines.append("  Sanitizers: none found")

    if flow.guards:
        guard_names = ", ".join(f"{g.name}({g.variable})" for g in flow.guards)
        lines.append(f"  Guards: {guard_names}")
    else:
        lines.append("  Guards: none found")

    if flow.confidence_factors:
        lines.append(f"  Confidence: {', '.join(flow.confidence_factors)}")

    lines.append(f"  Cross-file hops: {len(flow.cross_file_hops)}")

    return "\n".join(lines)
