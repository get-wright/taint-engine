"""Human-readable text formatter for taint flows."""

from __future__ import annotations

from typing import Optional

from ...models import SanitizerInfo, TaintFlow


def _sanitizer_display(san: SanitizerInfo) -> str:
    """Format a single sanitizer with effectiveness info."""
    if san.effective:
        state_suffix = f", state: {san.sets_state}" if san.sets_state else ""
        return f"{san.name} (effective{state_suffix})"

    if san.invalidated_by:
        return (
            f"{san.name} (INEFFECTIVE"
            f" \u2014 state changed to '{san.invalidated_by}')"
        )
    label_hint = ", ".join(san.removes) if san.removes and san.removes != ["*"] else ""
    if label_hint:
        return (
            f"{san.name} (INEFFECTIVE"
            f" \u2014 does not address '{label_hint}' sinks)"
        )
    return f"{san.name} (INEFFECTIVE)"


def _flow_state_chain(flow: TaintFlow) -> str | None:
    """Build the 'raw → html-encoded → ...' state chain if label tracking is active."""
    if not flow.active_label:
        return None

    states: list[str] = ["raw"]
    for san in sorted(flow.sanitizers, key=lambda s: s.discovery_order):
        if san.sets_state:
            states.append(san.sets_state)
    for tfm in sorted(flow.transformers, key=lambda t: t.discovery_order):
        states.append(tfm.sets_state)

    if flow.final_state and states[-1] != flow.final_state:
        states.append(flow.final_state)

    if len(states) < 2:
        return None

    chain = " \u2192 ".join(states)
    expected = flow.active_label
    return f"  Flow state: {chain} (sink expects: {expected})"


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
        for san in flow.sanitizers:
            lines.append(f"  Sanitizer: {_sanitizer_display(san)}")
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

    state_chain = _flow_state_chain(flow)
    if state_chain:
        lines.append(state_chain)

    return "\n".join(lines)
