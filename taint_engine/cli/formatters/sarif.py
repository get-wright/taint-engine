"""SARIF v2.1.0 formatter for taint flows.

Produces output compatible with GitHub code scanning and VS Code SARIF Viewer.
"""

from __future__ import annotations

import json

from ...models import SanitizerInfo, TaintFlow


def _sanitizer_message(san: SanitizerInfo) -> str:
    """Build a human-readable sanitizer message including effectiveness."""
    if san.effective:
        state_suffix = f", state: {san.sets_state}" if san.sets_state else ""
        return f"sanitizer: {san.name} (effective{state_suffix})"
    if san.invalidated_by:
        return (
            f"sanitizer: {san.name} (INEFFECTIVE"
            f" \u2014 state changed to '{san.invalidated_by}')"
        )
    return f"sanitizer: {san.name} (INEFFECTIVE)"


def format_sarif(flows: list[TaintFlow], *, file_path: str) -> str:
    """Format taint flows as SARIF v2.1.0 JSON."""
    results = []
    for flow in flows:
        thread_flow_locations = []
        for step in flow.path:
            thread_flow_locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": step.line},
                    },
                    "message": {"text": f"{step.kind}: {step.expression}"},
                },
            })

        result = {
            "ruleId": flow.inferred.sink_type if flow.inferred else "unknown",
            "level": "warning",
            "message": {
                "text": (
                    f"Taint flow from {flow.source.expression}"
                    f" to {flow.sink.expression}"
                ),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": flow.sink.line},
                    },
                }
            ],
            "codeFlows": [
                {
                    "threadFlows": [
                        {"locations": thread_flow_locations}
                    ],
                }
            ],
        }

        related = []
        for san in flow.sanitizers:
            related.append({
                "id": len(related),
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": san.line},
                },
                "message": {"text": _sanitizer_message(san)},
            })
        for guard in flow.guards:
            related.append({
                "id": len(related),
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": guard.line},
                },
                "message": {"text": f"guard: {guard.name}({guard.variable})"},
            })
        if related:
            result["relatedLocations"] = related

        props: dict = {}
        if flow.active_label is not None:
            props["active_label"] = flow.active_label
        if flow.final_state is not None:
            props["final_state"] = flow.final_state
        if flow.transformers:
            props["transformers"] = [t.to_dict() for t in flow.transformers]
        if props:
            result["properties"] = props

        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "taint-trace",
                        "version": "0.1.0",
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
