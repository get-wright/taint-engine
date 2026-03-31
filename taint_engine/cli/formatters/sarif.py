"""SARIF v2.1.0 formatter for taint flows.

Produces output compatible with GitHub code scanning and VS Code SARIF Viewer.
"""

from __future__ import annotations

import json

from ...models import TaintFlow


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
                "text": f"Taint flow from {flow.source.expression} to {flow.sink.expression}",
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
                "message": {"text": f"sanitizer: {san.name}"},
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
