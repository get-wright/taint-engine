"""Infer sink type and expected sources from check ID and code patterns."""

from __future__ import annotations

import re

from .models import InferredSinkSource

_EXPECTED_SOURCES: dict[str, list[str]] = {
    "sql_query": ["user_input", "external_data", "request_parameter"],
    "html_output": ["user_input", "external_data", "database_value"],
    "command_exec": ["user_input", "external_data", "environment_variable"],
    "file_path": ["user_input", "external_data"],
    "code_exec": ["user_input", "external_data"],
    "ssrf": ["user_input", "external_url"],
    "redirect": ["user_input", "external_url"],
    "xxe": ["user_input", "external_xml"],
    "deserialization": ["user_input", "external_data"],
    "crypto": [],
    "generic": ["user_input", "external_data"],
}

_RULE_ID_KEYWORDS: dict[str, str] = {
    "sql": "sql_query",
    "sqli": "sql_query",
    "xss": "html_output",
    "command": "command_exec",
    "cmdi": "command_exec",
    "exec": "command_exec",
    "path-traversal": "file_path",
    "file-inclusion": "file_path",
    "ssrf": "ssrf",
    "redirect": "redirect",
    "xxe": "xxe",
    "deserializ": "deserialization",
}

_CODE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(cursor|db|conn)\.(execute|query|raw)", re.I), "sql_query"),
    (re.compile(r"(RawSQL|raw_sql|rawQuery)", re.I), "sql_query"),
    (re.compile(r"(subprocess|os\.system|os\.popen|exec|Popen)", re.I), "command_exec"),
    (re.compile(r"(eval|exec)\s*\(", re.I), "code_exec"),
    (
        re.compile(
            r"(\.send|\.write|\.render|innerHTML|dangerouslySetInnerHTML)", re.I
        ),
        "html_output",
    ),
    (re.compile(r"(open|read_file|write_file|Path\()", re.I), "file_path"),
    (re.compile(r"(redirect|Location\s*:)", re.I), "redirect"),
    (re.compile(r"(requests\.get|urllib|http\.request|fetch)\s*\(", re.I), "ssrf"),
]


def infer_sink_source(
    check_id: str, flagged_line: str,
) -> InferredSinkSource:
    """Infer sink type and expected sources from check ID and code patterns."""
    # 1. Rule ID keywords
    rule_lower = check_id.lower()
    for keyword, sink_type in _RULE_ID_KEYWORDS.items():
        if keyword in rule_lower:
            return InferredSinkSource(
                sink_expression=flagged_line,
                sink_type=sink_type,
                expected_sources=_EXPECTED_SOURCES.get(sink_type, ["user_input"]),
                inferred_from="rule_id",
            )

    # 2. Code pattern heuristic
    for pattern, sink_type in _CODE_PATTERNS:
        if pattern.search(flagged_line):
            return InferredSinkSource(
                sink_expression=flagged_line,
                sink_type=sink_type,
                expected_sources=_EXPECTED_SOURCES.get(sink_type, ["user_input"]),
                inferred_from="code_pattern",
            )

    # 3. Generic fallback
    return InferredSinkSource(
        sink_expression=flagged_line,
        sink_type="generic",
        expected_sources=["user_input", "external_data"],
        inferred_from="heuristic",
    )
