"""Infer sink type and expected sources from Semgrep finding metadata."""

from __future__ import annotations

import re

from .models import InferredSinkSource

_CWE_ID_RE = re.compile(r"(CWE-\d+)")

CWE_SINK_MAP: dict[str, str] = {
    "CWE-89": "sql_query",
    "CWE-564": "sql_query",
    "CWE-79": "html_output",
    "CWE-87": "html_output",
    "CWE-78": "command_exec",
    "CWE-77": "command_exec",
    "CWE-88": "command_exec",
    "CWE-22": "file_path",
    "CWE-23": "file_path",
    "CWE-36": "file_path",
    "CWE-73": "file_path",
    "CWE-94": "code_exec",
    "CWE-95": "code_exec",
    "CWE-96": "code_exec",
    "CWE-918": "ssrf",
    "CWE-601": "redirect",
    "CWE-611": "xxe",
    "CWE-502": "deserialization",
    "CWE-327": "crypto",
    "CWE-338": "crypto",
}

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


def parse_cwe_ids(cwe_list: list[str]) -> list[str]:
    ids = []
    for entry in cwe_list:
        m = _CWE_ID_RE.search(entry)
        if m:
            ids.append(m.group(1))
    return ids


def infer_sink_source(
    check_id: str, cwe_list: list[str], flagged_line: str
) -> InferredSinkSource:
    # 1. CWE mapping
    cwe_ids = parse_cwe_ids(cwe_list)
    for cwe_id in cwe_ids:
        if cwe_id in CWE_SINK_MAP:
            sink_type = CWE_SINK_MAP[cwe_id]
            return InferredSinkSource(
                sink_expression=flagged_line,
                sink_type=sink_type,
                expected_sources=_EXPECTED_SOURCES.get(sink_type, ["user_input"]),
                inferred_from="cwe",
            )

    # 2. Rule ID keywords
    rule_lower = check_id.lower()
    for keyword, sink_type in _RULE_ID_KEYWORDS.items():
        if keyword in rule_lower:
            return InferredSinkSource(
                sink_expression=flagged_line,
                sink_type=sink_type,
                expected_sources=_EXPECTED_SOURCES.get(sink_type, ["user_input"]),
                inferred_from="rule_id",
            )

    # 3. Code pattern heuristic
    for pattern, sink_type in _CODE_PATTERNS:
        if pattern.search(flagged_line):
            return InferredSinkSource(
                sink_expression=flagged_line,
                sink_type=sink_type,
                expected_sources=_EXPECTED_SOURCES.get(sink_type, ["user_input"]),
                inferred_from="code_pattern",
            )

    # 4. Generic fallback
    return InferredSinkSource(
        sink_expression=flagged_line,
        sink_type="generic",
        expected_sources=["user_input", "external_data"],
        inferred_from="heuristic",
    )
