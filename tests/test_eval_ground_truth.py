"""Eval harness for source recovery ground truth.

Each case is a real-world taint flow from the spec's example repos.
Tests skip when the fixture files are absent (eval repos not cloned).
Initially xfail — flip to passing as implementation improves.
"""

import os

import pytest

from taint_engine.engine import trace_taint_flow
from taint_engine.rules import load_rules
from tests.parser_helpers import TreeSitterParser

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "taint_engine", "rules")
PARSER = TreeSitterParser()
RULES = load_rules(RULES_DIR)

GROUND_TRUTH = [
    {
        "id": "juice-shop-login",
        "file": "tmp/eval_repos/juice-shop-master/routes/login.ts",
        "function": "login",
        "sink_line": 34,
        "check_id": "typescript.sqli",
        "expected_source_contains": ["req.body"],
    },
    {
        "id": "juice-shop-redirect",
        "file": "tmp/eval_repos/juice-shop-master/routes/redirect.ts",
        "function": "redirect",
        "sink_line": 19,
        "check_id": "typescript.redirect",
        "expected_source_contains": ["query"],
    },
    {
        "id": "juice-shop-fileserver",
        "file": "tmp/eval_repos/juice-shop-master/routes/fileServer.ts",
        "function": "fileServer",
        "sink_line": 33,
        "check_id": "typescript.path",
        "expected_source_contains": ["params"],
    },
    {
        "id": "nodegoat-redirect",
        "file": "tmp/eval_repos/NodeGoat-master/app/routes/index.js",
        "function": "anonymous",
        "sink_line": 72,
        "check_id": "javascript.redirect",
        "expected_source_contains": ["req.query"],
    },
    {
        "id": "pygoat-eval-mitre",
        "file": "tmp/eval_repos/pygoat-master/introduction/mitre.py",
        "function": "mitre",
        "sink_line": 218,
        "check_id": "python.eval",
        "expected_source_contains": ["request.POST"],
    },
    {
        "id": "pygoat-eval-views",
        "file": "tmp/eval_repos/pygoat-master/introduction/views.py",
        "function": "cmd_lab",
        "sink_line": 460,
        "check_id": "python.eval",
        "expected_source_contains": ["request.POST"],
    },
    {
        "id": "pygoat-raw-sql",
        "file": "tmp/eval_repos/pygoat-master/introduction/views.py",
        "function": "sql_lab",
        "sink_line": 878,
        "check_id": "python.sqli",
        "expected_source_contains": ["request.POST"],
    },
    {
        "id": "flask-base-login-redirect",
        "file": "tmp/eval_repos_round2/flask-base-master/app/account/views.py",
        "function": "login",
        "sink_line": 43,
        "check_id": "python.redirect",
        "expected_source_contains": ["request.args"],
    },
    {
        "id": "simple-login-redirect",
        "file": "tmp/eval_repos_round2/app-master/app/dashboard/views/alias_transfer.py",
        "function": "alias_transfer",
        "sink_line": 55,
        "check_id": "python.redirect",
        "expected_source_contains": ["request"],
    },
    {
        "id": "simple-login-call-result",
        "file": "tmp/eval_repos_round2/app-master/app/alias_utils.py",
        "function": "export_aliases",
        "sink_line": 412,
        "check_id": "python.ssrf",
        "expected_source_contains": ["si"],
    },
    {
        "id": "django-realworld-password",
        "file": "tmp/eval_repos_round2/django-realworld-example-app-master/conduit/apps/authentication/serializers.py",
        "function": "create",
        "sink_line": 161,
        "check_id": "python.auth",
        "expected_source_contains": ["validated_data"],
    },
]


def _resolve_file(rel_path: str) -> str:
    """Resolve eval repo file path relative to project root."""
    project_root = os.path.join(os.path.dirname(__file__), "..")
    return os.path.join(project_root, rel_path)


@pytest.mark.parametrize("case", GROUND_TRUTH, ids=lambda c: c["id"])
def test_ground_truth(case):
    file_path = _resolve_file(case["file"])
    if not os.path.exists(file_path):
        pytest.skip(f"Eval repo file not found: {case['file']}")

    flow = trace_taint_flow(
        file_path=file_path,
        function_name=case["function"],
        sink_line=case["sink_line"],
        check_id=case["check_id"],
        rules=RULES,
        parser=PARSER,
    )

    # The flow should exist
    assert flow is not None, f"No flow found for {case['id']}"

    # Source should be identified (not just a minimal fallback)
    assert flow.source.kind in ("source", "parameter"), (
        f"Expected source/parameter, got {flow.source.kind} for {case['id']}"
    )

    # Source should reference the expected taint origin
    source_text = f"{flow.source.variable} {flow.source.expression}"
    for expected in case["expected_source_contains"]:
        assert expected in source_text, (
            f"Expected '{expected}' in source for {case['id']}, "
            f"got variable='{flow.source.variable}' expression='{flow.source.expression}'"
        )
