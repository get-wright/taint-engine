"""Tests for taint_engine/rules — rule loading and querying."""

import json
import os

from taint_engine.rules import load_rules, TaintRuleSet, LanguageRules

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "taint_engine", "rules")


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------


def test_load_rules_from_directory():
    ruleset = load_rules(RULES_DIR)
    assert isinstance(ruleset, TaintRuleSet)


def test_for_extension_python():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".py")
    assert rules is not None
    assert isinstance(rules, LanguageRules)


def test_for_extension_js():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".js")
    assert rules is not None


def test_for_extension_tsx():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".tsx")
    assert rules is not None


def test_for_extension_unknown():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.for_extension(".unknown") is None


def test_load_single_file():
    ruleset = load_rules(os.path.join(RULES_DIR, "python.json"))
    assert ruleset.for_extension(".py") is not None


def test_load_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    try:
        load_rules(str(bad))
        assert False, "Should raise ValueError"
    except ValueError as e:
        assert "bad.json" in str(e)


def test_load_missing_required_field(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"language": "test"}))
    try:
        load_rules(str(bad))
        assert False, "Should raise ValueError"
    except ValueError as e:
        assert "extensions" in str(e).lower()


def test_load_missing_file():
    try:
        load_rules("/nonexistent/path/rules.json")
        assert False, "Should raise FileNotFoundError"
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# New labeled format: sources dict → flat sources frozenset
# ---------------------------------------------------------------------------


def test_labeled_sources_flatten_to_sources():
    """sources dict keys become the flat sources frozenset."""
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".py")
    assert rules is not None
    assert "request.args" in rules.sources
    assert "os.environ" in rules.sources
    assert "input()" in rules.sources


def test_python_additional_request_sources_present():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".py")
    assert rules is not None
    assert "request.FILES" in rules.sources
    assert "request.META" in rules.sources


def test_javascript_additional_request_sources_present():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".js")
    assert rules is not None
    assert "request.body" in rules.sources
    assert "request.query" in rules.sources


# ---------------------------------------------------------------------------
# Labeled sinks: flatten into call_sinks/property_sinks + labeled_sinks
# ---------------------------------------------------------------------------


def test_language_rules_has_labeled_sinks():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".py")
    assert rules is not None
    assert rules.labeled_sinks is not None
    assert "sql" in rules.labeled_sinks
    assert "html" in rules.labeled_sinks
    assert "shell" in rules.labeled_sinks


def test_javascript_has_expanded_sink_labels():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".js")
    assert rules is not None
    assert rules.labeled_sinks is not None
    assert "sql" in rules.labeled_sinks
    assert "path" in rules.labeled_sinks
    assert "redirect" in rules.labeled_sinks
    assert "shell" in rules.labeled_sinks


def test_labeled_sinks_call_property_structure():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".py")
    assert rules is not None
    sql_sinks = rules.labeled_sinks["sql"]
    assert "call" in sql_sinks
    assert "cursor.execute" in sql_sinks["call"]


def test_labeled_sinks_flatten_to_call_sinks():
    """All call entries across labels are flattened into call_sinks."""
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_call_sink(".py", "eval") is True
    assert ruleset.is_call_sink(".py", "cursor.execute") is True
    assert ruleset.is_call_sink(".py", "os.system") is True
    assert ruleset.is_call_sink(".py", "print") is False


def test_labeled_sinks_flatten_to_property_sinks():
    """All property entries across labels are flattened into property_sinks."""
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_property_sink(".py", "innerHTML") is True
    assert ruleset.is_property_sink(".py", "outerHTML") is True


def test_python_html_response_sinks_present():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_call_sink(".py", "HttpResponse") is True
    assert ruleset.is_call_sink(".py", "HttpResponseBadRequest") is True


def test_python_raw_sql_sinks_present():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_call_sink(".py", "RawSQL") is True
    assert ruleset.is_call_sink(".py", "raw") is True


def test_javascript_expanded_call_sinks_present():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_call_sink(".js", "sequelize.query") is True
    assert ruleset.is_call_sink(".js", "res.redirect") is True
    assert ruleset.is_call_sink(".js", "res.sendFile") is True
    assert ruleset.is_call_sink(".js", "child_process.exec") is True


def test_is_property_sink_js():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_property_sink(".js", "innerHTML") is True
    assert ruleset.is_property_sink(".js", "textContent") is False
    assert ruleset.is_property_sink(".go", "innerHTML") is False


# ---------------------------------------------------------------------------
# Sanitizer labels and states
# ---------------------------------------------------------------------------


def test_language_rules_has_sanitizer_labels():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".py")
    assert rules is not None
    assert rules.sanitizer_labels is not None
    assert "html.escape" in rules.sanitizer_labels
    labels = rules.sanitizer_labels["html.escape"]
    assert "html" in labels


def test_language_rules_has_sanitizer_states():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".py")
    assert rules is not None
    assert rules.sanitizer_states is not None
    assert "html.escape" in rules.sanitizer_states
    assert rules.sanitizer_states["html.escape"] == "html-encoded"


def test_check_sanitizer_returns_removes_and_sets_state():
    """check_sanitizer populates removes and sets_state on SanitizerInfo."""
    ruleset = load_rules(RULES_DIR)
    san = ruleset.check_sanitizer(".py", "html.escape")
    assert san is not None
    assert san.name == "html.escape"
    assert "html" in san.removes
    assert san.sets_state == "html-encoded"


def test_check_sanitizer_int_removes_multiple_labels():
    ruleset = load_rules(RULES_DIR)
    san = ruleset.check_sanitizer(".py", "int")
    assert san is not None
    assert "sql" in san.removes
    assert "html" in san.removes
    assert san.sets_state == "int"


def test_check_sanitizer_cwe_categories_star():
    """cwe_categories is now ['*'] since label-based matching supersedes CWE."""
    ruleset = load_rules(RULES_DIR)
    san = ruleset.check_sanitizer(".py", "html.escape")
    assert san is not None
    assert san.cwe_categories == ["*"]


def test_check_sanitizer_unknown():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.check_sanitizer(".py", "my_func") is None


def test_case_insensitive_sanitizer_lookup():
    ruleset = load_rules(RULES_DIR)
    san = ruleset.check_sanitizer(".py", "HTML.Escape")
    assert san is not None


def test_case_insensitive_sanitizer_preserves_original_name():
    ruleset = load_rules(RULES_DIR)
    san = ruleset.check_sanitizer(".py", "HTML.Escape")
    assert san.name == "HTML.Escape"


def test_get_sanitizer_state():
    ruleset = load_rules(RULES_DIR)
    state = ruleset.get_sanitizer_state(".py", "shlex.quote")
    assert state == "shell-quoted"


def test_get_sanitizer_state_suffix_match():
    """Suffix matching for sanitizer state lookup."""
    ruleset = load_rules(RULES_DIR)
    state = ruleset.get_sanitizer_state(".py", "quote")
    assert state == "shell-quoted"


def test_get_sanitizer_state_unknown():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.get_sanitizer_state(".py", "unknown_func") is None


def test_get_sanitizer_state_unknown_ext():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.get_sanitizer_state(".unknown", "html.escape") is None


# ---------------------------------------------------------------------------
# Accepted states
# ---------------------------------------------------------------------------


def test_get_accepted_states():
    ruleset = load_rules(RULES_DIR)
    accepted = ruleset.get_accepted_states(".py", "sql")
    assert accepted is not None
    assert "parameterized" in accepted
    assert "int" in accepted
    assert "float" in accepted


def test_get_accepted_states_html():
    ruleset = load_rules(RULES_DIR)
    accepted = ruleset.get_accepted_states(".py", "html")
    assert accepted is not None
    assert "html-encoded" in accepted


def test_get_accepted_states_unknown_label():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.get_accepted_states(".py", "nonexistent_label") is None


def test_get_accepted_states_unknown_ext():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.get_accepted_states(".unknown", "sql") is None


# ---------------------------------------------------------------------------
# Transformers
# ---------------------------------------------------------------------------


def test_language_rules_has_transformers():
    ruleset = load_rules(RULES_DIR)
    rules = ruleset.for_extension(".py")
    assert rules is not None
    assert rules.transformers is not None
    assert "base64.b64decode" in rules.transformers
    assert rules.transformers["base64.b64decode"] == "raw-bytes"


def test_check_transformer_exact():
    ruleset = load_rules(RULES_DIR)
    result = ruleset.check_transformer(".py", "base64.b64decode")
    assert result is not None
    name, state = result
    assert name == "base64.b64decode"
    assert state == "raw-bytes"


def test_check_transformer_suffix():
    """Suffix indexing: 'b64decode' matches 'base64.b64decode'."""
    ruleset = load_rules(RULES_DIR)
    result = ruleset.check_transformer(".py", "b64decode")
    assert result is not None
    name, state = result
    assert name == "base64.b64decode"
    assert state == "raw-bytes"


def test_check_transformer_json_loads():
    ruleset = load_rules(RULES_DIR)
    result = ruleset.check_transformer(".py", "json.loads")
    assert result is not None
    _, state = result
    assert state == "parsed-object"


def test_check_transformer_unknown():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.check_transformer(".py", "unknown_func") is None


def test_check_transformer_unknown_ext():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.check_transformer(".unknown", "json.loads") is None


# ---------------------------------------------------------------------------
# Guards (unchanged)
# ---------------------------------------------------------------------------


def test_is_guard():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_guard(".py", "re.match") is True
    assert ruleset.is_guard(".py", "print") is False


def test_is_guard_urlsplit():
    """New guard added in labeled format."""
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_guard(".py", "urlsplit") is True


# ---------------------------------------------------------------------------
# Temp file with new format
# ---------------------------------------------------------------------------


def test_load_new_format_temp_file(tmp_path):
    """Verify new-format JSON loads correctly from a temp file."""
    rule = {
        "language": "test",
        "extensions": [".test"],
        "sources": {
            "input()": ["html", "sql"],
        },
        "sinks": {
            "html": {
                "call": ["render"],
                "property": ["innerHTML"],
                "accepts": ["escaped"],
            },
        },
        "sanitizers": [
            {"name": "esc", "removes": ["html"], "sets_state": "escaped"},
        ],
        "transformers": [
            {"name": "decode", "sets_state": "raw"},
        ],
        "guards": ["check"],
    }
    f = tmp_path / "test.json"
    f.write_text(json.dumps(rule))
    ruleset = load_rules(str(f))

    rules = ruleset.for_extension(".test")
    assert rules is not None
    assert "input()" in rules.sources
    assert rules.labeled_sinks is not None
    assert "html" in rules.labeled_sinks
    assert "render" in rules.call_sinks
    assert "innerHTML" in rules.property_sinks
    assert rules.sanitizer_labels is not None
    assert "esc" in rules.sanitizer_labels
    assert rules.sanitizer_states["esc"] == "escaped"
    assert rules.transformers is not None
    assert "decode" in rules.transformers
    assert rules.transformers["decode"] == "raw"

    san = ruleset.check_sanitizer(".test", "esc")
    assert san is not None
    assert san.removes == ["html"]
    assert san.sets_state == "escaped"
    assert san.cwe_categories == ["*"]

    result = ruleset.check_transformer(".test", "decode")
    assert result is not None
    assert result == ("decode", "raw")

    accepted = ruleset.get_accepted_states(".test", "html")
    assert accepted is not None
    assert "escaped" in accepted

    assert ruleset.is_guard(".test", "check") is True
