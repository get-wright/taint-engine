"""Tests for src/taint/rules — rule loading and querying."""

import json
import os
from taint_engine.rules import load_rules, TaintRuleSet, LanguageRules

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "taint_engine", "rules")


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


def test_is_source_python():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_source(".py", "request.args") is True
    assert ruleset.is_source(".py", "totally_safe") is False


def test_is_call_sink():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_call_sink(".py", "eval") is True
    assert ruleset.is_call_sink(".py", "print") is False


def test_is_property_sink():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_property_sink(".js", "innerHTML") is True
    assert ruleset.is_property_sink(".js", "textContent") is False
    assert ruleset.is_property_sink(".go", "innerHTML") is False


def test_check_sanitizer():
    ruleset = load_rules(RULES_DIR)
    san = ruleset.check_sanitizer(".py", "html.escape")
    assert san is not None
    assert san.name == "html.escape"
    assert "CWE-79" in san.cwe_categories


def test_check_sanitizer_unknown():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.check_sanitizer(".py", "my_func") is None


def test_check_sanitizer_no_neutralizes():
    """Sanitizer without neutralizes should have cwe_categories=['*']."""
    import tempfile

    rule = {
        "language": "test",
        "extensions": [".test"],
        "sources": [],
        "sanitizers": [{"name": "custom_sanitize"}],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(rule, f)
        f.flush()
        ruleset = load_rules(f.name)
    os.unlink(f.name)
    san = ruleset.check_sanitizer(".test", "custom_sanitize")
    assert san is not None
    assert san.cwe_categories == ["*"]


def test_is_guard():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.is_guard(".py", "re.match") is True
    assert ruleset.is_guard(".py", "print") is False


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
    bad.write_text(json.dumps({"language": "test"}))  # missing extensions
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


def test_case_insensitive_sanitizer_lookup():
    ruleset = load_rules(RULES_DIR)
    san = ruleset.check_sanitizer(".py", "HTML.Escape")
    assert san is not None


def test_case_insensitive_sanitizer_preserves_original_name():
    ruleset = load_rules(RULES_DIR)
    san = ruleset.check_sanitizer(".py", "HTML.Escape")
    assert san.name == "HTML.Escape"  # preserves caller's casing
