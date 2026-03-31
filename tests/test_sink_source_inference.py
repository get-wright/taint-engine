from taint_engine.sink_source_inference import infer_sink_source, parse_cwe_ids


def test_parse_cwe_ids_from_full_strings():
    cwe_list = [
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')",
    ]
    assert parse_cwe_ids(cwe_list) == ["CWE-89", "CWE-79"]


def test_parse_cwe_ids_bare():
    assert parse_cwe_ids(["CWE-89"]) == ["CWE-89"]


def test_parse_cwe_ids_empty():
    assert parse_cwe_ids([]) == []


def test_infer_from_cwe_sqli():
    result = infer_sink_source(check_id="python.django.security.sqli", cwe_list=["CWE-89: SQL Injection"], flagged_line="cursor.execute(query)")
    assert result.sink_type == "sql_query"
    assert result.inferred_from == "cwe"
    assert "user_input" in result.expected_sources or "external_data" in result.expected_sources


def test_infer_from_cwe_xss():
    result = infer_sink_source(check_id="javascript.express.xss", cwe_list=["CWE-79: XSS"], flagged_line="res.send(userInput)")
    assert result.sink_type == "html_output"


def test_infer_from_cwe_cmdi():
    result = infer_sink_source(check_id="python.lang.cmdi", cwe_list=["CWE-78: OS Command Injection"], flagged_line="os.system(cmd)")
    assert result.sink_type == "command_exec"


def test_infer_from_cwe_path_traversal():
    result = infer_sink_source(check_id="python.lang.path-traversal", cwe_list=["CWE-22: Path Traversal"], flagged_line="open(user_path)")
    assert result.sink_type == "file_path"


def test_infer_from_rule_id_fallback():
    result = infer_sink_source(check_id="python.django.security.sql-injection.raw-query", cwe_list=[], flagged_line="RawSQL(query)")
    assert result.sink_type == "sql_query"
    assert result.inferred_from == "rule_id"


def test_infer_from_code_pattern():
    result = infer_sink_source(check_id="custom.rule", cwe_list=[], flagged_line="subprocess.run(cmd, shell=True)")
    assert result.sink_type == "command_exec"
    assert result.inferred_from == "code_pattern"


def test_infer_generic_fallback():
    result = infer_sink_source(check_id="custom.unknown", cwe_list=[], flagged_line="some_function(x)")
    assert result.sink_type == "generic"
    assert result.inferred_from == "heuristic"
