from taint_engine.sink_source_inference import infer_sink_source


def test_infer_from_rule_id_sqli():
    result = infer_sink_source(check_id="python.django.security.sqli", flagged_line="cursor.execute(query)")
    assert result.sink_type == "sql_query"
    assert result.inferred_from == "rule_id"
    assert "user_input" in result.expected_sources or "external_data" in result.expected_sources


def test_infer_from_rule_id_xss():
    result = infer_sink_source(check_id="javascript.express.xss", flagged_line="res.send(userInput)")
    assert result.sink_type == "html_output"


def test_infer_from_rule_id_cmdi():
    result = infer_sink_source(check_id="python.lang.cmdi", flagged_line="os.system(cmd)")
    assert result.sink_type == "command_exec"


def test_infer_from_rule_id_path_traversal():
    result = infer_sink_source(check_id="python.lang.path-traversal", flagged_line="open(user_path)")
    assert result.sink_type == "file_path"


def test_infer_from_rule_id_sql_injection():
    result = infer_sink_source(check_id="python.django.security.sql-injection.raw-query", flagged_line="RawSQL(query)")
    assert result.sink_type == "sql_query"
    assert result.inferred_from == "rule_id"


def test_infer_from_code_pattern():
    result = infer_sink_source(check_id="custom.rule", flagged_line="subprocess.run(cmd, shell=True)")
    assert result.sink_type == "command_exec"
    assert result.inferred_from == "code_pattern"


def test_infer_generic_fallback():
    result = infer_sink_source(check_id="custom.unknown", flagged_line="some_function(x)")
    assert result.sink_type == "generic"
    assert result.inferred_from == "heuristic"
