from taint_engine.sanitizer_checker import check_known_sanitizer, is_conditional_ancestor


def test_known_sanitizer_xss():
    result = check_known_sanitizer("html.escape")
    assert result is not None
    assert result.cwe_categories == ["*"]
    assert "html" in result.removes
    assert result.sets_state == "html-encoded"
    assert result.verified is False


def test_known_sanitizer_sqli():
    result = check_known_sanitizer("parameterize")
    assert result is not None
    assert "sql" in result.removes
    assert result.sets_state == "parameterized"


def test_known_sanitizer_cmdi():
    result = check_known_sanitizer("shlex.quote")
    assert result is not None
    assert "shell" in result.removes
    assert result.sets_state == "shell-quoted"


def test_known_sanitizer_path_traversal():
    result = check_known_sanitizer("os.path.basename")
    assert result is not None
    assert "path" in result.removes
    assert result.sets_state == "basename-only"


def test_unknown_function_returns_none():
    result = check_known_sanitizer("my_custom_function")
    assert result is None


def test_known_sanitizer_case_insensitive():
    result = check_known_sanitizer("HtmlSpecialChars")
    assert result is not None


def test_is_conditional_ancestor_true(tmp_path):
    import tree_sitter_python as ts_python
    from tree_sitter import Language, Parser
    code = b"def f(x):\n    if True:\n        y = html_escape(x)\n    return y"
    parser = Parser(Language(ts_python.language()))
    tree = parser.parse(code)
    root = tree.root_node
    call_node = _find_call_node(root, "html_escape")
    assert call_node is not None
    assert is_conditional_ancestor(call_node, ("if_statement", "try_statement")) is True


def test_is_conditional_ancestor_false(tmp_path):
    import tree_sitter_python as ts_python
    from tree_sitter import Language, Parser
    code = b"def f(x):\n    y = html_escape(x)\n    return y"
    parser = Parser(Language(ts_python.language()))
    tree = parser.parse(code)
    root = tree.root_node
    call_node = _find_call_node(root, "html_escape")
    assert call_node is not None
    assert is_conditional_ancestor(call_node, ("if_statement", "try_statement")) is False


def _find_call_node(node, callee_name):
    if node.type == "call":
        func = node.child_by_field_name("function")
        if func and func.text.decode() == callee_name:
            return node
    for child in node.children:
        result = _find_call_node(child, callee_name)
        if result:
            return result
    return None
