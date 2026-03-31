# WARNING: Line numbers are load-bearing — tests assert against specific lines.
# Do not reformat or add/remove lines without updating test expectations.


def source_false_positive_string(x):
    msg = "mentions request.args in a string"
    cursor.execute(msg)


def source_false_positive_validate():
    result = validate_input()
    cursor.execute(result)


def keyword_arg_filtering(timeout):
    url = "http://safe.com"
    requests.get(url, timeout=5)
