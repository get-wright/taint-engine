# WARNING: Line numbers are load-bearing — tests assert against specific lines.
# Do not reformat or add/remove lines without updating test expectations.

import html
import base64


def wrong_sanitizer_for_context(user_input):
    safe = html.escape(user_input)
    cursor.execute("SELECT * FROM t WHERE name=" + safe)


def sanitization_invalidated(user_input):
    safe = html.escape(user_input)
    decoded = base64.b64decode(safe)
    response.write(decoded)


def correct_sanitization(user_input):
    safe = html.escape(user_input)
    response.write(safe)


def unknown_sink_all_sanitizers(user_input):
    safe = html.escape(user_input)
    some_unknown_func(safe)


def label_detection_sql(user_input):
    cursor.execute("SELECT * FROM t WHERE name=" + user_input)


def label_detection_ssrf(url):
    requests.get(url)


def try_except_flow(user_input):
    try:
        result = process(user_input)
    except Exception as e:
        cursor.execute(user_input)


def with_statement_flow(user_path):
    with open(user_path) as fh:
        content = fh.read()
    cursor.execute(content)


def augmented_assignment_flow(a, b):
    x = a
    x += b
    cursor.execute(x)
