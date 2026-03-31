# Line numbers are critical for tests — do not add/remove lines without updating tests
import os
from html import escape


def vulnerable_sqli(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)

def sanitized_xss(user_input):
    safe = escape(user_input)
    return f"<div>{safe}</div>"

def conditional_sanitizer(user_input, flag):
    data = user_input
    if flag:
        data = escape(data)
    return f"<div>{data}</div>"

def hardcoded_no_source():
    query = "SELECT * FROM config WHERE key = 'version'"
    cursor.execute(query)

def multi_step_flow(request):
    raw = request.args.get("q")
    trimmed = raw.strip()
    query = "SELECT * FROM users WHERE name = '" + trimmed + "'"
    cursor.execute(query)

def calls_unknown(user_input):
    processed = external_lib.process(user_input)
    cursor.execute(processed)

def multiline_call(request):
    url = request.args.get("url")
    owner = url.split("/")[0]
    repo = url.split("/")[1]
    result = requests.get(
        f"https://api.example.com/repos/{owner}/{repo}",
        timeout=5,
        headers={"Accept": "application/json"},
    )


def response_data_sink(request):
    user_input = request.args.get("data")
    response = make_response()
    response.data = user_input
