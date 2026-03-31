# Line numbers are critical for tests — do not add/remove lines without updating tests
import os


def straight_line(request):
    user_input = request.args.get("q")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)


def kill_semantics(request):
    x = request.args.get("q")
    x = "safe_value"
    cursor.execute(x)


def branch_merge(request, flag):
    if flag:
        x = request.args.get("q")
    else:
        x = "safe"
    cursor.execute(x)


def branch_no_else(request, flag):
    x = "default"
    if flag:
        x = request.args.get("q")
    cursor.execute(x)


def loop_taint(request):
    items = []
    for i in range(10):
        items.append(request.args.get("q"))
    cursor.execute(items)


def unknown_call_propagation(request):
    tainted = request.args.get("q")
    result = helper(tainted)
    cursor.execute(result)


def nested_branch(request, a, b):
    if a:
        if b:
            x = request.args.get("q")
        else:
            x = "safe_b"
    else:
        x = "safe_a"
    cursor.execute(x)


def tuple_unpacking(request):
    url = request.args.get("url")
    owner, repo = url.split("/")[3], url.split("/")[4]
    cursor.execute(owner)


def for_loop_variable(request):
    entries = request.args.getlist("items")
    for entry in entries:
        cursor.execute(entry)
