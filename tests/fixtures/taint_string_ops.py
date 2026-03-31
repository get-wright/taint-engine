# Line numbers are critical for tests — do not add/remove lines


def fstring_propagation(request):
    user_input = request.args.get("q")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)


def concat_propagation(request):
    user_input = request.args.get("q")
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)


def format_propagation(request):
    user_input = request.args.get("q")
    query = "SELECT * FROM users WHERE name = '{}'".format(user_input)
    cursor.execute(query)
