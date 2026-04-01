# Line numbers are critical for tests — do not add/remove lines without updating tests


def accessor_source(request):
    y = request.args.get("next")
    redirect(y)


def member_read_source(request):
    u = request.url
    redirect(u)


def inline_accessor_sink(request):
    redirect(request.args.get("next") or url_for("main.index"))


def call_result_in_sink(si):
    make_response(si.getvalue())


def alias_chain(request):
    q = request.args.get("q")
    query = q
    cursor.execute(query)
