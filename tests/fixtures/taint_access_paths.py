# Line numbers are critical for tests — do not add/remove lines


def field_taint(request):
    obj = SomeClass()
    obj.bad = request.args.get("q")
    obj.safe = "constant"
    cursor.execute(obj.bad)


def field_safe(request):
    obj = SomeClass()
    obj.bad = request.args.get("q")
    obj.safe = "constant"
    cursor.execute(obj.safe)


def container_taint(request):
    items = []
    items.append(request.args.get("q"))
    cursor.execute(items)
