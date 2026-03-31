# Line numbers are critical for tests — do not add/remove lines
import re


def guarded_sink(request):
    url = request.args.get("url")
    if re.match(r"^https://trusted\.com", url):
        requests.get(url)


def guard_with_return(request):
    url = request.args.get("url")
    if not re.match(r"^https://", url):
        return "bad url"
    requests.get(url)


def unguarded_sink(request):
    url = request.args.get("url")
    requests.get(url)
