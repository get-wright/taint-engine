def helper(x):
    return x.strip()

def sanitize(val):
    return val.replace("<", "&lt;")
