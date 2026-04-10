import re

def is_real(v):
    if not v or len(v) < 10:
        return False
    if v.lower() in ["true","false","null"]:
        return False
    return True

def analyze(item):

    line = item.get("line") or item.get("value","")

    match = re.search(r'(?i)(token|key|secret|password)[^"\']{0,10}["\']?([^"\']+)', line)

    if not match:
        return None

    val = match.group(2)

    if not is_real(val):
        return None

    return {
        "type": "secret",
        "value": val,
        "source": item["source"],
        "file": item.get("file"),
        "path": item.get("path"),
        "line": item.get("line")
    }