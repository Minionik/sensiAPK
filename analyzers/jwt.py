import re, base64, json

def analyze(item):

    line = item.get("line") or item.get("value","")

    tokens = re.findall(r"[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", line)

    for t in tokens:
        try:
            parts = t.split(".")
            if len(parts) != 3:
                continue

            payload = base64.urlsafe_b64decode(parts[1] + '==')
            data = json.loads(payload)

            return {
                "type": "jwt",
                "value": t,
                "payload": data,
                "source": item["source"],
                "file": item.get("file"),
                "path": item.get("path"),
                "line": item.get("line")
            }
        except:
            continue

    return None