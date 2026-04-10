import base64
import re
import math

def entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])

def enrich(f):

    val = f.get("value", "")

    f["length"] = len(val)
    f["entropy"] = round(entropy(val), 2) if val else 0

    # Base64 decode
    if re.match(r'^[A-Za-z0-9+/=]+$', val):
        try:
            decoded = base64.b64decode(val + "===")
            f["decoded"] = decoded.decode(errors="ignore")
        except:
            pass

    # Classification (basic)
    if "." in val and val.count(".") == 2:
        f["classification"] = "jwt"
    elif len(val) > 20 and f["entropy"] > 3.5:
        f["classification"] = "high_entropy_token"
    else:
        f["classification"] = "low_value"

    return f