import time

def validate(f):

    score = 0
    reasons = []

    if f.get("classification") == "jwt":
        payload = f.get("payload", {})
        exp = payload.get("exp")

        if exp:
            if exp < int(time.time()):
                reasons.append("expired token")
            else:
                score += 30
                reasons.append("valid expiry")

    if f.get("entropy", 0) > 3.5:
        score += 30
        reasons.append("high entropy")

    if f.get("related", 0) > 1:
        score += 20
        reasons.append("reused token")

    if f.get("length", 0) > 20:
        score += 10

    f["score"] = score
    f["validation"] = reasons

    return f